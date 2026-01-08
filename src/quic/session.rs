//! QUIC 会话管理
//!
//! 为每个 QUIC 连接 (DCID) 维护独立的 SOCKS5 UDP relay 会话。

use crate::config::Socks5Config;
use crate::router::Router;
use crate::socks5::udp::Socks5UdpClient;
use crate::quic::parser::extract_dcid;
use crate::quic::decrypt::extract_sni_from_quic_initial;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{info, debug, warn};
use fast_socks5::client::Socks5Datagram;

/// 会话配置
#[derive(Clone)]
pub struct QuicSessionConfig {
    /// 会话空闲超时
    pub idle_timeout: Duration,
    /// 会话清理间隔
    pub cleanup_interval: Duration,
}

impl Default for QuicSessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

/// QUIC 会话 - 对应一个 DCID
#[allow(dead_code)]
pub struct QuicSession {
    /// DCID (Destination Connection ID)
    pub dcid: Vec<u8>,
    /// 提取的 SNI
    pub sni: String,
    /// SOCKS5 UDP relay
    pub socks5_relay: Socks5Datagram<tokio::net::TcpStream>,
    /// SOCKS5 relay 地址
    pub relay_addr: SocketAddr,
    /// 客户端地址
    pub client_addr: SocketAddr,
    /// 最后活跃时间
    pub last_active: Instant,
    /// 创建时间
    pub created_at: Instant,
}

/// 会话管理器内部状态
struct SessionManagerInner {
    /// 活动会话: dcid -> session
    sessions: HashMap<Vec<u8>, QuicSession>,
    /// 会话配置
    config: QuicSessionConfig,
    /// 路由器 (白名单检查)
    router: Router,
    /// SOCKS5 配置
    socks5_config: Socks5Config,
    /// 本地 UDP socket
    socket: Arc<UdpSocket>,
}

/// 会话管理器
pub struct QuicSessionManager {
    /// 共享的内部状态
    inner: Arc<Mutex<SessionManagerInner>>,
    /// 配置 (用于 cleanup task)
    config: QuicSessionConfig,
}

impl QuicSessionManager {
    /// 创建新的会话管理器
    pub fn new(
        config: QuicSessionConfig,
        router: Router,
        socks5_config: Socks5Config,
        socket: Arc<UdpSocket>,
    ) -> Self {
        info!(
            "Created QUIC session manager: idle_timeout={:?}, cleanup_interval={:?}",
            config.idle_timeout, config.cleanup_interval
        );

        let inner = SessionManagerInner {
            sessions: HashMap::new(),
            config: config.clone(),
            router,
            socks5_config,
            socket,
        };

        Self {
            inner: Arc::new(Mutex::new(inner)),
            config,
        }
    }

    /// 处理 UDP 包
    ///
    /// 返回 Ok(true) 表示已转发，Ok(false) 表示未处理（非 QUIC 包）
    pub async fn handle_packet(&self, packet: &[u8], src: SocketAddr) -> Result<bool> {
        // 1. 提取 DCID
        let dcid = match extract_dcid(packet) {
            Ok(d) => d.to_vec(),
            Err(_) => {
                // 不是 QUIC Initial 包，忽略
                debug!("Not a QUIC Initial packet from {}", src);
                return Ok(false);
            }
        };

        // 2. 查找现有会话
        {
            let inner = self.inner.lock().await;
            if inner.sessions.contains_key(&dcid) {
                // 会话存在，需要更新活跃时间并转发
                drop(inner);
                return self.forward_to_existing_session(&dcid, packet).await;
            }
        }

        // 3. 会话不存在，尝试创建新会话
        self.create_and_forward_session(&dcid, packet, src).await
    }

    /// 转发到现有会话
    async fn forward_to_existing_session(&self, dcid: &[u8], packet: &[u8]) -> Result<bool> {
        // 获取会话中的 relay 地址
        let (_relay_addr, _socks5_relay) = {
            let mut inner = self.inner.lock().await;
            if let Some(session) = inner.sessions.get_mut(dcid) {
                session.last_active = Instant::now();
                // Socks5Datagram 不实现 Clone，但我们需要在锁外使用
                // 由于 QUIC session 创建后 relay 地址不变，我们直接通过 relay 发送
                (session.relay_addr, &session.socks5_relay as *const _ as usize)
            } else {
                return Ok(false);
            }
        };

        // 实际上我们需要使用 Socks5Datagram 发送，重新获取
        let result = {
            let inner = self.inner.lock().await;
            if let Some(session) = inner.sessions.get(dcid) {
                // 通过 SOCKS5 relay 发送包
                session
                    .socks5_relay
                    .send_to(packet, session.relay_addr)
                    .await
                    .map_err(|e| anyhow!("Failed to send via SOCKS5 relay: {}", e))?;
                Ok(true)
            } else {
                Ok(false)
            }
        };

        result
    }

    /// 创建新会话并转发
    async fn create_and_forward_session(
        &self,
        dcid: &[u8],
        packet: &[u8],
        src: SocketAddr,
    ) -> Result<bool> {
        // 提取 SNI
        let mut packet_copy = packet.to_vec();
        let sni = match extract_sni_from_quic_initial(&mut packet_copy)? {
            Some(s) => s,
            None => {
                debug!("No SNI found in packet from {}", src);
                return Ok(false);
            }
        };

        info!("New QUIC session request: DCID={:?}, SNI={}, client={}", dcid, sni, src);

        // 白名单检查
        {
            let inner = self.inner.lock().await;
            if !inner.router.is_allowed(&sni) {
                warn!("Domain {} not in whitelist, rejecting QUIC session from {}", sni, src);
                return Ok(false);
            }
        }

        // 创建 SOCKS5 UDP relay
        let (socks5_relay, relay_addr, _socket) = {
            let inner = self.inner.lock().await;
            let socket = Arc::clone(&inner.socket);

            let udp_client = if let (Some(username), Some(password)) =
                (&inner.socks5_config.username, &inner.socks5_config.password)
            {
                Socks5UdpClient::new(inner.socks5_config.addr.to_string())
                    .with_auth(username.clone(), password.clone())
            } else {
                Socks5UdpClient::new(inner.socks5_config.addr.to_string())
            };

            let (relay, relay_addr) = udp_client.associate().await?;
            (relay, relay_addr, socket)
        };

        info!(
            "Created QUIC session: DCID={:?}, SNI={}, relay={}",
            dcid, sni, relay_addr
        );

        // 创建会话
        let session = QuicSession {
            dcid: dcid.to_vec(),
            sni,
            socks5_relay,
            relay_addr,
            client_addr: src,
            last_active: Instant::now(),
            created_at: Instant::now(),
        };

        // 转发第一个包
        session
            .socks5_relay
            .send_to(packet, session.relay_addr)
            .await
            .map_err(|e| anyhow!("Failed to send via SOCKS5 relay: {}", e))?;

        // 保存会话
        {
            let mut inner = self.inner.lock().await;
            inner.sessions.insert(dcid.to_vec(), session);
        }

        Ok(true)
    }

    /// 清理过期会话
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let initial_count = inner.sessions.len();
        let idle_timeout = inner.config.idle_timeout;

        inner.sessions
            .retain(|_, session| now.duration_since(session.last_active) < idle_timeout);

        let removed = initial_count - inner.sessions.len();
        if removed > 0 {
            info!("Cleaned up {} expired QUIC sessions", removed);
        }

        removed
    }

    /// 获取会话数量
    #[allow(dead_code)]
    pub async fn session_count(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.sessions.len()
    }

    /// 启动会话清理任务
    pub fn spawn_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(manager.config.cleanup_interval);
            loop {
                interval.tick().await;
                manager.cleanup_expired_sessions().await;
            }
        })
    }
}

impl Clone for QuicSessionManager {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = QuicSessionConfig::default();
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
        assert_eq!(config.cleanup_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_dcid_key() {
        // DCID 用作 HashMap key，需要能正确比较
        let dcid1 = vec![0x01, 0x02, 0x03];
        let dcid2 = vec![0x01, 0x02, 0x03];
        let dcid3 = vec![0x01, 0x02, 0x04];

        assert_eq!(dcid1, dcid2);
        assert_ne!(dcid1, dcid3);

        // 可以用作 HashMap key
        let mut map = HashMap::new();
        map.insert(dcid1.clone(), "session1");
        assert_eq!(map.get(&dcid2), Some(&"session1"));
        assert_eq!(map.get(&dcid3), None);
    }
}
