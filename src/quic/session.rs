//! QUIC 会话管理
//!
//! 为每个 QUIC 连接 (DCID) 维护独立的 SOCKS5 UDP relay 会话。

use crate::config::Socks5Config;
use crate::router::Router;
use crate::socks5::udp::Socks5UdpClient;
use crate::quic::decrypt::extract_sni_from_quic_initial;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{info, debug, warn};
use tokio::sync::mpsc;

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
    /// 目标服务器地址（SNI 解析出来的 ip:port，通常是 :443）
    pub target_addr: SocketAddr,
    /// 客户端地址
    pub client_addr: SocketAddr,
    /// 发往该会话的客户端 QUIC 包（由会话任务负责通过 SOCKS5 UDP 发往 target_addr）
    pub tx: mpsc::Sender<Vec<u8>>,
    /// 最后活跃时间
    pub last_active: Instant,
    /// 创建时间
    pub created_at: Instant,
}

/// 会话管理器内部状态
struct SessionManagerInner {
    /// 活动会话: client_addr -> session
    ///
    /// 说明：QUIC 后续大量数据包会是 Short Header，无法可靠地从旁路解析出
    /// 连接 ID 长度/值来做无状态识别；因此我们采用更工程化的 5-tuple 方式：
    /// 一旦为某个 client_addr 建立会话，则转发该 client_addr 的全部 UDP 包。
    sessions: HashMap<SocketAddr, QuicSession>,
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
        // 1) 优先按 client_addr 查找现有会话（用于转发后续 Short Header 包）
        if self.has_session(src).await {
            return self.forward_to_existing_session(src, packet).await;
        }

        // 2) 无会话：只尝试从 QUIC Initial 提取 SNI 并建会话
        self.create_and_forward_session(packet, src).await
    }

    async fn has_session(&self, client: SocketAddr) -> bool {
        let inner = self.inner.lock().await;
        inner.sessions.contains_key(&client)
    }

    /// 转发到现有会话
    async fn forward_to_existing_session(&self, client: SocketAddr, packet: &[u8]) -> Result<bool> {
        let tx = {
            let mut inner = self.inner.lock().await;
            let Some(session) = inner.sessions.get_mut(&client) else {
                return Ok(false);
            };
            session.last_active = Instant::now();
            session.tx.clone()
        };

        tx.send(packet.to_vec())
            .await
            .map_err(|_| anyhow!("QUIC session task is gone (client={})", client))?;

        Ok(true)
    }

    /// 创建新会话并转发
    async fn create_and_forward_session(
        &self,
        packet: &[u8],
        src: SocketAddr,
    ) -> Result<bool> {
        // 仅处理 QUIC Initial。不是 Initial 直接忽略。
        let header = match crate::quic::parse_initial_header(packet) {
            Ok(h) => h,
            Err(_) => {
                debug!("Not a QUIC Initial packet from {}", src);
                return Ok(false);
            }
        };
        let dcid = header.dcid.to_vec();

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

        // 解析目标地址：SNI -> ip:443
        let target_addr = tokio::net::lookup_host((sni.as_str(), 443))
            .await
            .map_err(|e| anyhow!("Failed to resolve {}:443: {}", sni, e))?
            .next()
            .ok_or_else(|| anyhow!("No A/AAAA record for {}:443", sni))?;

        // 创建 SOCKS5 UDP relay
        let (socks5_relay, relay_addr, socket) = {
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
            "Created QUIC session: DCID={:?}, SNI={}, target={}, socks5_relay={}",
            dcid, sni, target_addr, relay_addr
        );

        // 会话任务：负责双向 UDP 转发
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        let dcid_for_task = dcid.to_vec();
        tokio::spawn(async move {
            let relay = socks5_relay;
            let mut buf = vec![0u8; 2048];

            loop {
                tokio::select! {
                    maybe_pkt = rx.recv() => {
                        let Some(pkt) = maybe_pkt else {
                            // sender dropped => session removed
                            debug!("QUIC session task exiting (dcid={:?})", dcid_for_task);
                            return;
                        };

                        // 注意：Socks5Datagram::send_to 的目标应该是“真实远端地址”，不是 SOCKS5 relay_addr
                        if let Err(e) = relay.send_to(&pkt, target_addr).await {
                            warn!("QUIC session send_to failed (dcid={:?}, target={}): {}", dcid_for_task, target_addr, e);
                            return;
                        }
                    }
                    recv_res = relay.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((n, _remote)) => {
                                if n == 0 {
                                    continue;
                                }
                                // 返回客户端：从同一个本地 UDP socket 发回，保持五元组一致
                                if let Err(e) = socket.send_to(&buf[..n], src).await {
                                    warn!("QUIC session failed to send back to client (dcid={:?}, client={}): {}", dcid_for_task, src, e);
                                    return;
                                }
                            }
                            Err(e) => {
                                warn!("QUIC session recv_from failed (dcid={:?}): {}", dcid_for_task, e);
                                return;
                            }
                        }
                    }
                }
            }
        });

        // 创建会话
        let session = QuicSession {
            dcid: dcid.to_vec(),
            sni,
            target_addr,
            client_addr: src,
            tx,
            last_active: Instant::now(),
            created_at: Instant::now(),
        };

        // 保存会话
        {
            let mut inner = self.inner.lock().await;
            inner.sessions.insert(src, session);
        }

        // 转发第一个包（通过会话 task）
        self.forward_to_existing_session(src, packet).await?;

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
