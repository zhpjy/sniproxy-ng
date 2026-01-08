//! QUIC/HTTP3 代理模块
//!
//! 本模块提供 QUIC Initial Packet 的 SNI 提取功能和 UDP relay 会话管理。
//!
//! # 架构
//!
//! - [`parser`]: QUIC Initial Packet 解析 (提取 DCID, Version 等)
//! - [`crypto`]: 密钥派生 (HKDF) 和解密 (AES-GCM)
//! - [`error`]: 错误类型定义
//! - [`session`]: QUIC 会话管理 (DCID → SOCKS5 UDP relay)
//!
//! # 使用流程
//!
//! 1. 接收 UDP packet
//! 2. 提取 DCID
//! 3. 查找现有会话 → 转发包
//! 4. 无会话 → 提取 SNI → 白名单检查 → 创建 SOCKS5 UDP relay → 创建会话 → 转发包
//! 5. 定期清理过期会话
//!
//! # 限制
//!
//! - 不支持 ECH (Encrypted ClientHello)
//! - 仅支持 QUIC v1 (0x00000001)
//! - 每个会话独立维护，不跨 Initial packets 处理分片

pub mod error;
pub mod parser;
pub mod crypto;
pub mod header;
pub mod decrypt;
pub mod session;

pub use parser::parse_initial_header;
pub use crypto::derive_initial_keys;
pub use header::remove_header_protection;

use crate::config::Config;
use crate::router::Router;
use anyhow::Result as AnyhowResult;
use tracing::{info, warn, debug};
use tokio::net::UdpSocket;
use std::sync::Arc;

/// 运行 QUIC/HTTP3 代理服务器
///
/// 接收 UDP packets，提取 SNI，管理会话，通过 SOCKS5 UDP relay 转发流量
pub async fn run(config: Config) -> AnyhowResult<()> {
    info!(
        "Starting QUIC/HTTP3 proxy server on {}",
        config.server.listen_addr
    );
    info!("QUIC SNI extraction module loaded");
    info!("Waiting for QUIC Initial packets...");

    // 绑定 UDP socket
    let socket = Arc::new(UdpSocket::bind(&config.server.listen_addr).await?);
    info!("UDP socket bound to {}", config.server.listen_addr);

    // 创建路由器
    let router = Router::new(config.clone());

    // 创建会话管理器
    let session_config = session::QuicSessionConfig::default();
    let session_manager = session::QuicSessionManager::new(
        session_config,
        router,
        config.socks5,
        Arc::clone(&socket),
    );

    // 启动会话清理任务
    session_manager.spawn_cleanup_task();

    let mut buf = [0u8; 1500]; // MTU 1500

    loop {
        // 接收 UDP packet
        let (len, src_addr) = socket.recv_from(&mut buf).await?;

        if len == 0 {
            continue;
        }

        debug!("Received {} bytes from {}", len, src_addr);

        // 处理包 (会话管理器会处理 SNI 提取、白名单检查、relay 创建)
        match session_manager.handle_packet(&buf[..len], src_addr).await {
            Ok(forwarded) => {
                if forwarded {
                    debug!("Packet forwarded from {}", src_addr);
                } else {
                    debug!("Packet not forwarded (not a valid QUIC Initial or no SNI)");
                }
            }
            Err(e) => {
                // 非致命错误，只记录警告
                warn!("Failed to handle packet from {}: {}", src_addr, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // 确保所有公共 API 都可以正常导入
        use crate::quic::{
            crypto::derive_initial_keys,
            error::QuicError,
            parser::extract_dcid,
            session::{QuicSession, QuicSessionManager, QuicSessionConfig},
        };

        // 这个测试只是检查编译，不实际运行
        assert!(true, "Module exports work");
    }
}
