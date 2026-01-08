//! QUIC/HTTP3 代理模块
//!
//! 本模块提供 QUIC Initial Packet 的 SNI 提取功能。
//!
//! # 架构
//!
//! - [`parser`]: QUIC Initial Packet 解析 (提取 DCID, Version 等)
//! - [`crypto`]: 密钥派生 (HKDF) 和解密 (AES-GCM)
//! - [`error`]: 错误类型定义
//!
//! # 使用流程
//!
//! 1. 解析 QUIC Initial Packet 提取 DCID
//! 2. 从 DCID 派生 Initial Keys (key, iv, hp_key)
//! 3. 移除 Header Protection
//! 4. 解密 CRYPTO Frame
//! 5. 解析 TLS ClientHello 提取 SNI
//!
//! # 限制
//!
//! - 不支持 ECH (Encrypted ClientHello)
//! - 仅支持 QUIC v1 (0x00000001)
//! - 无状态解析 (不处理跨多个 Initial packets 的分片)

pub mod error;
pub mod parser;
pub mod crypto;
pub mod header;
pub mod decrypt;

pub use error::{QuicError, Result};
pub use parser::{extract_dcid, parse_initial_header, InitialHeader};
pub use crypto::{derive_initial_keys, InitialKeys};
pub use header::{remove_header_protection, decode_packet_number};
pub use decrypt::extract_sni_from_quic_initial;

use crate::config::Config;
use anyhow::Result as AnyhowResult;
use tracing::{info, warn, debug};

/// 运行 QUIC/HTTP3 代理服务器
///
/// 接收 UDP packets，提取 SNI，路由到 SOCKS5 后端
pub async fn run(config: Config) -> AnyhowResult<()> {
    use tokio::net::UdpSocket;

    info!(
        "Starting QUIC/HTTP3 proxy server on {}",
        config.server.listen_addr
    );
    info!("QUIC SNI extraction module loaded");
    info!("Waiting for QUIC Initial packets...");

    // 绑定 UDP socket
    let socket = UdpSocket::bind(&config.server.listen_addr).await?;
    info!("UDP socket bound to {}", config.server.listen_addr);

    let mut buf = [0u8; 1500]; // MTU 1500

    loop {
        // 接收 UDP packet
        let (len, src_addr) = socket.recv_from(&mut buf).await?;

        if len == 0 {
            continue;
        }

        debug!("Received {} bytes from {}", len, src_addr);

        // 提取 SNI (这会修改 packet，所以使用 copy)
        let mut packet_copy = buf[..len].to_vec();
        match extract_sni_from_quic_initial(&mut packet_copy) {
            Ok(Some(sni)) => {
                info!(
                    "✅ Extracted SNI: '{}' from {}",
                    sni, src_addr
                );

                // TODO: 路由到 SOCKS5 后端
                // 这里需要：
                // 1. 根据路由规则确定后端
                // 2. 连接到 SOCKS5 代理
                // 3. 建立 UDP relay

                warn!("⚠️  SOCKS5 UDP relay not yet implemented");
            }
            Ok(None) => {
                debug!("No SNI found in packet from {}", src_addr);
            }
            Err(e) => {
                // 非致命错误，只记录警告
                warn!(
                    "⚠️  Failed to extract SNI from {}: {}",
                    src_addr, e
                );
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
        };

        // 这个测试只是检查编译，不实际运行
        assert!(true, "Module exports work");
    }
}
