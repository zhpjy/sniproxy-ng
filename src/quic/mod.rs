/// QUIC/HTTP3 代理模块
///
/// 由于 QUIC 协议中 TLS 1.3 ClientHello 是加密的,无法直接提取 SNI。
/// 本模块提供基础框架和文档说明。
use crate::config::Config;
use anyhow::Result;
use tracing::{info, warn};

/// 运行 QUIC/HTTP3 代理服务器
///
/// 当前限制:
/// - QUIC SNI 是加密的,无法直接提取
/// - 需要其他方式确定目标地址
pub async fn run(config: Config) -> Result<()> {
    info!("Starting QUIC/HTTP3 proxy server on {}", config.server.listen_addr);
    warn!("Note: QUIC SNI extraction is limited due to TLS 1.3 encryption");

    // TODO: 实现完整的 UDP 转发功能
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    Ok(())
}
