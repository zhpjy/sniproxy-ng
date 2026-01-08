use crate::config::Config;
use anyhow::Result;

/// 运行 QUIC/HTTP3 代理服务器
pub async fn run(config: Config) -> Result<()> {
    tracing::info!("Starting QUIC/HTTP3 proxy server on {}", config.server.listen_addr);

    // TODO: 实现 UDP 监听器和 QUIC SNI 提取
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    Ok(())
}
