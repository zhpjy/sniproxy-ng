mod config;
mod tls;
mod tcp;
mod quic;
mod socks5;

use anyhow::Result;
use tracing::{info, error};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志系统
    init_logging();

    info!("Starting sniproxy-ng...");

    // 加载配置
    let config = Config::load("config.toml")?;
    info!("Configuration loaded successfully");

    info!("Server listening on {}", config.server.listen_addr);
    info!("SOCKS5 backend: {}", config.socks5.addr);

    // 启动 TCP 监听器 (HTTP/1.1 + TLS)
    let tcp_handle = tokio::spawn(tcp::run(config.clone()));

    // 启动 UDP 监听器 (QUIC/HTTP3)
    let quic_handle = tokio::spawn(quic::run(config.clone()));

    // 等待任务完成
    tokio::select! {
        result = tcp_handle => {
            if let Err(e) = result {
                error!("TCP task failed: {}", e);
            }
        }
        result = quic_handle => {
            if let Err(e) = result {
                error!("QUIC task failed: {}", e);
            }
        }
    }

    Ok(())
}

/// 初始化日志系统
fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let formatting_layer = fmt::layer()
        .with_target(false)
        .with_thread_ids(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(formatting_layer)
        .init();
}
