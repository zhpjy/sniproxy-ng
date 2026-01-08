mod config;
mod tls;
mod tcp;
mod quic;
mod socks5;
mod router;

use anyhow::Result;
use tracing::{info, error, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志系统
    init_logging();

    info!("Starting sniproxy-ng...");

    // 加载配置
    let config = match Config::load("config.toml") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to load config.toml: {}", e);
            eprintln!("Please create config.toml based on config.toml.example");
            std::process::exit(1);
        }
    };
    info!("Configuration loaded successfully");

    info!("Server will listen on {}", config.server.listen_addr);
    info!("SOCKS5 backend: {}", config.socks5.addr);
    if config.rules.allow.is_empty() {
        info!("Whitelist: allowing all domains (no rules configured)");
    } else {
        info!("Whitelist: {} domain patterns", config.rules.allow.len());
    }

    // 检查端口是否需要权限
    if config.server.listen_addr.port() < 1024 {
        warn!("Warning: Port {} requires root privileges. Run with sudo if binding fails.", config.server.listen_addr.port());
    }

    // 启动 TCP 监听器 (HTTP/1.1 + TLS)
    let mut tcp_handle = tokio::spawn(tcp::run(config.clone()));

    // 启动 UDP 监听器 (QUIC/HTTP3)
    let mut quic_handle = tokio::spawn(quic::run(config.clone()));

    // 设置 Ctrl+C 信号处理
    let ctrl_c = tokio::signal::ctrl_c();

    tokio::select! {
        // Ctrl+C 信号
        _ = ctrl_c => {
            info!("Received shutdown signal, shutting down...");
        }
        // TCP 任务结束（通常不应该发生）
        result = &mut tcp_handle => {
            match result {
                Ok(Ok(())) => info!("TCP task ended normally"),
                Ok(Err(e)) => error!("TCP task failed: {}", e),
                Err(e) => error!("TCP task panicked: {}", e),
            }
        }
        // QUIC 任务结束（通常不应该发生）
        result = &mut quic_handle => {
            match result {
                Ok(Ok(())) => info!("QUIC task ended normally"),
                Ok(Err(e)) => error!("QUIC task failed: {}", e),
                Err(e) => error!("QUIC task panicked: {}", e),
            }
        }
    }

    info!("sniproxy-ng shutdown complete");
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
