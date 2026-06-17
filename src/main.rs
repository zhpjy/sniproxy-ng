mod config;
mod http;
mod quic;
mod relay;
mod router;
mod socks5;
mod tcp;
mod tls;

use anyhow::Result;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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

    info!("SOCKS5 backend: {}", config.socks5.addr);
    if config.rules.allow.is_empty() {
        info!("Whitelist: allowing all domains (no rules configured)");
    } else {
        info!("Whitelist: {} domain patterns", config.rules.allow.len());
    }

    // 创建路由器
    let router = std::sync::Arc::new(router::Router::new(config.clone()));
    let mut tasks = Vec::new();

    // HTTPS 监听器 (TCP + QUIC)
    if let Some(addr) = config.server.listen_https_addr {
        info!("HTTPS listener configured on {}", addr);

        // 检查端口是否需要权限
        if addr.port() < 1024 {
            warn!(
                "Warning: Port {} requires root privileges. Run with sudo if binding fails.",
                addr.port()
            );
        }

        let https_config = config.clone();
        // TCP 监听器
        let tcp_config = https_config.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = tcp::run(tcp_config).await {
                error!("TCP listener error: {}", e);
            }
        }));

        // UDP 监听器 (QUIC/HTTP3)
        match should_start_quic(&https_config).await {
            Ok(true) => {
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = quic::run(https_config).await {
                        error!("QUIC listener error: {}", e);
                    }
                }));
            }
            Ok(false) => {
                info!("QUIC/HTTP3 listener disabled; clients should fall back to HTTPS/TCP");
            }
            Err(e) => {
                error!("QUIC startup check failed: {}", e);
            }
        }
    }

    // HTTP 监听器
    if let Some(addr) = config.server.listen_http_addr {
        info!("HTTP listener configured on {}", addr);

        // 检查端口是否需要权限
        if addr.port() < 1024 {
            warn!(
                "Warning: Port {} requires root privileges. Run with sudo if binding fails.",
                addr.port()
            );
        }

        let http_config = config.clone();
        let http_router = router.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = http::run(http_config, http_router).await {
                error!("HTTP listener error: {}", e);
            }
        }));
    }

    // 检查是否至少配置了一个监听器
    if tasks.is_empty() {
        anyhow::bail!(
            "No listener configured. Please set listen_https_addr or listen_http_addr in config."
        );
    }

    // 设置 Ctrl+C 信号处理
    let ctrl_c = tokio::signal::ctrl_c();

    tokio::select! {
        // Ctrl+C 信号
        _ = ctrl_c => {
            info!("Received shutdown signal, shutting down...");
        }
        // 等待任意任务结束
        result = async {
            for task in tasks {
                task.await.ok();
            }
            Ok::<(), anyhow::Error>(())
        } => {
            if let Err(e) = result {
                error!("Task error: {}", e);
            }
        }
    }

    info!("sniproxy-ng shutdown complete");
    Ok(())
}

async fn should_start_quic(config: &Config) -> Result<bool> {
    let mode = std::env::var("SNIPROXY_QUIC_MODE").unwrap_or_else(|_| "auto".to_string());

    match mode.as_str() {
        "off" => Ok(false),
        "on" => {
            if let Err(e) = quic::session::probe_socks5_udp_relay(&config.socks5).await {
                warn!(
                    "SOCKS5 UDP relay probe failed, but SNIPROXY_QUIC_MODE=on; starting QUIC anyway: {}",
                    e
                );
            }
            Ok(true)
        }
        "auto" => match quic::session::probe_socks5_udp_relay(&config.socks5).await {
            Ok(()) => {
                info!("SOCKS5 UDP relay probe succeeded; enabling QUIC/HTTP3");
                Ok(true)
            }
            Err(e) => {
                warn!(
                    "SOCKS5 UDP relay probe failed; disabling QUIC/HTTP3 so clients can fall back to HTTPS/TCP: {}",
                    e
                );
                Ok(false)
            }
        },
        other => anyhow::bail!(
            "Invalid SNIPROXY_QUIC_MODE '{}'; expected auto, on, or off",
            other
        ),
    }
}

/// 初始化日志系统
fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let formatting_layer = fmt::layer().with_target(false).with_thread_ids(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(formatting_layer)
        .init();
}
