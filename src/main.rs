mod config;
mod http;
mod quic;
mod relay;
mod router;
mod socks5;
mod tcp;
mod tls;

use anyhow::Result;
use std::path::Path;
use tracing::{error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // 加载配置
    let config = match Config::load("config.toml") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to load config.toml: {}", e);
            eprintln!("Please create config.toml based on config.toml.example");
            std::process::exit(1);
        }
    };

    let _log_guard = init_logging(&config)?;

    info!("Starting sniproxy-ng...");
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
    let mode = std::env::var("SNIPROXY_QUIC_MODE")
        .unwrap_or_else(|_| config.server.quic_mode.clone());
    info!("QUIC/HTTP3 startup mode: {}", mode);

    match mode.as_str() {
        "off" => Ok(false),
        "on" => {
            match quic::session::probe_socks5_udp_relay(&config.socks5).await {
                Ok(()) => {
                    info!("SOCKS5 UDP relay probe succeeded; forcing QUIC/HTTP3 on");
                }
                Err(e) => {
                    warn!(
                        "SOCKS5 UDP relay probe failed, but SNIPROXY_QUIC_MODE=on; starting QUIC anyway: {}",
                        e
                    );
                }
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
fn init_logging(config: &Config) -> Result<WorkerGuard> {
    let log_path = Path::new(&config.server.log_file);
    let log_dir = log_path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = log_dir {
        std::fs::create_dir_all(dir)?;
    }

    let file_name = log_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sniproxy-ng.log");
    let appender =
        tracing_appender::rolling::never(log_dir.unwrap_or_else(|| Path::new(".")), file_name);
    let (file_writer, guard) = tracing_appender::non_blocking(appender);

    let rust_log = std::env::var(EnvFilter::DEFAULT_ENV).ok();
    let file_filter = rust_log
        .as_deref()
        .map(EnvFilter::new)
        .unwrap_or_else(|| EnvFilter::new(config.server.log_level.clone()));
    let console_filter = rust_log
        .as_deref()
        .map(EnvFilter::new)
        .unwrap_or_else(|| EnvFilter::new(config.server.console_log_level.clone()));

    match config.server.log_format.as_str() {
        "json" => {
            let console_layer = fmt::layer()
                .json()
                .with_writer(std::io::stderr)
                .with_target(false)
                .with_thread_ids(false)
                .with_filter(console_filter);
            let file_layer = fmt::layer()
                .json()
                .with_writer(file_writer)
                .with_target(false)
                .with_thread_ids(true)
                .with_filter(file_filter);

            tracing_subscriber::registry()
                .with(console_layer)
                .with(file_layer)
                .init();
        }
        _ => {
            let console_layer = fmt::layer()
                .compact()
                .with_writer(std::io::stderr)
                .with_target(false)
                .with_thread_ids(false)
                .with_filter(console_filter);
            let file_layer = fmt::layer()
                .with_writer(file_writer)
                .with_target(false)
                .with_thread_ids(true)
                .with_filter(file_filter);

            tracing_subscriber::registry()
                .with(console_layer)
                .with(file_layer)
                .init();
        }
    }

    Ok(guard)
}
