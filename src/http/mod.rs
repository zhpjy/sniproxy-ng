//! HTTP/1.1 代理模块
//!
//! 通过 Host 请求头提取目标域名,通过 SOCKS5 转发流量。

use crate::config::Config;
use crate::router::Router;
use anyhow::{Result, anyhow, bail};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, debug, warn, error};

pub mod error;
pub mod parser;

pub use error::{HttpError, Result as HttpResult};
pub use parser::extract_host;

/// 运行 HTTP 代理服务器
pub async fn run(
    config: Config,
    router: Arc<Router>,
) -> Result<()> {
    let listen_addr = config.server.listen_http_addr
        .ok_or_else(|| anyhow!("HTTP listen address not configured"))?;

    info!("Starting HTTP proxy server on {}", listen_addr);

    let listener = TcpListener::bind(&listen_addr).await?;
    info!("HTTP proxy server listening on {}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((client_stream, client_addr)) => {
                info!("Accepted HTTP connection from {}", client_addr);

                let router_clone = router.clone();
                let socks5_addr = config.socks5.addr.to_string();
                let socks5_username = config.socks5.username.clone();
                let socks5_password = config.socks5.password.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_client(
                        client_stream,
                        client_addr,
                        router_clone,
                        socks5_addr,
                        socks5_username,
                        socks5_password,
                    ).await {
                        error!("Error handling HTTP client {}: {}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting HTTP connection: {}", e);
            }
        }
    }
}

/// 处理单个 HTTP 客户端连接
async fn handle_client(
    client_stream: tokio::net::TcpStream,
    client_addr: std::net::SocketAddr,
    router: Arc<Router>,
    socks5_addr: String,
    socks5_username: Option<String>,
    socks5_password: Option<String>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    debug!("Handling HTTP client {}", client_addr);

    let mut buffer = vec![0u8; 4096];
    let mut client_stream = client_stream;
    let n = client_stream.peek(&mut buffer).await?;

    if n == 0 {
        warn!("HTTP client {} closed connection immediately", client_addr);
        return Ok(());
    }

    debug!("Peeked {} bytes from {}", n, client_addr);

    let host = match extract_host(&buffer[..n]) {
        Ok(h) => {
            info!("Extracted Host: {} from {}", h, client_addr);
            h
        }
        Err(e) => {
            warn!("Failed to extract Host from {}: {}", client_addr, e);
            bail!("Host extraction failed: {}", e);
        }
    };

    if !router.is_allowed(&host) {
        warn!("Domain '{}' not in whitelist, rejecting HTTP connection from {}", host, client_addr);
        bail!("Domain '{}' is not in the whitelist", host);
    }

    let target_host = host.clone();
    let target_port = 80;

    debug!("Connecting to {}:{} via SOCKS5", target_host, target_port);

    use crate::socks5::Socks5Client;

    let client = if let (Some(username), Some(password)) = (socks5_username, socks5_password) {
        Socks5Client::new(&socks5_addr)
            .with_auth(username, password)
    } else {
        Socks5Client::new(&socks5_addr)
    };

    let mut socks5_stream = client.connect(&target_host, target_port).await?;

    info!("Established HTTP connection to {}:{} via SOCKS5", target_host, target_port);

    client_stream.read_exact(&mut buffer[..n]).await?;
    socks5_stream.write_all(&buffer[..n]).await?;
    debug!("Wrote {} bytes of initial data to SOCKS5 stream", n);

    let (mut client_read, mut client_write) = client_stream.split();
    let (mut proxy_read, mut proxy_write) = tokio::io::split(socks5_stream);

    let client_to_proxy = async {
        tokio::io::copy(&mut client_read, &mut proxy_write).await
            .map_err(|e| anyhow!("Client to proxy copy failed: {}", e))
    };

    let proxy_to_client = async {
        tokio::io::copy(&mut proxy_read, &mut client_write).await
            .map_err(|e| anyhow!("Proxy to client copy failed: {}", e))
    };

    tokio::select! {
        result = client_to_proxy => {
            if let Err(e) = result {
                debug!("HTTP client to proxy forwarding ended: {}", e);
            }
            let _ = proxy_write.shutdown().await;
        }
        result = proxy_to_client => {
            if let Err(e) = result {
                debug!("HTTP proxy to client forwarding ended: {}", e);
            }
            let _ = client_write.shutdown().await;
        }
    }

    info!("HTTP connection from {} closed", client_addr);
    Ok(())
}
