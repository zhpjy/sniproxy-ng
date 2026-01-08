use crate::config::Config;
use crate::socks5::Socks5Client;
use crate::tls::sni::extract_sni;
use anyhow::{Result, anyhow, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, debug, error, warn};

/// 运行 TCP 代理服务器 (HTTP/1.1 + TLS)
pub async fn run(config: Config) -> Result<()> {
    info!("Starting TCP proxy server on {}", config.server.listen_addr);

    let listener = TcpListener::bind(&config.server.listen_addr).await?;
    info!("TCP proxy server listening on {}", config.server.listen_addr);

    // 创建 SOCKS5 客户端
    let socks5_client = if config.socks5.username.is_some() && config.socks5.password.is_some() {
        Socks5Client::new(config.socks5.addr.to_string())
            .with_auth(
                config.socks5.username.clone().unwrap(),
                config.socks5.password.clone().unwrap()
            )
    } else {
        Socks5Client::new(config.socks5.addr.to_string())
    };

    loop {
        match listener.accept().await {
            Ok((client_stream, client_addr)) => {
                info!("Accepted connection from {}", client_addr);

                // 克隆配置以供任务使用
                let socks5_client_clone = socks5_client.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(client_stream, client_addr, socks5_client_clone).await {
                        error!("Error handling client {}: {}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }
}

/// 处理单个客户端连接
async fn handle_client(
    client_stream: TcpStream,
    client_addr: std::net::SocketAddr,
    socks5_client: Socks5Client,
) -> Result<()> {
    debug!("Handling client {}", client_addr);

    // 1. 读取初始数据以提取 SNI
    // 我们需要读取足够的数据来捕获 TLS ClientHello
    let mut buffer = vec![0u8; 4096];
    let mut client_stream = client_stream;
    let n = client_stream.peek(&mut buffer).await?;

    if n == 0 {
        warn!("Client {} closed connection immediately", client_addr);
        return Ok(());
    }

    // 2. 尝试提取 SNI
    let sni = match extract_sni(&buffer[..n])? {
        Some(hostname) => {
            info!("Extracted SNI: {} from {}", hostname, client_addr);
            hostname
        }
        None => {
            // 没有 SNI,可能是直接连接或非 TLS 流量
            warn!("No SNI found from {}", client_addr);

            // 检查是否是 HTTP 明文请求
            if let Ok(http_data) = std::str::from_utf8(&buffer[..n]) {
                if http_data.starts_with("GET ") || http_data.starts_with("POST ") ||
                   http_data.starts_with("HEAD ") || http_data.starts_with("PUT ") ||
                   http_data.starts_with("DELETE ") || http_data.starts_with("OPTIONS ") ||
                   http_data.starts_with("CONNECT ") {
                    bail!("HTTP plaintext requests not supported from {}", client_addr);
                }
            }

            bail!("No SNI found and cannot determine target from {}", client_addr);
        }
    };

    // 3. 从 SNI 提取目标主机和端口
    // 默认使用 443 端口 (HTTPS)
    let target_host = sni;
    let target_port = 443;

    // 4. 通过 SOCKS5 代理连接到目标服务器
    debug!("Connecting to {}:{} via SOCKS5 proxy", target_host, target_port);
    let proxy_stream = socks5_client.connect(&target_host, target_port).await
        .map_err(|e| anyhow!("Failed to connect via SOCKS5: {}", e))?;

    info!("Established connection to {}:{} via SOCKS5", target_host, target_port);

    // 5. 现在我们需要实际读取之前 peek 的数据
    // 因为 SOCKS5 连接已建立,我们开始转发数据
    client_stream.read_exact(&mut buffer[..n]).await?;

    // 6. 双向转发数据
    let (mut client_read, mut client_write) = client_stream.split();
    let (mut proxy_read, mut proxy_write) = tokio::io::split(proxy_stream);

    // 创建双向转发任务
    let client_to_proxy = async {
        tokio::io::copy(&mut client_read, &mut proxy_write).await
            .map_err(|e| anyhow!("Client to proxy copy failed: {}", e))
    };

    let proxy_to_client = async {
        tokio::io::copy(&mut proxy_read, &mut client_write).await
            .map_err(|e| anyhow!("Proxy to client copy failed: {}", e))
    };

    // 运行双向转发,任一方向结束时关闭连接
    tokio::select! {
        result = client_to_proxy => {
            if let Err(e) = result {
                debug!("Client to proxy forwarding ended: {}", e);
            }
            // 关闭另一半
            proxy_write.shutdown().await.ok();
        }
        result = proxy_to_client => {
            if let Err(e) = result {
                debug!("Proxy to client forwarding ended: {}", e);
            }
            // 关闭另一半
            client_write.shutdown().await.ok();
        }
    }

    info!("Connection from {} closed", client_addr);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parsing() {
        // 简单的配置解析测试
        let toml_str = r#"
[server]
listen_addr = "127.0.0.1:8443"
log_level = "debug"

[socks5]
addr = "127.0.0.1:1080"
timeout = 30

[rules]
default_backend = "127.0.0.1:1080"
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen_addr.port(), 8443);
        assert_eq!(config.socks5.addr.port(), 1080);
    }
}
