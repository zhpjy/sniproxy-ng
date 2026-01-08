use crate::config::Config;
use crate::socks5::{Socks5Client, ConnectionPool, PoolConfig};
use crate::tls::sni::extract_sni;
use crate::router::Router;
use anyhow::{Result, anyhow, bail};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, debug, error, warn};

/// 运行 TCP 代理服务器 (HTTP/1.1 + TLS)
pub async fn run(config: Config) -> Result<()> {
    let listen_addr = config.server.listen_https_addr
        .ok_or_else(|| anyhow!("HTTPS listen address not configured"))?;

    info!("Starting TCP proxy server on {}", listen_addr);

    let listener = TcpListener::bind(&listen_addr).await?;
    info!("TCP proxy server listening on {}", listen_addr);

    // 创建路由器
    let router = Arc::new(Router::new(config.clone()));

    // 创建连接池
    let pool_config = PoolConfig {
        max_connections: config.socks5.max_connections,
        ..Default::default()
    };
    let pool = Arc::new(ConnectionPool::new(pool_config));
    info!("SOCKS5 connection pool created");

    // 启动连接池清理任务
    pool.clone().spawn_cleanup_task();
    info!("TCP connection pool cleanup task started");

    loop {
        match listener.accept().await {
            Ok((client_stream, client_addr)) => {
                info!("Accepted connection from {}", client_addr);

                // 克隆以供任务使用
                let router_clone = router.clone();
                let pool_clone = pool.clone();
                let socks5_addr = config.socks5.addr.to_string();
                let socks5_username = config.socks5.username.clone();
                let socks5_password = config.socks5.password.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(
                        client_stream,
                        client_addr,
                        router_clone,
                        pool_clone,
                        socks5_addr,
                        socks5_username,
                        socks5_password,
                    ).await {
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
    router: Arc<Router>,
    pool: Arc<ConnectionPool>,
    socks5_addr: String,
    socks5_username: Option<String>,
    socks5_password: Option<String>,
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

    // 3. 白名单检查
    if !router.is_allowed(&sni) {
        warn!("Domain {} not in whitelist, rejecting connection from {}", sni, client_addr);
        bail!("Domain '{}' is not in the whitelist", sni);
    }

    // 4. 从 SNI 提取目标主机和端口
    // 默认使用 443 端口 (HTTPS)
    let target_host = sni.clone();
    let target_port = 443;

    // 5. 通过连接池获取 SOCKS5 连接
    debug!("Getting connection to {}:{} from pool", target_host, target_port);

    // 克隆需要移动到闭包中的值
    let socks5_addr = socks5_addr.clone();
    let socks5_username = socks5_username.clone();
    let socks5_password = socks5_password.clone();

    let conn_guard = pool.get_connection(&target_host, target_port, move |host, port| {
        // 将这些值移入 async block
        let socks5_addr = socks5_addr.clone();
        let socks5_username = socks5_username.clone();
        let socks5_password = socks5_password.clone();
        let host = host.to_string();
        let port = port;

        Box::pin(async move {
            // 创建 SOCKS5 客户端并连接
            let client = if let (Some(username), Some(password)) = (socks5_username, socks5_password) {
                Socks5Client::new(socks5_addr)
                    .with_auth(username, password)
            } else {
                Socks5Client::new(socks5_addr)
            };

            client.connect(&host, port).await
        })
    }).await?;

    info!("Established connection to {}:{} via SOCKS5", target_host, target_port);

    // 6. 现在我们需要实际读取之前 peek 的数据
    // 因为 SOCKS5 连接已建立,我们开始转发数据
    client_stream.read_exact(&mut buffer[..n]).await?;

    // 获取 SOCKS5 流的所有权以进行 split
    // 注意：连接将不会被归还到池中，因为所有权已转移
    let socks5_stream = conn_guard.into_inner();
    let mut socks5_stream = socks5_stream;

    // 先将 peek 的数据写入 SOCKS5 流
    socks5_stream.write_all(&buffer[..n]).await?;
    debug!("Wrote {} bytes of initial data to SOCKS5 stream", n);

    // 7. 双向转发数据
    let (mut client_read, mut client_write) = client_stream.split();
    let (mut proxy_read, mut proxy_write) = tokio::io::split(socks5_stream);

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
            let _ = proxy_write.shutdown().await;
        }
        result = proxy_to_client => {
            if let Err(e) = result {
                debug!("Proxy to client forwarding ended: {}", e);
            }
            // 关闭另一半
            let _ = client_write.shutdown().await;
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
listen_https_addr = "127.0.0.1:8443"
log_level = "debug"

[socks5]
addr = "127.0.0.1:1080"
timeout = 30

[rules]
allow = ["*.google.com", "api.*.com"]
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen_https_addr.unwrap().port(), 8443);
        assert_eq!(config.socks5.addr.port(), 1080);
    }
}
