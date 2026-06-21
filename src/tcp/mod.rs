use crate::config::Config;
use crate::relay::{copy_with_idle_timeout, log_accept_error};
use crate::router::Router;
use crate::socks5::{ConnectionPool, PoolConfig, Socks5Client};
use crate::tls::sni::extract_sni;
use anyhow::{anyhow, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn};

#[derive(Clone)]
struct Socks5Runtime {
    addr: String,
    username: Option<String>,
    password: Option<String>,
    timeout: Duration,
    transfer_idle_timeout: Duration,
}

/// 运行 TCP 代理服务器 (HTTP/1.1 + TLS)
pub async fn run(config: Config) -> Result<()> {
    let listen_addr = config
        .server
        .listen_https_addr
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
    debug!("SOCKS5 connection pool created");

    // 启动连接池清理任务
    pool.clone().spawn_cleanup_task();
    debug!("TCP connection pool cleanup task started");

    let accept_limit = Arc::new(Semaphore::new(config.server.max_client_connections.max(1)));

    loop {
        let client_permit = accept_limit
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| anyhow!("TCP accept limiter closed: {}", e))?;

        match listener.accept().await {
            Ok((client_stream, client_addr)) => {
                trace!("Accepted TCP connection from {}", client_addr);

                // 克隆以供任务使用
                let router_clone = router.clone();
                let pool_clone = pool.clone();
                let socks5 = Socks5Runtime {
                    addr: config.socks5.addr.to_string(),
                    username: config.socks5.username.clone(),
                    password: config.socks5.password.clone(),
                    timeout: Duration::from_secs(config.socks5.timeout),
                    transfer_idle_timeout: Duration::from_secs(
                        config.server.transfer_idle_timeout.max(1),
                    ),
                };
                tokio::spawn(async move {
                    let _client_permit = client_permit;
                    if let Err(e) =
                        handle_client(client_stream, client_addr, router_clone, pool_clone, socks5)
                            .await
                    {
                        warn!("TCP client {} failed: {}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                drop(client_permit);
                log_accept_error("connection", &e).await;
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
    socks5: Socks5Runtime,
) -> Result<()> {
    trace!("Handling TCP client {}", client_addr);

    // 1. 读取初始数据以提取 SNI
    // 我们需要读取足够的数据来捕获 TLS ClientHello
    let mut buffer = vec![0u8; 4096];
    let mut client_stream = client_stream;
    let n = tokio::time::timeout(socks5.timeout, client_stream.peek(&mut buffer))
        .await
        .map_err(|_| {
            anyhow!(
                "Timed out waiting for initial TLS data from {}",
                client_addr
            )
        })??;

    if n == 0 {
        debug!("TCP client {} closed connection immediately", client_addr);
        return Ok(());
    }

    // 2. 尝试提取 SNI
    let sni = match extract_sni(&buffer[..n])? {
        Some(hostname) => {
            debug!("Extracted SNI: {} from {}", hostname, client_addr);
            hostname
        }
        None => {
            // 没有 SNI,可能是直接连接或非 TLS 流量
            warn!("No SNI found from {}", client_addr);

            // 检查是否是 HTTP 明文请求
            if let Ok(http_data) = std::str::from_utf8(&buffer[..n]) {
                if http_data.starts_with("GET ")
                    || http_data.starts_with("POST ")
                    || http_data.starts_with("HEAD ")
                    || http_data.starts_with("PUT ")
                    || http_data.starts_with("DELETE ")
                    || http_data.starts_with("OPTIONS ")
                    || http_data.starts_with("CONNECT ")
                {
                    return Ok(());
                }
            }

            return Ok(());
        }
    };

    // 3. 白名单检查
    if !router.is_allowed(&sni) {
        warn!(
            "Domain {} not in whitelist, rejecting connection from {}",
            sni, client_addr
        );
        return Ok(());
    }

    // 4. 从 SNI 提取目标主机和端口
    // 默认使用 443 端口 (HTTPS)
    let target_host = sni.clone();
    let target_port = 443;

    // 5. 通过连接池获取 SOCKS5 连接
    debug!(
        "Getting TCP upstream connection to {}:{}",
        target_host, target_port
    );

    // 克隆需要移动到闭包中的值
    let socks5_for_connect = socks5.clone();

    let conn_guard = pool
        .get_connection(&target_host, target_port, move |host, port| {
            // 将这些值移入 async block
            let socks5 = socks5_for_connect.clone();
            let host = host.to_string();

            Box::pin(async move {
                // 创建 SOCKS5 客户端并连接
                let client =
                    if let (Some(username), Some(password)) = (socks5.username, socks5.password) {
                        Socks5Client::new(socks5.addr)
                            .with_auth(username, password)
                            .with_timeout(socks5.timeout)
                    } else {
                        Socks5Client::new(socks5.addr).with_timeout(socks5.timeout)
                    };

                client.connect(&host, port).await
            })
        })
        .await?;

    info!(
        "TCP route established: client={}, sni={}, target={}:{}",
        client_addr, sni, target_host, target_port
    );

    // 6. 现在我们需要实际读取之前 peek 的数据
    // 因为 SOCKS5 连接已建立,我们开始转发数据
    client_stream.read_exact(&mut buffer[..n]).await?;

    // 获取 SOCKS5 流的所有权以进行 split
    // 注意：连接将不会被归还到池中，因为所有权已转移
    let socks5_stream = conn_guard.into_inner();
    let mut socks5_stream = socks5_stream;

    // 先将 peek 的数据写入 SOCKS5 流
    socks5_stream.write_all(&buffer[..n]).await?;
    trace!("Wrote {} bytes of initial TLS data to SOCKS5 stream", n);

    // 7. 双向转发数据
    let (mut client_read, mut client_write) = client_stream.split();
    let (mut proxy_read, mut proxy_write) = tokio::io::split(socks5_stream);

    // 创建双向转发任务
    let idle_timeout = socks5.transfer_idle_timeout;
    let client_to_proxy = async {
        copy_with_idle_timeout(&mut client_read, &mut proxy_write, idle_timeout)
            .await
            .map_err(|e| anyhow!("Client to proxy copy failed: {}", e))
    };

    let proxy_to_client = async {
        copy_with_idle_timeout(&mut proxy_read, &mut client_write, idle_timeout)
            .await
            .map_err(|e| anyhow!("Proxy to client copy failed: {}", e))
    };

    // 运行双向转发,任一方向结束时关闭连接
    tokio::select! {
        result = client_to_proxy => {
            if let Err(e) = result {
                debug!("TCP client-to-proxy forwarding ended: {}", e);
            }
        }
        result = proxy_to_client => {
            if let Err(e) = result {
                debug!("TCP proxy-to-client forwarding ended: {}", e);
            }
        }
    }

    trace!("TCP connection from {} closed", client_addr);
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
