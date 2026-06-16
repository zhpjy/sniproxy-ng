use anyhow::{anyhow, Result};
use fast_socks5::client::Socks5Datagram;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

/// SOCKS5 UDP ASSOCIATE 客户端 (使用 fast-socks5)
pub struct Socks5UdpClient {
    proxy_addr: String,
    /// 可选的认证信息
    auth: Option<(String, String)>,
    /// UDP ASSOCIATE 建连和握手超时
    timeout: Duration,
}

impl Socks5UdpClient {
    /// 创建新的 SOCKS5 UDP 客户端
    pub fn new<S: Into<String>>(proxy_addr: S) -> Self {
        Self {
            proxy_addr: proxy_addr.into(),
            auth: None,
            timeout: Duration::from_secs(30),
        }
    }

    /// 设置认证信息
    pub fn with_auth(mut self, username: String, password: String) -> Self {
        self.auth = Some((username, password));
        self
    }

    /// 设置 UDP ASSOCIATE 建连和握手超时
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 建立 UDP ASSOCIATE 会话
    ///
    /// # 返回
    /// 返回 (Socks5Datagram, 中继服务器地址)
    pub async fn associate(&self) -> Result<(Socks5Datagram<TcpStream>, SocketAddr)> {
        debug!("SOCKS5 UDP ASSOCIATE via proxy {}", self.proxy_addr);

        // 1. 先建立 TCP 连接到 SOCKS5 代理
        let tcp_stream = tokio::time::timeout(self.timeout, TcpStream::connect(&self.proxy_addr))
            .await
            .map_err(|_| anyhow!("SOCKS5 UDP TCP connect timed out after {:?}", self.timeout))?
            .map_err(|e| anyhow!("Failed to connect to SOCKS5 proxy: {}", e))?;

        // 2. 使用 fast-socks5 建立 UDP ASSOCIATE
        let associate = async {
            if let Some((username, password)) = &self.auth {
                // 带认证
                Socks5Datagram::bind_with_password(tcp_stream, "0.0.0.0:0", username, password)
                    .await
                    .map_err(|e| anyhow!("SOCKS5 UDP ASSOCIATE failed: {}", e))
            } else {
                // 无认证
                Socks5Datagram::bind(tcp_stream, "0.0.0.0:0")
                    .await
                    .map_err(|e| anyhow!("SOCKS5 UDP ASSOCIATE failed: {}", e))
            }
        };

        let socks5_datagram = tokio::time::timeout(self.timeout, associate)
            .await
            .map_err(|_| anyhow!("SOCKS5 UDP ASSOCIATE timed out after {:?}", self.timeout))??;

        // 获取中继服务器地址
        let proxy_addr = socks5_datagram
            .proxy_addr()
            .map_err(|e| anyhow!("Failed to get relay address: {}", e))?;

        let relay_addr = proxy_addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("No relay address"))?;

        debug!(
            "SOCKS5 UDP ASSOCIATE established via {}, relay: {}",
            self.proxy_addr, relay_addr
        );

        Ok((socks5_datagram, relay_addr))
    }
}

/// 导出 fast-socks5 的 UDP 类型
#[allow(dead_code)]
pub type Socks5UdpDatagram = Socks5Datagram<TcpStream>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::net::TcpListener;

    #[test]
    fn test_udp_client_creation() {
        let client = Socks5UdpClient::new("127.0.0.1:1080");
        assert_eq!(client.proxy_addr, "127.0.0.1:1080");
        assert!(client.auth.is_none());
    }

    #[test]
    fn test_udp_client_with_auth() {
        let client = Socks5UdpClient::new("127.0.0.1:1080")
            .with_auth("user".to_string(), "pass".to_string());

        assert!(client.auth.is_some());
        let (username, password) = client.auth.unwrap();
        assert_eq!(username, "user");
        assert_eq!(password, "pass");
    }

    #[tokio::test]
    async fn associate_times_out_when_proxy_accepts_but_never_responds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client = Socks5UdpClient::new(addr.to_string()).with_timeout(Duration::from_millis(50));
        let started = Instant::now();
        let result = client.associate().await;

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
