use anyhow::{Result, anyhow};
use fast_socks5::client::Socks5Datagram;
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// SOCKS5 UDP ASSOCIATE 客户端 (使用 fast-socks5)
pub struct Socks5UdpClient {
    proxy_addr: String,
    /// 可选的认证信息
    auth: Option<(String, String)>,
}

impl Socks5UdpClient {
    /// 创建新的 SOCKS5 UDP 客户端
    pub fn new<S: Into<String>>(proxy_addr: S) -> Self {
        Self {
            proxy_addr: proxy_addr.into(),
            auth: None,
        }
    }

    /// 设置认证信息
    pub fn with_auth(mut self, username: String, password: String) -> Self {
        self.auth = Some((username, password));
        self
    }

    /// 建立 UDP ASSOCIATE 会话
    ///
    /// # 返回
    /// 返回 (Socks5Datagram, 中继服务器地址)
    pub async fn associate(&self) -> Result<(Socks5Datagram<TcpStream>, SocketAddr)> {
        debug!("SOCKS5 UDP ASSOCIATE via proxy {}", self.proxy_addr);

        // 1. 先建立 TCP 连接到 SOCKS5 代理
        let tcp_stream = TcpStream::connect(&self.proxy_addr)
            .await
            .map_err(|e| anyhow!("Failed to connect to SOCKS5 proxy: {}", e))?;

        // 2. 使用 fast-socks5 建立 UDP ASSOCIATE
        let socks5_datagram = if let Some((username, password)) = &self.auth {
            // 带认证
            Socks5Datagram::bind_with_password(tcp_stream, "0.0.0.0:0", username, password)
                .await
                .map_err(|e| anyhow!("SOCKS5 UDP ASSOCIATE failed: {}", e))?
        } else {
            // 无认证
            Socks5Datagram::bind(tcp_stream, "0.0.0.0:0")
                .await
                .map_err(|e| anyhow!("SOCKS5 UDP ASSOCIATE failed: {}", e))?
        };

        // 获取中继服务器地址
        let proxy_addr = socks5_datagram
            .proxy_addr()
            .map_err(|e| anyhow!("Failed to get relay address: {}", e))?;

        let relay_addr = proxy_addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("No relay address"))?;

        info!(
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
}
