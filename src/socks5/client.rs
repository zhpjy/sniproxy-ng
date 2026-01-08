use anyhow::{Result, anyhow};
use fast_socks5::client::{Config, Socks5Stream};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// SOCKS5 客户端 (使用 fast-socks5 库)
#[derive(Clone)]
pub struct Socks5Client {
    proxy_addr: String,
    /// 可选的认证信息
    auth: Option<(String, String)>,
}

impl Socks5Client {
    /// 创建新的 SOCKS5 客户端
    ///
    /// # 参数
    /// * `proxy_addr` - SOCKS5 代理地址,格式: "IP:PORT" 或 "域名:PORT"
    ///
    /// # 示例
    /// ```
    /// let client = Socks5Client::new("127.0.0.1:1080");
    /// ```
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

    /// 连接到目标服务器 (通过 SOCKS5 代理)
    ///
    /// # 参数
    /// * `target` - 目标主机 (域名或IP)
    /// * `port` - 目标端口
    ///
    /// # 返回
    /// 返回连接后的 Socks5Stream (实现了 AsyncRead + AsyncWrite)
    ///
    /// # 示例
    /// ```no_run
    /// # use sniproxy_ng::socks5::Socks5Client;
    /// # async fn test() -> anyhow::Result<()> {
    /// let client = Socks5Client::new("127.0.0.1:1080");
    /// let stream = client.connect("www.google.com", 443).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(&self, target: &str, port: u16) -> Result<Socks5Stream<TcpStream>> {
        debug!(
            "SOCKS5 CONNECT to {}:{} via proxy {}",
            target, port, self.proxy_addr
        );

        // 使用 fast-socks5 库连接
        let socks5_stream = if let Some((username, password)) = &self.auth {
            // 带认证
            Socks5Stream::connect_with_password(
                &self.proxy_addr,
                target.to_string(),
                port,
                username.clone(),
                password.clone(),
                Config::default(), // Config 不实现 Clone, 使用 default
            )
            .await
            .map_err(|e| anyhow!("SOCKS5 connection failed: {}", e))?
        } else {
            // 无认证
            Socks5Stream::connect(
                &self.proxy_addr,
                target.to_string(),
                port,
                Config::default(), // Config 不实现 Clone, 使用 default
            )
            .await
            .map_err(|e| anyhow!("SOCKS5 connection failed: {}", e))?
        };

        info!(
            "SOCKS5 CONNECT established: {}:{} via {}",
            target, port, self.proxy_addr
        );

        Ok(socks5_stream)
    }
}

/// 导出 fast-socks5 的类型以方便使用
pub type Socks5TcpStream = Socks5Stream<TcpStream>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = Socks5Client::new("127.0.0.1:1080");
        assert_eq!(client.proxy_addr, "127.0.0.1:1080");
        assert!(client.auth.is_none());
    }

    #[test]
    fn test_client_with_auth() {
        let client = Socks5Client::new("127.0.0.1:1080")
            .with_auth("user".to_string(), "pass".to_string());

        assert!(client.auth.is_some());
        let (username, password) = client.auth.unwrap();
        assert_eq!(username, "user");
        assert_eq!(password, "pass");
    }

    // 注意: 实际的连接测试需要运行中的 SOCKS5 代理
    // 这里只测试客户端创建
}
