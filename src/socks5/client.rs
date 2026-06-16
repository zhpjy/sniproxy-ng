use anyhow::{anyhow, Result};
use fast_socks5::client::{Config, Socks5Stream};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

/// SOCKS5 客户端 (使用 fast-socks5 库)
#[derive(Clone)]
pub struct Socks5Client {
    proxy_addr: String,
    /// 可选的认证信息
    auth: Option<(String, String)>,
    /// SOCKS5 建连和握手超时
    timeout: Duration,
}

impl Socks5Client {
    /// 创建新的 SOCKS5 客户端
    ///
    /// # 参数
    /// * `proxy_addr` - SOCKS5 代理地址,格式: "IP:PORT" 或 "域名:PORT"
    ///
    /// # 示例
    /// ```
    /// # use sniproxy_ng::socks5::client::Socks5Client;
    /// let client = Socks5Client::new("127.0.0.1:1080");
    /// ```
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

    /// 设置 SOCKS5 建连和握手超时
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
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

        let mut config = Config::default();
        config.set_connect_timeout(self.timeout.as_secs().max(1));

        // 使用 fast-socks5 库连接，并用外层 timeout 覆盖完整握手/请求过程
        let connect = async {
            if let Some((username, password)) = &self.auth {
                // 带认证
                Socks5Stream::connect_with_password(
                    &self.proxy_addr,
                    target.to_string(),
                    port,
                    username.clone(),
                    password.clone(),
                    config,
                )
                .await
                .map_err(|e| anyhow!("SOCKS5 connection failed: {}", e))
            } else {
                // 无认证
                Socks5Stream::connect(&self.proxy_addr, target.to_string(), port, config)
                    .await
                    .map_err(|e| anyhow!("SOCKS5 connection failed: {}", e))
            }
        };

        let socks5_stream = tokio::time::timeout(self.timeout, connect)
            .await
            .map_err(|_| anyhow!("SOCKS5 connection timed out after {:?}", self.timeout))??;

        debug!(
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
    use std::time::{Duration, Instant};
    use tokio::net::TcpListener;

    #[test]
    fn test_client_creation() {
        let client = Socks5Client::new("127.0.0.1:1080");
        assert_eq!(client.proxy_addr, "127.0.0.1:1080");
        assert!(client.auth.is_none());
    }

    #[test]
    fn test_client_with_auth() {
        let client =
            Socks5Client::new("127.0.0.1:1080").with_auth("user".to_string(), "pass".to_string());

        assert!(client.auth.is_some());
        let (username, password) = client.auth.unwrap();
        assert_eq!(username, "user");
        assert_eq!(password, "pass");
    }

    // 注意: 实际的连接测试需要运行中的 SOCKS5 代理
    // 这里只测试客户端创建

    #[tokio::test]
    async fn connect_times_out_when_proxy_accepts_but_never_responds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client = Socks5Client::new(addr.to_string()).with_timeout(Duration::from_millis(50));
        let started = Instant::now();
        let result = client.connect("example.com", 443).await;

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
