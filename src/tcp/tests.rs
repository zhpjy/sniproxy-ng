#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::config::Config;
    use std::net::SocketAddr;
    use std::time::Duration;

    // 注意:这些是集成测试,需要真实的 SOCKS5 代理服务器
    // 在 CI/CD 环境中,应该先启动一个测试用的 SOCKS5 代理

    #[test]
    fn test_config_creation() {
        let config = Config {
            server: crate::config::ServerConfig {
                listen_https_addr: Some("127.0.0.1:8443".parse().unwrap()),
                listen_http_addr: None,
                log_level: "debug".to_string(),
                log_format: "pretty".to_string(),
            },
            socks5: crate::config::Socks5Config {
                addr: "127.0.0.1:1080".parse().unwrap(),
                timeout: 30,
                max_connections: 100,
                username: None,
                password: None,
            },
            rules: crate::config::RulesConfig::default(),
        };

        assert_eq!(config.server.listen_https_addr.unwrap().port(), 8443);
        assert_eq!(config.socks5.addr.port(), 1080);
    }

    // 注意:以下测试需要真实的 SOCKS5 代理和目标服务器
    // 可以使用 docker-compose 在测试环境中启动这些服务

    // #[tokio::test]
    // async fn test_tcp_proxy_integration() {
    //     // 这个测试需要:
    //     // 1. 运行中的 SOCKS5 代理 (127.0.0.1:1080)
    //     // 2. 运行中的 HTTPS 服务器 (例如 nginx)
    //
    //     let config = Config::load("config.toml").unwrap();
    //
    //     // 在后台启动 TCP 代理
    //     tokio::spawn(async move {
    //         tcp::run(config).await.unwrap();
    //     });
    //
    //     tokio::time::sleep(Duration::from_secs(1)).await;
    //
    //     // 连接到代理并发送 TLS ClientHello
    //     // 验证 SNI 被正确提取
    //     // 验证数据被正确转发
    // }
}
