/// 路由规则引擎
///
/// 根据 SNI 和配置规则匹配后端目标。
use crate::config::{Config, DomainRule, Socks5Config};
use anyhow::{Result, bail};
use std::net::SocketAddr;
use tracing::{info, debug, warn};

/// 路由决策
#[derive(Debug, Clone)]
pub struct RouteDecision {
    /// 目标后端地址
    pub backend: SocketAddr,
    /// 匹配的规则(如果有)
    pub rule: Option<String>,
}

/// 路由器
pub struct Router {
    config: Config,
}

impl Router {
    /// 创建新的路由器
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// 根据 SNI 查找路由
    pub fn route(&self, sni: &str) -> Result<RouteDecision> {
        debug!("Routing SNI: {}", sni);

        // 1. 尝试匹配域名规则
        for rule in &self.config.rules.domain {
            if self.match_pattern(sni, &rule.pattern) {
                info!("SNI '{}' matched rule pattern '{}'", sni, rule.pattern);
                return Ok(RouteDecision {
                    backend: rule.backend,
                    rule: Some(rule.pattern.clone()),
                });
            }
        }

        // 2. 使用默认后端
        warn!("No rule matched for SNI '{}', using default backend", sni);
        Ok(RouteDecision {
            backend: self.config.rules.default_backend,
            rule: None,
        })
    }

    /// 匹配通配符模式
    fn match_pattern(&self, hostname: &str, pattern: &str) -> bool {
        // 简单的通配符匹配
        if pattern == "*" {
            return true;
        }

        if let Some(pattern_prefix) = pattern.strip_prefix('*') {
            // *.example.com 匹配 foo.example.com
            return hostname.ends_with(pattern_prefix);
        }

        if pattern.contains('*') {
            // 更复杂的通配符(暂不支持)
            warn!("Complex wildcard patterns not supported yet: {}", pattern);
            return false;
        }

        // 精确匹配
        hostname == pattern
    }

    /// 获取 SOCKS5 配置
    pub fn socks5_config(&self) -> &Socks5Config {
        &self.config.socks5
    }

    /// 获取服务器监听地址
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.server.listen_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> Config {
        Config {
            server: crate::config::ServerConfig {
                listen_addr: "127.0.0.1:8443".parse().unwrap(),
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
            rules: crate::config::RulesConfig {
                default_backend: "127.0.0.1:1080".parse().unwrap(),
                domain: vec![
                    DomainRule {
                        pattern: "*.google.com".to_string(),
                        backend: "192.168.1.10:1080".parse().unwrap(),
                    },
                    DomainRule {
                        pattern: "www.example.com".to_string(),
                        backend: "192.168.1.20:1080".parse().unwrap(),
                    },
                ],
            },
        }
    }

    #[test]
    fn test_exact_match() {
        let router = Router::new(create_test_config());
        let decision = router.route("www.example.com").unwrap();
        
        assert_eq!(decision.backend, "192.168.1.20:1080".parse::<SocketAddr>().unwrap());
        assert_eq!(decision.rule, Some("www.example.com".to_string()));
    }

    #[test]
    fn test_wildcard_match() {
        let router = Router::new(create_test_config());
        let decision = router.route("www.google.com").unwrap();
        
        assert_eq!(decision.backend, "192.168.1.10:1080".parse::<SocketAddr>().unwrap());
        assert_eq!(decision.rule, Some("*.google.com".to_string()));
    }

    #[test]
    fn test_default_backend() {
        let router = Router::new(create_test_config());
        let decision = router.route("unknown.com").unwrap();
        
        assert_eq!(decision.backend, "127.0.0.1:1080".parse::<SocketAddr>().unwrap());
        assert_eq!(decision.rule, None);
    }

    #[test]
    fn test_wildcard_subdomain() {
        let router = Router::new(create_test_config());
        
        // 测试多个子域名
        let domains = vec![
            "mail.google.com",
            "drive.google.com",
            "accounts.google.com",
        ];

        for domain in domains {
            let decision = router.route(domain).unwrap();
            assert_eq!(
                decision.backend,
                "192.168.1.10:1080".parse::<SocketAddr>().unwrap(),
                "Failed for domain: {}",
                domain
            );
        }
    }
}
