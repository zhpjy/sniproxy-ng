/// 域名白名单规则引擎
///
/// 根据配置的白名单规则检查域名是否被允许。
use crate::config::{Config, Socks5Config};
use tracing::{debug, info};

/// 路由器
#[derive(Clone)]
pub struct Router {
    config: Config,
}

impl Router {
    /// 创建新的路由器
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// 检查域名是否被允许
    ///
    /// 当 allow 数组为空时，允许所有域名。
    /// 当 allow 数组有值时，只允许匹配任一模式的域名。
    pub fn is_allowed(&self, hostname: &str) -> bool {
        // 空 allow 数组 → 允许所有
        if self.config.rules.allow.is_empty() {
            debug!("No whitelist configured, allowing all domains");
            return true;
        }

        // 检查是否匹配任一模式
        for pattern in &self.config.rules.allow {
            if self.match_pattern(hostname, pattern) {
                info!(
                    "Domain '{}' matched whitelist pattern '{}'",
                    hostname, pattern
                );
                return true;
            }
        }

        debug!("Domain '{}' did not match any whitelist pattern", hostname);
        false
    }

    /// 灵活通配符匹配
    ///
    /// 支持多个 `*` 的通配符模式，例如：
    /// - `*google.com` 匹配 `google.com` 和 `www.google.com`
    /// - `*.google.com` 只匹配 `www.google.com`，不匹配 `google.com`
    /// - `api.*.com` 匹配 `api.example.com`
    /// - `*.prod.*.internal` 匹配 `web.prod.db.internal`
    fn match_pattern(&self, hostname: &str, pattern: &str) -> bool {
        // "*" 匹配所有
        if pattern == "*" {
            return true;
        }

        // 按 * 分割模式
        let parts: Vec<&str> = pattern.split('*').collect();
        let mut pos = 0;

        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            // 在 hostname 从 pos 位置开始查找 part
            if let Some(idx) = hostname[pos..].find(part) {
                pos += idx + part.len();

                // 最后一个片段：检查是否匹配到末尾
                if i == parts.len() - 1 {
                    // 如果模式以 * 结尾，允许后面有内容
                    if pattern.ends_with('*') {
                        return true;
                    }
                    // 否则必须精确匹配到末尾
                    return pos == hostname.len();
                }
            } else {
                return false;
            }
        }

        true
    }

    /// 获取 SOCKS5 配置
    #[allow(dead_code)]
    pub fn socks5_config(&self) -> &Socks5Config {
        &self.config.socks5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config(allow_patterns: Vec<&str>) -> Config {
        Config {
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
            rules: crate::config::RulesConfig {
                allow: allow_patterns.into_iter().map(|s| s.to_string()).collect(),
            },
        }
    }

    #[test]
    fn test_empty_rules_allow_all() {
        let router = Router::new(create_test_config(vec![]));
        assert!(router.is_allowed("google.com"));
        assert!(router.is_allowed("any.domain.com"));
        assert!(router.is_allowed("unknown.com"));
    }

    #[test]
    fn test_wildcard_with_self() {
        let router = Router::new(create_test_config(vec!["*google.com"]));
        assert!(router.is_allowed("google.com")); // 自身
        assert!(router.is_allowed("www.google.com")); // 子域名
        assert!(router.is_allowed("mail.google.com"));
        assert!(!router.is_allowed("evil.com"));
    }

    #[test]
    fn test_wildcard_subdomain_only() {
        let router = Router::new(create_test_config(vec!["*.google.com"]));
        assert!(!router.is_allowed("google.com")); // 不包括自身
        assert!(router.is_allowed("www.google.com"));
        assert!(router.is_allowed("mail.google.com"));
        assert!(!router.is_allowed("evil.com"));
    }

    #[test]
    fn test_multi_wildcard() {
        let router = Router::new(create_test_config(vec!["*.prod.*.internal"]));
        assert!(router.is_allowed("web.prod.db.internal"));
        assert!(router.is_allowed("api.prod.cache.internal"));
        assert!(router.is_allowed("app.prod.api.internal"));
        assert!(router.is_allowed("dev.prod.db.internal")); // 也匹配
        assert!(!router.is_allowed("web.dev.db.internal")); // 第二段不是 prod
        assert!(!router.is_allowed("web.prod.db.com")); // 不是 .internal 结尾
    }

    #[test]
    fn test_api_wildcard() {
        let router = Router::new(create_test_config(vec!["api.*.com"]));
        assert!(router.is_allowed("api.example.com"));
        assert!(router.is_allowed("api.foo.com"));
        assert!(router.is_allowed("api.bar.com"));
        assert!(!router.is_allowed("api.com")); // 中间必须有内容
        assert!(!router.is_allowed("www.api.com")); // 前缀不匹配
    }

    #[test]
    fn test_exact_match() {
        let router = Router::new(create_test_config(vec!["www.example.com"]));
        assert!(router.is_allowed("www.example.com"));
        assert!(!router.is_allowed("example.com"));
        assert!(!router.is_allowed("www.example.org"));
    }

    #[test]
    fn test_multiple_patterns() {
        let router = Router::new(create_test_config(vec![
            "*.google.com",
            "api.*.com",
            "*.prod.*.internal",
        ]));
        assert!(router.is_allowed("www.google.com"));
        assert!(router.is_allowed("mail.google.com"));
        assert!(router.is_allowed("api.example.com"));
        assert!(router.is_allowed("web.prod.db.internal"));
        assert!(!router.is_allowed("evil.com"));
        assert!(!router.is_allowed("www.api.com"));
    }

    #[test]
    fn test_asterisk_only() {
        let router = Router::new(create_test_config(vec!["*"]));
        assert!(router.is_allowed("anything"));
        assert!(router.is_allowed("any.domain.com"));
        assert!(router.is_allowed("foo.bar.baz"));
    }
}
