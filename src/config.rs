use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use anyhow::{Result, Context};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub socks5: Socks5Config,
    #[serde(default)]
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfig {
    /// HTTPS 监听地址 (例如: "0.0.0.0:443")
    pub listen_https_addr: Option<SocketAddr>,
    /// HTTP 监听地址 (例如: "0.0.0.0:80")
    pub listen_http_addr: Option<SocketAddr>,
    /// 日志级别: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// 日志格式: json, pretty
    #[serde(default = "default_log_format")]
    pub log_format: String,
}

// 自定义 deserialize 实现向后兼容
impl<'de> serde::de::Deserialize<'de> for ServerConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct RawServerConfig {
            listen_addr: Option<SocketAddr>,
            listen_https_addr: Option<SocketAddr>,
            listen_http_addr: Option<SocketAddr>,
            #[serde(default = "default_log_level")]
            log_level: String,
            #[serde(default = "default_log_format")]
            log_format: String,
        }

        let raw = RawServerConfig::deserialize(deserializer)?;
        let listen_https_addr = raw.listen_https_addr.or(raw.listen_addr);
        let listen_http_addr = raw.listen_http_addr;

        Ok(ServerConfig {
            listen_https_addr,
            listen_http_addr,
            log_level: raw.log_level,
            log_format: raw.log_format,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    /// SOCKS5 代理地址
    pub addr: SocketAddr,
    /// TCP 连接超时(秒)
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// 连接池最大连接数
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// 可选: SOCKS5 认证 - 用户名
    #[serde(default)]
    pub username: Option<String>,
    /// 可选: SOCKS5 认证 - 密码
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesConfig {
    /// 白名单域名模式数组，空数组表示允许所有域名
    #[serde(default)]
    pub allow: Vec<String>,
}

// 默认值函数
fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

fn default_timeout() -> u64 {
    30
}

fn default_max_connections() -> usize {
    100
}

impl Config {
    /// 从文件加载配置
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path))?;

        Ok(config)
    }

    /// 保存配置到文件
    #[allow(dead_code)]
    pub fn save(&self, path: &str) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parsing() {
        // 测试旧格式向后兼容
        let toml_str = r#"
[server]
listen_addr = "0.0.0.0:443"
log_level = "info"
log_format = "pretty"

[socks5]
addr = "127.0.0.1:1080"
timeout = 30
max_connections = 100

[rules]
allow = ["*.google.com", "api.*.com"]
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen_https_addr.unwrap().port(), 443);
        assert!(config.server.listen_http_addr.is_none());
        assert_eq!(config.socks5.addr.port(), 1080);
        assert_eq!(config.rules.allow.len(), 2);
    }

    #[test]
    fn test_new_config_format() {
        // 测试新格式：独立的 HTTPS/HTTP 配置
        let toml_str = r#"
[server]
listen_https_addr = "0.0.0.0:443"
listen_http_addr = "0.0.0.0:80"
log_level = "debug"
log_format = "json"

[socks5]
addr = "127.0.0.1:1080"
timeout = 30
max_connections = 100

[rules]
allow = ["*.google.com"]
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen_https_addr.unwrap().port(), 443);
        assert_eq!(config.server.listen_http_addr.unwrap().port(), 80);
        assert_eq!(config.server.log_level, "debug");
        assert_eq!(config.server.log_format, "json");
        assert_eq!(config.rules.allow.len(), 1);
    }

    #[test]
    fn test_https_only_config() {
        // 测试仅配置 HTTPS
        let toml_str = r#"
[server]
listen_https_addr = "0.0.0.0:443"

[socks5]
addr = "127.0.0.1:1080"
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen_https_addr.unwrap().port(), 443);
        assert!(config.server.listen_http_addr.is_none());
    }

    #[test]
    fn test_http_only_config() {
        // 测试仅配置 HTTP
        let toml_str = r#"
[server]
listen_http_addr = "0.0.0.0:80"

[socks5]
addr = "127.0.0.1:1080"
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.server.listen_https_addr.is_none());
        assert_eq!(config.server.listen_http_addr.unwrap().port(), 80);
    }

    #[test]
    fn test_empty_rules_default() {
        let toml_str = r#"
[server]
listen_addr = "0.0.0.0:443"

[socks5]
addr = "127.0.0.1:1080"
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.rules.allow.is_empty());
    }
}
