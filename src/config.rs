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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 监听地址 (例如: "0.0.0.0:443")
    pub listen_addr: SocketAddr,
    /// 日志级别: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// 日志格式: json, pretty
    #[serde(default = "default_log_format")]
    pub log_format: String,
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
        assert_eq!(config.server.listen_addr.port(), 443);
        assert_eq!(config.socks5.addr.port(), 1080);
        assert_eq!(config.rules.allow.len(), 2);
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
