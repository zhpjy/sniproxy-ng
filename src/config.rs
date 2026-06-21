use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub socks5: Socks5Config,
    #[serde(default)]
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// 本地日志文件路径
    #[serde(default = "default_log_file")]
    pub log_file: String,
    /// 控制台日志级别，默认只输出告警和错误，避免前台噪声
    #[serde(default = "default_console_log_level")]
    pub console_log_level: String,
    /// 最大同时处理的客户端连接数
    #[serde(default = "default_max_client_connections")]
    pub max_client_connections: usize,
    /// 转发阶段空闲超时(秒)
    #[serde(default = "default_transfer_idle_timeout")]
    pub transfer_idle_timeout: u64,
    #[serde(default = "default_quic_mode")]
    pub quic_mode: String,
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

fn default_log_file() -> String {
    "logs/sniproxy-ng.log".to_string()
}

fn default_console_log_level() -> String {
    "warn".to_string()
}

fn default_max_client_connections() -> usize {
    512
}

fn default_transfer_idle_timeout() -> u64 {
    300
}

fn default_quic_mode() -> String {
    "off".to_string()
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
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_config_format() {
        // 测试新格式：独立的 HTTPS/HTTP 配置
        let toml_str = r#"
[server]
listen_https_addr = "0.0.0.0:443"
listen_http_addr = "0.0.0.0:80"
log_level = "debug"
log_format = "json"
log_file = "logs/test.log"
console_log_level = "error"
max_client_connections = 512
transfer_idle_timeout = 300

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
        assert_eq!(config.server.log_file, "logs/test.log");
        assert_eq!(config.server.console_log_level, "error");
        assert_eq!(config.server.max_client_connections, 512);
        assert_eq!(config.server.transfer_idle_timeout, 300);
        assert_eq!(config.server.quic_mode, "off");
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
        assert_eq!(config.server.log_level, "info");
        assert_eq!(config.server.log_format, "pretty");
        assert_eq!(config.server.log_file, "logs/sniproxy-ng.log");
        assert_eq!(config.server.console_log_level, "warn");
        assert_eq!(config.server.max_client_connections, 512);
        assert_eq!(config.server.transfer_idle_timeout, 300);
        assert_eq!(config.server.quic_mode, "off");
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
listen_https_addr = "0.0.0.0:443"

[socks5]
addr = "127.0.0.1:1080"
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.rules.allow.is_empty());
    }
}
