//! HTTP Host 头解析器

use crate::http::{HttpError, Result};

/// 从 HTTP 请求中提取 Host 头
///
/// # 参数
/// - `buf`: HTTP 请求数据（至少包含请求行和头部）
///
/// # 返回
/// - Host 值（不含端口号）
///
/// # 示例
/// ```
/// use sniproxy_ng::http::extract_host;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///
/// let request = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
/// let host = extract_host(request)?;
/// assert_eq!(host, "www.example.com");
/// # Ok(()) }
/// ```
pub fn extract_host(buf: &[u8]) -> Result<String> {
    let request = std::str::from_utf8(buf)?;

    for line in request.lines() {
        let line = line.trim();

        if line.to_lowercase().starts_with("host:") {
            let host_value = line[5..].trim();

            let host = if host_value.starts_with('[') {
                if let Some(end) = host_value.find(']') {
                    &host_value[..=end]
                } else {
                    host_value
                }
            } else {
                host_value.split(':').next().unwrap_or(host_value)
            };

            if host.is_empty() {
                return Err(HttpError::MalformedHost("empty host".to_string()).into());
            }

            return Ok(host.to_string());
        }
    }

    Err(HttpError::HostNotFound.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_simple() {
        let request = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
        let host = extract_host(request).unwrap();
        assert_eq!(host, "www.example.com");
    }

    #[test]
    fn test_extract_host_with_port() {
        let request = b"GET / HTTP/1.1\r\nHost: www.example.com:8080\r\n\r\n";
        let host = extract_host(request).unwrap();
        assert_eq!(host, "www.example.com");
    }

    #[test]
    fn test_extract_host_case_insensitive() {
        let request = b"GET / HTTP/1.1\r\nhost: www.example.com\r\n\r\n";
        let host = extract_host(request).unwrap();
        assert_eq!(host, "www.example.com");
    }

    #[test]
    fn test_extract_host_with_spaces() {
        let request = b"GET / HTTP/1.1\r\nHost:   www.example.com   \r\n\r\n";
        let host = extract_host(request).unwrap();
        assert_eq!(host, "www.example.com");
    }

    #[test]
    fn test_extract_host_ipv6() {
        let request = b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        let host = extract_host(request).unwrap();
        assert_eq!(host, "[::1]");
    }

    #[test]
    fn test_extract_host_not_found() {
        let request = b"GET / HTTP/1.1\r\n\r\n";
        let result = extract_host(request);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_host_invalid_utf8() {
        let request = b"GET / HTTP/1.1\r\nHost: \xff\xfe\r\n\r\n";
        let result = extract_host(request);
        assert!(result.is_err());
    }
}
