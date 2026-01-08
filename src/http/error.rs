//! HTTP 代理错误类型

use thiserror::Error;

/// HTTP 代理过程中可能出现的错误
#[derive(Error, Debug)]
pub enum HttpError {
    /// 无效的 HTTP 请求
    #[error("Invalid HTTP request: {0}")]
    InvalidRequest(String),

    /// Host 头未找到
    #[error("Host header not found")]
    HostNotFound,

    /// Host 头格式错误
    #[error("Malformed host header: {0}")]
    MalformedHost(String),

    /// 域名不被允许
    #[error("Domain not allowed: {0}")]
    DomainNotAllowed(String),

    /// UTF-8 解码错误
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
}

pub type Result<T> = std::result::Result<T, HttpError>;
