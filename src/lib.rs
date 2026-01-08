//! sniproxy-ng 库
//!
//! SNI 代理服务器，支持 QUIC/HTTP3 和 HTTP/1.1，使用 SOCKS5 后端

pub mod config;
pub mod quic;
pub mod router;
pub mod socks5;
pub mod tcp;
pub mod tls;

// 重新导出常用类型
pub use config::Config;
