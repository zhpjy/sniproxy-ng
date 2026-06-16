pub mod client;
pub mod pool;
pub mod udp;

// 重新导出常用类型
pub use client::{Socks5Client, Socks5TcpStream};
pub use pool::{ConnectionPool, PoolConfig};
