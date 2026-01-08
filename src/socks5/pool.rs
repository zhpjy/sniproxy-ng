/// SOCKS5 连接池
///
/// 复用 SOCKS5 连接以提升性能,避免频繁建立连接的开销。
use crate::socks5::Socks5TcpStream;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info};

/// 连接池配置
#[derive(Clone)]
pub struct PoolConfig {
    /// 最大连接数
    pub max_connections: usize,
    /// 连接空闲超时
    pub idle_timeout: Duration,
    /// 连接最大生命周期
    pub max_lifetime: Duration,
    /// 清理间隔
    pub cleanup_interval: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

/// 连接池中的单个连接
struct PooledConnection {
    /// SOCKS5 流
    stream: Socks5TcpStream,
    /// 创建时间
    created_at: Instant,
    /// 最后使用时间
    last_used: Instant,
    /// 使用次数
    use_count: u64,
}

/// 连接池
pub struct ConnectionPool {
    /// 连接池配置
    config: PoolConfig,
    /// 空闲连接: target_addr -> Vec<Connection>
    idle_connections: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>,
    /// 信号量:限制总连接数
    semaphore: Arc<Semaphore>,
    /// 活跃连接数
    active_count: Arc<Mutex<usize>>,
}

impl ConnectionPool {
    /// 创建新的连接池
    pub fn new(config: PoolConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_connections));
        
        info!(
            "Created SOCKS5 connection pool: max_connections={}, idle_timeout={:?}",
            config.max_connections, config.idle_timeout
        );

        Self {
            config,
            idle_connections: Arc::new(Mutex::new(HashMap::new())),
            semaphore,
            active_count: Arc::new(Mutex::new(0)),
        }
    }

    /// 获取连接
    pub async fn get_connection(
        &self,
        target: &str,
        port: u16,
        connector: impl FnOnce(&str, u16) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Socks5TcpStream>> + Send>>,
    ) -> Result<PooledConnectionGuard> {
        let key = format!("{}:{}", target, port);

        // 1. 尝试从空闲连接中获取
        {
            let mut idle = self.idle_connections.lock().await;
            if let Some(conns) = idle.get_mut(&key) {
                if let Some(idx) = conns.iter().position(|c| {
                    Instant::now().duration_since(c.last_used) < self.config.idle_timeout
                }) {
                    let conn = conns.remove(idx);
                    debug!("Reusing pooled connection to {}", key);
                    
                    // 如果没有空闲连接了,移除 key
                    if conns.is_empty() {
                        idle.remove(&key);
                    }

                    return Ok(PooledConnectionGuard {
                        pool: self.clone(),
                        key,
                        connection: Some(conn),
                    });
                }
            }
        }

        // 2. 没有可用连接,创建新连接
        debug!("Creating new SOCKS5 connection to {}", key);
        
        // 等待信号量(限制总连接数)
        let _permit = self.semaphore.acquire().await
            .map_err(|e| anyhow!("Failed to acquire semaphore: {}", e))?;

        let stream = connector(target, port).await?;

        // 增加活跃连接计数
        {
            let mut count = self.active_count.lock().await;
            *count += 1;
        }

        let conn = PooledConnection {
            stream,
            created_at: Instant::now(),
            last_used: Instant::now(),
            use_count: 1,
        };

        Ok(PooledConnectionGuard {
            pool: self.clone(),
            key,
            connection: Some(conn),
        })
    }

    /// 归还连接到池中
    async fn return_connection(&self, key: String, conn: PooledConnection) {
        // 检查连接是否仍然有效
        let now = Instant::now();
        let age = now.duration_since(conn.created_at);
        let idle = now.duration_since(conn.last_used);

        // 如果连接太老或空闲太久,丢弃它
        if age > self.config.max_lifetime || idle > self.config.idle_timeout {
            debug!("Dropping expired connection to {} (age={:?}, idle={:?})", key, age, idle);
            let mut count = self.active_count.lock().await;
            *count = count.saturating_sub(1);
            return;
        }

        // 将连接返回到池中
        let mut idle = self.idle_connections.lock().await;
        let conns = idle.entry(key.clone()).or_insert_with(Vec::new);
        
        // 限制每个目标的空闲连接数(最多5个)
        if conns.len() < 5 {
            debug!("Returning connection to {} to pool (use_count={})", key, conn.use_count);
            conns.push(conn);
        } else {
            debug!("Pool full for {}, dropping connection", key);
            let mut count = self.active_count.lock().await;
            *count = count.saturating_sub(1);
        }
    }

    /// 获取统计信息
    #[allow(dead_code)]
    pub async fn stats(&self) -> PoolStats {
        let idle = self.idle_connections.lock().await;
        let active = *self.active_count.lock().await;

        let idle_count = idle.values().map(|v| v.len()).sum();
        let targets: Vec<String> = idle.keys().cloned().collect();

        PoolStats {
            active_connections: active,
            idle_connections: idle_count,
            total_targets: targets.len(),
            targets,
        }
    }

    /// 清理过期连接
    #[allow(dead_code)]
    pub async fn cleanup(&self) {
        let mut idle = self.idle_connections.lock().await;
        let now = Instant::now();
        let mut removed = 0;

        idle.retain(|_key, conns| {
            conns.retain(|conn| {
                let idle_time = now.duration_since(conn.last_used);
                let age = now.duration_since(conn.created_at);
                
                let keep = idle_time < self.config.idle_timeout && age < self.config.max_lifetime;
                if !keep {
                    removed += 1;
                }
                keep
            });

            // 如果没有空闲连接了,移除 key
            !conns.is_empty()
        });

        if removed > 0 {
            info!("Cleaned up {} expired connections", removed);
        }
    }

    /// 启动连接池清理任务
    ///
    /// 定期清理过期的空闲连接，返回任务句柄
    pub fn spawn_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.config.cleanup_interval);
            loop {
                interval.tick().await;
                self.cleanup().await;
            }
        })
    }
}

impl Clone for ConnectionPool {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            idle_connections: Arc::clone(&self.idle_connections),
            semaphore: Arc::clone(&self.semaphore),
            active_count: Arc::clone(&self.active_count),
        }
    }
}

/// 连接池守卫,自动归还连接
pub struct PooledConnectionGuard {
    pool: ConnectionPool,
    key: String,
    connection: Option<PooledConnection>,
}

impl PooledConnectionGuard {
    /// 获取底层的 SOCKS5 流引用
    #[allow(dead_code)]
    pub fn get(&self) -> &Socks5TcpStream {
        &self.connection.as_ref().unwrap().stream
    }

    /// 获取底层的 SOCKS5 流可变引用
    #[allow(dead_code)]
    pub fn get_mut(&mut self) -> &mut Socks5TcpStream {
        &mut self.connection.as_mut().unwrap().stream
    }

    /// 取出流的所有权，用于需要转移所有权的场景 (如 split)
    ///
    /// 注意：取出后连接不会被归还到池中
    pub fn into_inner(mut self) -> Socks5TcpStream {
        // 取出连接，阻止 Drop 中的归还逻辑
        self.connection.take().unwrap().stream
    }
}

impl Drop for PooledConnectionGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            let pool = self.pool.clone();
            let key = self.key.clone();
            
            tokio::spawn(async move {
                pool.return_connection(key, conn).await;
            });
        }
    }
}

/// 连接池统计信息
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PoolStats {
    pub active_connections: usize,
    pub idle_connections: usize,
    pub total_targets: usize,
    pub targets: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_pool_creation() {
        let config = PoolConfig {
            max_connections: 10,
            idle_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(120),
        };

        let pool = ConnectionPool::new(config);
        let stats = pool.stats().await;
        
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.idle_connections, 0);
    }
}
