use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{error, warn};

pub async fn log_accept_error(kind: &str, error: &std::io::Error) {
    error!(
        fd_used = current_fd_count(),
        "Error accepting {}: {}", kind, error
    );

    if matches!(error.raw_os_error(), Some(23 | 24)) {
        warn!(
            "File descriptor limit reached while accepting {}; backing off before retry",
            kind
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    } else {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn copy_with_idle_timeout<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0;

    loop {
        let n = tokio::time::timeout(idle_timeout, reader.read(&mut buf))
            .await
            .map_err(|_| anyhow!("Forwarding idle timeout after {:?}", idle_timeout))??;

        if n == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }

        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

fn current_fd_count() -> i64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc/self/fd")
            .map(|entries| entries.count() as i64)
            .unwrap_or(-1)
    }

    #[cfg(not(target_os = "linux"))]
    {
        -1
    }
}
