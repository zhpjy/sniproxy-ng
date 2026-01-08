# HTTP 代理功能设计文档

## 概述

在现有 TLS SNI 代理基础上，新增 HTTP/1.1 明文代理功能，通过 Host 请求头提取目标域名。

## 架构

```
                        ┌─────────────┐
┌────────────┐          │             │ ┌──────────┐
│ :80 HTTP   │─────────→│ HTTP Parser │→│ Router   │
└────────────┘          │             │ │          │
                        └─────────────┘ │          │
┌────────────┐          ┌─────────────┐ │          │
│ :443 TLS   │─────────→│ SNI Extract │→│          │────→┐
└────────────┘          └─────────────┘ │          │     │
                                        │ Session  │     │
                                        │ Manager  │     │
                                        └──────────┘     │
                                                          ▼
                                                   ┌─────────┐
                                                   │ SOCKS5   │
                                                   │ Proxy   │
                                                   └─────────┘
```

## 新增模块

```
src/
├── http/
│   ├── mod.rs       # HTTP 监听器主逻辑
│   ├── parser.rs    # Host 头解析
│   └── error.rs     # HTTP 错误类型
```

## 配置变更

```toml
[server]
listen_https_addr = "0.0.0.0:443"   # 可选
listen_http_addr = "0.0.0.0:80"     # 可选
log_level = "info"

[socks5]
addr = "127.0.0.1:1080"

[rules]
allow = ["*.google.com", "*youtube.com"]
```

两个端口独立配置，可分别启用。

## Host 提取逻辑

1. `peek()` 读取初期数据（4KB 缓冲区）
2. 解析 `Host:` 请求头
3. 去除端口号（`:8080`）
4. 验证白名单规则

```rust
pub fn extract_host(buf: &[u8]) -> Result<String> {
    let request = std::str::from_utf8(buf)?;

    for line in request.lines() {
        if line.to_lowercase().starts_with("host:") {
            let host = line[5..].trim().split(':').next().unwrap_or("");
            return Ok(host.to_string());
        }
    }

    Err(HttpError::HostNotFound)
}
```

## 错误处理策略

与 HTTPS 端口保持一致：**静默关闭连接**，不返回 HTTP 响应。

| 场景 | 处理 |
|------|------|
| 连接立即关闭 | 静默 |
| 无 Host 头 | 记录警告，关闭 |
| 域名不允许 | 记录警告，关闭 |
| SOCKS5 失败 | 记录错误，关闭 |

## 复用组件

- `socks5::pool` → 共享连接池
- `router::Router` → 共享白名单
- `tracing` → 统一日志
