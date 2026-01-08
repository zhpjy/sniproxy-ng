# sniproxy-ng

基于 SNI 的透明代理服务器，支持 HTTPS 和 HTTP，通过 SOCKS5 转发流量。

## 特性

- **HTTPS (443)** - 从 TLS ClientHello 提取 SNI
- **HTTP (80)** - 从 Host 请求头提取域名
- **QUIC/HTTP3 支持** - 解密 Initial Packet 提取 SNI
- **SOCKS5 转发** - TCP CONNECT 和 UDP ASSOCIATE
- **域名白名单** - 灵活的通配符匹配
- **连接池** - TCP 和 QUIC 会话复用

## 配置

```toml
[server]
listen_https_addr = "0.0.0.0:443"   # HTTPS 端口（可选）
listen_http_addr = "0.0.0.0:80"     # HTTP 端口（可选）
log_level = "info"

[socks5]
addr = "127.0.0.1:1080"
timeout = 30
max_connections = 100

[rules]
allow = ["*.google.com", "*youtube.com"]  # 空数组允许所有域名
```

两个端口独立配置，可分别启用。

## 使用

```bash
# 构建
cargo build --release

# 运行（443/80 端口需要 root 权限）
sudo ./target/release/sniproxy-ng
```

## 测试

**无需 root 权限的测试方法**：

临时修改配置文件，使用非特权端口：

```toml
[server]
listen_https_addr = "0.0.0.0:8443"   # HTTPS 测试端口
listen_http_addr = "0.0.0.0:8080"    # HTTP 测试端口
```

```bash
# 测试 QUIC/HTTP3 (HTTPS)
curl --http3 https://www.google.com --connect-to www.google.com:443:127.0.0.1:8443

# 测试 HTTP/1.1 (HTTP)
curl -v http://www.google.com/ --connect-to www.google.com:80:127.0.0.1:8080
```

`--connect-to` 参数将流量重定向到本地测试端口，无需修改 `/etc/hosts`。

## 工作原理

```
HTTP (80)  → Host 头提取 ↘
                          → Router → SOCKS5 → 目标服务器
HTTPS (443) → SNI 提取   ↗
```

1. **HTTPS**：客户端连接 443 端口 → 提取 TLS SNI → 验证白名单 → 转发
2. **HTTP**：客户端连接 80 端口 → 提取 Host 头 → 验证白名单 → 转发
3. 两个端口共享连接池和路由规则

## 技术栈

- Tokio (异步运行时)
- rustls (TLS)
- ring (QUIC 加密)
- fast-socks5 (SOCKS5 客户端)

## License

MIT
