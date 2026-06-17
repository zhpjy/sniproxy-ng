# sniproxy-ng

基于 SNI 的透明代理服务器，支持 HTTPS 和 HTTP，通过 SOCKS5 转发流量。

## 特性

- **HTTPS (443)** - 从 TLS ClientHello 提取 SNI
- **HTTP (80)** - 从 Host 请求头提取域名
- **QUIC/HTTP3（best-effort）** - 仅解密 QUIC Initial Packet 提取 SNI，用于白名单/放行决策，然后做 UDP 透明转发（不终止 QUIC，不解析 HTTP/3）
- **SOCKS5 转发** - TCP CONNECT 和 UDP ASSOCIATE
- **域名白名单** - 灵活的通配符匹配
- **连接池** - TCP 和 QUIC 会话复用

## 配置

```toml
[server]
listen_https_addr = "0.0.0.0:443"   # HTTPS 端口（可选）
listen_http_addr = "0.0.0.0:80"     # HTTP 端口（可选）
log_level = "info"
max_client_connections = 512        # 最大同时处理的客户端连接数
transfer_idle_timeout = 300         # 转发空闲超时（秒）

[socks5]
addr = "127.0.0.1:1080"
timeout = 30
max_connections = 100               # SOCKS5 后端最大连接数

[rules]
allow = ["*.google.com", "*youtube.com"]  # 空数组允许所有域名
```

两个端口独立配置，可分别启用。

`max_client_connections` 是入站客户端并发上限，用于保护进程 fd；`max_connections` 是到 SOCKS5 后端的连接上限。生产环境还应配合 systemd `LimitNOFILE` 或 `ulimit -n` 设置足够的 fd 上限。

QUIC/HTTP3 依赖 SOCKS5 UDP relay。默认 `SNIPROXY_QUIC_MODE=auto` 会在启动时探测 SOCKS5 UDP relay，探测成功才启用 UDP/H3；失败则不启动 UDP listener，让客户端自动回退到 HTTPS/TCP。

```bash
SNIPROXY_QUIC_MODE=auto
SNIPROXY_DNS_SERVER=1.1.1.1:53
```

QUIC 目标 DNS 默认通过 SOCKS5 UDP relay 查询 `SNIPROXY_DNS_SERVER`，不会使用本机系统 DNS。也可设置 `SNIPROXY_QUIC_MODE=on|off` 强制启用或禁用 QUIC/H3。

详细说明见 [DNS Resolution](docs/DNS_RESOLUTION.md)。

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
