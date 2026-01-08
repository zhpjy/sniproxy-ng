# sniproxy-ng

基于 TLS SNI 的透明代理服务器，通过 SOCKS5 转发流量。

## 特性

- **TLS SNI 提取** - 从 ClientHello 中提取目标域名
- **SOCKS5 转发** - 支持 TCP CONNECT 和 UDP ASSOCIATE
- **QUIC/HTTP3 支持** - 解密 Initial Packet 提取 SNI
- **域名白名单** - 灵活的通配符匹配规则
- **连接池** - TCP 和 QUIC 会话复用

## 配置

```toml
[server]
listen_addr = "0.0.0.0:443"  # 标准 HTTPS 端口
log_level = "info"

[socks5]
addr = "127.0.0.1:1080"
timeout = 30
max_connections = 100

[rules]
allow = ["*.google.com", "*youtube.com"]  # 空数组允许所有域名
```

## 使用

```bash
# 构建
cargo build --release

# 运行（监听 443 端口需要 root 权限）
sudo ./target/release/sniproxy-ng
```

## 测试

**无需 root 权限的测试方法**：

临时修改配置文件，使用非特权端口（如 8443）：

```toml
[server]
listen_addr = "0.0.0.0:8443"  # 临时测试端口
```

```bash
# 测试 QUIC/HTTP3
curl --http3 https://www.google.com --connect-to www.google.com:443:127.0.0.1:8443

# 测试 HTTP/2
curl -v --proxy socks5://127.0.0.1:1080 https://www.google.com
```

`--connect-to` 参数将流量重定向到本地测试端口，无需修改 `/etc/hosts`。

## 工作原理

```
客户端 → sniproxy-ng:443 → 提取 SNI → SOCKS5 代理 → 目标服务器
```

1. 客户端连接到 sniproxy-ng 监听的 443 端口
2. sniproxy-ng 提取 TLS ClientHello 中的 SNI
3. 根据白名单规则验证域名
4. 通过 SOCKS5 代理转发流量

## 技术栈

- Tokio (异步运行时)
- rustls (TLS)
- ring (QUIC 加密)
- fast-socks5 (SOCKS5 客户端)

## License

MIT
