# sniproxy-ng

下一代 SNI 代理服务器,支持 QUIC/HTTP3 和 HTTP/1.1,通过 SOCKS5 代理转发流量。

## 功能特性

- ✅ **TLS SNI 提取** - 从 TLS ClientHello 中提取 Server Name Indication
- ✅ **SOCKS5 代理** - 通过 SOCKS5 代理转发流量
  - 支持 TCP CONNECT
  - 支持 UDP ASSOCIATE
  - 支持用户名/密码认证
- ✅ **TCP 代理** - 完整的 HTTP/1.1 和 HTTPS 代理功能
- 🚧 **QUIC/HTTP3 支持** - 开发中
- ✅ **结构化日志** - 使用 tracing 框架
- ✅ **配置管理** - TOML 格式配置文件
- ✅ **高性能** - 基于 Tokio 异步运行时

## 使用场景

将特定域名(如 Google 服务)的流量透明地通过 SOCKS5 代理转发:

1. 在 `/etc/hosts` 中将目标域名指向 sniproxy-ng 服务器
2. sniproxy-ng 提取 TLS SNI 并确定目标主机
3. 通过 SOCKS5 代理转发加密流量
4. 对客户端完全透明

## 配置示例

```toml
[server]
listen_addr = "0.0.0.0:443"
log_level = "info"
log_format = "pretty"

[socks5]
addr = "127.0.0.1:1080"
timeout = 30
max_connections = 100
# 可选认证
# username = "user"
# password = "pass"

[rules]
default_backend = "127.0.0.1:1080"

[[rules.domain]]
pattern = "*.google.com"
backend = "127.0.0.1:1080"

[[rules.domain]]
pattern = "*.youtube.com"
backend = "127.0.0.1:1080"
```

## 构建

```bash
# 使用 cargo 构建
cargo build --release

# 或使用 nix (开发环境)
nix build
```

## 运行

```bash
# 1. 创建配置文件 (见上方示例)

# 2. 启动服务器
./target/release/sniproxy-ng

# 或使用 nix run
nix run
```

## 开发

### 依赖

- Rust 1.70+
- Nix (可选,用于开发环境)

### 运行测试

```bash
cargo test
```

### 代码结构

```
src/
├── main.rs          # 程序入口
├── config.rs        # 配置管理
├── tcp/             # TCP 代理实现
│   └── mod.rs       # TCP 监听器和转发逻辑
├── quic/            # QUIC/HTTP3 支持 (开发中)
├── tls/             # TLS SNI 提取
│   └── sni.rs       # SNI 解析实现
└── socks5/          # SOCKS5 客户端
    ├── client.rs    # TCP CONNECT
    └── udp.rs       # UDP ASSOCIATE
```

## 测试状态

- ✅ 10/10 单元测试通过
- ✅ TLS SNI 提取测试 (4 tests)
- ✅ SOCKS5 客户端测试 (4 tests)
- ✅ 配置解析测试 (2 tests)

## TODO

- [ ] 完整的 QUIC/HTTP3 支持
- [ ] 连接池和连接复用
- [ ] 路由规则引擎
- [ ] 性能测试和优化
- [ ] Docker 镜像
- [ ] 更多文档

## 技术栈

- **运行时**: Tokio (异步 Rust)
- **TLS**: rustls
- **QUIC**: Quinn
- **SOCKS5**: fast-socks5
- **日志**: tracing + tracing-subscriber
- **配置**: serde + toml

## 许可证

[待定]

## 贡献

欢迎提交 Issue 和 Pull Request!
