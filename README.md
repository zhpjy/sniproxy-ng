# sniproxy-ng

基于 SNI 的透明代理服务器，支持 HTTPS 和 HTTP，通过 SOCKS5 转发流量。

## 特性

- **HTTPS (443)** - 从 TLS ClientHello 提取 SNI
- **HTTP (80)** - 从 Host 请求头提取域名
- **QUIC/HTTP3（实验性，默认关闭）** - 需在配置中启用
- **SOCKS5 转发** - TCP CONNECT 和 UDP ASSOCIATE
- **域名白名单** - 灵活的通配符匹配
- **连接池** - TCP 连接复用

## 配置

```toml
[server]
listen_https_addr = "0.0.0.0:443"   # HTTPS 端口（可选）
listen_http_addr = "0.0.0.0:80"     # HTTP 端口（可选）
log_level = "info"                   # 本地文件日志级别；RUST_LOG 可覆盖文件和控制台
log_format = "pretty"                # pretty 或 json
log_file = "logs/sniproxy-ng.log"    # 默认写本地文件
console_log_level = "warn"           # 控制台默认只显示 warn/error
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

默认日志会追加写入 `logs/sniproxy-ng.log`，控制台只输出 `warn` 及以上，避免被连接级流水刷屏。排查问题时可临时设置 `RUST_LOG=debug` 或 `RUST_LOG=trace` 同时提升文件和控制台日志详细度；`trace` 会包含逐包/逐连接细节。

`max_client_connections` 是入站客户端并发上限，用于保护进程 fd；`max_connections` 是到 SOCKS5 后端的连接上限。生产环境还应配合 systemd `LimitNOFILE` 或 `ulimit -n` 设置足够的 fd 上限。

QUIC/HTTP3 是实验性模式，默认关闭。配置 `server.quic_mode = "auto|on"` 可启用，环境变量 `SNIPROXY_QUIC_MODE` 可覆盖配置文件。禁用时客户端自动回退到 HTTPS/TCP。

详细说明见 [QUIC 实现说明](docs/QUIC_IMPLEMENTATION_NOTES.md)、[DNS 解析](docs/DNS_RESOLUTION.md)。

## 使用

```bash
# 构建
cargo build --release

# 运行（443/80 端口需要 root 权限）
sudo ./target/release/sniproxy-ng
```

## Nix

项目提供了 flake、开发环境、可构建包、`nix run` app 和 NixOS module，支持直接通过 GitHub flake URL 使用：`github:zhpjy/sniproxy-ng`。

```bash
# 进入开发环境（本地仓库）
nix develop

# 构建程序（本地仓库）
nix build

# 运行程序（本地仓库）
# 注意：程序当前会从当前工作目录读取 config.toml
nix run
```

也可以不克隆仓库，直接从 GitHub 使用：

```bash
# 进入开发环境
nix develop github:zhpjy/sniproxy-ng

# 构建默认包
nix build github:zhpjy/sniproxy-ng

# 或显式指定包名
nix build github:zhpjy/sniproxy-ng#sniproxy-ng

# 运行默认 app
# 注意：程序当前会从当前工作目录读取 config.toml
nix run github:zhpjy/sniproxy-ng

# 或显式指定 app 名称
nix run github:zhpjy/sniproxy-ng#sniproxy-ng
```

如果要直接运行，请先准备当前目录下的 `config.toml`；或先用 `nix build github:zhpjy/sniproxy-ng`，再在包含配置文件的目录中执行 `./result/bin/sniproxy-ng`。

## NixOS

flake 暴露了 `nixosModules.default` 和 `nixosModules.sniproxy-ng`，可直接在 NixOS 配置中引入。

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    sniproxy-ng.url = "github:zhpjy/sniproxy-ng";
  };

  outputs = { nixpkgs, sniproxy-ng, ... }: {
    nixosConfigurations.my-machine = nixpkgs.lib.nixosSystem {
      modules = [
        sniproxy-ng.nixosModules.default
        {
          services.sniproxy-ng = {
            enable = true;
            settings = {
              server = {
                listen_https_addr = "0.0.0.0:443";
                listen_http_addr = "0.0.0.0:80";
              };
              socks5 = {
                addr = "127.0.0.1:1080";
              };
              rules.allow = [ ];
            };
          };
        }
      ];
    };
  };
}
```

服务会以 systemd `DynamicUser` 运行，并自动申请 `CAP_NET_BIND_SERVICE` 以绑定 80/443。

如果你想在自己的 flake 中复用包，也可以直接引用：

```nix
inputs.sniproxy-ng.packages.${pkgs.system}.default
# 或 inputs.sniproxy-ng.packages.${pkgs.system}.sniproxy-ng
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

## Docker

Build the image locally:

```bash
docker build -t sniproxy-ng .
```

Run with the bundled default config (`/app/config.toml`):

```bash
docker run --rm -p 443:443/tcp -p 443:443/udp -p 80:80/tcp sniproxy-ng
```

Mount a custom config at `/app/config.toml` to override the default:

```bash
docker run --rm -p 443:443/tcp -p 443:443/udp -p 80:80/tcp \
  -v "$(pwd)/config.toml:/app/config.toml:ro" \
  sniproxy-ng
```

If your custom config listens on non-privileged ports such as `8443` or `8080`, adjust the published ports accordingly.
