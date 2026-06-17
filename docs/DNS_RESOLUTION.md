# DNS 解析与 QUIC 降级说明

sniproxy-ng 在转发 QUIC/HTTP3 时需要从 QUIC Initial packet 中提取 SNI，并把这个域名解析成目标 IP。当前 SOCKS5 UDP 转发路径最终会把 QUIC UDP 包发往解析出的 `IP:443`。

## 启动时 UDP Relay 探测

默认启动模式是：

```bash
SNIPROXY_QUIC_MODE=auto
```

`auto` 模式会在启动时做一次真实的 SOCKS5 UDP relay 探测：通过 SOCKS5 UDP ASSOCIATE 向上游 DNS 服务器发送 DNS 查询，并要求收到有效 DNS 响应。

探测成功：

```text
启用 UDP/443 listener
客户端可使用 QUIC/HTTP3
QUIC 目标 DNS 通过 SOCKS5 UDP 查询
```

探测失败：

```text
不启动 UDP/443 listener
只保留 TCP/443 listener
客户端自动回退到 HTTPS/TCP
```

sniproxy-ng 不会把已经进入的 QUIC/H3 连接转换成 TCP。所谓“降级”是指不提供 UDP/H3 入口，让浏览器或客户端按自身机制回退到 TCP/TLS。这个过程通常对用户无感，最多表现为首次连接略慢。

## QUIC 模式

| 变量 | 含义 |
| --- | --- |
| `SNIPROXY_QUIC_MODE=auto` | 默认。探测 SOCKS5 UDP relay，成功才启用 QUIC/H3 |
| `SNIPROXY_QUIC_MODE=on` | 强制启用 QUIC/H3。即使探测失败也启动 UDP listener |
| `SNIPROXY_QUIC_MODE=off` | 强制禁用 QUIC/H3，只走 HTTPS/TCP |

生产环境建议使用默认 `auto`。

## 默认 DNS 路径：SOCKS5 UDP DNS

当 QUIC/H3 启用时，DNS 查询默认通过 SOCKS5 UDP relay 发出：

```text
sniproxy-ng
  -> SOCKS5 UDP ASSOCIATE
  -> SOCKS5 UDP relay
  -> DNS server:53
```

默认 DNS 服务器：

```bash
SNIPROXY_DNS_SERVER=1.1.1.1:53
```

可以换成其他可信 DNS：

```bash
SNIPROXY_DNS_SERVER=8.8.8.8:53
```

这种模式不会使用代理本机的系统 DNS，也不会从代理本机直接发出 UDP/53。DNS 查询会从 SOCKS5 后端出口发出。

注意：这是明文 DNS。它可以防止代理本机网络或系统 resolver 污染查询结果，但不能防止 SOCKS5 出口网络篡改明文 DNS。这里的前提是你信任 SOCKS5 出口网络。

## 系统 DNS 调试模式

如果需要排查本机 resolver 行为，可以启用系统 DNS：

```bash
SNIPROXY_DNS_DIRECT=1
```

流量路径：

```text
sniproxy-ng
  -> system resolver
```

这个模式会受到 `/etc/hosts`、本地 DNS 服务、透明代理规则、DNS 劫持等影响，不建议生产使用。

## 为什么不用 DoH？

之前实现过 DoH over SOCKS5 TCP。它的安全性更强，但实现更复杂，并且在当前设计里不是必需项：

```text
SOCKS5 UDP relay 可用:
  QUIC/H3 可以工作
  DNS 可通过 SOCKS5 UDP 查询

SOCKS5 UDP relay 不可用:
  QUIC/H3 禁用
  客户端回退 HTTPS/TCP
  TCP 路径使用 SOCKS5 domain CONNECT，不需要本机 DNS
```

因此当前实现移除了 DoH，统一使用 SOCKS5 UDP DNS 作为 QUIC/H3 的上游 DNS，并通过启动探测决定是否启用 QUIC/H3。

## 为什么不直接把 QUIC 发往 SOCKS5 UDP 域名目标？

SOCKS5 UDP 协议上支持在 UDP request header 中写入域名目标。但是部分 SOCKS5 后端不能正确转发“目标地址为域名”的 UDP 包。本项目测试时出现过包已经发出但没有任何上游 QUIC 响应的情况。

为了兼容这些后端，sniproxy-ng 会先通过 SOCKS5 UDP DNS 解析 SNI 域名，再把 QUIC UDP 包通过 SOCKS5 UDP 发往解析出的 IP：

```text
SNI hostname
  -> SOCKS5 UDP DNS
  -> target IP:443
  -> SOCKS5 UDP relay
```
