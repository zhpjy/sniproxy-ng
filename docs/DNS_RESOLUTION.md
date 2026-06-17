# DNS 解析说明

sniproxy-ng 在转发 QUIC/HTTP3 时需要做 DNS 解析。流程是先从 QUIC Initial packet 中提取 SNI，然后把这个域名解析成目标 IP，因为当前 SOCKS5 UDP 转发路径最终需要把 UDP 包发往一个 IP 目标。

## 默认模式：DoH over SOCKS5

默认情况下，DNS 查询会以 DNS-over-HTTPS 的方式通过已配置的 SOCKS5 后端发出：

```text
sniproxy-ng
  -> SOCKS5 TCP CONNECT
  -> DoH server:443
  -> HTTPS DNS query
```

默认 DoH 地址：

```bash
SNIPROXY_DOH_URL=https://cloudflare-dns.com/dns-query
```

这种模式可以避免代理本机的系统 DNS 被污染，也可以避免代理本机网络上的明文 UDP/53 DNS 被劫持。本地网络侧只能看到 sniproxy-ng 连接 SOCKS5 后端，看不到明文 DNS 查询。

如果要换成其他 DoH 服务：

```bash
SNIPROXY_DOH_URL=https://dns.google/dns-query
```

## UDP DNS 调试模式

仅调试时可以使用明文 UDP DNS：

```bash
SNIPROXY_DNS_MODE=udp
SNIPROXY_DNS_SERVER=1.1.1.1:53
```

流量路径：

```text
sniproxy-ng
  -> 从代理本机直接发出 UDP/53
  -> DNS server
```

这个 UDP DNS 查询不走 SOCKS5 代理，也没有加密。如果目标是防 DNS 劫持，不要使用这个模式。

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

这个模式会受到 `/etc/hosts`、本地 DNS 服务、透明代理规则、DNS 劫持等影响。生产环境如果要处理可能被本地污染的域名，不建议使用该模式。

## 为什么不总是使用 SOCKS5 UDP 域名目标？

SOCKS5 UDP 协议上支持在 UDP request header 中写入域名目标。但是部分 SOCKS5 后端不能正确转发“目标地址为域名”的 UDP 包。本项目测试时出现过包已经发出但没有任何上游 QUIC 响应的情况。

为了兼容这些后端，sniproxy-ng 会先解析 SNI 域名，再把 QUIC UDP 包通过 SOCKS5 UDP 发往解析出的 IP：

```text
SNI hostname
  -> DoH over SOCKS5
  -> target IP:443
  -> SOCKS5 UDP relay
```

这样可以同时避免本机 DNS 污染，以及 SOCKS5 UDP 后端不兼容域名目标的问题。

## 配置汇总

| 变量 | 默认值 | 流量路径 | 用途 |
| --- | --- | --- | --- |
| `SNIPROXY_DOH_URL` | `https://cloudflare-dns.com/dns-query` | DoH over SOCKS5 TCP | 生产默认 |
| `SNIPROXY_DNS_MODE=udp` | 未设置 | 从代理本机直接发出 UDP/53 | 仅调试 |
| `SNIPROXY_DNS_SERVER` | UDP 模式下默认 `1.1.1.1:53` | 从代理本机直接发出 UDP/53 | 仅调试 |
| `SNIPROXY_DNS_DIRECT=1` | 未设置 | 系统 resolver | 仅调试 |

如果需要防 DNS 劫持，应使用默认的 DoH-over-SOCKS5 模式，不要设置 `SNIPROXY_DNS_MODE=udp` 或 `SNIPROXY_DNS_DIRECT=1`。
