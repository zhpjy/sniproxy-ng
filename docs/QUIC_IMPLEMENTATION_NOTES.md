# QUIC/HTTP3 代理实现说明

## 概述

本文档说明 sniproxy-ng 中 QUIC/HTTP3 代理的实现逻辑、架构设计、已知局限和运维说明。

QUIC/HTTP3 代理的定位是 **best-effort 的 UDP 旁路代理**：不解密完整的 TLS，不终止 QUIC 连接，不解析 HTTP/3 语义。它只解密 QUIC Initial Packet 提取 TLS ClientHello 中的 SNI，拿到域名后做白名单判断，然后通过 SOCKS5 UDP ASSOCIATE 将后续 UDP 流量原样转发到目标站点。

## 技术背景：为什么 QUIC SNI 是加密的

### 1. QUIC 中的 SNI 加密

与传统的 TCP+TLS 不同，QUIC 协议有以下特点：

- **TLS 1.3 集成**: QUIC 深度集成了 TLS 1.3
- **加密握手**: 从第一个数据包开始，所有握手数据都是加密的
- **无明文 SNI**: Server Name Indication (SNI) 不再以明文传输

根据 **RFC 9001** (Using TLS to Secure QUIC):
> QUIC 使用 TLS 1.3 保护握手数据，ClientHello 消息完全封装在加密的 QUIC 帧中

### 2. 实现对比

| 特性 | TCP+TLS (HTTP/2) | QUIC (HTTP/3) |
|------|------------------|---------------|
| SNI 可见性 | ✅ 明文 (TLS ClientHello) | 🔒 加密 (TLS 1.3) |
| 解析难度 | 🟢 直接读取 | 🟡 需要解密 Initial Packet |
| 需要证书 | ❌ 否 | ❌ 否（利用初始密钥派生） |
| 性能 | 较低 (TCP 头部阻塞) | 较高 (多路复用) |

### 3. 核心洞察

QUIC 的 Initial Packet 虽然经过了加密，但**其加密密钥可以从公开的 DCID（Destination Connection ID）推导出来**。原因是 QUIC RFC 9001 Section 5.2 规定了在连接建立前，服务端和客户端都使用一个公开的 INITIAL_SALT + DCID 来派生初始密钥。这意味着：

- **在不持有任何 TLS 证书的情况下，任何中间设备都可以解密 QUIC Initial Packet 的 payload**
- 这仅限于 Initial Packet，后续的 Handshake/Short Header 包使用密文通信无法旁路解密
- 利用这一特性，代理可以提取 SNI，但不会破坏真正的端到端加密

## 实现架构

### 模块结构

```
src/quic/
├── mod.rs       ─ 模块入口，UDP socket 绑定 & 事件循环
├── parser.rs    ─ QUIC Initial Header 解析（DCID、Version、Token、PN 等）
├── crypto.rs    ─ 密钥派生（HKDF），支持 QUIC v1/v2
├── header.rs    ─ 移除 Header Protection，解码 Packet Number
├── decrypt.rs   ─ AEAD payload 解密 + CRYPTO Frame 解析 + TLS ClientHello 提取
├── session.rs   ─ 会话管理 + SOCKS5 UDP relay + DNS
└── error.rs     ─ 错误类型
```

### 核心流程

```
UDP 接收
  │
  ├── 按 client_addr 查现有会话 → 有 → 直接通过 mpsc channel 发送到 relay
  │
  └── 无现有会话（尝试解析 Initial）:
        │
        ├── [parser.rs] 解析 QUIC Initial Header
        │   - 验证 Long Header / packet type / version
        │   - 提取 DCID、SCID、Token、payload_len、pn_offset
        │   - 支持 QUIC v1 (0x00000001) 和 v2 draft (0x709a50c4)
        │
        ├── [crypto.rs] 用 DCID + INITIAL_SALT 派生 Initial Keys
        │   - HKDF-Extract(salt, DCID) → initial_secret
        │   - HKDF-Expand(initial_secret, "client in"/"server in") → direction_secret
        │   - HKDF-Expand → key (16B) | iv (12B) | hp_key (16B)
        │
        ├── [header.rs] 移除 Header Protection
        │   - 用 AES-ECB 和 16-byte sample 生成 mask
        │   - 修复 first byte 低 4 bits
        │   - XOR 解密 Packet Number（1-4 bytes）
        │
        ├── [decrypt.rs] 解密 payload + 解析 CRYPTO Frame
        │   - 构造 Nonce = IV ⊕ PN（big-endian）
        │   - AES-128-GCM 解密 payload
        │   - 解析 QUIC frames: PADDING / PING / CRYPTO / ACK
        │   - 收集 CRYPTO fragment，按 offset 在 BTreeMap 中排序重组
        │   - 自动在两个方向（client/server 角色）尝试
        │
        ├── [src/tls/sni.rs] 从 TLS ClientHello 提取 SNI
        │   - 识别 handshake type 0x01 (ClientHello)
        │   - 遍历 extensions，匹配 type 0x0000 (server_name)
        │   - 返回 hostname
        │
        ├── [Router] 白名单检查
        │
        └── [session.rs] 创建 SOCKS5 UDP ASSOCIATE
            - 自定义 DNS 解析（支持 SOCKS5 UDP DNS 或直接 DNS）
            - 建立双向 UDP relay 任务
            - 将 client_addr → session 存入 HashMap
```

### 密钥派生细节

```text
INITIAL_SALT (v1: 0x38762cf7..., v2: 0x0dede3de...)
        │
        ▼
initial_secret = HKDF-Extract(salt, DCID)
        │
        ├──→ "client in" → client_initial_secret
        │       ├──→ "quic key"  → AES-128-GCM key (16 bytes)
        │       ├──→ "quic iv"   → IV (12 bytes)
        │       └──→ "quic hp"   → Header Protection key (16 bytes)
        │
        └──→ "server in" → server_initial_secret
                ├──→ "quic key"  → AES-128-GCM key (16 bytes)
                ├──→ "quic iv"   → IV (12 bytes)
                └──→ "quic hp"   → Header Protection key (16 bytes)
```

由于 Initial Header 在客户端到服务端和服务端到客户端方向看起来完全相同，`extract_sni_from_quic_initial()` 会依次尝试 `client` 和 `server` 两个角色，选择 reserved bits 验证通过且 AEAD 解密成功的那个。

### 会话管理

- Session 按 `client_addr`（即 UDP 5-tuple 中的远程地址）为 key 存储
- 理由：QUIC 后续大量 Short Header 包无法可靠解析出连接 ID，5-tuple 更工程化
- 每个 session 维护一个 `mpsc::Sender`，对应一个 tokio 任务做双向转发：
  - 客户端 → relay: `rx.recv()` → `relay.send_to(target)`
  - relay → 客户端: `relay.recv_from()` → `socket.send_to(client)`
- 空闲超过 60 秒的 session 会被定期清理

### DNS 解析

- 默认通过 SOCKS5 UDP relay 向 `SNIPROXY_DNS_SERVER` 查询 DNS
- 支持 `SNIPROXY_DNS_DIRECT=1` 跳过 SOCKS5，直接调用 `tokio::net::lookup_host`
- 启动时通过 `probe_socks5_udp_relay()` 探测 SOCKS5 UDP 可用性

## 局限性与设计取舍

| 局限性 | 说明 |
|--------|------|
| **不支持 ECH** | 如果客户端使用 Encrypted ClientHello（ECH），SNI 在 TLS 层被加密，无法提取 |
| **仅支持特定 QUIC 版本** | 支持 QUIC v1 (0x00000001) 和 v2 draft (0x709a50c4)；其他版本返回 UnsupportedVersion |
| **仅处理 Initial Packet** | 不解析 Handshake / Short Header 包，无法获取加密握手后的信息 |
| **不终止 QUIC** | 不解密 HTTP/3 数据，不处理 QUIC 流（stream）、乱序重传、连接迁移等语义 |
| **CRYPTO 分片 best-effort** | 多包 Initial（fragmented CRYPTO）使用全局 `Mutex<HashMap<DCID, fragments>>` 尽力重组，但不是完整的 QUIC 接收窗口实现 |
| **会话按 client addr 识别** | Short Header 无法可靠解析 DCID，所以按 (client_ip, client_port) 管理 session；同一端口的多路连接会被路由到同一 target |
| **依赖 SOCKS5 UDP ASSOCIATE** | QUIC 路由依赖上游 SOCKS5 的 UDP 转发支持；启动时若探测失败则退回 |
| **DNS 复杂度** | 目标地址解析走自定义 SOCKS5 UDP DNS 或直接 DNS，不保证与客户端预期一致 |
| **共享 HTTPS 端口** | QUIC UDP listener 使用 `listen_https_addr`，没有独立的 UDP 配置，与 TCP HTTPS 共享端口号 |
| **无真实流量验证** | 现有测试使用合成数据包，在真实 QUIC 流量环境下的测试不充分 |
| **全局静态 pending CRYPTO** | `decrypt.rs` 中使用了 `static mut` + `Once` 的 `Mutex<HashMap>`，跨 DCID 共享 CRYPTO 片段状态 |

### 设计取舍说明

**为什么不解密 Handshake 之后的包？**
- Handshake 包和 Short Header 包的密钥来自 TLS 1.3 握手协商，中间设备无法获取
- 只有 Initial Packet 使用公开 salt 派生密钥，后续通信是真正的端到端加密
- 因此代理只能从 Initial 提取 SNI，无法做更细粒度的路由

**为什么不直接用 Quinn 做完整 QUIC 代理？**
- 完整 QUIC 代理需要持有服务端私钥/证书来终止 TLS 连接
- 作为透明 SNI 代理，项目目标是无侵入地路由流量，不介入 TLS
- 自定义 wire-format 解析比完整 QUIC 栈启动快、资源开销低

**为什么按 client_addr 而不是按 DCID 做 session 路由？**
- Short Header 包（占连接生命周期中 99% 以上的包）不携带完整的 DCID 长度信息
- 通用的 UDP 转发层无法可靠地从每个包中提取 DCID
- 用 client_addr 做 key 是 "5-tuple 工程化优先" 的实用折中

## 配置与运维

### QUIC 模式控制

| 环境变量 | 取值 | 说明 |
|----------|------|------|
| `server.quic_mode` | `off` / `auto` / `on` | 配置文件选项，默认 `off` |
| `SNIPROXY_QUIC_MODE` | `auto` / `on` / `off` | 运行时环境变量覆盖配置；`auto`: 启动时探测 SOCKS5 UDP，成功则启动；`on`: 强制启用；`off`: 禁用 |
| `SNIPROXY_DNS_SERVER` | `1.1.1.1:53` | QUIC 目标 DNS 服务器（默认 Cloudflare） |
| `SNIPROXY_DNS_DIRECT` | `1` | 跳过 SOCKS5 UDP DNS，改用本机系统 DNS |

默认配置 `server.quic_mode = "off"`。若设置 `SNIPROXY_QUIC_MODE`，其值会覆盖配置；当最终模式为 `auto` 且探测失败时，不会启动 UDP listener，客户端自动回退到 HTTPS/TCP。

### 端口共享

QUIC UDP listener 复用 `[server].listen_https_addr` 端口，与 TCP HTTPS 代理共享同一个端口号（如 443）。这是 QUIC 协议的设计（同一端口同时服务于 UDP QUIC 和 TCP TLS）。

## 参考资源

### RFC 标准
- [RFC 9000: QUIC Transport Protocol](https://datatracker.ietf.org/doc/html/rfc9000)
- [RFC 9001: Using TLS to Secure QUIC](https://datatracker.ietf.org/doc/html/rfc9001)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

### Rust 库
- [ring: 加密库](https://github.com/briansmith/ring)
- [rustls: TLS library in Rust](https://github.com/rustls/rustls)

### 研究论文
- [An Analysis of QUIC Connection Migration in the Wild](https://arxiv.org/html/2410.06066v1)
- [Exposing and Circumventing SNI-based QUIC Censorship](https://gfw.report/publications/usenixsecurity25/en/)

## 总结

**当前状态**: QUIC SNI 代理已实现 best-effort 级别的功能。它通过对 QUIC Initial Packet 进行 wire-format 解析、公开 salt 派生密钥、AEAD 解密来提取 SNI，然后通过 SOCKS5 UDP 做透明转发。

**适用范围**: 白名单分流、透明代理场景，对 QUIC/HTTP3 流量进行域名级路由决策。

**不适用场景**: 需要 QUIC 连接终止、HTTP/3 语义解析、全量 QUIC 版本兼容性的场景。

**核心文件**:
- `src/quic/mod.rs` — 入口和事件循环
- `src/quic/parser.rs` — Initial Header 解析
- `src/quic/crypto.rs` — HKDF 密钥派生
- `src/quic/header.rs` — Header Protection 解除
- `src/quic/decrypt.rs` — payload 解密 + CRYPTO 帧解析
- `src/quic/session.rs` — 会话管理 + SOCKS5 UDP relay
- `src/tls/sni.rs` — TLS ClientHello SNI 提取（TCP 和 QUIC 共用）
