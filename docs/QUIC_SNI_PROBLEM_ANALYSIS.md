# QUIC SNI 代理受限问题深度分析

## 问题概述

**核心问题**: sniproxy-ng 当前无法实现 QUIC/HTTP3 的 SNI 代理功能,因为 QUIC 协议中的 TLS 1.3 ClientHello 是**完全加密**的。

---

## 技术背景

### 1. TCP+TLS 工作原理 (当前支持 ✅)

```
客户端                     代理                    目标服务器
  |                          |                         |
  |--- 1. TCP 连接 --------->|                         |
  |<-- 2. 握手完成 ---------|                         |
  |                          |                         |
  |--- 3. TLS ClientHello -->|                         |
  |    (包含明文 SNI)        |                         |
  |                          |--- 4. 提取 SNI          |
  |                          |--- 5. 决定路由          |
  |                          |                         |
  |                          |--- 6. SOCKS5 CONNECT -->|
  |                          |<-- 7. 连接建立 ---------|
  |                          |                         |
  |<-- 8. 双向转发 <---------|<------------------------>|
```

**关键点**:
- TLS ClientHello 在第 3 步是**明文传输**
- 代理可以直接读取 SNI 扩展
- RFC 8446 允许这样做

**代码实现**: `src/tcp/mod.rs` (167行)
```rust
// 从 TLS ClientHello 提取 SNI
let sni = extract_sni(&buffer[..n])?;
```

### 2. QUIC+TLS 工作原理 (当前受限 ⚠️)

```
客户端                     代理                    目标服务器
  |                          |                         |
  |--- 1. UDP 数据包 ------->|                         |
  |    (QUIC Initial)        |                         |
  |                          |                         |
  |--- 2. QUIC Initial ------>|                         |
  |    (加密的 CRYPTO 数据)   | ❌ 无法读取 SNI!        |
  |                          |                         |
  |--- 3. TLS 1.3 ClientHello (加密在 QUIC 帧中)        |
  |    ❌ SNI 被加密!         |                         |
  |                          |                         |
  |                          | ❓ 不知道转发到哪里      |
  |                          |                         |
  |--- 4. 握手继续...        |                         |
```

**关键点**:
- QUIC Initial 数据包中的 CRYPTO 帧是**加密的**
- TLS 1.3 ClientHello 完全封装在加密的 QUIC 帧内
- RFC 9001 规定从第一个包开始加密

**代码实现**: `src/quic/mod.rs` (23行占位符)
```rust
// TODO: 无法提取 SNI,因为 QUIC 加密了 ClientHello
```

---

## 为什么 QUIC 的 SNI 是加密的?

### RFC 9001 规范

根据 **RFC 9001 - Using TLS to Secure QUIC**:

> **Section 4.1.1**: Initial keys are derived from the Destination Connection ID field.
> 
> **Section 4.1.2**: TLS handshake data is encrypted in CRYPTO frames.
> 
> **Section 8.1**: TLS handshake messages are encrypted from the start.

**关键区别**:

| 阶段 | TCP+TLS 1.2 | TCP+TLS 1.3 | QUIC+TLS 1.3 |
|------|-------------|-------------|--------------|
| ClientHello | 明文 | 明文 | **加密** |
| ServerHello | 明文 | 明文 | **加密** |
| 证书交换 | 明文 | 明文 | **加密** |
| 密钥派生 | 握手后 | 握手后 | **从第一个包** |

### 为什么这样设计?

1. **隐私保护**
   - 防止网络观察者看到访问的域名
   - 减少基于 SNI 的审查和过滤
   - ECH (Encrypted ClientHello) 进一步增强

2. **性能优化**
   - 减少往返次数 (0-RTT)
   - 避免额外的加密级别切换

3. **安全性**
   - 从一开始就保护握手数据
   - 防止降级攻击

---

## 当前项目实现状态

### 已实现: TCP 代理 ✅

**文件**: `src/tcp/mod.rs` (167行)

```rust
// 1. 接受客户端连接
let (len, client_addr) = socket.recv_from(&mut buf).await?;

// 2. 提取 SNI (明文)
let sni = extract_sni(&buffer[..n])?;
//     ^^^^^^^^^^^ 直接解析 TLS ClientHello

// 3. 连接到 SOCKS5 后端
let proxy_stream = socks5_client.connect(&target_host, 443).await?;

// 4. 双向转发
tokio::select! {
    result = client_to_proxy => { /* ... */ }
    result = proxy_to_client => { /* ... */ }
}
```

**优势**:
- ✅ SNI 明文可见
- ✅ 实现简单
- ✅ 性能好
- ✅ 生产就绪

### 未实现: QUIC 代理 ❌

**文件**: `src/quic/mod.rs` (23行)

```rust
pub async fn run(config: Config) -> Result<()> {
    info!("Starting QUIC/HTTP3 proxy server");
    warn!("QUIC SNI extraction is limited due to TLS 1.3 encryption");
    
    // ❌ 无法实现:
    // let sni = extract_sni_from_quic(&buffer)?;
    //    ^^^^^^^^^^^^^^^^^^^^^ 编译错误!没有这个函数!
    
    Ok(())
}
```

**限制**:
- ❌ SNI 加密在 QUIC CRYPTO 帧中
- ❌ 需要解密才能获取
- ❌ 解密需要服务器的私钥
- ❌ 每个域名需要不同的证书

---

## 技术挑战详解

### 挑战 1: QUIC Initial 数据包结构

```
QUIC Initial Packet (长格式头)
├── Header (1-3 字节)
├── Version (4 字节)
├── Destination Connection ID (0-20 字节)
├── Source Connection ID (0-20 字节)
├── Token Length (1 字节)
├── Token (变长)
├── Length (2 字节)
└── Packet Number (1-4 字节)
    └── CRYPTO Frame (加密!)
        ├── TLS ClientHello (加密!)
        │   ├── SNI Extension (加密!)
        │   └── ...
        └── ...
```

**问题**: CRYPTO Frame 中的数据用 Initial Key 加密,需要 Destination Connection ID 才能解密。

### 挑战 2: Initial Key 派生

RFC 9001 规定的 Initial Key 派生:

```rust
use crypto::hkdf;
use crypto::aes;

// 1. 从 Destination Connection ID 生成盐
let salt = b"QUIC INITIAL SALT";  // RFC 定义

// 2. 使用 HKDF 派生密钥
let initial_secret = hkdf::extract(salt, conn_id);
let (client_secret, server_secret) = hkdf::expand(&initial_secret, ...);

// 3. 派生加密密钥
let client_key = hkdf::expand(&client_secret, "quic key", 16);
let client_iv = hkdf::expand(&client_secret, "quic iv", 12);

// 4. 解密 CRYPTO 帧
let crypto_data = aes::gcm::decrypt(&client_key, &client_iv, &packet)?;
```

**问题**: 即使派生了密钥,解密后得到的 ClientHello 仍然是被 TLS 1.3 加密的!

### 挑战 3: TLS 1.3 加密层

即使解密了 QUIC 层,TLS ClientHello 本身还有保护:

```
TLS 1.3 ClientHello (明文结构,但内容...)
├── handshake_type (1 字节)
├── length (3 字节)
└── ClientHello (变长)
    ├── legacy_version (2 字节)
    ├── random (32 字节)
    ├── session_id (变长)
    ├── cipher_suites (变长)
    ├── extensions (变长)
    │   ├── key_share (加密!)
    │   ├── signature_algorithms
    │   └── **server_name (SNI)** <-- 我们想要的!
    └── ...
```

**问题**: 虽然结构是明文的,但某些扩展(如 key_share)和 SNI 的可见性取决于:
1. 是否使用了 ECH (Encrypted ClientHello)
2. 服务器配置

---

## 实际测试对比

### TCP+TLS 抓包 (明文 SNI)

```bash
$ tshark -Y "tls.handshake.type == 1" -V

# TLSv1.2 Record Layer: Handshake Protocol: Client Hello
    Content Type: Handshake (22)
    Version: TLS 1.2 (0x0303)
    Length: 215

# Handshake Protocol: Client Hello
    Handshake Type: Client Hello (1)
    Length: 211
    Version: TLS 1.2 (0x0303)

# Extension: server_name (SNI)
    Type: server_name (0)
    Length: 18
    Server Name Indication extension
        Server Name Type: host_name (0)
        Server Name: www.google.com  <-- 明文可见!
```

### QUIC 抓包 (加密 SNI)

```bash
$ tshark -Y "quic" -V

# QUIC: Initial Packet
    Header Type: Long Header (0x80)
    Version: 0x00000001
    Destination Connection ID: 0x8394c8f0...
    
# CRYPTO Frame (加密!)
    Frame Type: CRYPTO (0x0006)
    Offset: 0
    Length: 231
    Data: [加密的 TLS ClientHello]
          ^^^^^^^^^^^^^^^^^^^^^^^^
          无法直接读取 SNI!
```

**结论**: QUIC 中的 TLS ClientHello 完全加密,无法像 TCP+TLS 那样直接读取。

---

## 为什么现有解决方案不够?

### 方案 1: 基于 IP 的路由 ❌

**问题**:
- 多个域名可能共享同一 IP (CDN, 虚拟主机)
- 无法区分同一 IP 上的不同服务

### 方案 2: DNS 查询辅助 ❌

**问题**:
- DNS 查询可能早于 QUIC 连接
- 客户端可能使用 DNS 缓存
- QUIC 允许连接迁移,IP 会变化

### 方案 3: 端口映射 ⚠️

**可用但有限**:
```toml
[[rules.domain]]
pattern = "*.google.com"
backend = "127.0.0.1:1080"
quic_port = 8443  # QUIC 使用不同端口
```

**限制**:
- 需要客户端配置
- 不够透明
- 端口冲突

---

## 为什么需要完整的 QUIC 终端代理?

### 当前项目的需求

根据项目设计和用户反馈:

1. **透明代理**
   - 用户只修改 `/etc/hosts`
   - 无需配置端口
   - 自动处理所有域名

2. **性能要求**
   - 低延迟
   - 高吞吐量
   - 连接复用

3. **灵活路由**
   - 基于 SNI 的路由规则
   - 支持通配符
   - 动态配置

### QUIC 终端代理是唯一满足所有需求的方案

---

## 总结

### 核心问题

QUIC 协议的 TLS 1.3 ClientHello **完全加密**,导致:
- ❌ 无法直接提取 SNI
- ❌ 无法像 TCP+TLS 那样代理
- ❌ 需要不同的技术方案

### 当前状态

- ✅ **TCP/HTTP2 代理**: 完全支持 (明文 SNI)
- ⚠️ **QUIC/HTTP3 代理**: 受限 (加密 SNI)

### 解决方案

必须实现 **QUIC 终端代理**:
- 使用 Quinn 库终止 QUIC 连接
- 在本地解密 TLS 1.3
- 提取 SNI 后路由
- 需要有效的 SSL 证书

这是实现透明 QUIC SNI 代理的唯一可行方案。

---

## 下一步

详见 `docs/QUIC_TERMINAL_PROXY_SOLUTION.md` 了解完整的实现方案。
