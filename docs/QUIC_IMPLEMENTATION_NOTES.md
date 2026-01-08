# QUIC/HTTP3 代理实现说明

## 概述

本文档说明 sniproxy-ng 中 QUIC/HTTP3 代理的实现状态、技术挑战和可能的解决方案。

## 技术挑战

### 1. QUIC 中的 SNI 加密

与传统的 TCP+TLS 不同,QUIC 协议有以下特点:

- **TLS 1.3 集成**: QUIC 深度集成了 TLS 1.3
- **加密握手**: 从第一个数据包开始,所有握手数据都是加密的
- **无明文 SNI**: Server Name Indication (SNI) 不再以明文传输

根据 **RFC 9001** (Using TLS to Secure QUIC):
> QUIC 使用 TLS 1.3 保护握手数据,ClientHello 消息完全封装在加密的 QUIC 帧中

这意味着我们无法像处理 TCP+TLS 那样简单地解析数据包并提取 SNI。

### 2. 实现对比

| 特性 | TCP+TLS (HTTP/2) | QUIC (HTTP/3) |
|------|------------------|---------------|
| SNI 可见性 | ✅ 明文 (TLS ClientHello) | ❌ 加密 (TLS 1.3) |
| 解析难度 | 🟢 简单 | 🔴 困难 |
| 需要证书 | ❌ 否 | ✅ 是 (如需终止连接) |
| 性能 | 较低 (TCP 头部阻塞) | 较高 (多路复用) |

## 当前实现

### TCP 代理 (已完成) ✅

```
src/tcp/mod.rs - 167 行
```

**功能**:
- 接受客户端 TLS 连接
- 提取明文 SNI (从 TLS ClientHello)
- 通过 SOCKS5 转发到目标服务器
- 双向数据转发

**流程**:
```
客户端 → [sniproxy-ng 提取 SNI] → SOCKS5 代理 → 目标服务器
```

### QUIC 代理 (未完全实现) ⚠️

```
src/quic/mod.rs - 23 行 (占位符)
```

**状态**:
- 基础框架已创建
- 包含技术限制说明
- 未实现实际转发功能

**限制**:
- 无法直接提取加密的 SNI
- 需要其他机制确定目标地址

## 可能的解决方案

### 方案 1: QUIC 终端代理

**原理**:
- 使用 Quinn 库终止 QUIC 连接
- 在本地解密 TLS 1.3
- 提取 SNI 后路由到后端

**优点**:
- 可以获取完整 SNI
- 支持完整的 HTTP/3 功能

**缺点**:
- 需要 SSL 证书 (每个域名)
- 高 CPU 开销 (加密/解密)
- 复杂的实现

**技术栈**:
```toml
quinn = "0.11"
rustls = "0.23"
```

**示例架构**:
```
客户端 → [QUIC 终端代理 (解密)] → [提取 SNI] → 后端服务器
         ↓ 需要 SSL 证书
```

### 方案 2: 基于配置的路由

**原理**:
- 在配置文件中预定义域名到后端的映射
- 不依赖 SNI 提取
- 简单的 UDP 转发

**优点**:
- 实现简单
- 无需证书
- 低开销

**缺点**:
- 不够灵活
- 需要预配置
- 无法处理动态域名

**配置示例**:
```toml
[[rules.domain]]
pattern = "*.google.com"
backend = "127.0.0.1:1080"
quic_target = "www.google.com:443"
```

### 方案 3: DNS 查询辅助

**原理**:
- 监听 DNS 查询
- 记录域名到 IP 的映射
- 结合客户端 IP 推断目标

**优点**:
- 无需修改 QUIC 流量
- 可以处理动态域名

**缺点**:
- 依赖 DNS 查询顺序
- 可能不准确
- 隐私问题

### 方案 4: Encrypted Client Hello (ECH)

**原理**:
- 利用 ECH 扩展的某些信息
- 部分暴露 SNI 或相关标识

**状态**:
- 仍在研究中
- 支持有限
- 未来方案

## 推荐实现路径

### 短期 (当前版本)

保持现状:
- ✅ TCP 代理 (已完成)
- ⚠️ QUIC 代理 (文档说明限制)
- 专注于 TCP/HTTP/2 的 SNI 代理

### 中期 (下一版本)

实现方案 2 (基于配置的路由):
```rust
// 伪代码
if let Some(rule) = config.rules.find_by_client_ip(client_ip) {
    target = rule.quic_target;
    forward_udp_packet(target);
}
```

### 长期 (未来版本)

实现方案 1 (QUIC 终端代理):
- 使用 Quinn 终止 QUIC 连接
- 支持多域名证书
- 完整的 HTTP/3 支持

## 参考资源

### RFC 标准
- [RFC 9000: QUIC Transport Protocol](https://datatracker.ietf.org/doc/html/rfc9000)
- [RFC 9001: Using TLS to Secure QUIC](https://datatracker.ietf.org/doc/html/rfc9001)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

### Rust 库
- [Quinn: QUIC implementation in Rust](https://github.com/quinn-rs/quinn)
- [rustls: TLS library in Rust](https://github.com/rustls/rustls)

### 研究论文
- [An Analysis of QUIC Connection Migration in the Wild](https://arxiv.org/html/2410.06066v1)
- [Exposing and Circumventing SNI-based QUIC Censorship](https://gfw.report/publications/usenixsecurity25/en/)

### 类似项目
- [sniproxy-rs: SNI-based reverse proxy](https://github.com/jameysharp/sniproxy-rs)
- [rust-rpxy-l4: L4 reverse proxy](https://github.com/junkurihara/rust-rpxy-l4)

## 总结

**当前状态**: TCP 代理功能完整可用,QUIC 代理因加密限制暂未实现。

**建议**: 
1. 对于大多数用例,TCP 代理已足够 (HTTP/1.1, HTTP/2)
2. QUIC/HTTP3 支持需要权衡性能和复杂性
3. 可以根据实际需求选择合适的实现方案

**优先级**:
1. ✅ TCP SNI 代理 (已完成)
2. ⚠️ QUIC UDP 转发 (基础框架)
3. 🔮 连接池优化 (下一步)
4. 🔮 完整 QUIC 支持 (未来)
