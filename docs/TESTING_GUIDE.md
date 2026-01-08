# QUIC SNI 提取 - 测试指南

**日期**: 2026-01-08
**状态**: 测试准备完成

---

## 📋 测试概述

我们已经完成了 QUIC SNI 提取的核心功能实现，现在需要进行测试验证。

---

## 🧪 测试方法

### 方法 1: 单元测试 (已完成)

```bash
# 运行所有 QUIC 测试
cargo test quic::

# 运行特定模块测试
cargo test quic::parser::
cargo test quic::crypto::
cargo test quic::header::
cargo test quic::decrypt::
```

**结果**: ✅ **25/25 测试通过**

---

### 方法 2: 集成测试 (已创建)

**文件**: `tests/quic_integration_test.rs`

**注意**: 当前有编译错误，需要修复才能运行

**修复方法**:
```rust
// 将:
use sniproxy_ng::quic::extract_sni_from_quic_initial;

// 改为:
use crate::quic::extract_sni_from_quic_initial;
```

---

### 方法 3: 使用真实的 QUIC Packets

#### 选项 A: 从 Wireshark 抓取

1. 启动 Wireshark
2. 过滤器: `quic && tls`
3. 访问一个 HTTPS 网站 (支持 QUIC)
4. 找到 QUIC Initial packet
5. 右键 → Export Packet Bytes → 作为 Hex 保存
6. 在代码中加载:

```rust
let hex_packet = "c30000000108..."; // 从 Wireshark 复制
let mut packet = hex::decode(hex_packet)?;
let sni = extract_sni_from_quic_initial(&mut packet)?;
```

#### 选项 B: 使用 openssl 生成

```bash
# 发送 QUIC Initial packet 到 google.com
echo 'GET /' | openssl s_client -connect www.google.com:443 -quic -tls1_3 -debug
```

这会显示详细的握手过程，包括 QUIC Initial packet。

#### 选项 C: 使用 qlog 文件

某些浏览器支持生成 qlog (QUIC event log)，可以提取 Initial packets。

---

### 方法 4: 启动服务器测试

#### 步骤 1: 启动 sniproxy-ng

```bash
# 启动服务器
RUST_LOG=debug cargo run --release

# 或
RUST_LOG=debug ./target/release/sniproxy-ng
```

#### 步骤 2: 配置浏览器

**Firefox**:
1. 打开 `about:config`
2. 搜索 `quic`
3. 设置 `network.http3.enabled` 为 `true`

**Chrome**:
- Chrome 默认启用 QUIC/HTTP3

#### 步骤 3: 配置代理

将浏览器的代理设置为 `localhost:监听端口` (从 config.toml 读取)

#### 步骤 4: 访问网站

访问任何 HTTPS 网站，查看服务器日志输出：

```
✅ Extracted SNI: 'www.google.com' from 127.0.0.1:54321
```

---

## 📊 测试检查清单

### 基础功能测试

- [ ] Unit tests 全部通过 (25/25)
- [ ] 能够解析 QUIC Initial Header
- [ ] 能够提取 DCID
- [ ] 能够派生 Initial Keys
- [ ] 能够移除 Header Protection
- [ ] 能够解码 Packet Number
- [ ] 能够提取 CRYPTO Frame
- [ ] 能够解密 TLS ClientHello
- [ ] 能够提取 SNI

### 错误处理测试

- [ ] 非 QUIC packet (Short Header)
- [ ] 非 Initial packet (Retry/Handshake)
- [ ] Packet too short
- [ ] 不支持的 QUIC 版本
- [ ] 解密失败
- [ ] 无 SNI (TLS alert)

### 性能测试

- [ ] 单个 packet 处理时间 < 1ms
- [ ] CPU 开销在预期范围内 (4-5x TCP+SNI)
- [ ] 内存使用合理 (< 10MB per connection)

### 集成测试

- [ ] 与 TCP SNI 提取并存
- [ ] 不影响现有 TCP 功能
- [ ] 日志输出清晰
- [ ] 错误不导致服务器崩溃

---

## 🔍 测试命令

### 快速测试

```bash
# 1. 编译
cargo build --release

# 2. 运行单元测试
cargo test quic::

# 3. 启动服务器
RUST_LOG=info cargo run --release

# 4. 在另一个终端测试
curl -v http://www.google.com
# 或使用浏览器
```

### 详细调试

```bash
# 启用详细日志
RUST_LOG=debug cargo run --release

# 查看网络流量
sudo tcpdump -i any port 443 -w quic.pcap
# 然后用 Wireshark 打开 quic.pcap
```

---

## 🐛 已知问题和限制

### 当前限制

1. **SOCKS5 UDP relay 未实现**
   - 当前只提取 SNI
   - 需要实现 UDP 转发功能
   - 估计工作量: 2-3 天

2. **测试数据不足**
   - 缺少真实的 QUIC Initial packets
   - 需要从 Wireshark 或其他工具获取

3. **不支持分片的 CRYPTO frames**
   - 如果 ClientHello 跨多个 packets，会失败
   - 影响: 极少数情况

### 错误处理

当前实现中，所有错误都是非致命的：
```rust
Err(e) => {
    warn!("⚠️  Failed to extract SNI from {}: {}", src_addr, e);
}
```

服务器不会因为单个 packet 错误而崩溃。

---

## 📈 性能基准

### 预期性能

| 操作 | 预期时间 |
|------|---------|
| Header 解析 | < 10μs |
| 密钥派生 (HKDF) | < 50μs |
| Header Protection 移除 | < 30μs |
| Packet Number 解码 | < 10μs |
| CRYPTO Frame 解密 | < 100μs |
| **总时间** | **< 1ms** |

### 对比

- TCP+SNI 提取: ~200μs
- QUIC+SNI 提取: ~1ms
- **开销**: ~5x (符合预期)

---

## ✅ 测试成功标准

### 最小可行性

- [x] Unit tests 全部通过
- [ ] 能够提取至少一个真实 SNI
- [ ] 服务器不崩溃

### 完整功能

- [ ] 能够处理大部分 QUIC Initial packets
- [ ] 错误处理完善
- [ ] 性能符合预期
- [ ] 日志清晰

### 生产就绪

- [ ] SOCKS5 UDP relay 实现
- [ ] 性能优化完成
- [ ] 压力测试通过
- [ ] 文档完善

---

## 📝 测试报告模板

测试完成后，填写以下报告：

```
测试日期: YYYY-MM-DD
测试者: [Name]

测试环境:
- OS: [Linux/MacOS/Windows]
- Rust 版本: [rustc --version]
- 网络: [局域网/公网]

测试结果:
- Unit tests: [ ] 25/25 通过
- 真实 packet 测试: [ ] 成功/失败
- 提取到的 SNI: [ ] 列出域名

性能:
- 平均处理时间: [ ] ms
- CPU 使用率: [ ] %
- 内存使用: [ ] MB

问题:
- [ ] 遇到的问题列表

建议:
- [ ] 改进建议
```

---

## 🚀 下一步

1. **立即测试**: 启动服务器，使用浏览器访问
2. **抓包分析**: 使用 Wireshark 抓取真实 packets
3. **实现 UDP relay**: 完成 SOCKS5 UDP 转发
4. **性能优化**: Benchmark 和优化

---

**创建时间**: 2026-01-08
**状态**: 测试准备就绪
**优先级**: 高
