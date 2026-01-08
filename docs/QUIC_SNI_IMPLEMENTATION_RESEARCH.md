# QUIC SNI 提取实现方案调研报告

## 📋 文档概述

**目标**: 为 sniproxy-ng 项目确定 QUIC SNI 提取的具体实现方案
**基于**: Gemini 提供的方案 A + Pingora/s2n-quic/libdquic 实现参考
**约束**: 不支持 ECH (Encrypted ClientHello)
**日期**: 2026-01-08

---

## 🎯 调研结论

经过深入研究 Gemini 的方案和现有实现,我们确定了**可行的技术路线**:

✅ **技术上完全可行** - QUIC Initial Packet 解密已有成熟实现
✅ **性能开销可接受** - 相比 TCP+SNI 提取,预计 4-5倍开销
✅ **代码复杂度可控** - 预计 1000-1250 行 Rust 代码
✅ **生产环境可用** - GFW、Cloudflare、AWS 已大规模使用类似技术

---

## 📚 1. 现有实现调研

### 1.1 **libdquic** - 专门解密 QUIC Initial 消息

**仓库**: https://github.com/Waujito/libdquic
**语言**: C (58.7%) + C++ (36.9%)
**许可证**: GPL-3.0
**特点**:
- 专注于 QUIC Initial 消息解密
- 使用 cycloneCRYPTO 提供简单但强大的加密接口
- 可作为独立共享库或嵌入式到其他项目
- 实现了 RFC 9000 和 RFC 9001 的复杂加密系统

**关键价值**:
> "QUIC intends to encrypt as much data as possible. Even initial packets are being encrypted, but with open keys. This library implements decryption for initial packets."

**对我们项目的意义**:
- ✅ 证明了 Initial Packet 解密的可行性
- ✅ 提供了加密算法的具体实现参考
- ⚠️ 使用 C/C++,需要参考其算法并用 Rust 重新实现
- ⚠️ GPL-3.0 许可证,不能直接复制代码到我们的 MIT 项目

### 1.2 **s2n-quic** - AWS 的 Rust QUIC 实现

**仓库**: https://github.com/aws/s2n-quic
**语言**: Rust
**许可证**: Apache-2.0
**MSRV**: 1.71.0
**特点**:
- 完整的 QUIC 协议实现 (不仅是 Initial Packet)
- 集成 s2n-tls 和 rustls
- 高度可配置的 Provider 架构
- 生产级质量 (AWS 使用)

**关键功能**:
- Simple, easy-to-use API
- 支持连接级别的 SNI 处理
- 与 TLS 后端完全集成

**对我们项目的意义**:
- ✅ Rust 实现,语言匹配
- ✅ Apache-2.0 许可证友好
- ✅ 生产级代码质量
- ✅ 完整的 crypto 模块可参考
- ⚠️ 功能过于完整,我们只需要 Initial Packet 解密部分

### 1.3 **Quinn** - 流行的 Rust QUIC 实现

**仓库**: https://github.com/quinn-rs/quinn
**语言**: Rust
**许可证**: MIT/Apache-2.0
**特点**:
- 纯 Rust,async-friendly
- 最流行的 Rust QUIC 实现
- 使用 rustls 进行 TLS 处理

**对我们项目的意义**:
- ✅ MIT 许可证,可以直接参考代码
- ✅ 社区活跃,文档完善
- ✅ rustls 集成方式值得学习

### 1.4 **Pingora** - Cloudflare 的 Rust 代理框架

**仓库**: https://github.com/cloudflare/pingora
**语言**: Rust
**许可证**: Apache-2.0
**MSRV**: 1.84 (rolling MSRV policy)
**特点**:
- Cloudflare 替代 NGINX 的框架
- 服务超过 40M RPS
- HTTP/1, HTTP/2 代理 (HTTP/3 在开发中)
- L4 API (TCP/UDP) 支持

**关键发现**:
> Issue #115: "You can probably build an SNI sniffing logic on top of the APIs we provide but Pingora at the moment does not offer a full-fledged L4 proxy."

**对我们项目的意义**:
- ✅ L4 API 可能支持我们需要的低级数据包访问
- ✅ Cloudflare 的工程实践
- ⚠️ QUIC 支持尚未完全成熟
- ⚠️ 主要专注于 HTTP 代理,不是纯粹的 SNI 提取

---

## 📊 2. Gemini 方案评估

### 2.1 Gemini 的技术方向

**核心思路**: 无状态解析器,手动解密 QUIC Initial Packet

**推荐库**:
```toml
ring = "0.16"        # Google 高性能密码学库
hkdf = "0.12"        # HMAC-based Key Derivation
tls-parser = "0.15"  # 零拷贝 TLS 解析
bytes = "1.0"        # 字节操作
aes-gcm = "0.10"     # AEAD 加密
```

**技术路线**:
```
UDP Packet → QUIC Initial Header →
提取 DCID → HKDF 密钥派生 →
AES-GCM 解密 CRYPTO Frame →
TLS ClientHello 解析 → SNI
```

### 2.2 Gemini 方案的优点 ✅

1. **技术正确性**: ⭐⭐⭐⭐ (4/5)
   - 密钥派生算法符合 RFC 9001
   - 使用标准加密库 (ring, hkdf)
   - 无状态解析器设计合理

2. **库选择优秀**:
   - `ring`: Google 的 Rust crypto 库,性能卓越
   - `hkdf`: RustCrypto 官方 HKDF 实现
   - `tls-parser`: 基于 nom 的零拷贝解析器
   - `aes-gcm`: 纯 Rust AEAD 实现

3. **架构合理**:
   - 模块化设计 (header, crypto, sni modules)
   - 错误处理完善
   - 单元测试覆盖

### 2.3 Gemini 方案的问题 ⚠️

1. **Salt 值错误**:

**Gemini 的错误代码**:
```rust
const QUIC_V1_SALT: &[u8] = &[0x38, 0x76, 0x2c, 0xf7, ...];
```

**正确的 RFC 9001 Salt**:
```rust
const INITIAL_SALT: &[u8] = &[
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0xeb, 0xb6, 0xa4,
    0xac, 0x6f, 0x08, 0x78, 0x11, 0x8a, 0xf1, 0x4b,
    0x9c, 0x5d, 0x3a, 0x1a,
];
```

2. **HKDF Label 不完整**:

**Gemini 的代码**:
```rust
let label = b"client in";  // ❌ 不完整
```

**正确的格式** (RFC 9001 Section 5):
```rust
use hkdf::Hkdf;

// 完整的 HKDF-Expand-Label 格式
fn hkdf_expand_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let label_prefix = b"tls13 ";
    let full_label = [label_prefix, label.as_bytes()].concat();
    // ... 实现 RFC 8446 Section 7.1 格式
}
```

3. **复杂度低估**:

Gemini 声称 "simple",但实际需要:
- Header Protection 处理 (额外 ~200 行)
- Packet Number 解码 (额外 ~150 行)
- CRYPTO Frame 分片重组 (额外 ~200 行)
- 完善的错误处理 (额外 ~200 行)
- **实际估算: ~1250 行,不是 Gemini 说的 ~600 行**

4. **未提及 ECH 问题**:
   - Gemini 完全没有提及 ECH
   - 我们的约束明确: 不支持 ECH ✅
   - 但应该在文档中说明这个限制

### 2.4 Gemini 方案评分总结

| 维度 | 评分 | 说明 |
|------|------|------|
| 技术正确性 | ⭐⭐⭐⭐ (4/5) | 方向正确,但有代码错误 |
| 实用性 | ⭐⭐⭐ (3/5) | 库选择好,但复杂度低估 |
| 完整性 | ⭐⭐⭐ (3/5) | 缺少关键细节 |
| 总分 | ⭐⭐⭐⭐ (4/5) | **推荐作为基础,需要补充** |

---

## 🛠️ 3. 推荐实现方案

### 3.1 核心架构

基于 Gemini 方案 + 现有实现经验,推荐以下架构:

```
src/quic/
├── mod.rs              # 模块导出
├── parser.rs           # QUIC Initial Packet 解析 (~300 行)
├── crypto.rs           # 密钥派生和解密 (~350 行)
├── header.rs           # Header Protection 处理 (~250 行)
├── tls_sni.rs          # TLS ClientHello SNI 提取 (~200 行)
└── tests/
    ├── mock_packets.rs # 测试用 QUIC packets
    └── integration_test.rs
```

**总代码量估算**: ~1100-1250 行

### 3.2 依赖库 (Cargo.toml)

```toml
[dependencies]
# 现有依赖保持不变...

# QUIC SNI 提取新增依赖
ring = "0.16"              # Google 高性能密码学库
hkdf = "0.12"              # HMAC-based Key Derivation (RFC 5869)
aes-gcm = "0.10"           # AEAD 加密 (RFC 5116)
sha2 = "0.10"              # SHA-2 实现

# TLS 解析 - 两个选项:
# 选项 1: tls-parser (零拷贝,更快)
tls-parser = "0.15"        # 推荐

# 选项 2: 纯手工解析 (我们已有的 tls/sni.rs)
# 无需额外依赖,但需要适配 QUIC CRYPTO frame

# 字节操作
bytes = "1.7"              # 已有

# 错误处理
thiserror = "1.0"          # 已有
anyhow = "1.0"             # 已有
```

**依赖对比**:

| 库 | 版本 | 用途 | 必需? |
|---|------|------|-------|
| ring | 0.16 | Header Protection, AEAD | ✅ 必需 |
| hkdf | 0.12 | Initial Secret 派生 | ✅ 必需 |
| aes-gcm | 0.10 | Payload 解密 | ✅ 必需 |
| sha2 | 0.10 | HKDF 的 Hash 函数 | ✅ 必需 |
| tls-parser | 0.15 | TLS 解析 (推荐) | ⚠️ 可选 |

### 3.3 核心算法流程

#### Step 1: 提取 DCID (Destination Connection ID)

```rust
// src/quic/parser.rs
pub fn extract_dcid(packet: &[u8]) -> Result<&[u8]> {
    // 检查 QUIC Initial Packet 标记
    if packet.is_empty() {
        bail!(QuicError::PacketTooShort);
    }

    let first_byte = packet[0];
    // Initial Packet: 0bxxxx1xxx (bit 3 is 1)
    if (first_byte & 0x08) == 0 {
        bail!(QuicError::NotInitialPacket);
    }

    // 跳过 Version (4 bytes)
    if packet.len() < 5 {
        bail!(QuicError::PacketTooShort);
    }

    // DCID Length 和 DCID
    let dcil = (packet[5] & 0x0F) as usize; // 低 4 bits
    if packet.len() < 6 + dcil {
        bail!(QuicError::InvalidDcid);
    }

    let dcid = &packet[6..6 + dcil];
    tracing::debug!("Extracted DCID: {:?}", dcid);
    Ok(dcid)
}
```

#### Step 2: 密钥派生 (HKDF)

```rust
// src/quic/crypto.rs
use ring::hkdf::{KeyDerivation, Prk, Salt, HKDF_SHA256};
use ring::digest;

/// RFC 9001 Section 5
const INITIAL_SALT: &[u8] = &[
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0xeb, 0xb6, 0xa4,
    0xac, 0x6f, 0x08, 0x78, 0x11, 0x8a, 0xf1, 0x4b,
    0x9c, 0x5d, 0x3a, 0x1a,
];

pub fn derive_initial_keys(dcid: &[u8]) -> Result<InitialKeys> {
    // HKDF-Extract
    let salt = Salt::new(HKDF_SHA256, INITIAL_SALT);
    let initial_secret = salt.extract(dcid);

    // HKDF-Expand-Label for "client in"
    let client_initial_secret = hkdf_expand_label(
        &initial_secret,
        b"client in",
        &[],
        32,
    )?;

    // Derive key and IV
    let key = hkdf_expand_label(
        &client_initial_secret,
        b"quic key",
        &[],
        16,
    )?;

    let iv = hkdf_expand_label(
        &client_initial_secret,
        b"quic iv",
        &[],
        12,
    )?;

    // Header protection key
    let hp_key = hkdf_expand_label(
        &client_initial_secret,
        b"quic hp",
        &[],
        16,
    )?;

    Ok(InitialKeys { key, iv, hp_key })
}

/// RFC 8446 Section 7.1 HKDF-Expand-Label
fn hkdf_expand_label(
    secret: &Prk,
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let hkdf_label_prefix = b"tls13 ";
    let hkdf_label = HkdfLabel::new(length, label, context);

    let info = hkdf_label.as_bytes();

    let mut okm = vec![0u8; length];
    secret.expand(&info, &mut okm)
        .map_err(|_| QuicError::KeyDerivationFailed)?;

    Ok(okm)
}

struct HkdfLabel {
    length: u16,
    label: Vec<u8>,
    context: Vec<u8>,
}

impl HkdfLabel {
    fn new(length: usize, label: &[u8], context: &[u8]) -> Self {
        let full_label = [b"tls13 ", label].concat();
        Self {
            length: length as u16,
            label: full_label,
            context: context.to_vec(),
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.push(self.label.len() as u8);
        bytes.extend_from_slice(&self.label);
        bytes.push(self.context.len() as u8);
        bytes.extend_from_slice(&self.context);
        bytes
    }
}
```

#### Step 3: Header Protection 移除

```rust
// src/quic/header.rs
use ring::aead::quic::HeaderProtectionKey;

pub fn remove_header_protection(
    packet: &mut [u8],
    hp_key: &[u8],
) -> Result<()> {
    // 创建 Header Protection Key
    let key = HeaderProtectionKey::new(ring::aead::quic::AES_128, hp_key)
        .map_err(|_| QuicError::InvalidKey)?;

    // 找到 sample 的位置
    // 对于 Initial packet: header 长度 + 4 bytes
    let header_len = get_header_length(packet)?;
    if packet.len() < header_len + 4 {
        bail!(QuicError::PacketTooShort);
    }

    let sample = &packet[header_len..header_len + 4];

    // 解密
    let mut mask = [0u8; 5];
    key.unmask(sample, &mut mask)
        .map_err(|_| QuicError::HeaderProtectionFailed)?;

    // 应用 mask
    // 第一个字节: flip bits 0-2 and 5-7
    packet[0] ^= mask[0] & 0x0f; // 只翻转低 4 bits

    // Packet Number: flip the entire PN
    let pn_offset = header_len - 1; // PN 是最后一个字节
    packet[pn_offset] ^= mask[1];

    tracing::trace!("Header protection removed");
    Ok(())
}

fn get_header_length(packet: &[u8]) -> Result<usize> {
    // 简化版本,实际需要解析 DCID length, SCID length 等
    // 格式: First Byte (1) + Version (4) + DCIL (1) + DCID (dcil) +
    //       SCIL (1) + SCID (scil) + Token Length (1) + Token (var)
    //
    // Initial Packet 固定部分: 1 + 4 + 1 + DCID + 1 + SCID + 1 + Token
    // Packet Number 长度在 First Byte 的 bits 0-1

    let first_byte = packet[0];
    let dcil = (packet[5] & 0x0F) as usize;
    let scil_pos = 6 + dcil;
    let scil = packet[scil_pos] as usize;

    // 简化:假设 token length 为 0
    let token_len_pos = scil_pos + 1 + scil;
    let token_len = packet[token_len_pos] as usize;

    // Header length = First Byte + Version + DCIL + DCID + SCIL + SCID +
    //                Token Len + Token + Packet Number (1 byte, simplified)
    let header_len = 1 + 4 + 1 + dcil + 1 + scil + 1 + token_len + 1;

    Ok(header_len)
}
```

#### Step 4: 解密 CRYPTO Frame

```rust
// src/quic/crypto.rs
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM;

pub fn decrypt_crypto_frame(
    encrypted: &[u8],
    key: &[u8],
    iv: &[u8],
    packet_number: u64,
) -> Result<Vec<u8>> {
    // 创建 AEAD key
    let unbound_key = UnboundKey::new(&AES_128_GCM, key)
        .map_err(|_| QuicError::InvalidKey)?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    // 构造 nonce (IV xor packet_number)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(iv);
    let pn_bytes = packet_number.to_be_bytes();
    let pn_offset = 12 - pn_bytes.len();
    nonce_bytes[pn_offset..].copy_from_slice(&pn_bytes);

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // 分离 tag 和 ciphertext
    if encrypted.len() < 16 {
        bail!(QuicError::PacketTooShort);
    }
    let tag_start = encrypted.len() - 16;
    let ciphertext = &encrypted[..tag_start];
    let tag = &encrypted[tag_start..];

    // 拼接 ciphertext + tag (ring 的格式)
    let mut ciphertext_and_tag = ciphertext.to_vec();
    ciphertext_and_tag.extend_from_slice(tag);

    // 解密
    let mut plaintext = ciphertext_and_tag.clone();
    less_safe_key
        .open_in_place(
            &nonce,
            Aad::empty(), // Initial packets 没有 additional data
            &mut plaintext,
        )
        .map_err(|_| QuicError::DecryptionFailed)?;

    // 移除 tag
    plaintext.truncate(plaintext.len() - 16);

    tracing::debug!("Decrypted {} bytes", plaintext.len());
    Ok(plaintext)
}
```

#### Step 5: 解析 TLS ClientHello 获取 SNI

```rust
// src/quic/tls_sni.rs
// 重用我们已有的 tls::sni 模块!

use crate::tls::sni::extract_sni;

pub fn extract_sni_from_crypto_frame(
    crypto_data: &[u8],
) -> Result<Option<String>> {
    // CRYPTO frame 格式:
    // Frame Type (1 byte) + Offset (2 bytes) + Length (2 bytes) + Data

    if crypto_data.len() < 5 {
        bail!(QuicError::CryptoFrameTooShort);
    }

    let frame_type = crypto_data[0];
    if frame_type != 0x06 {
        bail!(QuicError::NotCryptoFrame);
    }

    // Skip Offset (assume 0)
    // Length
    let length = u16::from_be_bytes([crypto_data[3], crypto_data[4]]) as usize;

    if crypto_data.len() < 5 + length {
        bail!(QuicError::CryptoFrameTooShort);
    }

    let tls_data = &crypto_data[5..5 + length];

    // 重用我们已有的 TLS SNI 提取!
    extract_sni(tls_data)
        .map_err(|e| QuicError::TlsError(e.to_string()))
}
```

### 3.4 完整处理流程

```rust
// src/quic/mod.rs
pub fn extract_sni_from_quic_initial(packet: &[u8]) -> Result<Option<String>> {
    // Step 1: 提取 DCID
    let dcid = extract_dcid(packet)?;
    tracing::debug!("DCID: {:?}", dcid);

    // Step 2: 派生 Initial Keys
    let keys = derive_initial_keys(dcid)?;
    tracing::trace!("Keys derived successfully");

    // Step 3: 移除 Header Protection
    let mut packet_copy = packet.to_vec();
    remove_header_protection(&mut packet_copy, &keys.hp_key)?;
    tracing::trace!("Header protection removed");

    // Step 4: 解码 Packet Number
    let pn = decode_packet_number(&packet_copy)?;
    tracing::debug!("Packet Number: {}", pn);

    // Step 5: 提取 CRYPTO Frame
    let crypto_frame = extract_crypto_frame(&packet_copy)?;
    tracing::debug!("CRYPTO frame length: {}", crypto_frame.len());

    // Step 6: 解密 CRYPTO Frame
    let decrypted = decrypt_crypto_frame(
        &crypto_frame,
        &keys.key,
        &keys.iv,
        pn,
    )?;
    tracing::debug!("Decrypted {} bytes", decrypted.len());

    // Step 7: 提取 SNI (重用现有代码!)
    let sni = extract_sni_from_crypto_frame(&decrypted)?;
    tracing::info!("Extracted SNI: {:?}", sni);

    Ok(sni)
}
```

---

## 📝 4. 测试策略

### 4.1 单元测试

```rust
// src/quic/tests/crypto_test.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dcid_extraction() {
        // 构造测试包
        let packet = [
            0x0f, 0x01, 0x02, 0x03, 0x04, // First byte + Version
            0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID length 8 + DCID
            // ... rest
        ];
        let dcid = extract_dcid(&packet).unwrap();
        assert_eq!(dcid, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_key_derivation() {
        let dcid = vec![0x01, 0x02, 0x03, 0x04];
        let keys = derive_initial_keys(&dcid).unwrap();
        assert_eq!(keys.key.len(), 16);
        assert_eq!(keys.iv.len(), 12);
        assert_eq!(keys.hp_key.len(), 16);
    }

    #[test]
    fn test_full_sni_extraction() {
        // 使用真实的 QUIC Initial Packet (从 Wireshark 抓取)
        let packet = include_bytes!("test_data/quic_initial_with_sni.bin");
        let sni = extract_sni_from_quic_initial(packet).unwrap();
        assert_eq!(sni, Some("www.google.com".to_string()));
    }
}
```

### 4.2 集成测试

```rust
// tests/quic_integration_test.rs
use sniproxy_ng::quic::extract_sni_from_quic_initial;
use std::net::UdpSocket;

#[tokio::test]
async fn test_real_world_quic() {
    // 发送真实的 UDP packet 到 google.com
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("www.google.com:443").unwrap();

    // 发送空的 QUIC Initial packet (会触发响应)
    let packet = build_quic_initial_packet();
    socket.send(&packet).unwrap();

    let mut buf = [0u8; 1500];
    let (len, _addr) = socket.recv_from(&mut buf).unwrap();

    // 解析响应
    let sni = extract_sni_from_quic_initial(&buf[..len]).unwrap();
    assert!(sni.is_some());
}
```

### 4.3 性能测试

```rust
// benches/quic_sni_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_quic_sni_extraction(c: &mut Criterion) {
    let packet = include_bytes!("../test_data/quic_initial.bin");

    c.bench_function("quic_sni_extraction", |b| {
        b.iter(|| {
            extract_sni_from_quic_initial(black_box(packet))
        })
    });
}

criterion_group!(benches, bench_quic_sni_extraction);
criterion_main!(benches);
```

---

## 🚀 5. 实施计划

### Phase 1: 基础模块 (3-4 天)

- [ ] 创建 `src/quic/` 模块结构
- [ ] 实现 `parser.rs`: DCID 提取
- [ ] 实现 `crypto.rs`: HKDF 密钥派生
- [ ] 单元测试: 密钥派生正确性 (使用 RFC 测试向量)

**验证标准**:
- 所有单元测试通过
- 密钥派生结果与 RFC 9001 附录一致

### Phase 2: Header Protection (2-3 天)

- [ ] 实现 `header.rs`: Header Protection 移除
- [ ] 实现 Packet Number 解码
- [ ] 单元测试: Header protection/removal

**验证标准**:
- 能正确移除真实 QUIC packet 的 header protection
- Packet number 解码正确

### Phase 3: CRYPTO Frame 解密 (3-4 天)

- [ ] 实现 `crypto.rs`: AES-GCM 解密
- [ ] 实现 CRYPTO frame 提取
- [ ] 单元测试: 解密正确性

**验证标准**:
- 能解密真实 QUIC Initial packet 的 CRYPTO frame
- 解密结果是有效的 TLS ClientHello

### Phase 4: SNI 提取 (1-2 天)

- [ ] 实现 `tls_sni.rs`: 重用现有 `tls::sni` 模块
- [ ] 集成测试: 端到端 SNI 提取
- [ ] 使用 Wireshark 抓取的真实 packets 测试

**验证标准**:
- 能从真实 QUIC packets 提取 SNI
- 与 Wireshark 显示的 SNI 一致

### Phase 5: 性能优化和文档 (2-3 天)

- [ ] 性能 benchmark
- [ ] 优化热点路径
- [ ] 编写使用文档
- [ ] 添加到 `src/main.rs` 集成

**验证标准**:
- 性能开销 < 5x TCP+SNI
- 文档完善

**总时间估算**: 11-16 天

---

## ⚠️ 6. 限制和注意事项

### 6.1 技术限制

1. **不支持 ECH (Encrypted ClientHello)**
   - 我们的实现无法处理 ECH 加密的 SNI
   - 影响: 使用 ECH 的网站 (如 Google 部分 services) 无法代理
   - 缓解: 文档中明确说明,用户可以选择使用 TCP 模式

2. **仅支持 QUIC v1**
   - QUIC v2 (draft) 使用不同的 Salt 值
   - 影响: 未来 QUIC v2 普及后需要更新
   - 缓解: 检测 Version 字段,支持多个版本

3. **无状态解析的限制**
   - 无法处理分片的 CRYPTO frames (多个 Initial packets)
   - 影响: 极少数情况下 SNI 跨多个 packets
   - 缓解: 返回 None,让 fallback 到 TCP

### 6.2 性能考虑

1. **CPU 开销**
   - 相比 TCP+SNI 提取,预计 4-5x CPU 开销
   - 主要来源: HKDF, AES-GCM, Header Protection

2. **延迟**
   - 额外延迟: < 1ms (单个 packet 处理时间)
   - 可接受,因为只是 SNI 提取,不是数据转发

### 6.3 安全考虑

1. **不泄露 Initial Secrets**
   - 密钥仅用于解密,不存储
   - 每个连接独立派生

2. **DoS 防护**
   - 限制单个 IP 的 UDP packet 速率
   - 验证 packet 格式后再处理

---

## 📖 7. 参考资源

### RFC 规范
- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001: Using TLS to Secure QUIC
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

### 实现参考
- libdquic: https://github.com/Waujito/libdquic (C implementation)
- s2n-quic: https://github.com/aws/s2n-quic (Rust implementation)
- Quinn: https://github.com/quinn-rs/quinn (Rust implementation)
- Pingora: https://github.com/cloudflare/pingora (Rust proxy)

### 测试资源
- Wireshark: QUIC packet capture
- `openssl s_client -connect www.google.com:443 -quic` - 生成测试 packets
- RFC 测试向量: RFC 9001 Appendix A

---

## 📊 8. 方案对比总结

| 方案 | 代码量 | 复杂度 | 性能 | 推荐度 |
|------|--------|--------|------|--------|
| **Gemini 方案** | ~600 行 (估算) | 中等 | 好 | ⭐⭐⭐⭐ |
| **libdquic 参考实现** | ~800 行 (C) | 中等 | 好 | ⭐⭐⭐ |
| **完整 QUIC 实现** | ~10000+ 行 | 极高 | 优秀 | ⭐⭐ |
| **我们的方案 (Gemini+libdquic+s2n-quic)** | ~1100-1250 行 | 中等 | 好 | ⭐⭐⭐⭐⭐ |

**最终推荐**: 采用 **Gemini 方案 + libdquic 算法参考 + s2n-quic Rust 实践** 的混合方案

---

## ✅ 下一步行动

1. **创建实现计划文档** (本文档已完成)
2. **准备测试数据**:
   - 从 Wireshark 抓取真实 QUIC Initial packets
   - 或使用 `openssl s_client -quic` 生成
3. **开始 Phase 1 实现**:
   - 创建模块结构
   - 实现 DCID 提取
   - 实现 HKDF 密钥派生

**是否开始实现?** (等待用户确认)

---

**文档作者**: Claude (基于 Gemini 方案和开源实现调研)
**最后更新**: 2026-01-08
