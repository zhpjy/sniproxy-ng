# Gemini QUIC SNI 代码评价报告

**代码来源**: Gemini 提供的 QUIC SNI 解析实现
**评价日期**: 2026-01-08
**评价者**: Claude (基于 RFC 9000/9001 和生产实践)

---

## 📊 总体评分

| 维度 | 评分 | 说明 |
|------|------|------|
| **正确性** | ⭐⭐⭐ (3/5) | 核心思路正确,但有多个严重错误 |
| **完整性** | ⭐⭐⭐⭐ (4/5) | 端到端流程完整,包含示例数据 |
| **可用性** | ⭐⭐ (2/5) | **无法直接运行**,多处错误需要修复 |
| **代码质量** | ⭐⭐⭐ (3/5) | 结构清晰,但缺少错误处理和注释 |
| **生产就绪度** | ⭐ (1/5) | 远未达到生产标准 |

**综合评分**: ⭐⭐⭐ (3/5) - **良好的学习示例,但不可直接用于生产**

---

## ❌ 严重错误 (Critical Errors)

### 1. **致命错误: Salt 值完全错误**

```rust
// Gemini 的代码
const QUIC_V1_SALT: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
```

**正确的 RFC 9001 Salt**:
```rust
const INITIAL_SALT: &[u8] = &[
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0xeb, 0xb6, 0xa4,
    0xac, 0x6f, 0x08, 0x78, 0x11, 0x8a, 0xf1, 0x4b,
    0x9c, 0x5d, 0x3a, 0x1a,
];
```

**影响**:
- ❌ **完全无法解密**任何真实的 QUIC Initial Packet
- ❌ 所有密钥派生都会得到错误结果
- ❌ 这是复制粘贴错误或其他版本的 Salt

**修复方案**:
```rust
// RFC 9001 Section A.3 - QUIC Version 1 Initial Salt
const INITIAL_SALT_V1: &[u8] = &[
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0xeb, 0xb6, 0xa4,
    0xac, 0x6f, 0x08, 0x78, 0x11, 0x8a, 0xf1, 0x4b,
    0x9c, 0x5d, 0x3a, 0x1a,
];
```

---

### 2. **密钥推导算法错误: HKDF-Label 构造问题**

```rust
// Gemini 的代码
fn hkdf_label(label: &[u8], context: &[u8], len: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&len.to_be_bytes());
    let label_full = [b"tls13 ", label].concat();
    out.push(label_full.len() as u8);
    out.extend_from_slice(&label_full);
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out
}
```

**问题分析**:
- ✅ 添加了 "tls13 " 前缀 (正确!)
- ⚠️ **但调用时使用了错误的 label**:

```rust
// Gemini 的调用 - ❌ 错误!
hk.expand(&hkdf_label(b"initial", b"", 32), &mut initial_secret)

// 应该是:
hk.expand(&hkdf_label(b"", b"", 32), &mut initial_secret)
// 或者更明确:
hk.expand(b"", &mut initial_secret)  // HKDF-Extract 不需要 label
```

**RFC 9001 正确流程**:
```rust
// Step 1: HKDF-Extract (不需要 label)
let salt = Salt::new(HKDF_SHA256, INITIAL_SALT);
let initial_secret = salt.extract(dcid);

// Step 2: HKDF-Expand-Label for "client in"
let client_label = hkdf_expand_label(b"client in", b"", 32);

// Step 3: Derive key, iv, hp
let key = hkdf_expand_label(&client_secret, b"quic key", b"", 16);
let iv = hkdf_expand_label(&client_secret, b"quic iv", b"", 12);
let hp = hkdf_expand_label(&client_secret, b"quic hp", b"", 16);
```

**当前代码的调用**:
```rust
// Gemini 的代码
hk.expand(&hkdf_label(b"initial", b"", 32), &mut initial_secret)
```
这会生成 label "tls13 initial",**这是完全错误的**!

---

### 3. **Header Protection Mask 生成使用了错误的 Sample**

```rust
// Gemini 的代码
let sample_offset = pn_offset + 4;
if packet.len() < sample_offset + 16 {
    return Err(anyhow!("包太短，无法采样 Header Protection"));
}
let sample = &packet[sample_offset..sample_offset + 16];
```

**RFC 9001 规定**:
> For the Initial packet, the sample is from the packet number field,
> starting at the 4th byte after the start of the packet number.

**问题**:
- ✅ Offset 计算正确: `pn_offset + 4`
- ⚠️ **但 Sample 位置应该在加密的 payload 中,而不是明文 packet 中**

正确逻辑:
```rust
// Sample 应该从 protected payload 中取
// 注意: packet[pn_offset..] 是加密的部分 (包括 PN 和 payload)
let pn_length = (unprotected_first_byte & 0x03) + 1;
let sample_start = pn_offset + pn_length;  // PN 之后
let sample = &packet[sample_start..sample_start + 16];
```

---

### 4. **Packet Number 解码逻辑有严重 Bug**

```rust
// Gemini 的代码
let mut decoded_pn: u64 = 0;
for i in 0..pn_len {
    let byte = packet[pn_offset + i] ^ mask[i + 1];
    decoded_pn = (decoded_pn << 8) | (byte as u64);
}
```

**问题**:
1. ❌ **没有先去除 Header Protection** 就读取 PN
2. ❌ **Packet Number 需要使用 QUIC 的解码算法** (RFC 9000 Section 17.1)
3. ❌ **直接 XOR 后作为整数是错误的**

**正确的 Packet Number 解码** (RFC 9000):
```rust
// 1. 先去除 protection
let mut pn_bytes = [0u8; 4];
for i in 0..pn_len {
    pn_bytes[i] = packet[pn_offset + i] ^ mask[1 + i];
}

// 2. 转换为整数
let truncated_pn = u64::from_be_bytes(pn_bytes);

// 3. 使用期望的 PN 进行完整解码 (RFC 9000 17.1)
fn decode_packet_number(truncated: u64, expected_pn: u64, pn_len: u8) -> u64 {
    let pn_win = 1u64 << (8 * pn_len as u64);
    let pn_hwin = pn_win / 2;
    let mask_pn = pn_win - 1;

    // The candidate packet numbers are:
    let candidate = (expected_pn & !mask_pn) | truncated;
    if candidate <= expected_pn + pn_hwin &&
       candidate + pn_win > expected_pn + pn_hwin {
        candidate
    } else if candidate > expected_pn + pn_hwin {
        candidate - pn_win
    } else {
        candidate + pn_win
    }
}

// 对于 Initial packet, expected_pn 通常是 0
let decoded_pn = decode_packet_number(truncated_pn, 0, pn_len as u8);
```

---

### 5. **AAD 构造错误**

```rust
// Gemini 的代码
let mut aad = BytesMut::from(&packet[0..pn_offset + pn_len]);
aad[0] = unprotected_first_byte;
for i in 0..pn_len {
    aad[pn_offset + i] = packet[pn_offset + i] ^ mask[i + 1];
}
```

**RFC 9001 Section 5.3 规定**:
> The AAD for a packet is the header of the packet, with the
> Packet Number field replaced by the unprotected value.

**问题**:
- ✅ 替换了 First Byte (正确)
- ✅ 替换了 Packet Number (正确)
- ❌ **但应该是原始 header,不包括 DCID/SCID 等字段的保护部分**

实际上这里的逻辑**基本正确**,但注释不清楚:
```rust
// AAD = header (不包括 PN 字段本身) + unprotected PN
// 对于 Initial packet:
// AAD = First Byte (unprotected) + Version + DCID + SCID + Token + Payload Length +
//       Packet Number (unprotected, 1-4 bytes)
```

**但 Gemini 的问题**:
- ❌ **AAD 构造时包含了原始的 protected PN**,应该只包含 unprotected PN
- ❌ **没有说明 AAD 不包含 auth tag**

---

### 6. **Nonce 构造有潜在问题**

```rust
// Gemini 的代码
let mut nonce_bytes = [0u8; 12];
nonce_bytes.copy_from_slice(&iv);
for i in 0..pn_len {
    nonce_bytes[12 - 1 - i] ^= (decoded_pn >> (8 * i)) as u8;
}
```

**问题**:
- ⚠️ **对于 pn_len < 4 的情况,这个逻辑是正确的**
- ⚠️ **但更清晰的写法是**:

```rust
fn construct_nonce(iv: &[u8], packet_number: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);

    // Packet number 作为 64-bit integer,放在 nonce 的最后部分
    let pn_bytes = packet_number.to_be_bytes();
    let pn_offset = 12 - pn_bytes.len();

    for i in 0..pn_bytes.len() {
        nonce[pn_offset + i] ^= pn_bytes[i];
    }

    nonce
}
```

---

### 7. **CRYPTO Frame 解析不完整**

```rust
// Gemini 的代码
match frame_type {
    0x06 => { // CRYPTO Frame
        let _offset = get_varint(&mut cursor)?;
        let length = get_varint(&mut cursor)? as usize;
        let crypto_data = cursor.copy_to_bytes(length);
        return parse_tls_sni(&crypto_data);
    }
    0x02 | 0x03 => { // ACK Frame
        return Err(anyhow!("复杂 Frame 结构，建议使用 quinn-proto 解析"));
    }
    _ => { break; }
}
```

**问题**:
1. ⚠️ **CRYPTO Frame 可能在多个 Initial packets 中分片**
2. ❌ **遇到 ACK frame 直接返回错误,应该跳过**
3. ❌ **没有处理多个 CRYPTO frames 的情况**

**更好的处理**:
```rust
// 收集所有 CRYPTO data
let mut crypto_buffer = Vec::new();

while cursor.has_remaining() {
    let frame_type = get_varint(&mut cursor)?;

    match frame_type {
        0x00 => continue, // PADDING
        0x06 => { // CRYPTO
            let offset = get_varint(&mut cursor)?;
            let length = get_varint(&mut cursor)? as usize;
            let data = cursor.copy_to_bytes(length);

            // 简化:假设连续的 offset
            if offset as usize == crypto_buffer.len() {
                crypto_buffer.extend_from_slice(&data);
            }
        }
        0x02 | 0x03 => { // ACK - 需要完整解析才能跳过
            // 简化:尝试解析 TLS,如果失败说明数据不完整
            if !crypto_buffer.is_empty() {
                if let Ok(sni) = parse_tls_sni(&crypto_buffer) {
                    return Ok(sni);
                }
            }
        }
        _ => { break; }
    }
}

// 最后尝试解析
parse_tls_sni(&crypto_buffer)
```

---

## ⚠️ 次要问题 (Minor Issues)

### 1. **版本检查过于严格**

```rust
// Gemini 的代码
let version = reader.get_u32();
if version != 1 {
    // return Err(anyhow!("仅支持 QUIC Version 1"));
}
```

**问题**:
- QUIC Version 1 的版本号应该是 `0x00000001`,不是 `1`
- 注释掉了错误,但没有处理其他版本

**修复**:
```rust
let version = reader.get_u32();
match version {
    0x00000001 => { /* QUIC v1 */ }
    0x709a50c4 => { /* QUIC v2 draft */ }
    _ => {
        return Err(anyhow!("不支持的 QUIC 版本: {:#x}", version));
    }
}
```

---

### 2. **VarInt 解码可以更高效**

```rust
// Gemini 的代码
fn get_varint<B: Buf>(buf: &mut B) -> Result<u64> {
    if !buf.has_remaining() { return Err(anyhow!("EOF")); }
    let first = buf.chunk()[0];
    let prefix = first >> 6;
    let len = 1 << prefix;
    if buf.remaining() < len { return Err(anyhow!("VarInt 不完整")); }

    let b = buf.get_uint(len);
    let val = b & ((1u64 << (len * 8 - 2)) - 1);
    Ok(val)
}
```

**问题**:
- ✅ 逻辑正确
- ⚠️ **效率问题**: `buf.get_uint(len)` 会读取 1/2/4/8 字节,然后需要 mask
- ⚠️ **更好的实现**: 使用 `bytes` crate 的 `get_uint_le` 或手动处理

**更高效的实现**:
```rust
fn get_varint<B: Buf>(buf: &mut B) -> Result<u64> {
    if !buf.has_remaining() {
        return Err(anyhow!("EOF in VarInt"));
    }

    let first = buf.get_u8();
    let (len, mask) = match first >> 6 {
        0b00 => (1, 0x3F as u64),
        0b01 => (2, 0x3FFF as u64),
        0b10 => (4, 0x3FFFFFFF as u64),
        0b11 => (8, 0x3FFFFFFFFFFFFFFF as u64),
        _ => unreachable!(),
    };

    if buf.remaining() < len - 1 {
        return Err(anyhow!("VarInt truncated"));
    }

    let mut val = (first as u64 & mask) << (8 * (len - 1));
    for _ in 0..len - 1 {
        val = (val << 8) | (buf.get_u8() as u64);
    }

    Ok(val)
}
```

---

### 3. **缺少 Packet Number Length 的初始判断**

```rust
// Gemini 的代码
let pn_len = ((unprotected_first_byte & 0x03) + 1) as usize;
```

**问题**:
- ❌ **在去除 protection 之前就知道 pn_len**
- ⚠️ **实际上应该从 protected first byte 推断**

**正确流程**:
```rust
// 1. 从 protected first byte 获取 PN length
let protected_pn_len = ((packet[0] & 0x03) + 1) as usize;

// 2. 生成 mask
let mask = generate_hp_mask(&hp_key, sample)?;

// 3. 去除 first byte protection
let unprotected_first_byte = packet[0] ^ (mask[0] & 0x0F);

// 4. 确认 pn_len
let pn_len = ((unprotected_first_byte & 0x03) + 1) as usize;
assert!(pn_len == protected_pn_len, "PN length mismatch!");
```

---

### 4. **测试数据可能是伪造的**

```rust
// Gemini 的代码
let raw_hex = "c300000001088d59187123924f7e08f5728b75369666060044e511413d077b949f572d3129532657e3f421528628fd78311100e4e5aa9a8e0f607144e569970e4e531855e92552697b0a79430c0423c21c78160249c5e53303534d87170133a8c5757d7607a82c38864757c284a123f972b260f89816d22d355883d297a7a284687a412f1f00880f0891d4e0e52514578e9f50625a6e60b64d1469e2c60e5728a30646c10b71340a6b7201c90066d814";
```

**问题**:
- ❌ **我无法验证这是真实的 QUIC packet**
- ⚠️ **可能是 Gemini 编造的测试数据**
- ⚠️ **如果 Salt 是错的,这个 packet 可能也无法正确解析**

**建议**:
```rust
// 使用真实的 QUIC packet
// 从 Wireshark 抓取,或使用以下方法生成:
// openssl s_client -connect www.google.com:443 -quic -tls1_3

// 或者使用 RFC 测试向量
// https://www.rfc-editor.org/rfc/rfc9001.html-appendix-A
```

---

## ✅ 代码优点 (Strengths)

### 1. **整体结构清晰** ⭐⭐⭐⭐

```rust
fn extract_sni(packet: &[u8]) -> Result<String> {
    // 1. Header 解析
    // 2. 密钥推导
    // 3. Header Protection
    // 4. Payload 解密
    // 5. Frame 解析
    // 6. TLS SNI 提取
}
```

✅ **步骤划分明确**,符合 QUIC 规范

---

### 2. **依赖选择合理** ⭐⭐⭐⭐

```toml
anyhow = "1.0"      # 错误处理
bytes = "1.5"       # 字节操作
aes-gcm = "0.10"    # AEAD 加密
hkdf = "0.12"       # 密钥派生
sha2 = "0.10"       # Hash 函数
tls-parser = "0.11" # TLS 解析
```

✅ **都是成熟、稳定的库**
✅ **没有使用不维护的库**

---

### 3. **错误处理基本到位** ⭐⭐⭐

```rust
if packet.len() < sample_offset + 16 {
    return Err(anyhow!("包太短，无法采样 Header Protection"));
}
```

✅ **有边界检查**
✅ **使用 `anyhow` 提供清晰的错误信息**

---

### 4. **使用 tls-parser 而不是手工解析** ⭐⭐⭐⭐⭐

```rust
fn parse_tls_sni(data: &[u8]) -> Result<String> {
    if let Ok((_, msg)) = parse_tls_plaintext(data) {
        // ...
    }
}
```

✅ **非常好的选择!**
✅ **零拷贝解析,性能好**
✅ **避免重复造轮子**

---

### 5. **包含可运行的示例** ⭐⭐⭐⭐

```rust
fn main() -> Result<()> {
    let raw_hex = "c30000000108...";
    let packet = hex::decode(raw_hex)?;
    match extract_sni(&packet) {
        Ok(sni) => println!("✅ 成功提取 SNI: {}", sni),
        Err(e) => println!("❌ 提取失败: {}", e),
    }
    Ok(())
}
```

✅ **完整的端到端示例**
✅ **方便测试和验证**

---

## 🔧 必须修复才能运行的问题

### 优先级 1 (P0) - 致命错误,必须修复

1. **修复 Salt 值**:
```rust
const INITIAL_SALT_V1: &[u8] = &[
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0xeb, 0xb6, 0xa4,
    0xac, 0x6f, 0x08, 0x78, 0x11, 0x8a, 0xf1, 0x4b,
    0x9c, 0x5d, 0x3a, 0x1a,
];
```

2. **修复 HKDF 密钥推导**:
```rust
// 错误:
hk.expand(&hkdf_label(b"initial", b"", 32), &mut initial_secret)

// 正确:
let salt = Salt::new(HKDF_SHA256, INITIAL_SALT_V1);
let initial_secret = salt.extract(dcid);
```

3. **修复 Packet Number 解码**:
```rust
// 使用 RFC 9000 的解码算法
let decoded_pn = decode_packet_number(truncated_pn, 0, pn_len);
```

---

### 优先级 2 (P1) - 严重错误,影响功能

4. **修复 Sample Offset**:
```rust
// Sample 应该从 PN 之后开始
let sample_start = pn_offset + pn_len;
let sample = &packet[sample_start..sample_start + 16];
```

5. **修复 CRYPTO Frame 解析**:
```rust
// 支持跳过 ACK frames
// 支持多个 CRYPTO frames
// 收集完整的 ClientHello
```

---

### 优先级 3 (P2) - 改进建议

6. **添加单元测试**:
```rust
#[test]
fn test_rfc9001_test_vectors() {
    // RFC 9001 Appendix A
}
```

7. **添加更多注释**:
```rust
// RFC 9001 Section 5.3: Header Protection
// The mask is computed by encrypting the sample with the hp_key
```

8. **性能优化**:
```rust
// 使用更高效的 VarInt 解码
// 避免不必要的 Vec 分配
```

---

## 🎯 与我们项目集成的影响

### ✅ 可以借鉴的部分

1. **整体流程设计** - 步骤清晰
2. **tls-parser 的使用** - 避免重复解析 TLS
3. **依赖库选择** - 都是我们计划使用的

### ❌ 必须修复的部分

1. **Salt 值** - 使用正确的 RFC 9001 值
2. **密钥推导** - 参考 `libdquic` 或 `s2n-quic` 的实现
3. **Packet Number 解码** - 使用完整的 RFC 9000 算法

### 📋 集成到 sniproxy-ng 的建议

**不要直接使用这段代码**,而是:

1. **参考其结构**,但重写所有加密相关函数
2. **使用我们现有的 `tls::sni` 模块**,不使用 tls-parser
3. **参考 s2n-quic 的实现**验证每个加密步骤
4. **使用真实的 QUIC packets 测试**

---

## 📝 总结

### ✅ Gemini 做对的事情

- 整体架构合理
- 依赖选择优秀
- 步骤划分清晰
- 使用了 tls-parser (聪明!)
- 包含完整示例

### ❌ Gemini 做错的事情

- **Salt 值完全错误** (致命!)
- **密钥推导算法有严重错误** (致命!)
- **Packet Number 解码不完整** (严重!)
- **Sample offset 计算** (严重!)
- **CRYPTO Frame 解析过于简化** (中等)

### 🎯 最终评价

**这段代码是**: ⭐⭐⭐ **3/5**

> **良好的学习示例,展示了 QUIC SNI 提取的整体思路,
> 但由于多个严重错误,无法直接用于生产环境。
>
> 建议:**
> 1. 参考其结构
> 2. 重写所有加密函数
> 3. 使用 RFC 9001 测试向量验证
> 4. 使用真实的 QUIC packets 测试**

---

## 🔗 参考资源

- RFC 9000: QUIC Transport
- RFC 9001: Using TLS to Secure QUIC
- RFC 9001 Appendix A: Test Vectors
- libdquic: https://github.com/Waujito/libdquic
- s2n-quic: https://github.com/aws/s2n-quic

---

**评价完成时间**: 2026-01-08
**下次更新**: 修复这些错误后重新评价
