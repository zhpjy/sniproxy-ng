# TLS SNI 提取实现原理详解

## 1. 什么是 SNI (Server Name Indication)?

SNI 是 TLS 协议的一个扩展,用于在 TLS 握手阶段告知客户端想要连接的主机名(域名)。

**为什么需要 SNI?**
- 一个 IP 地址可以托管多个 HTTPS 网站
- 服务器需要知道客户端想要访问哪个域名
- 这样才能返回正确的 SSL/TLS 证书

**SNI 的工作位置:**
```
客户端                      服务器
  │                           │
  │  1. TCP 连接              │
  │──────────────────────────>│
  │                           │
  │  2. TLS ClientHello       │
  │     (包含 SNI: example.com)│
  │──────────────────────────>│
  │                           │
  │  3. TLS ServerHello       │
  │     (返回对应证书)         │
  │<──────────────────────────│
  │                           │
  │  4. 加密的应用数据         │
  │<═══════════════════════════│
```

## 2. TLS 握手详细流程

### 2.1 TLS 记录层结构

TLS 协议使用"记录层"(Record Layer)来封装数据:

```
+-------+-------+-------+-------------------+
| Type  |Version| Length|     Payload       |
| (1B)  | (2B)  | (2B)  |   (Length bytes)  |
+-------+-------+-------+-------------------+
```

**字段说明:**
- **Type (1 字节)**: 内容类型
  - `0x14` = ChangeCipherSpec
  - `0x15` = Alert
  - `0x16` = Handshake (我们关心的!)
  - `0x17` = ApplicationData
  - `0x18` = Heartbeat

- **Version (2 字节)**: TLS 版本
  - `0x0301` = TLS 1.0
  - `0x0302` = TLS 1.1
  - `0x0303` = TLS 1.2
  - `0x0304` = TLS 1.3

- **Length (2 字节)**: Payload 长度(大端序)

- **Payload**: 实际数据

### 2.2 Handshake 消息结构

Handshake 类型有多个,我们只关心 `ClientHello`:

```
+----------+--------+----------+----------------+
|Msg Type  | Length |  (3B)    |  Message Data  |
|  (1B)    | (3B)   |          |                |
+----------+--------+----------+----------------+
```

**Handshake 消息类型:**
- `0x01` = ClientHello ✅ (我们需要的!)
- `0x02` = ServerHello
- `0x0B` = Certificate
- `0x0C` = ServerKeyExchange
- `0x0D` = CertificateRequest
- `0x0E` = ServerHelloDone

### 2.3 ClientHello 详细结构

```
ClientHello 结构:
├─ TLS Version (2B)           例如: 0x0303 (TLS 1.2)
├─ Random (32B)               随机数
├─ Session ID (1B + length)   会话 ID
├─ Cipher Suites (2B + length) 加密套件列表
├─ Compression Methods (1B + length) 压缩方法
└─ Extensions (2B + length)   扩展字段 ⭐
    ├─ Extension Type (2B)
    ├─ Extension Length (2B)
    └─ Extension Data
        └─ SNI:
            ├─ Server Name List Length (2B)
            ├─ Server Name Entry:
            │   ├─ Name Type (1B) = 0x00 (hostname)
            │   ├─ Name Length (2B)
            │   └─ Name (variable) = "example.com"
```

## 3. SNI 扩展详细格式

**SNI 扩展类型:** `0x0000`

**完整结构:**
```
+-----------------+----------------+
|Extension Type   | 0x00 0x00      | (SNI = 0)
+-----------------+----------------+
|Extension Length | 0x00 0x09      | (9 字节)
+-----------------+----------------+
|Server Name List |                |
|Length           | 0x00 0x07      | (7 字节)
+-----------------+----------------+
|Server Name Type | 0x00           | (hostname)
+-----------------+----------------+
|Name Length      | 0x00 0x03      | (3 字节)
+-----------------+----------------+
|Name             | "com"          |
|                 | (example.com)   |
+-----------------+----------------+
```

**实际例子 (访问 www.google.com):**
```
十六进制:
00 00              // Extension Type: SNI (0x0000)
00 0C              // Extension Length: 12 字节
00 0A              // Server Name List Length: 10 字节
00                 // Server Name Type: hostname (0x00)
00 07              // Name Length: 7 字节
77 77 77 06        // "www" + 长度前缀
67 6F 6F 67 6C 65  // "google"
03 63 6F 6D        // ".com" (标签 + "com")
```

## 4. 实现步骤详解

### 步骤 1: 读取 TCP 流

```rust
// 读取前 5 字节 (TLS 记录头)
let mut header = [0u8; 5];
stream.read_exact(&mut header).await?;

let content_type = header[0];
let version = u16::from_be_bytes([header[1], header[2]]);
let length = u16::from_be_bytes([header[3], header[4]]) as usize;

// 检查是否是 Handshake (0x16)
assert_eq!(content_type, 0x16);
```

### 步骤 2: 读取 Handshake 消息

```rust
// 读取 payload
let mut payload = vec![0u8; length];
stream.read_exact(&mut payload).await?;

// 解析 Handshake 类型
let handshake_type = payload[0];
assert_eq!(handshake_type, 0x01); // ClientHello

// 跳过 Handshake 长度 (3 字节)
// 跳过 TLS Version (2 字节)
// 跳过 Random (32 字节)
let mut offset = 1 + 3 + 2 + 32;
```

### 步骤 3: 跳过 Session ID

```rust
let session_id_length = payload[offset] as usize;
offset += 1 + session_id_length;
```

### 步骤 4: 跳过 Cipher Suites

```rust
let cipher_suites_length = u16::from_be_bytes([
    payload[offset],
    payload[offset + 1]
]) as usize;
offset += 2 + cipher_suites_length;
```

### 步骤 5: 跳过 Compression Methods

```rust
let compression_length = payload[offset] as usize;
offset += 1 + compression_length;
```

### 步骤 6: 解析扩展

```rust
// 扩展总长度
let extensions_length = u16::from_be_bytes([
    payload[offset],
    payload[offset + 1]
]) as usize;
offset += 2;

// 遍历扩展
let mut end = offset + extensions_length;
while offset < end {
    let ext_type = u16::from_be_bytes([
        payload[offset],
        payload[offset + 1]
    ]);
    offset += 2;

    let ext_length = u16::from_be_bytes([
        payload[offset],
        payload[offset + 1]
    ]) as usize;
    offset += 2;

    // 检查是否是 SNI 扩展 (0x0000)
    if ext_type == 0x0000 {
        return parse_sni_extension(&payload[offset..offset + ext_length]);
    }

    offset += ext_length;
}
```

### 步骤 7: 解析 SNI 扩展内容

```rust
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    let mut offset = 0;

    // Server Name List Length
    let list_length = u16::from_be_bytes([
        data[offset],
        data[offset + 1]
    ]) as usize;
    offset += 2;

    // 通常只有一个 Server Name
    let name_type = data[offset];
    if name_type != 0x00 {
        return None; // 不是 hostname 类型
    }
    offset += 1;

    // Name Length
    let name_length = u16::from_be_bytes([
        data[offset],
        data[offset + 1]
    ]) as usize;
    offset += 2;

    // Name (域名)
    let name = &data[offset..offset + name_length];
    String::from_utf8(name.to_vec()).ok()
}
```

## 5. 实际数据包示例

### 完整的 TLS ClientHello 数据包 (简化版)

```
TLS Record Layer:
Content Type: 0x16 (Handshake)
Version: 0x0303 (TLS 1.2)
Length: 0x00 0xA0 (160 字节)

Handshake Message:
Type: 0x01 (ClientHello)
Length: 0x00 0x00 9C (156 字节)
TLS Version: 0x0303 (TLS 1.2)
Random: 32 字节随机数
Session ID: 32 字节会话 ID
Cipher Suites: 0x00 0x08 (8 个加密套件)
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - ...

Compression Methods: 0x01 (1 个方法)
  - 0x00 (null compression)

Extensions: 0x00 0x3C (60 字节)
  Extension 1:
    Type: 0x0000 (SNI)
    Length: 0x00 0x09 (9 字节)
    Data:
      List Length: 0x00 0x07
      Name Type: 0x00
      Name Length: 0x00 0x0B
      Name: "www.example.com"

  Extension 2:
    Type: 0x000A (Supported Elliptic Curves)
    Length: 0x00 0x08
    ...

  Extension 3:
    Type: 0x000B (EC Point Formats)
    Length: 0x00 0x02
    ...
```

## 6. 关键注意事项

### 6.1 为什么不需要完整的 TLS 握手?

**传统代理:**
```
客户端 ←→ 代理 (解密+重新加密) ←→ 服务器
         需要私钥!
```

**SNI 代理:**
```
客户端 ←→ 代理 (只读 SNI) ←→ SOCKS5 ←→ 服务器
         不需要解密!
```

**优势:**
- ✅ 不需要服务器私钥
- ✅ 性能更好(不解密)
- ✅ 部署简单
- ✅ 安全(不看到内容)

### 6.2 边界情况处理

1. **没有 SNI 扩展**
   - 老旧客户端
   - 返回 None 或使用默认后端

2. **多个 SNI**
   - 通常是第一个
   - 或使用列表中任何一个

3. **SNI 域名格式**
   - 可能是 punycode (xn--)
   - 可能是 Unicode
   - 需要验证 UTF-8

4. **数据包分片**
   - TCP 流可能分片
   - 需要缓冲和重组

### 6.3 性能优化

```rust
// 1. 只读取需要的字节
// 不要读取整个数据包

// 2. 使用零拷贝解析
// 避免不必要的内存复制

// 3. 使用查找表而不是顺序遍历扩展
// 如果只需要 SNI,可以快速定位
```

## 7. 测试方法

### 7.1 使用 OpenSSL 生成测试数据

```bash
# 生成 TLS ClientHello
openssl s_client -connect www.google.com:443 \
  -servername www.google.com \
  -tlsextdebug \
  -prexit
```

### 7.2 使用 Wireshark 抓包

1. 启动 Wireshark
2. 过滤器: `tls.handshake.type == 1`
3. 查看 ClientHello 消息
4. 展开 "Extensions" → "Server Name Indication"

### 7.3 使用 Python 测试

```python
import socket
import ssl

# 创建连接
sock = socket.create_connection(("www.google.com", 443))
ssl_sock = ssl.wrap_socket(sock)

# SNI 会自动发送
# 你可以在代理端捕获这个包
```

## 8. 在 QUIC 中的 SNI 提取

**QUIC 的不同之处:**
- QUIC 使用 UDP 而不是 TCP
- QUIC Initial Packet 包含完整的 TLS ClientHello
- 数据包格式不同,但 TLS 部分相同

**QUIC Initial Packet 结构:**
```
+------+-------+--------+-----+
|Header|Length |PN Len |PN   |
+------+-------+--------+-----+
|Crypto Frame (TLS数据)      |
+---------------------------+
```

**好消息:** TLS ClientHello 的内容是一样的!
只是封装方式不同,解析逻辑可以复用。

## 9. 调试技巧

### 9.1 打印调试信息

```rust
eprintln!("Type: 0x{:02X}", content_type);
eprintln!("Version: 0x{:04X}", version);
eprintln!("Length: {}", length);
eprintln!("Payload: {:02X?}", &payload[..20]);
```

### 9.2 使用 Wireshark 验证

对比你的解析结果和 Wireshark 的解析结果:
- 1. 你的程序打印 SNI
- 2. Wireshark 打开同一数据包
- 3. 对比是否一致

## 10. 完整代码示例

(将在下一个实现步骤中提供完整的 Rust 代码)

---

## 总结

**核心要点:**
1. SNI 在 TLS ClientHello 的扩展中 (扩展类型 0x0000)
2. 需要逐层解析: TLS Record → Handshake → ClientHello → Extensions → SNI
3. 不需要完整握手,只读 ClientHello
4. 解析完 SNI 后可以直接转发,不修改数据流

**下一步:** 实现 Rust 代码
