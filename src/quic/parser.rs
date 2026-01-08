//! QUIC Initial Packet 解析器
//!
//! 参考 RFC 9000 Section 17.2: Initial Packet

use crate::quic::error::{QuicError, Result};
use bytes::Bytes;
use tracing::{debug, trace};

/// QUIC Initial Packet Header 结构
#[derive(Debug, Clone)]
pub struct InitialHeader {
    /// 第一个字节 (包含 Packet Type 和 Packet Number Length)
    pub first_byte: u8,
    /// QUIC 版本号
    pub version: u32,
    /// Destination Connection ID (DCID)
    pub dcid: Bytes,
    /// Source Connection ID (SCID)
    pub scid: Bytes,
    /// Token 长度
    pub token_len: usize,
    /// Payload 长度 (包括 Packet Number 和加密的 Payload)
    pub payload_len: usize,
    /// Packet Number 在数据包中的偏移量
    pub pn_offset: usize,
}

/// 从 UDP payload 中提取 DCID (Destination Connection ID)
///
/// 这是提取 SNI 的第一步，因为 DCID 用于密钥派生。
///
/// # 参数
/// - `packet`: 完整的 UDP payload (QUIC Initial Packet)
///
/// # 返回
/// - DCID 的字节切片
///
/// # 示例
/// ```ignore
/// let packet = hex::decode("c30000000108...")?;
/// let dcid = extract_dcid(&packet)?;
/// assert_eq!(dcid.len(), 8);
/// ```
pub fn extract_dcid(packet: &[u8]) -> Result<&[u8]> {
    // 首先检查是否有至少 1 字节
    if packet.is_empty() {
        return Err(QuicError::PacketTooShort {
            expected: 1,
            actual: 0,
        });
    }

    let first_byte = packet[0];

    // 检查是否为 Long Header (bit 7 = 1)
    if (first_byte & 0x80) == 0 {
        return Err(QuicError::NotInitialPacket(first_byte));
    }

    // 检查最小长度: First Byte (1) + Version (4) + DCID Length (1) + 最小 DCID (0)
    if packet.len() < 6 {
        return Err(QuicError::PacketTooShort {
            expected: 6,
            actual: packet.len(),
        });
    }

    // 检查 Packet Type: Initial packet 的 bits 6-5 是 0b00
    // Long Header 格式: 0b1TTxxxxx
    // 其中 TT 是 packet type:
    //   0b00 = Initial
    //   0b01 = 0-RTT
    //   0b10 = Handshake
    //   0b11 = Retry
    let packet_type = (first_byte & 0x30) >> 4;
    if packet_type != 0x00 {
        return Err(QuicError::NotInitialPacket(first_byte));
    }

    // 跳过 First Byte (1 byte)
    // 跳过 Version (4 bytes)
    // Version 是 big-endian u32
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);

    debug!("QUIC Version: {:#010x}", version);

    // DCID Length (1 byte)
    let dcil_pos = 5;
    let dcil = packet[dcil_pos] as usize;

    trace!("DCID Length: {}", dcil);

    // 检查长度是否足够
    if packet.len() < dcil_pos + 1 + dcil {
        return Err(QuicError::PacketTooShort {
            expected: dcil_pos + 1 + dcil,
            actual: packet.len(),
        });
    }

    // 提取 DCID
    let dcid_start = dcil_pos + 1;
    let dcid_end = dcid_start + dcil;
    let dcid = &packet[dcid_start..dcid_end];

    debug!("Extracted DCID: {:?} ({} bytes)", dcid, dcid.len());

    Ok(dcid)
}

/// 解析完整的 QUIC Initial Packet Header
///
/// # 参数
/// - `packet`: 完整的 UDP payload
///
/// # 返回
/// - 包含所有关键字段的 InitialHeader 结构
pub fn parse_initial_header(packet: &[u8]) -> Result<InitialHeader> {
    if packet.is_empty() {
        return Err(QuicError::PacketTooShort {
            expected: 1,
            actual: 0,
        });
    }

    let first_byte = packet[0];

    // 检查 Long Header
    if (first_byte & 0x80) == 0 {
        return Err(QuicError::NotInitialPacket(first_byte));
    }

    // 检查 Initial Packet Type
    let packet_type = (first_byte & 0x30) >> 4;
    if packet_type != 0x00 {
        return Err(QuicError::NotInitialPacket(first_byte));
    }

    if packet.len() < 6 {
        return Err(QuicError::PacketTooShort {
            expected: 6,
            actual: packet.len(),
        });
    }

    // 解析 Version
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);

    // 验证版本
    match version {
        0x00000001 => {
            debug!("QUIC Version 1");
        }
        0x709a50c4 => {
            debug!("QUIC Version 2 (draft)");
        }
        _ => {
            return Err(QuicError::UnsupportedVersion { version });
        }
    }

    let mut offset = 5;

    // 解析 DCID
    let dcil = packet[offset] as usize;
    offset += 1;

    if packet.len() < offset + dcil {
        return Err(QuicError::PacketTooShort {
            expected: offset + dcil,
            actual: packet.len(),
        });
    }

    let dcid = Bytes::copy_from_slice(&packet[offset..offset + dcil]);
    offset += dcil;

    trace!("DCID: {:?} ({} bytes)", dcid, dcil);

    // 解析 SCID
    if packet.len() < offset + 1 {
        return Err(QuicError::PacketTooShort {
            expected: offset + 1,
            actual: packet.len(),
        });
    }

    let scil = packet[offset] as usize;
    offset += 1;

    if packet.len() < offset + scil {
        return Err(QuicError::PacketTooShort {
            expected: offset + scil,
            actual: packet.len(),
        });
    }

    let scid = Bytes::copy_from_slice(&packet[offset..offset + scil]);
    offset += scil;

    trace!("SCID: {:?} ({} bytes)", scid, scil);

    // 解析 Token Length (VarInt)
    let (token_len, varint_len) = parse_varint(&packet[offset..])
        .map_err(|e| QuicError::VarIntError(e.to_string()))?;
    offset += varint_len as usize;

    let token_len = token_len as usize; // 转换为 usize

    trace!("Token Length: {} bytes", token_len);

    // 跳过 Token
    if packet.len() < offset + token_len {
        return Err(QuicError::PacketTooShort {
            expected: offset + token_len,
            actual: packet.len(),
        });
    }

    offset += token_len;

    // 解析 Payload Length (VarInt)
    let (payload_len, varint_len2) = parse_varint(&packet[offset..])
        .map_err(|e| QuicError::VarIntError(e.to_string()))?;
    offset += varint_len2 as usize;

    let payload_len = payload_len as usize; // 转换为 usize

    trace!("Payload Length: {} bytes", payload_len);

    // 记录 Packet Number 的起始位置
    let pn_offset = offset;

    debug!("Packet Number Offset: {}", pn_offset);

    Ok(InitialHeader {
        first_byte,
        version,
        dcid,
        scid,
        token_len,
        payload_len,
        pn_offset,
    })
}

/// 解析 QUIC VarInt (Variable-Length Integer)
///
/// RFC 9000 Section 16: Variable-Length Integer Encoding
///
/// # 返回
/// - (value, bytes_consumed)
pub fn parse_varint(data: &[u8]) -> std::result::Result<(u64, usize), String> {
    if data.is_empty() {
        return Err("No data for VarInt".to_string());
    }

    let first = data[0];
    let prefix = (first & 0xC0) >> 6; // 取最高 2 bits
    let length = 1 << prefix;          // 1, 2, 4, or 8 bytes

    if data.len() < length {
        return Err(format!(
            "VarInt truncated: expected {} bytes, got {}",
            length,
            data.len()
        ));
    }

    let value = match prefix {
        0b00 => {
            // 1 byte: 0b00xxxxxx
            (first & 0x3F) as u64
        }
        0b01 => {
            // 2 bytes: 0b01xxxxxx xxxxxxxx
            let b1 = (first & 0x3F) as u64;
            let b2 = data[1] as u64;
            (b1 << 8) | b2
        }
        0b10 => {
            // 4 bytes: 0b10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            let b1 = (first & 0x3F) as u64;
            let b2 = data[1] as u64;
            let b3 = data[2] as u64;
            let b4 = data[3] as u64;
            (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
        }
        0b11 => {
            // 8 bytes: 0b11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            let b1 = (first & 0x3F) as u64;
            let b2 = data[1] as u64;
            let b3 = data[2] as u64;
            let b4 = data[3] as u64;
            let b5 = data[4] as u64;
            let b6 = data[5] as u64;
            let b7 = data[6] as u64;
            let b8 = data[7] as u64;
            (b1 << 56) | (b2 << 48) | (b3 << 40) | (b4 << 32)
                | (b5 << 24) | (b6 << 16) | (b7 << 8) | b8
        }
        _ => unreachable!(),
    };

    Ok((value, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_dcid_valid_initial_packet() {
        // 构造一个简单的 QUIC Initial packet
        // Format: [First Byte][Version (4)][DCID Len][DCID][SCID Len][SCID][Token Len][Token][Payload Len][PN+Payload]
        let packet = [
            0xC0,       // Initial packet (Long Header, Type=0b00)
            0x00, 0x00, 0x00, 0x01, // Version 1
            0x08,       // DCID Length = 8
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x08,       // SCID Length = 8
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // SCID
            0x00,       // Token Length = 0
            0x05,       // Payload Length = 5
            0x00, 0x01, 0x02, 0x03, 0x04, // PN + Payload (示例)
        ];

        let dcid = extract_dcid(&packet).expect("Failed to extract DCID");
        assert_eq!(dcid, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_extract_dcid_not_initial_packet() {
        // Short Header (not Initial) - bit 7 = 0
        let packet = [0x40, 0x00, 0x01, 0x02, 0x03];

        let result = extract_dcid(&packet);
        assert!(result.is_err());
        // 0x40 = 0b01000000, bit 7 = 0, so it's a Short Header
        if let Err(QuicError::NotInitialPacket(b)) = result {
            assert_eq!(b, 0x40);
        } else {
            panic!("Expected NotInitialPacket error");
        }
    }

    #[test]
    fn test_extract_dcid_packet_too_short() {
        let packet = [0xC0, 0x00, 0x00, 0x00, 0x01]; // 缺少 DCID Length

        let result = extract_dcid(&packet);
        assert!(result.is_err());
        assert!(matches!(result, Err(QuicError::PacketTooShort { .. })));
    }

    #[test]
    fn test_parse_varint() {
        // Test 0b00xxxxxx (1 byte)
        let data = [0x3F]; // value = 63
        let (value, len) = parse_varint(&data).unwrap();
        assert_eq!(value, 63);
        assert_eq!(len, 1);

        // Test 0b01xxxxxx (2 bytes)
        let data = [0x7F, 0xFF]; // value = 16383
        let (value, len) = parse_varint(&data).unwrap();
        assert_eq!(value, 16383);
        assert_eq!(len, 2);

        // Test 0b10xxxxxx (4 bytes)
        let data = [0xBF, 0xFF, 0xFF, 0xFF]; // value = 1073741823
        let (value, len) = parse_varint(&data).unwrap();
        assert_eq!(value, 1073741823);
        assert_eq!(len, 4);
    }

    #[test]
    fn test_parse_initial_header() {
        let packet = [
            0xC0,       // Initial packet
            0x00, 0x00, 0x00, 0x01, // Version 1
            0x08,       // DCID Length = 8
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x08,       // SCID Length = 8
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // SCID
            0x00,       // Token Length = 0
            0x05,       // Payload Length = 5
            0x00, 0x01, 0x02, 0x03, 0x04, // PN + Payload
        ];

        let header = parse_initial_header(&packet).expect("Failed to parse header");
        assert_eq!(header.version, 0x00000001);
        assert_eq!(header.dcid.len(), 8);
        assert_eq!(header.scid.len(), 8);
        assert_eq!(header.token_len, 0);
        assert_eq!(header.payload_len, 5);
        // pn_offset = 1 (First) + 4 (Version) + 1 (DCIL) + 8 (DCID) + 1 (SCIL) + 8 (SCID) + 1 (Token Len) + 0 (Token) + 1 (Payload Len) = 25
        assert_eq!(header.pn_offset, 25);
    }

    #[test]
    fn test_unsupported_version() {
        let packet = [
            0xC0,       // Initial packet
            0xFF, 0xFF, 0xFF, 0xFF, // Invalid version
            0x08,       // DCID Length = 8
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00,       // SCID Length = 0
            0x00,       // Token Length = 0
            0x00,       // Payload Length = 0
        ];

        let result = parse_initial_header(&packet);
        assert!(result.is_err());
        assert!(matches!(result, Err(QuicError::UnsupportedVersion { .. })));
    }
}
