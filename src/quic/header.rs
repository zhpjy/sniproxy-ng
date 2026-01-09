//! QUIC Header Protection 移除和 Packet Number 解码
//!
//! 参考 RFC 9001 Section 5.4: Header Protection
//! 参考 RFC 9000 Section 17.1: Packet Number Encoding and Decoding

use crate::quic::crypto::InitialKeys;
use crate::quic::error::{QuicError, Result};
use ring::aead::quic::{HeaderProtectionKey, AES_128};
use tracing::{debug, info, warn};

/// 移除 QUIC Initial Packet 的 Header Protection
///
/// RFC 9001 Section 5.4:
/// ```text
/// 对于 Initial packet，sample 是从 packet number 字段开始的
/// 第 4 个字节开始采样的 16 字节
/// ```
///
/// # 参数
/// - `packet`: 完整的 QUIC Initial Packet (会被修改)
/// - `pn_offset`: Packet Number 在 packet 中的偏移量
/// - `keys`: Initial Keys (包含 hp_key)
///
/// # 返回
/// - (unprotected_first_byte, packet_number, pn_length)
///
/// # 修改
/// - `packet` 的 first byte 和 packet number 会被 in-place 解密
pub fn remove_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    keys: &InitialKeys,
) -> Result<(u8, u64, u8)> {
    // 检查包长度
    // 最小长度：pn_offset + 4 (sample) + 16 (sample length)
    if packet.len() < pn_offset + 4 {
        return Err(QuicError::PacketTooShort {
            expected: pn_offset + 4,
            actual: packet.len(),
        });
    }

    // 注意：Packet Number Length (低 2 bits) 是被 header protection 保护的，
    // 不能从 protected first byte 可靠地读取。
    // 正确流程：先用 sample 生成 mask → 解除 first byte 保护 → 再从 unprotected first byte 读取 PN length。
    let protected_first_byte = packet[0];
    let protected_pn_len = (protected_first_byte & 0x03) + 1;
    info!(
        "Protected first byte: {:#04x}, protected_pn_len(UNRELIABLE): {}",
        protected_first_byte, protected_pn_len
    );

    // 计算 sample 位置
    // RFC 9001: sample 是从 PN 字段开始的第 4 个字节
    let sample_start = pn_offset + 4;
    let sample_end = sample_start + 16;

    if packet.len() < sample_end {
        return Err(QuicError::PacketTooShort {
            expected: sample_end,
            actual: packet.len(),
        });
    }

    let sample = &packet[sample_start..sample_end];
    info!("Sample: start={}, end={}, first 16 bytes: {:02x?}",
           sample_start, sample_end, sample);

    // 创建 Header Protection Key
    let hp_key = HeaderProtectionKey::new(&AES_128, &keys.hp_key)
        .map_err(|e| QuicError::HeaderProtectionFailed(format!("Failed to create HP key: {:?}", e)))?;

    // 生成 mask
    let mask = hp_key.new_mask(sample)
        .map_err(|e| QuicError::HeaderProtectionFailed(format!("Failed to generate mask: {:?}", e)))?;

    info!("Mask generated: {:02x?}", mask);

    // 解密 first byte
    // 只需要修改低 4 bits (packet number length)
    // High 4 bits (packet type) 保持不变
    let unprotected_first_byte = protected_first_byte ^ (mask[0] & 0x0F);

    debug!(
        "First byte: protected={:#04x}, unprotected={:#04x}",
        protected_first_byte, unprotected_first_byte
    );

    // 从 unprotected first byte 获取 PN length (RFC 9001 Section 5.4)
    // pn_len = (first_byte & 0x03) + 1, range: 1..=4
    let pn_len = (unprotected_first_byte & 0x03) + 1;
    debug!("Unprotected PN length: {}", pn_len);

    // 解密 Packet Number
    // ⚠️ 重要：先读取 protected bytes，因为 XOR 是 in-place 的
    let protected_pn_bytes: Vec<u8> = packet[pn_offset..pn_offset + pn_len as usize].to_vec();
    info!("Protected PN bytes (at offset {}): {:02x?}", pn_offset, protected_pn_bytes);
    info!("Mask for PN: {:02x?}", &mask[1..pn_len as usize + 1]);

    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len as usize {
        let idx = pn_offset + i;
        pn_bytes[i] = packet[idx] ^ mask[1 + i];
        packet[idx] = pn_bytes[i]; // In-place 解密
    }

    info!("Unprotected PN bytes: {:02x?}", &pn_bytes[..pn_len as usize]);

    // 解码 Packet Number
    //
    // 对于我们当前场景（抓到的通常是连接早期的 Initial），直接将截断的 PN
    // 作为数值使用即可（等价于 expected_pn=0 的标准解码结果）。
    // 这也避免了在没有“expected_pn 状态机”的情况下错误恢复 PN。
    let mut packet_number = 0u64;
    for &b in pn_bytes[..pn_len as usize].iter() {
        packet_number = (packet_number << 8) | (b as u64);
    }
    info!("Packet Number decoded: {}", packet_number);

    // ⚠️ 对于 Initial packet，PN 通常很小（第一个包 PN=0）
    // 但如果 PN>100，可能：
    // 1. 客户端发送了多个 Initial packet（PN 递增）
    // 2. 或这是一个非标准实现
    // 我们记录警告但继续尝试解密
    if packet_number > 100 {
        warn!("Decoded PN {} is unusually large for Initial packet. \
              This might be a retransmission or non-standard implementation.",
              packet_number);
        // 不返回错误，继续尝试解密
    }

    // 更新 first byte
    packet[0] = unprotected_first_byte;

    Ok((unprotected_first_byte, packet_number, pn_len))
}

/// 解码 Packet Number
///
/// RFC 9000 Section 17.1:
/// ```text
/// Packet Number 解码使用期望的 PN (expected_pn) 来恢复完整值
/// ```
///
/// # 参数
/// - `truncated_pn`: 截断的 Packet Number (1-4 bytes)
/// - `expected_pn`: 期望的 Packet Number (对于 Initial packet，通常是 0)
///
/// # 返回
/// - 完整的 Packet Number (u64)
///
/// # 算法
/// ```text
/// pn_win = 1 << (8 * pn_len)
/// pn_hwin = pn_win / 2
/// candidate = (expected_pn & !(pn_win - 1)) | truncated_pn
///
/// if candidate <= expected_pn + pn_hwin && candidate + pn_win > expected_pn + pn_hwin:
///     return candidate
/// elif candidate > expected_pn + pn_hwin:
///     return candidate - pn_win
/// else:
///     return candidate + pn_win
/// ```
pub fn decode_packet_number(truncated_pn: &[u8], expected_pn: u64) -> Result<u64> {
    let pn_len = truncated_pn.len();

    if pn_len > 4 {
        return Err(QuicError::PacketNumberError(format!(
            "PN length too large: {}",
            pn_len
        )));
    }

    // 将截断的 PN 转换为整数
    let mut truncated = 0u64;
    for (_i, &byte) in truncated_pn.iter().enumerate() {
        truncated = (truncated << 8) | (byte as u64);
    }

    // 计算 pn_win = 2^(8*pn_len)
    let pn_win = 1u64 << (8 * pn_len as u64);
    let pn_hwin = pn_win / 2;
    let mask = pn_win - 1;

    // 计算 candidate packet number
    let candidate = (expected_pn & !mask) | truncated;

    // 选择最接近 expected_pn 的值
    let decoded = if candidate <= expected_pn + pn_hwin
        && candidate + pn_win > expected_pn + pn_hwin
    {
        candidate
    } else if candidate > expected_pn + pn_hwin {
        candidate.saturating_sub(pn_win)
    } else {
        candidate + pn_win
    };

    debug!(
        "PN decode: truncated={}, expected={}, decoded={}",
        truncated, expected_pn, decoded
    );

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_packet_number_1_byte() {
        // 1 byte PN: value = 0x00
        let pn_bytes = [0x00];
        let decoded = decode_packet_number(&pn_bytes, 0).unwrap();
        assert_eq!(decoded, 0);
    }

    #[test]
    fn test_decode_packet_number_2_bytes() {
        // 2 byte PN: value = 0x0123
        let pn_bytes = [0x01, 0x23];
        let decoded = decode_packet_number(&pn_bytes, 0).unwrap();
        assert_eq!(decoded, 0x0123);
    }

    #[test]
    fn test_decode_packet_number_with_expected() {
        // 测试当 expected_pn 较大时的解码
        // expected = 10000, truncated = 5 (1 byte)
        // pn_win = 256, pn_hwin = 128
        // candidate = (10000 & !255) | 5 = 9984 | 5 = 9989
        // candidate (9989) <= expected + hwin (10128)? Yes
        // candidate + pn_win (10245) > expected + hwin (10128)? Yes
        // 所以返回 candidate = 9989
        let pn_bytes = [5u8];
        let decoded = decode_packet_number(&pn_bytes, 10000).unwrap();
        assert_eq!(decoded, 9989);
    }

    #[test]
    fn test_decode_packet_number_rollover() {
        // 测试 PN 溢出情况
        // expected = 255, truncated = 0 (1 byte)
        // pn_win = 256, pn_hwin = 128
        // candidate = (255 & !0xFF) | 0 = 0 | 0 = 0
        // candidate (0) > expected + hwin (383)? No
        // candidate + pn_win (256) > expected + hwin (383)? No
        // 所以返回 candidate + pn_win = 256
        let pn_bytes = [0x00];
        let decoded = decode_packet_number(&pn_bytes, 255).unwrap();
        assert_eq!(decoded, 256);
    }

    #[test]
    fn test_decode_packet_number_4_bytes() {
        // 4 byte PN: value = 0x12345678
        let pn_bytes = [0x12, 0x34, 0x56, 0x78];
        let decoded = decode_packet_number(&pn_bytes, 0).unwrap();
        assert_eq!(decoded, 0x12345678);
    }

    #[test]
    fn test_decode_packet_number_invalid_length() {
        let pn_bytes = [0x00, 0x01, 0x02, 0x03, 0x04]; // 5 bytes
        let result = decode_packet_number(&pn_bytes, 0);
        assert!(result.is_err());
        assert!(matches!(result, Err(QuicError::PacketNumberError(_))));
    }

    #[test]
    fn test_remove_header_protection_simple() {
        // 这个测试需要真实的 QUIC Initial packet 才能正确测试
        // 暂时跳过，等到 Phase 3/4 有真实数据时再测试
        // 这里我们只测试 Packet Number 解码部分

        // 测试 PN 解码
        let pn_bytes = [0x00, 0x01, 0x02, 0x03];
        let decoded = decode_packet_number(&pn_bytes[..1], 0).unwrap();
        assert_eq!(decoded, 0);

        // 测试错误处理
        let mut short_packet = [0u8; 30];
        let keys = crate::quic::crypto::InitialKeys {
            key: vec![0u8; 16],
            iv: vec![0u8; 12],
            hp_key: vec![0u8; 16],
        };

        let result = remove_header_protection(&mut short_packet, 25, &keys);
        // 应该失败，因为 packet 太短
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_header_protection_packet_too_short() {
        let mut packet = [0u8; 10]; // 太短
        let keys = crate::quic::crypto::InitialKeys {
            key: vec![0u8; 16],
            iv: vec![0u8; 12],
            hp_key: vec![0u8; 16],
        };

        let result = remove_header_protection(&mut packet, 8, &keys);
        assert!(result.is_err());
        assert!(matches!(result, Err(QuicError::PacketTooShort { .. })));
    }
}
