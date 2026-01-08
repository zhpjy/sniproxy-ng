//! QUIC CRYPTO Frame 解密和 TLS SNI 提取
//!
//! 参考 RFC 9001 Section 5: Packet Protection
//! 参考 RFC 9000 Section 18: QUIC Frames (CRYPTO Frame)

use crate::quic::crypto::InitialKeys;
use crate::quic::error::{QuicError, Result};
use crate::quic::parser::parse_varint;
use crate::tls::sni::extract_sni;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use tracing::{debug, info};

/// 从 QUIC Initial Packet 中提取 SNI
///
/// 这是端到端的主函数，执行完整的 SNI 提取流程：
/// 1. 提取 DCID
/// 2. 派生密钥
/// 3. 移除 Header Protection
/// 4. 解密 CRYPTO Frame
/// 5. 解析 TLS ClientHello 提取 SNI
///
/// # 参数
/// - `packet`: 完整的 UDP payload (QUIC Initial Packet)
///
/// # 返回
/// - SNI (如果找到)
///
/// # 示例
/// ```ignore
/// let packet = hex::decode("c30000000108...")?;
/// let sni = extract_sni_from_quic_initial(&packet)?;
/// assert_eq!(sni, Some("www.google.com".to_string()));
/// ```
pub fn extract_sni_from_quic_initial(packet: &mut [u8]) -> Result<Option<String>> {
    info!("Starting QUIC SNI extraction (packet length: {})", packet.len());

    // Step 1: 解析 Initial Header
    let header = crate::quic::parse_initial_header(packet)?;
    debug!("Initial header parsed: version={:#x}, dcid_len={}",
           header.version, header.dcid.len());

    // Step 2: 派生 Initial Keys
    let keys = crate::quic::derive_initial_keys(&header.dcid)?;
    debug!("Initial keys derived from DCID");

    // Step 3: 移除 Header Protection
    let (_unprotected_first_byte, packet_number, pn_len) =
        crate::quic::remove_header_protection(packet, header.pn_offset, &keys)?;
    debug!("Header protection removed: PN={}", packet_number);

    // Step 4: 提取并解密 CRYPTO Frame
    let crypto_data = extract_and_decrypt_crypto_frame(
        packet,
        header.pn_offset,
        pn_len,
        packet_number,
        &keys,
    )?;
    debug!("CRYPTO frame decrypted: {} bytes", crypto_data.len());

    // Step 5: 解析 TLS ClientHello 提取 SNI
    let sni = extract_sni(&crypto_data)
        .map_err(|e| QuicError::TlsError(format!("Failed to extract SNI from TLS: {}", e)))?;

    if let Some(ref sni) = sni {
        info!("✅ Successfully extracted SNI: {}", sni);
    } else {
        info!("⚠️  No SNI found in packet");
    }

    Ok(sni)
}

/// 提取并解密 CRYPTO Frame
///
/// # 参数
/// - `packet`: 完整的 QUIC packet (Header Protection 已移除)
/// - `pn_offset`: Packet Number 在 packet 中的偏移量
/// - `pn_len`: Packet Number 长度 (1-4 bytes)
/// - `packet_number`: Packet Number (已解码)
/// - `keys`: Initial Keys
///
/// # 返回
/// - 解密后的 CRYPTO data (TLS ClientHello)
fn extract_and_decrypt_crypto_frame(
    packet: &[u8],
    pn_offset: usize,
    pn_len: u8,
    packet_number: u64,
    keys: &InitialKeys,
) -> Result<Vec<u8>> {
    // 计算 payload 的起始位置
    // Payload = PN 之后的所有数据
    let payload_start = pn_offset + pn_len as usize;

    if packet.len() <= payload_start {
        return Err(QuicError::PacketTooShort {
            expected: payload_start + 1,
            actual: packet.len(),
        });
    }

    // 获取加密的 payload
    let encrypted_payload = &packet[payload_start..];

    // 解析 QUIC Frames，寻找 CRYPTO frame
    let mut cursor = encrypted_payload;
    let mut crypto_data = Vec::new();

    // 简化的 Frame 解析：寻找第一个 CRYPTO frame
    while cursor.len() > 0 {
        // 读取 Frame Type (VarInt)
        let (frame_type, varint_len) = parse_varint(cursor)
            .map_err(|e| QuicError::CryptoFrameError(format!("Failed to parse frame type: {}", e)))?;

        let frame_data = &cursor[varint_len..];

        match frame_type {
            0x00 => {
                // PADDING frame - skip
                debug!("Skipping PADDING frame");
                // PADDING frame 没有额外数据，继续
                cursor = frame_data;
                continue;
            }
            0x01 => {
                // PING frame - 跳过
                debug!("Skipping PING frame");
                // PING frame 没有额外数据，继续
                cursor = frame_data;
                continue;
            }
            0x06 => {
                // CRYPTO Frame - 这是我们想要的！
                debug!("Found CRYPTO frame");

                // CRYPTO frame 格式:
                // Type (VarInt) + Offset (VarInt) + Length (VarInt) + Data

                // Skip Type (already read)
                let mut offset = varint_len;

                // Read Offset
                let (crypto_offset, offset_len) = parse_varint(&frame_data[offset..])
                    .map_err(|e| QuicError::CryptoFrameError(format!("Failed to parse CRYPTO offset: {}", e)))?;
                offset += offset_len;

                // Read Length
                let (crypto_length, length_len) = parse_varint(&frame_data[offset..])
                    .map_err(|e| QuicError::CryptoFrameError(format!("Failed to parse CRYPTO length: {}", e)))?;
                offset += length_len;

                let crypto_length = crypto_length as usize;

                if frame_data.len() < offset + crypto_length {
                    return Err(QuicError::CryptoFrameError(format!(
                        "CRYPTO data truncated: expected {}, got {}",
                        crypto_length,
                        frame_data.len() - offset
                    )));
                }

                let data = &frame_data[offset..offset + crypto_length];

                debug!("CRYPTO frame: offset={}, length={}, data_len={}",
                       crypto_offset, crypto_length, data.len());

                // 对于 Initial packet，我们假设 offset = 0
                // 如果 offset != 0，说明有分片，需要重组
                if crypto_offset != 0 {
                    return Err(QuicError::CryptoFrameError(
                        format!("CRYPTO frame offset {} != 0 (fragmented data not supported)", crypto_offset)
                    ));
                }

                crypto_data.extend_from_slice(data);

                // 找到我们需要的 CRYPTO data，跳出循环
                break;
            }
            0x02 | 0x03 => {
                // ACK frame - 跳过
                debug!("Skipping ACK frame");
                // ACK frame 格式复杂，暂时跳过
                // 简化处理：假设 CRYPTO frame 在 ACK 之前
                return Err(QuicError::CryptoFrameError(
                    "ACK frame encountered before CRYPTO frame (parsing not implemented)".to_string()
                ));
            }
            _ => {
                // Unknown frame type
                debug!("Unknown frame type: {:#x}", frame_type);
                return Err(QuicError::CryptoFrameError(
                    format!("Unknown frame type: {:#x}", frame_type)
                ));
            }
        }
    }

    if crypto_data.is_empty() {
        return Err(QuicError::NoSniFound);
    }

    // Step 5: 解密 CRYPTO data
    let decrypted = decrypt_crypto_payload(&crypto_data, packet_number, keys)?;

    Ok(decrypted)
}

/// 解密 CRYPTO payload
///
/// # 参数
/// - `encrypted`: 加密的 CRYPTO data (包括 auth tag)
/// - `packet_number`: Packet Number
/// - `keys`: Initial Keys
///
/// # 返回
/// - 解密后的 TLS ClientHello
fn decrypt_crypto_payload(
    encrypted: &[u8],
    packet_number: u64,
    keys: &InitialKeys,
) -> Result<Vec<u8>> {
    // AES-128-GCM Auth Tag 长度 = 16 bytes
    const TAG_LEN: usize = 16;

    if encrypted.len() < TAG_LEN {
        return Err(QuicError::DecryptionFailed(format!(
            "Encrypted data too short: {} < {}",
            encrypted.len(),
            TAG_LEN
        )));
    }

    // 分离 ciphertext 和 auth tag
    let ciphertext_len = encrypted.len() - TAG_LEN;
    let ciphertext = &encrypted[..ciphertext_len];
    let tag = &encrypted[ciphertext_len..];

    // 构造 nonce: IV xor Packet Number
    // RFC 9001: nonce = IV ^ (packet_number as big-endian)
    let nonce = construct_nonce(&keys.iv, packet_number)?;

    debug!("Nonce constructed: {:02x?}", nonce.as_ref());

    // 创建 AEAD key
    let unbound_key = UnboundKey::new(&AES_128_GCM, &keys.key)
        .map_err(|e| QuicError::DecryptionFailed(format!("Failed to create AEAD key: {:?}", e)))?;
    let aead_key = LessSafeKey::new(unbound_key);

    // 拼接 ciphertext + tag (ring 的格式)
    let mut ciphertext_and_tag = ciphertext.to_vec();
    ciphertext_and_tag.extend_from_slice(tag);

    // 解密 (Initial packet 没有 AAD)
    let mut plaintext = ciphertext_and_tag.clone();
    aead_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut plaintext,
        )
        .map_err(|e| QuicError::DecryptionFailed(format!("Decryption failed: {:?}", e)))?;

    // 移除 auth tag
    plaintext.truncate(ciphertext_len);

    debug!("Decrypted {} bytes", plaintext.len());

    Ok(plaintext)
}

/// 构造 Nonce (IV xor Packet Number)
///
/// RFC 9001: nonce 是通过将 Packet Number (作为 big-endian)
/// 放置在 IV 的最后部分进行 XOR 构造的
///
/// # 参数
/// - `iv`: Initial Vector (12 bytes for QUIC)
/// - `packet_number`: Packet Number
///
/// # 返回
/// - Nonce (12 bytes)
fn construct_nonce(iv: &[u8], packet_number: u64) -> Result<[u8; 12]> {
    if iv.len() != 12 {
        return Err(QuicError::DecryptionFailed(format!(
            "Invalid IV length: {} (expected 12)",
            iv.len()
        )));
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);

    // 将 packet_number 作为 big-endian 放入 nonce 的最后部分
    let pn_bytes = packet_number.to_be_bytes();
    let pn_len = pn_bytes.len();

    // Packet Number 作为 64-bit integer
    // XOR 到 nonce 的最后 8 bytes
    let nonce_offset = 12 - pn_len;
    for i in 0..pn_len {
        nonce[nonce_offset + i] ^= pn_bytes[i];
    }

    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_nonce() {
        let iv = [0u8; 12];
        let packet_number = 0x12345678;

        let nonce = construct_nonce(&iv, packet_number).unwrap();

        // nonce 应该是 packet_number 在最后 8 bytes
        let expected = [
            0, 0, 0, 0,
            0x12, 0x34, 0x56, 0x78,
        ];

        assert_eq!(&nonce[4..12], &expected[..]);
    }

    #[test]
    fn test_construct_nonce_with_iv() {
        let iv = [
            0x5b, 0x6c, 0x9f, 0x0e, 0x7e, 0x6a, 0x7b, 0xb4,
            0x1d, 0xb6, 0x56, 0x34,
        ];
        let packet_number = 0;

        let nonce = construct_nonce(&iv, packet_number).unwrap();

        // PN = 0，所以 nonce 应该等于 IV
        assert_eq!(nonce.as_ref(), iv);
    }

    #[test]
    fn test_construct_nonce_invalid_iv_length() {
        let iv = [0u8; 10]; // 错误长度
        let packet_number = 0;

        let result = construct_nonce(&iv, packet_number);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_crypto_payload_too_short() {
        let encrypted = [0u8; 8]; // 少于 TAG_LEN (16)
        let packet_number = 0;
        let keys = crate::quic::crypto::InitialKeys {
            key: vec![0u8; 16],
            iv: vec![0u8; 12],
            hp_key: vec![0u8; 16],
        };

        let result = decrypt_crypto_payload(&encrypted, packet_number, &keys);
        assert!(result.is_err());
    }
}
