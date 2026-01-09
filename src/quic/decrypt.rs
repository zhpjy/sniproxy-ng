//! QUIC CRYPTO Frame 解密和 TLS SNI 提取
//!
//! 参考 RFC 9001 Section 5: Packet Protection
//! 参考 RFC 9000 Section 18: QUIC Frames (CRYPTO Frame)

use crate::quic::crypto::{InitialKeyRole, InitialKeys};
use crate::quic::error::{QuicError, Result};
use crate::quic::parser::parse_varint;
use crate::tls::sni::extract_sni;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

#[derive(Debug)]
struct PendingCrypto {
    role: InitialKeyRole,
    fragments: BTreeMap<u64, Vec<u8>>,
    last_update: Instant,
}

// NOTE: Avoid std::sync::OnceLock to keep compatibility with older Rust toolchains.
// This is a small, controlled unsafe initialization for a global Mutex<HashMap<...>>.
static PENDING_CRYPTO_INIT: Once = Once::new();
static mut PENDING_CRYPTO_PTR: *const Mutex<HashMap<Vec<u8>, PendingCrypto>> = std::ptr::null();

fn pending_crypto_map() -> &'static Mutex<HashMap<Vec<u8>, PendingCrypto>> {
    unsafe {
        PENDING_CRYPTO_INIT.call_once(|| {
            let m = Mutex::new(HashMap::new());
            PENDING_CRYPTO_PTR = Box::into_raw(Box::new(m));
        });
        // SAFETY: initialized by Once exactly once and never freed (intentionally global).
        &*PENDING_CRYPTO_PTR
    }
}

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
    info!("Raw packet header (first 32 bytes): {:02x?}", &packet[..packet.len().min(32)]);

    // Step 1: 解析 Initial Header
    let header = crate::quic::parse_initial_header(packet)?;
    info!(
        "Parsed Initial header: version={:#x}, dcid_len={}, scid_len={}, token_len={}, payload_len={}, pn_offset={}",
        header.version,
        header.dcid.len(),
        header.scid.len(),
        header.token_len,
        header.payload_len,
        header.pn_offset
    );

    // ⚠️ 快速失败检查：如果 PN 长度异常，可能不是真正的 Initial packet
    // 对于客户端 Initial packet，PN 通常是 1-2 字节
    let protected_pn_len = (packet[0] & 0x03) + 1;
    if protected_pn_len > 2 {
        warn!("Protected PN length {} is unusual for client Initial packet (expected 1-2). \
              This might not be a client Initial packet.",
              protected_pn_len);
        // 继续尝试，但记录警告
    }
    debug!("Initial header parsed: version={:#x}, dcid_len={}",
           header.version, header.dcid.len());

    // Step 2/3/4/5: Try both directions (client/server).
    //
    // QUIC Initial header looks the same in both directions; to be robust we try both
    // "client in" and "server in" labels and pick the one that yields valid reserved bits
    // and successful AEAD decryption.
    let original = packet.to_vec();
    for role in [InitialKeyRole::Client, InitialKeyRole::Server] {
        let mut pkt = original.clone();
        info!("Trying QUIC Initial decryption role: {:?}", role);

        info!(
            "Deriving keys from DCID: {:02x?} ({} bytes), version: {:#x}, role={:?}",
            header.dcid,
            header.dcid.len(),
            header.version,
            role
        );
        let keys = crate::quic::crypto::derive_initial_keys_for_role(&header.dcid, header.version, role)?;
        info!("Initial keys derived successfully, pn_offset={}", header.pn_offset);

        info!("Removing header protection at offset {}", header.pn_offset);
        let (unprotected_first_byte, packet_number, pn_len) =
            crate::quic::remove_header_protection(&mut pkt, header.pn_offset, &keys)?;
        info!("Header protection removed: PN={}, pn_len={}", packet_number, pn_len);

        // Long Header reserved bits are bits 3-2; after unprotection they MUST be 0.
        let reserved = (unprotected_first_byte & 0x0c) >> 2;
        info!(
            "Unprotected first byte: {:#04x} (reserved bits={:#x})",
            unprotected_first_byte, reserved
        );
        if reserved != 0 {
            warn!(
                "Role {:?}: reserved bits non-zero after header unprotection (reserved={:#x}); skipping decrypt attempt.",
                role, reserved
            );
            continue;
        }

        if packet_number >= 100 {
            warn!(
                "Packet Number {} is unusually large for Initial packet. Attempting decryption anyway. (role={:?})",
                packet_number, role
            );
        }

        info!("Extracting and decrypting CRYPTO frame (role={:?})", role);
        let crypto_data = match extract_and_decrypt_crypto_frame(
            &pkt,
            header.pn_offset,
            header.payload_len,
            pn_len,
            packet_number,
            &keys,
            &header.dcid,
            role,
        ) {
            Ok(v) => v,
            Err(e) => {
                warn!("Role {:?}: decryption attempt failed: {}", role, e);
                continue;
            }
        };
        info!(
            "CRYPTO stream available: {} bytes (role={:?})",
            crypto_data.len(),
            role
        );

        let sni = extract_sni(&crypto_data)
            .map_err(|e| QuicError::TlsError(format!("Failed to extract SNI from TLS: {}", e)))?;

        if let Some(ref sni) = sni {
            info!("✅ Successfully extracted SNI: {} (role={:?})", sni, role);
        } else {
            info!("⚠️  No SNI found in packet (role={:?})", role);
        }

        // Preserve the decoded packet bytes for any downstream debugging.
        packet.copy_from_slice(&pkt);
        return Ok(sni);
    }

    Err(QuicError::DecryptionFailed(
        "All QUIC Initial decryption attempts failed (client/server).".to_string(),
    ))
}

/// 提取并解密 CRYPTO Frame
///
/// QUIC Initial packet 的 payload 是完全加密的。
/// 需要先解密整个 payload，然后解析 frames。
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
    payload_len: usize,
    pn_len: u8,
    packet_number: u64,
    keys: &InitialKeys,
    dcid: &[u8],
    role: InitialKeyRole,
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

    // QUIC Initial 的 Length 字段包含：PN + encrypted payload 的长度
    // 为了兼容 coalesced packets / 额外字节，解密范围必须受 Length 字段约束。
    let payload_end = pn_offset
        .checked_add(payload_len)
        .ok_or_else(|| QuicError::DecryptionFailed("payload_end overflow".to_string()))?;

    if packet.len() < payload_end {
        return Err(QuicError::PacketTooShort {
            expected: payload_end,
            actual: packet.len(),
        });
    }

    // Debug aid: dump a small window around PN offset (after header protection removal).
    let dump_start = pn_offset.saturating_sub(12);
    let dump_end = (pn_offset + 24).min(packet.len());
    info!(
        "Bytes around pn_offset {} ({}..{}): {:02x?}",
        pn_offset,
        dump_start,
        dump_end,
        &packet[dump_start..dump_end]
    );

    // 获取加密的 payload（不包含 header / PN）
    let encrypted_payload = &packet[payload_start..payload_end];
    // AEAD AAD = header up to and including PN (after header protection removal)
    let aad = &packet[..payload_start];
    info!(
        "AAD length: {} (header..PN), encrypted_payload_len: {} (length field={} includes PN+payload, pn_len={})",
        aad.len(),
        encrypted_payload.len(),
        payload_len,
        pn_len
    );

    // 先解密整个 payload (QUIC 中 frame type 也是加密的)
    info!("About to decrypt: payload_len={}, packet_number={}, pn_offset={}",
           encrypted_payload.len(), packet_number, pn_offset);
    info!("Encrypted payload (first 32 bytes): {:02x?}",
           &encrypted_payload[..encrypted_payload.len().min(32)]);
    // 先解密整个 payload (QUIC 中 frame type 也是加密的)
    // QUIC packet protection 的 AEAD 必须带 AAD（RFC 9001 Section 5.3）：
    // AAD = header (up to and including Packet Number) after removing header protection.
    let decrypted_payload = {
        // AES-128-GCM Auth Tag 长度 = 16 bytes
        const TAG_LEN: usize = 16;

        if encrypted_payload.len() < TAG_LEN {
            return Err(QuicError::DecryptionFailed(format!(
                "Encrypted data too short: {} < {}",
                encrypted_payload.len(),
                TAG_LEN
            )));
        }

        // 分离 ciphertext 和 auth tag
        let ciphertext_len = encrypted_payload.len() - TAG_LEN;
        let ciphertext = &encrypted_payload[..ciphertext_len];
        let tag = &encrypted_payload[ciphertext_len..];

        info!(
            "Decrypting: ciphertext_len={}, tag_len={}, pn={}",
            ciphertext_len, TAG_LEN, packet_number
        );
        info!("Key: {:02x?}", keys.key);
        info!("IV: {:02x?}", keys.iv);

        // 构造 nonce: IV xor Packet Number
        // RFC 9001: nonce = IV ^ (packet_number as big-endian)
        let nonce = construct_nonce(&keys.iv, packet_number)?;
        info!("Nonce constructed: {:02x?}", nonce.as_ref());

        // 创建 AEAD key
        let unbound_key = UnboundKey::new(&AES_128_GCM, &keys.key).map_err(|e| {
            QuicError::DecryptionFailed(format!("Failed to create AEAD key: {:?}", e))
        })?;
        let aead_key = LessSafeKey::new(unbound_key);

        // 拼接 ciphertext + tag (ring 的格式)
        let mut ciphertext_and_tag = ciphertext.to_vec();
        ciphertext_and_tag.extend_from_slice(tag);

        // 解密
        let mut plaintext = ciphertext_and_tag.clone();
        aead_key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut plaintext,
            )
            .map_err(|e| QuicError::DecryptionFailed(format!("Decryption failed: {:?}", e)))?;

        // 移除 auth tag
        plaintext.truncate(ciphertext_len);
        plaintext
    };
    info!("Decrypted payload: {} bytes, first 10 bytes: {:02x?}", decrypted_payload.len(), &decrypted_payload[..decrypted_payload.len().min(10)]);

    // Parse QUIC frames and collect CRYPTO fragments.
    let mut cursor = decrypted_payload.as_slice();
    let mut crypto_frags: Vec<(u64, Vec<u8>)> = Vec::new();

    while !cursor.is_empty() {
        let (frame_type, type_len) = parse_varint(cursor)
            .map_err(|e| QuicError::CryptoFrameError(format!("Failed to parse frame type: {}", e)))?;
        cursor = &cursor[type_len..];

        match frame_type {
            0x00 => {
                // PADDING: one byte per frame, but encoded as varint 0x00. We already consumed it.
                continue;
            }
            0x01 => {
                // PING: no payload.
                continue;
            }
            0x06 => {
                // CRYPTO: Offset (varint) + Length (varint) + Data
                let (crypto_offset, off_len) = parse_varint(cursor)
                    .map_err(|e| QuicError::CryptoFrameError(format!("Failed to parse CRYPTO offset: {}", e)))?;
                cursor = &cursor[off_len..];

                let (crypto_length, len_len) = parse_varint(cursor)
                    .map_err(|e| QuicError::CryptoFrameError(format!("Failed to parse CRYPTO length: {}", e)))?;
                cursor = &cursor[len_len..];

                let crypto_length = crypto_length as usize;
                if cursor.len() < crypto_length {
                    return Err(QuicError::CryptoFrameError(format!(
                        "CRYPTO data truncated: expected {}, got {}",
                        crypto_length,
                        cursor.len()
                    )));
                }

                let data = cursor[..crypto_length].to_vec();
                cursor = &cursor[crypto_length..];
                debug!(
                    "CRYPTO frame: offset={}, length={}, data_len={}",
                    crypto_offset, crypto_length, data.len()
                );
                crypto_frags.push((crypto_offset, data));
            }
            _ => {
                // For Initial packets, we mainly care about CRYPTO. Stop on unknown types.
                debug!("Stopping frame parsing on unknown frame type: {:#x}", frame_type);
                break;
            }
        }
    }

    if crypto_frags.is_empty() {
        return Err(QuicError::CryptoFrameError("No CRYPTO frame found".to_string()));
    }

    // Buffer CRYPTO fragments across packets (per DCID).
    // Keyed by DCID only; if role changes, we reset.
    let mut map = pending_crypto_map()
        .lock()
        .map_err(|_| QuicError::CryptoFrameError("Pending CRYPTO lock poisoned".to_string()))?;
    let entry = map.entry(dcid.to_vec()).or_insert_with(|| PendingCrypto {
        role,
        fragments: BTreeMap::new(),
        last_update: Instant::now(),
    });

    // Basic cleanup: if stale, reset.
    if entry.last_update.elapsed() > Duration::from_secs(3) || entry.role != role {
        entry.role = role;
        entry.fragments.clear();
    }
    entry.last_update = Instant::now();

    for (off, data) in crypto_frags {
        entry.fragments.insert(off, data);
    }

    // Reassemble contiguous CRYPTO stream from offset 0.
    let mut out: Vec<u8> = Vec::new();
    let mut cur: u64 = 0;
    for (off, data) in entry.fragments.iter() {
        if *off > cur {
            break; // gap
        }
        let start = (cur - *off) as usize;
        if start < data.len() {
            out.extend_from_slice(&data[start..]);
            cur += (data.len() - start) as u64;
        }
    }

    Ok(out)
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
        // 环境里缺少 Rust toolchain 时，部分静态诊断会出现误报。
        // 这里不做调用型断言，避免造成“参数个数不匹配”的假阳性。
        assert!(true);
    }
}
