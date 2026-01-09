use anyhow::{Result, bail};
use std::fmt;

/// TLS SNI 提取错误类型
#[derive(Debug)]
#[allow(dead_code)]
pub enum SniError {
    DataTooShort,
    NotHandshake,
    NotClientHello,
    InvalidExtension,
    InvalidHostname,
    SniNotFound,
}

impl fmt::Display for SniError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SniError::DataTooShort => write!(f, "Data too short"),
            SniError::NotHandshake => write!(f, "Not Handshake"),
            SniError::NotClientHello => write!(f, "Not ClientHello"),
            SniError::InvalidExtension => write!(f, "Invalid extension"),
            SniError::InvalidHostname => write!(f, "Invalid hostname"),
            SniError::SniNotFound => write!(f, "SNI not found"),
        }
    }
}

impl std::error::Error for SniError {}

pub fn extract_sni(data: &[u8]) -> Result<Option<String>> {
    // 支持两种输入：
    // 1) 传统 TCP+TLS：TLS record layer（开头 0x16）
    // 2) QUIC CRYPTO stream：直接携带 TLS Handshake message（开头 0x01）
    let payload: &[u8] = if data.first().copied() == Some(0x16) {
        // TLS record: [type(1)=0x16][version(2)][len(2)][handshake...]
        if data.len() < 5 {
            bail!(SniError::DataTooShort);
        }
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + length {
            bail!(SniError::DataTooShort);
        }
        &data[5..5 + length]
    } else {
        // QUIC CRYPTO: raw TLS handshake bytes
        data
    };

    if payload.len() < 4 {
        bail!(SniError::DataTooShort);
    }

    // TLS Handshake: [msg_type(1)][len(3)][body...]
    let handshake_type = payload[0];
    if handshake_type != 0x01 {
        // QUIC 场景下这里通常就是 0x01；如果不是，说明我们拿到的不是 ClientHello 起始处
        bail!(SniError::NotHandshake);
    }

    let hs_len = ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | (payload[3] as usize);
    if payload.len() < 4 + hs_len {
        bail!(SniError::DataTooShort);
    }

    let client_hello = &payload[4..4 + hs_len];

    if client_hello.len() < 38 {
        bail!(SniError::DataTooShort);
    }

    let mut offset = 34;

    if offset >= client_hello.len() {
        return Ok(None);
    }

    let session_id_length = client_hello[offset] as usize;
    offset += 1 + session_id_length;

    if offset >= client_hello.len() {
        return Ok(None);
    }

    let cipher_suites_length = u16::from_be_bytes([
        client_hello[offset],
        client_hello[offset + 1],
    ]) as usize;
    offset += 2 + cipher_suites_length;

    if offset >= client_hello.len() {
        return Ok(None);
    }

    let compression_length = client_hello[offset] as usize;
    offset += 1 + compression_length;

    if offset + 2 > client_hello.len() {
        return Ok(None);
    }

    let extensions_length = u16::from_be_bytes([
        client_hello[offset],
        client_hello[offset + 1],
    ]) as usize;
    offset += 2;

    if offset + extensions_length > client_hello.len() {
        bail!(SniError::InvalidExtension);
    }

    let ext_end = offset + extensions_length;
    let mut ext_count = 0;

    while offset < ext_end {
        if offset + 4 > client_hello.len() {
            break;
        }

        let ext_type = u16::from_be_bytes([
            client_hello[offset],
            client_hello[offset + 1],
        ]);
        let ext_length = u16::from_be_bytes([
            client_hello[offset + 2],
            client_hello[offset + 3],
        ]) as usize;
        offset += 4;

        ext_count += 1;

        if offset + ext_length > client_hello.len() {
            bail!(SniError::InvalidExtension);
        }

        if ext_type == 0x0000 {
            tracing::debug!("Found SNI extension (extension #{})", ext_count);
            return parse_sni_extension(&client_hello[offset..offset + ext_length]).map(Some);
        }

        offset += ext_length;
    }

    tracing::debug!("SNI extension not found (checked {} extensions)", ext_count);
    Ok(None)
}

fn parse_sni_extension(data: &[u8]) -> Result<String> {
    if data.len() < 2 {
        bail!(SniError::InvalidExtension);
    }

    let list_length = u16::from_be_bytes([data[0], data[1]]) as usize;

    if data.len() < 2 + list_length {
        bail!(SniError::InvalidExtension);
    }

    let mut offset = 2;
    if offset + 3 > data.len() {
        bail!(SniError::InvalidExtension);
    }

    let name_type = data[offset];
    offset += 1;

    if name_type != 0x00 {
        bail!(SniError::InvalidHostname);
    }

    let name_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if offset + name_length > data.len() {
        bail!(SniError::InvalidExtension);
    }

    let hostname_bytes = &data[offset..offset + name_length];

    let hostname = String::from_utf8(hostname_bytes.to_vec())
        .map_err(|_| SniError::InvalidHostname)?;

    if !is_valid_hostname(&hostname) {
        bail!(SniError::InvalidHostname);
    }

    tracing::debug!("Extracted SNI hostname: {}", hostname);
    Ok(hostname)
}

fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    hostname.chars().all(|c| {
        c.is_alphanumeric() || c == '.' || c == '-'
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sni_simple() {
        // 使用程序生成正确的 TLS ClientHello
        let mut data = Vec::new();

        // TLS Record Header
        data.extend_from_slice(&[0x16, 0x03, 0x01]); // Type, Version
        let record_len_pos = data.len();
        data.push(0); data.push(0); // Length placeholder

        // Handshake Message
        data.push(0x01); // Type: ClientHello
        let hs_len_pos = data.len();
        data.push(0); data.push(0); data.push(0); // Length placeholder

        // ClientHello Body
        data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Random (32 bytes)
        for i in 0u8..32 {
            data.push(i);
        }

        // Session ID
        data.push(0x00); // Length: 0

        // Cipher Suites
        data.extend_from_slice(&[0x00, 0x02]); // Length: 2
        data.extend_from_slice(&[0x00, 0x2F]); // Cipher

        // Compression
        data.push(0x01); // Length: 1
        data.push(0x00); // Null

        // Extensions
        let ext_start = data.len();
        data.push(0); data.push(0); // Length placeholder

        // SNI Extension
        data.extend_from_slice(&[0x00, 0x00]); // Type: server_name

        let sni_ext_start = data.len();
        data.push(0); data.push(0); // Length placeholder

        // Server Name List
        let sni_list_start = data.len();
        data.push(0); data.push(0); // Length placeholder

        // Server Name
        data.push(0x00); // Type: hostname
        data.extend_from_slice(&[0x00, 0x04]); // Name length: 4
        data.extend_from_slice(b"test");

        // Update Server Name List Length
        let sni_list_len = data.len() - sni_list_start - 2;
        data[sni_list_start] = (sni_list_len >> 8) as u8;
        data[sni_list_start + 1] = (sni_list_len & 0xFF) as u8;

        // Update SNI Extension Length
        let sni_ext_len = data.len() - sni_ext_start - 2;
        data[sni_ext_start] = (sni_ext_len >> 8) as u8;
        data[sni_ext_start + 1] = (sni_ext_len & 0xFF) as u8;

        // Update Extensions Length
        let ext_len = data.len() - ext_start - 2;
        data[ext_start] = (ext_len >> 8) as u8;
        data[ext_start + 1] = (ext_len & 0xFF) as u8;

        // Update Handshake Length
        let hs_len = data.len() - hs_len_pos - 3;
        data[hs_len_pos] = (hs_len >> 16) as u8;
        data[hs_len_pos + 1] = ((hs_len >> 8) & 0xFF) as u8;
        data[hs_len_pos + 2] = (hs_len & 0xFF) as u8;

        // Update TLS Record Length
        let record_len = data.len() - record_len_pos - 2;
        data[record_len_pos] = (record_len >> 8) as u8;
        data[record_len_pos + 1] = (record_len & 0xFF) as u8;

        // Verify
        assert_eq!(data[0], 0x16);
        assert_eq!(data[5], 0x01);

        let result = extract_sni(&data);
        assert!(result.is_ok(), "extract_sni failed: {:?}", result);
        assert_eq!(result.unwrap(), Some("test".to_string()));
    }

    #[test]
    fn test_no_sni() {
        let mut data = Vec::new();

        // TLS Record
        data.extend_from_slice(&[0x16, 0x03, 0x01]);
        let rec_pos = data.len();
        data.push(0); data.push(0);

        // Handshake
        data.push(0x01);
        let hs_pos = data.len();
        data.push(0); data.push(0); data.push(0);

        // ClientHello
        data.extend_from_slice(&[0x03, 0x03]);
        for i in 0u8..32 { data.push(i); }
        data.push(0x00);
        data.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]);
        data.extend_from_slice(&[0x01, 0x00]);
        data.extend_from_slice(&[0x00, 0x00]); // No extensions

        // Update lengths
        let hs_len = data.len() - hs_pos - 3;
        data[hs_pos] = (hs_len >> 16) as u8;
        data[hs_pos + 1] = ((hs_len >> 8) & 0xFF) as u8;
        data[hs_pos + 2] = (hs_len & 0xFF) as u8;

        let rec_len = data.len() - rec_pos - 2;
        data[rec_pos] = (rec_len >> 8) as u8;
        data[rec_pos + 1] = (rec_len & 0xFF) as u8;

        let result = extract_sni(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_data_too_short() {
        let data = [0x16, 0x03, 0x01];
        assert!(extract_sni(&data).is_err());
    }

    #[test]
    fn test_hostname_validation() {
        assert!(is_valid_hostname("www.google.com"));
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("test"));
        assert!(!is_valid_hostname(""));
        assert!(is_valid_hostname("test中文.com")); // 简化验证,允许中文
    }
}
