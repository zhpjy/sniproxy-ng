//! QUIC SNI 提取错误类型
use thiserror::Error;

/// QUIC SNI 提取过程中可能出现的错误
#[derive(Error, Debug)]
pub enum QuicError {
    /// 数据包太短，无法解析
    #[error("Packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    /// 不是 QUIC Initial Packet
    #[error("Not a QUIC Initial packet (first byte: {0:#04x})")]
    NotInitialPacket(u8),

    /// DCID (Destination Connection ID) 无效
    #[error("Invalid DCID: {0}")]
    InvalidDcid(String),

    /// 密钥派生失败
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Header Protection 移除失败
    #[error("Header protection removal failed: {0}")]
    HeaderProtectionFailed(String),

    /// 解密失败
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Packet Number 解码失败
    #[error("Packet number decoding failed: {0}")]
    PacketNumberError(String),

    /// CRYPTO Frame 解析失败
    #[error("CRYPTO frame parsing failed: {0}")]
    CryptoFrameError(String),

    /// TLS SNI 解析失败
    #[error("TLS SNI parsing failed: {0}")]
    TlsError(String),

    /// VarInt 解码失败
    #[error("VarInt decoding failed: {0}")]
    VarIntError(String),

    /// 不支持的 QUIC 版本
    #[error("Unsupported QUIC version: {:#010x}", version)]
    UnsupportedVersion { version: u32 },

    /// 未找到 SNI
    #[error("No SNI found in packet")]
    NoSniFound,

    /// 其他错误
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, QuicError>;
