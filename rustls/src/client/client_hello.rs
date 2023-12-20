use crate::msgs::base::Payload;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{ClientExtension, UnknownExtension};
use crate::{CipherSuite, NamedGroup, ProtocolVersion};
use core::fmt;
use std::prelude::rust_2015::Vec;
use std::vec;

/// Override the original construction in rustls.
pub trait ClientHelloOverride: Send + Sync + fmt::Debug {
    /// Override cipher suites
    fn override_cipher_suites(&self, cipher_suites: Vec<CipherSuite>) -> Vec<CipherSuite> {
        cipher_suites
    }

    /// override TLS extensions
    fn override_extensions(&self, extensions: Vec<ClientExtension>) -> Vec<ClientExtension> {
        extensions
    }
}

fn grease_value() -> u16 {
    let v = (crate::rand::random_u32(crate::crypto::ring::default_provider().secure_random)
        .unwrap_or(0)
        % 16) as u16;
    (v << 12) | (v << 4) | 0xa0a
}

impl CipherSuite {
    /// Generate a Grease
    pub fn grease() -> Self {
        Self::Unknown(grease_value())
    }
}

impl NamedGroup {
    /// Generate a Grease
    pub fn grease() -> Self {
        Self::Unknown(grease_value())
    }
}

impl ProtocolVersion {
    /// Generate a Grease
    pub fn grease() -> Self {
        Self::Unknown(grease_value())
    }
}

impl ClientExtension {
    /// Generate a Grease
    pub fn grease() -> Self {
        Self::Unknown(UnknownExtension {
            typ: ExtensionType::Unknown(grease_value()),
            payload: Payload::empty(),
        })
    }

    /// Generate a extended msr
    pub fn extended_master_secret_request() -> Self {
        Self::Unknown(UnknownExtension {
            typ: ExtensionType::ExtendedMasterSecret,
            payload: Payload::empty(),
        })
    }

    /// Generate a renegotiation info
    pub fn renegotiation_info() -> Self {
        Self::Unknown(UnknownExtension {
            typ: ExtensionType::RenegotiationInfo,
            payload: Payload::new(vec![0]),
        })
    }

    /// Generate a status request
    pub fn status_request() -> Self {
        Self::Unknown(UnknownExtension {
            typ: ExtensionType::StatusRequest,
            payload: Payload::new(vec![1, 0, 0, 0, 0]),
        })
    }

    /// Generate a SCT
    pub fn signed_certificate_timestamp() -> Self {
        Self::Unknown(UnknownExtension {
            typ: ExtensionType::SCT,
            payload: Payload::empty(),
        })
    }

    /// compress_certificate, RFC 8879
    pub fn compress_certificate(list: &[CompressCertificateOptions]) -> Self {
        let mut payload = Vec::with_capacity(list.len() + 2);
        payload.extend_from_slice(&[list.len() as u8, 0x00]);
        list.iter().for_each(|op| {
            payload.push(match *op {
                CompressCertificateOptions::Zlib => 0x1,
                CompressCertificateOptions::Brotli => 0x2,
                CompressCertificateOptions::Zstd => 0x3,
            })
        });
        Self::Unknown(UnknownExtension {
            typ: ExtensionType::Unknown(27),
            payload: Payload::new(payload),
        })
    }

    /// Generate a SCT
    pub fn padding(payload: impl Into<Vec<u8>>) -> Self {
        Self::Unknown(UnknownExtension {
            typ: ExtensionType::Padding,
            payload: Payload::new(payload),
        })
    }

    /// Fallback option
    pub fn unknown(typ: ExtensionType, payload: impl Into<Vec<u8>>) -> Self {
        Self::Unknown(UnknownExtension {
            typ,
            payload: Payload::new(payload),
        })
    }
}

/// RFC 8879
#[derive(Debug, Copy, Clone)]
pub enum CompressCertificateOptions {
    /// zlib(0x01)
    Zlib,
    /// brotli(0x02)
    Brotli,
    /// zstd(0x03)
    Zstd,
}
