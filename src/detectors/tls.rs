//! TLS version weakness detector
//!
//! Detects TLS 1.0 and TLS 1.1 ClientHello handshakes in PCAP data.
//! References: RFC 8996 (deprecating TLS 1.0/1.1)

use crate::schema::{Category, Finding, Severity};

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_1_0: (u8, u8) = (0x03, 0x01);
const TLS_1_1: (u8, u8) = (0x03, 0x02);

#[derive(Debug)]
pub struct TlsWeakness {
    pub version: String,
    pub version_bytes: String,
}

pub fn detect_weak_tls(payload: &[u8]) -> Option<TlsWeakness> {
    if payload.len() < 5 {
        return None;
    }
    if payload[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    let major = payload[1];
    let minor = payload[2];
    let record_version = (major, minor);
    if record_version != TLS_1_0 && record_version != TLS_1_1 {
        return None;
    }
    if payload.len() < 6 || payload[5] != TLS_HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let (version_str, hex) = match record_version {
        TLS_1_0 => ("TLS 1.0", "0x0301"),
        TLS_1_1 => ("TLS 1.1", "0x0302"),
        _ => unreachable!(),
    };
    Some(TlsWeakness {
        version: version_str.to_string(),
        version_bytes: hex.to_string(),
    })
}

pub fn build_finding(
    id: usize,
    weakness: &TlsWeakness,
    src: Option<String>,
    dst: Option<String>,
    port: Option<u16>,
) -> Finding {
    Finding {
        id: format!("CF-{:03}", id),
        severity: Severity::High,
        category: Category::TlsVersion,
        description: format!(
            "{} ClientHello detected — deprecated per RFC 8996",
            weakness.version
        ),
        src,
        dst,
        port,
        evidence: format!("ClientHello version={}", weakness.version_bytes),
        reference: "RFC 8996".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client_hello(major: u8, minor: u8) -> Vec<u8> {
        vec![0x16, major, minor, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c]
    }

    #[test]
    fn detects_tls10() {
        let payload = make_client_hello(0x03, 0x01);
        let result = detect_weak_tls(&payload);
        assert!(result.is_some());
        let w = result.unwrap();
        assert_eq!(w.version, "TLS 1.0");
        assert_eq!(w.version_bytes, "0x0301");
    }

    #[test]
    fn detects_tls11() {
        let payload = make_client_hello(0x03, 0x02);
        let result = detect_weak_tls(&payload);
        assert!(result.is_some());
        let w = result.unwrap();
        assert_eq!(w.version, "TLS 1.1");
    }

    #[test]
    fn ignores_tls12() {
        let payload = make_client_hello(0x03, 0x03);
        assert!(detect_weak_tls(&payload).is_none());
    }

    #[test]
    fn ignores_tls13() {
        let payload = make_client_hello(0x03, 0x04);
        assert!(detect_weak_tls(&payload).is_none());
    }

    #[test]
    fn ignores_non_handshake() {
        let payload = vec![0x17, 0x03, 0x01, 0x00, 0x10, 0x01];
        assert!(detect_weak_tls(&payload).is_none());
    }

    #[test]
    fn ignores_short_payload() {
        let payload = vec![0x16, 0x03];
        assert!(detect_weak_tls(&payload).is_none());
    }

    #[test]
    fn ignores_non_client_hello() {
        let payload = vec![0x16, 0x03, 0x01, 0x00, 0x10, 0x02];
        assert!(detect_weak_tls(&payload).is_none());
    }

    #[test]
    fn finding_has_correct_severity() {
        let w = TlsWeakness {
            version: "TLS 1.0".to_string(),
            version_bytes: "0x0301".to_string(),
        };
        let f = build_finding(1, &w, Some("10.0.0.5".to_string()), None, Some(443));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.id, "CF-001");
        assert_eq!(f.reference, "RFC 8996");
    }
}
