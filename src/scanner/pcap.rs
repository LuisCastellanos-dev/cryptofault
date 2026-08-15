//! PCAP scanner — offline file and live capture modes
//!
//! Copyright (C) 2026 Luis Fidel Castellanos Diaz
//! A Vector Telemetry Research (VTR) open-source tool
//! Licensed under Apache-2.0

use crate::detectors::{plaintext, tls};
use crate::schema::{Finding, Source};
use anyhow::Result;
use std::path::Path;

/// Compute SHA-256 of a file — chain of custody
pub fn sha256_file(path: &str) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(sha256_bytes(&buf))
}

pub fn sha256_bytes(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // NOTE: DefaultHasher is NOT cryptographic.
    // Replace with sha2::Sha256 when sha2 crate is added.
    // Tracked as technical debt — v0.3.0.
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    format!("{:016x}[placeholder-sha2-pending]", h.finish())
}

/// Build a Source struct for a PCAP file
pub fn pcap_source(path: &str) -> Result<Source> {
    let sha256 = sha256_file(path)?;
    Ok(Source {
        source_type: "pcap".to_string(),
        path: path.to_string(),
        sha256,
    })
}

/// Scan a PCAP file offline — returns all findings
pub fn scan_file(path: &str) -> Result<(Source, Vec<Finding>)> {
    let source = pcap_source(path)?;
    let mut findings = Vec::new();
    let mut finding_id = 1usize;

    let mut cap = pcap::Capture::from_file(path)?;

    while let Ok(packet) = cap.next_packet() {
        let data = packet.data;

        // Extract TCP payload — skip Ethernet(14) + IP(20) + TCP(20) headers
        // This is a best-effort heuristic for standard frames
        if data.len() > 54 {
            let payload = &data[54..];

            // TLS detector
            if let Some(weakness) = tls::detect_weak_tls(payload) {
                let (src, dst, port) = extract_ip_port(data);
                findings.push(tls::build_finding(
                    finding_id,
                    &weakness,
                    src,
                    dst,
                    port,
                ));
                finding_id += 1;
            }

            // Plaintext OT detector — check destination port
            if let Some(port) = extract_dst_port(data) {
                if let Some(ot) = plaintext::is_ot_port(port) {
                    // Only flag if no TLS detected on this payload
                    if tls::detect_weak_tls(payload).is_none() && !looks_encrypted(payload) {
                        let (src, dst, _) = extract_ip_port(data);
                        let session = plaintext::PlaintextSession {
                            src: src.unwrap_or_else(|| "unknown".to_string()),
                            dst: dst.unwrap_or_else(|| "unknown".to_string()),
                            port,
                            protocol: ot.protocol.to_string(),
                            reference: ot.reference.to_string(),
                        };
                        findings.push(plaintext::build_finding(finding_id, &session));
                        finding_id += 1;
                    }
                }
            }
        }
    }

    Ok((source, findings))
}

/// Scan live from a network interface
pub fn scan_live(interface: &str, count: i32) -> Result<(Source, Vec<Finding>)> {
    let source = Source {
        source_type: "live".to_string(),
        path: interface.to_string(),
        sha256: "live-capture-no-hash".to_string(),
    };

    let mut findings = Vec::new();
    let mut finding_id = 1usize;

    let mut cap = pcap::Capture::from_device(interface)?
        .promisc(true)
        .snaplen(65535)
        .open()?;

    let mut captured = 0;
    while captured < count {
        match cap.next_packet() {
            Ok(packet) => {
                let data = packet.data;
                if data.len() > 54 {
                    let payload = &data[54..];
                    if let Some(weakness) = tls::detect_weak_tls(payload) {
                        let (src, dst, port) = extract_ip_port(data);
                        findings.push(tls::build_finding(
                            finding_id,
                            &weakness,
                            src,
                            dst,
                            port,
                        ));
                        finding_id += 1;
                    }
                    if let Some(port) = extract_dst_port(data) {
                        if let Some(ot) = plaintext::is_ot_port(port) {
                            if !looks_encrypted(payload) {
                                let (src, dst, _) = extract_ip_port(data);
                                let session = plaintext::PlaintextSession {
                                    src: src.unwrap_or_else(|| "unknown".to_string()),
                                    dst: dst.unwrap_or_else(|| "unknown".to_string()),
                                    port,
                                    protocol: ot.protocol.to_string(),
                                    reference: ot.reference.to_string(),
                                };
                                findings.push(plaintext::build_finding(finding_id, &session));
                                finding_id += 1;
                            }
                        }
                    }
                }
                captured += 1;
            }
            Err(_) => break,
        }
    }

    Ok((source, findings))
}

/// Heuristic: first byte of payload in known encrypted range
fn looks_encrypted(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    // TLS record types: 0x14-0x17
    matches!(payload[0], 0x14..=0x17)
}

/// Extract src IP, dst IP, dst port from raw Ethernet frame
/// Returns (src_ip, dst_ip, dst_port)
fn extract_ip_port(data: &[u8]) -> (Option<String>, Option<String>, Option<u16>) {
    if data.len() < 34 {
        return (None, None, None);
    }
    // Ethernet header: 14 bytes
    // IP src: bytes 26-29, dst: bytes 30-33
    let src = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
    let dst = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);
    let port = extract_dst_port(data);
    (Some(src), Some(dst), port)
}

/// Extract destination TCP/UDP port from raw Ethernet frame
fn extract_dst_port(data: &[u8]) -> Option<u16> {
    // Ethernet(14) + IP(20) = 34, dst port at bytes 36-37
    if data.len() < 38 {
        return None;
    }
    Some(u16::from_be_bytes([data[36], data[37]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_bytes_returns_string() {
        let result = sha256_bytes(b"test");
        assert!(!result.is_empty());
    }

    #[test]
    fn sha256_bytes_differs_for_different_input() {
        let a = sha256_bytes(b"hello");
        let b = sha256_bytes(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn looks_encrypted_tls_record() {
        assert!(looks_encrypted(&[0x16, 0x03, 0x01]));
        assert!(looks_encrypted(&[0x17, 0x03, 0x03]));
    }

    #[test]
    fn looks_encrypted_plaintext() {
        assert!(!looks_encrypted(&[0x00, 0x01, 0x00]));
        assert!(!looks_encrypted(&[]));
    }

    #[test]
    fn extract_dst_port_short_frame() {
        let short = vec![0u8; 10];
        assert!(extract_dst_port(&short).is_none());
    }

    #[test]
    fn extract_ip_port_short_frame() {
        let short = vec![0u8; 10];
        let (src, dst, port) = extract_ip_port(&short);
        assert!(src.is_none());
        assert!(dst.is_none());
        assert!(port.is_none());
    }
}
