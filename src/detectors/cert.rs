//! X.509 certificate weakness detector
//!
//! Detects: RSA keys < 2048 bits, MD5/SHA-1 signatures, expired/expiring certs.
//! References: NIST SP 800-131A Rev 2, RFC 3279, RFC 4055

use crate::schema::{Category, Finding, Severity};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

const MIN_RSA_BITS: u32 = 2048;
const EXPIRY_WARN_DAYS: i64 = 90;

#[derive(Debug)]
pub enum CertWeakness {
    WeakRsaKey { bits: u32, cn: String },
    WeakSignature { algorithm: String, cn: String },
    ExpiringCert { cn: String, days_remaining: i64 },
    ExpiredCert { cn: String },
}

pub fn analyze_cert(der: &[u8], source_path: &str) -> Vec<CertWeakness> {
    let mut weaknesses = Vec::new();
    let (_, cert) = match X509Certificate::from_der(der) {
        Ok(c) => c,
        Err(_) => return weaknesses,
    };
    let cn = extract_cn(&cert);

    // Check signature algorithm
    let sig_alg = cert.signature_algorithm.algorithm.to_string();
    if is_weak_signature(&sig_alg) {
        weaknesses.push(CertWeakness::WeakSignature {
            algorithm: sig_alg_display(&sig_alg),
            cn: cn.clone(),
        });
    }

    // Check RSA key size
    if let Ok(parsed_key) = cert.public_key().parsed() {
        if let PublicKey::RSA(rsa) = parsed_key {
            let bits = (rsa.modulus.len() as u32).saturating_sub(1) * 8;
            if bits < MIN_RSA_BITS {
                weaknesses.push(CertWeakness::WeakRsaKey {
                    bits,
                    cn: cn.clone(),
                });
            }
        }
    }

    // Check expiry using chrono
    let not_after_ts = cert.validity().not_after.timestamp();
    let now_ts = chrono::Utc::now().timestamp();
    let diff_days = (not_after_ts - now_ts) / 86400;
    if diff_days < 0 {
        weaknesses.push(CertWeakness::ExpiredCert { cn: cn.clone() });
    } else if diff_days < EXPIRY_WARN_DAYS {
        weaknesses.push(CertWeakness::ExpiringCert {
            cn: cn.clone(),
            days_remaining: diff_days,
        });
    }

    let _ = source_path;
    weaknesses
}

fn extract_cn(cert: &X509Certificate) -> String {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

fn is_weak_signature(oid: &str) -> bool {
    matches!(
        oid,
        "1.2.840.113549.1.1.4"
        | "1.2.840.113549.1.1.5"
        | "1.2.840.10040.4.3"
    )
}

fn sig_alg_display(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "MD5withRSA".to_string(),
        "1.2.840.113549.1.1.5" => "SHA1withRSA".to_string(),
        "1.2.840.10040.4.3" => "DSAwithSHA1".to_string(),
        other => other.to_string(),
    }
}

pub fn build_findings(weaknesses: &[CertWeakness], start_id: usize, source_path: &str) -> Vec<Finding> {
    weaknesses
        .iter()
        .enumerate()
        .map(|(i, w)| build_finding(start_id + i, w, source_path))
        .collect()
}

fn build_finding(id: usize, weakness: &CertWeakness, source_path: &str) -> Finding {
    match weakness {
        CertWeakness::WeakRsaKey { bits, cn } => Finding {
            id: format!("CF-{:03}", id),
            severity: Severity::High,
            category: Category::WeakKey,
            description: format!("RSA key {} bits — below minimum 2048 bits (NIST SP 800-131A)", bits),
            src: Some(source_path.to_string()),
            dst: None,
            port: None,
            evidence: format!("RSA {}bit — CN={}", bits, cn),
            reference: "NIST SP 800-131A Rev 2".to_string(),
        },
        CertWeakness::WeakSignature { algorithm, cn } => Finding {
            id: format!("CF-{:03}", id),
            severity: Severity::High,
            category: Category::WeakSignature,
            description: format!("{} signature algorithm — deprecated", algorithm),
            src: Some(source_path.to_string()),
            dst: None,
            port: None,
            evidence: format!("signatureAlgorithm={} CN={}", algorithm, cn),
            reference: "RFC 3279, NIST SP 800-131A Rev 2".to_string(),
        },
        CertWeakness::ExpiringCert { cn, days_remaining } => Finding {
            id: format!("CF-{:03}", id),
            severity: Severity::Medium,
            category: Category::CertificateExpiry,
            description: format!("Certificate expiring in {} days", days_remaining),
            src: Some(source_path.to_string()),
            dst: None,
            port: None,
            evidence: format!("CN={} expires in {}d", cn, days_remaining),
            reference: "IEC 62443-3-3 SR 1.9".to_string(),
        },
        CertWeakness::ExpiredCert { cn } => Finding {
            id: format!("CF-{:03}", id),
            severity: Severity::High,
            category: Category::CertificateExpiry,
            description: "Certificate has expired".to_string(),
            src: Some(source_path.to_string()),
            dst: None,
            port: None,
            evidence: format!("CN={} — EXPIRED", cn),
            reference: "IEC 62443-3-3 SR 1.9".to_string(),
        },
    }
}
