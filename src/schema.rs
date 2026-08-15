//! cryptofault output schema — VTR interoperability contract
//!
//! Copyright (C) 2026 Luis Fidel Castellanos Diaz
//! A Vector Telemetry Research (VTR) open-source tool
//! Licensed under Apache-2.0

use serde::{Deserialize, Serialize};

/// Schema version — increment on breaking changes
pub const SCHEMA_VERSION: &str = "1.0";

/// Severity levels — aligned with IEC 62443-3-3 and NERC CIP-007-6
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
        }
    }
}

/// Detection category
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    TlsVersion,
    WeakKey,
    WeakSignature,
    PlaintextSession,
    CertificateExpiry,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::TlsVersion => write!(f, "tls_version"),
            Category::WeakKey => write!(f, "weak_key"),
            Category::WeakSignature => write!(f, "weak_signature"),
            Category::PlaintextSession => write!(f, "plaintext_session"),
            Category::CertificateExpiry => write!(f, "certificate_expiry"),
        }
    }
}

/// Individual finding — one detected weakness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding ID within this report (e.g. "CF-001")
    pub id: String,
    pub severity: Severity,
    pub category: Category,
    pub description: String,
    /// Source IP or file path.
    /// Convention: for tls_version/plaintext_session findings this is an IP address;
    /// for weak_key/weak_signature/certificate_expiry findings this is a file path.
    /// If a explicit src_kind field is needed in the future, add Option<String> with skip_serializing_if.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    /// Destination IP
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst: Option<String>,
    /// Port number if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Raw evidence string (protocol field, hex value, etc.)
    pub evidence: String,
    /// RFC, CVE, or standard reference
    pub reference: String,
}

/// Source of analysis input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    /// "pcap" or "cert"
    #[serde(rename = "type")]
    pub source_type: String,
    pub path: String,
    /// SHA-256 of input file — chain of custody
    pub sha256: String,
}

/// Summary counters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Summary {
    pub total_findings: usize,
    #[serde(rename = "HIGH")]
    pub high: usize,
    #[serde(rename = "MEDIUM")]
    pub medium: usize,
    #[serde(rename = "LOW")]
    pub low: usize,
    #[serde(rename = "INFO")]
    pub info: usize,
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Summary::default();
        s.total_findings = findings.len();
        for f in findings {
            match f.severity {
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
                Severity::Info => s.info += 1,
            }
        }
        s
    }
}

/// Root report — top-level JSON output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub tool: String,
    pub tool_version: String,
    /// Unique report ID — "cf-{date}-{uuid4_short}"
    pub analysis_id: String,
    /// ISO 8601 UTC timestamp
    pub timestamp: String,
    pub source: Source,
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

impl Report {
    pub fn new(source: Source, findings: Vec<Finding>) -> Self {
        let summary = Summary::from_findings(&findings);
        Report {
            schema_version: SCHEMA_VERSION.to_string(),
            tool: "cryptofault".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            analysis_id: Self::generate_id(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            source,
            findings,
            summary,
        }
    }

    fn generate_id() -> String {
        let date = chrono::Utc::now().format("%Y%m%d");
        let uid = uuid::Uuid::new_v4().to_string();
        let short = &uid[..8];
        format!("cf-{}-{}", date, short)
    }
}
