//! Output formatting — text and JSON
//!
//! Copyright (C) 2026 Luis Fidel Castellanos Diaz
//! A Vector Telemetry Research (VTR) open-source tool
//! Licensed under Apache-2.0

use crate::schema::{Report, Severity};

pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            _ => OutputFormat::Text,
        }
    }
}

pub fn render(report: &Report, format: &OutputFormat) {
    match format {
        OutputFormat::Json => render_json(report),
        OutputFormat::Text => render_text(report),
    }
}

fn render_json(report: &Report) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("error: failed to serialize report — {}", e),
    }
}

fn render_text(report: &Report) {
    println!("cryptofault {}", report.tool_version);
    println!("analysis_id : {}", report.analysis_id);
    println!("timestamp   : {}", report.timestamp);
    println!("source      : {} ({})", report.source.path, report.source.source_type);
    println!("sha256      : {}", report.source.sha256);
    println!();

    if report.findings.is_empty() {
        println!("[OK] No weaknesses detected.");
        return;
    }

    for f in &report.findings {
        let prefix = match f.severity {
            Severity::High   => "[HIGH]  ",
            Severity::Medium => "[MEDIUM]",
            Severity::Low    => "[LOW]   ",
            Severity::Info   => "[INFO]  ",
        };
        println!("{} {} — {}", prefix, f.id, f.description);
        if let Some(src) = &f.src {
            print!("         src: {}", src);
            if let Some(dst) = &f.dst {
                print!(" -> {}", dst);
            }
            if let Some(port) = f.port {
                print!(":{}", port);
            }
            println!();
        }
        println!("         evidence  : {}", f.evidence);
        println!("         reference : {}", f.reference);
        println!();
    }

    println!("--- summary ---");
    println!(
        "total: {}  HIGH: {}  MEDIUM: {}  LOW: {}  INFO: {}",
        report.summary.total_findings,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Category, Finding, Report, Severity, Source, Summary};

    fn make_report(findings: Vec<Finding>) -> Report {
        let summary = Summary::from_findings(&findings);
        Report {
            schema_version: "1.0".to_string(),
            tool: "cryptofault".to_string(),
            tool_version: "0.2.0".to_string(),
            analysis_id: "cf-test-00000000".to_string(),
            timestamp: "2026-08-15T00:00:00Z".to_string(),
            source: Source {
                source_type: "pcap".to_string(),
                path: "test.pcap".to_string(),
                sha256: "abc123".to_string(),
            },
            findings,
            summary,
        }
    }

    fn make_finding(severity: Severity) -> Finding {
        Finding {
            id: "CF-001".to_string(),
            severity,
            category: Category::TlsVersion,
            description: "TLS 1.0 ClientHello detected".to_string(),
            src: Some("10.0.0.1".to_string()),
            dst: Some("10.0.0.2".to_string()),
            port: Some(443),
            evidence: "ClientHello version=0x0301".to_string(),
            reference: "RFC 8996".to_string(),
        }
    }

    #[test]
    fn json_output_is_valid() {
        let report = make_report(vec![make_finding(Severity::High)]);
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("cryptofault"));
        assert!(json.contains("CF-001"));
        assert!(json.contains("RFC 8996"));
        assert!(json.contains("\"HIGH\""));
    }

    #[test]
    fn summary_counts_correctly() {
        let findings = vec![
            make_finding(Severity::High),
            make_finding(Severity::High),
            make_finding(Severity::Medium),
            make_finding(Severity::Info),
        ];
        let report = make_report(findings);
        assert_eq!(report.summary.total_findings, 4);
        assert_eq!(report.summary.high, 2);
        assert_eq!(report.summary.medium, 1);
        assert_eq!(report.summary.info, 1);
        assert_eq!(report.summary.low, 0);
    }

    #[test]
    fn empty_report_has_zero_findings() {
        let report = make_report(vec![]);
        assert_eq!(report.summary.total_findings, 0);
    }

    #[test]
    fn format_from_str_json() {
        assert!(matches!(OutputFormat::from_str("json"), OutputFormat::Json));
        assert!(matches!(OutputFormat::from_str("JSON"), OutputFormat::Json));
    }

    #[test]
    fn format_from_str_text_default() {
        assert!(matches!(OutputFormat::from_str("text"), OutputFormat::Text));
        assert!(matches!(OutputFormat::from_str("anything"), OutputFormat::Text));
    }
}
