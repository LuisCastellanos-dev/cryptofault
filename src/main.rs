//! cryptofault — Legacy crypto weakness detector for OT/ICS environments.
//!
//! Copyright (C) 2026 Luis Fidel Castellanos Diaz
//! A Vector Telemetry Research (VTR) open-source tool
//! Licensed under Apache-2.0

mod detectors;
mod output;
mod scanner;
mod schema;

use clap::{Parser, Subcommand};
use output::{OutputFormat, render};
use schema::Report;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHOR: &str = "Luis Fidel Castellanos Diaz (@LuisCastellanos-dev)";
const PROJECT: &str = "A Vector Telemetry Research (VTR) open-source tool";
const WEBSITE: &str = "https://vectortelemetryresearch.com";

#[derive(Parser)]
#[command(
    name = "cryptofault",
    version = VERSION,
    about = "Legacy crypto weakness detector for OT/ICS environments",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a PCAP file or live interface for crypto weaknesses
    Scan {
        /// Path to PCAP file
        #[arg(long)]
        pcap: Option<String>,

        /// Network interface for live capture
        #[arg(long)]
        live: Option<String>,

        /// Number of packets to capture in live mode (default: 1000)
        #[arg(long, default_value = "1000")]
        count: i32,

        /// Path to X.509 certificate (PEM or DER)
        #[arg(long)]
        cert: Option<String>,

        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        format: String,
    },
}

fn print_attribution() {
    eprintln!("cryptofault {}", VERSION);
    eprintln!("Copyright (C) 2026 {}", AUTHOR);
    eprintln!("{}", PROJECT);
    eprintln!("{}", WEBSITE);
    eprintln!("Licensed under Apache-2.0");
    eprintln!();
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { pcap, live, count, cert, format } => {
            print_attribution();

            if pcap.is_none() && live.is_none() && cert.is_none() {
                eprintln!("error: provide at least one of --pcap, --live, or --cert");
                std::process::exit(1);
            }

            let fmt = OutputFormat::from_str(&format);
            let mut all_findings = Vec::new();
            let mut source = None;

            // PCAP file scan
            if let Some(ref path) = pcap {
                let (src, findings) = scanner::pcap::scan_file(path)?;
                source = Some(src);
                all_findings.extend(findings);
            }

            // Live capture scan
            if let Some(ref iface) = live {
                let (src, findings) = scanner::pcap::scan_live(iface, count)?;
                if source.is_none() {
                    source = Some(src);
                }
                all_findings.extend(findings);
            }

            // Certificate scan
            if let Some(ref path) = cert {
                let der = load_cert(path)?;
                let weaknesses = detectors::cert::analyze_cert(&der, path);
                let start_id = all_findings.len() + 1;
                let cert_findings = detectors::cert::build_findings(&weaknesses, start_id, path);
                if source.is_none() {
                    source = Some(schema::Source {
                        source_type: "cert".to_string(),
                        path: path.clone(),
                        sha256: scanner::pcap::sha256_file(path)?,
                    });
                }
                all_findings.extend(cert_findings);
            }

            let source = source.unwrap();
            let report = Report::new(source, all_findings);
            render(&report, &fmt);

            // Exit code 1 if any HIGH findings
            if report.summary.high > 0 {
                std::process::exit(1);
            }

            Ok(())
        }
    }
}

/// Load a certificate file — supports PEM and DER
fn load_cert(path: &str) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::fs::File::open(path)?.read_to_end(&mut buf)?;

    // Detect PEM by header
    if buf.starts_with(b"-----BEGIN") {
        // Strip PEM wrapper and decode base64
        let pem_str = std::str::from_utf8(&buf)?;
        let b64: String = pem_str
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        use std::io::Read as _;
        let decoded = base64_decode(&b64)?;
        return Ok(decoded);
    }

    Ok(buf)
}

fn base64_decode(input: &str) -> anyhow::Result<Vec<u8>> {
    // Minimal base64 decoder — replace with data-encoding crate in v0.3.0
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [0u8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let input: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b'=').collect();
    let mut out = Vec::new();
    for chunk in input.chunks(4) {
        if chunk.len() < 2 { break; }
        let b0 = table[chunk[0] as usize];
        let b1 = table[chunk[1] as usize];
        out.push((b0 << 2) | (b1 >> 4));
        if chunk.len() > 2 {
            let b2 = table[chunk[2] as usize];
            out.push((b1 << 4) | (b2 >> 2));
        }
        if chunk.len() > 3 { let b2 = table[chunk[2] as usize];
            let b3 = table[chunk[3] as usize];
            out.push((b2 << 6) | b3);
        }
    }
    Ok(out)
}
