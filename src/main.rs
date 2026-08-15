//! cryptofault — Legacy crypto weakness detector for OT/ICS environments.
//!
//! Copyright (C) 2026 Luis Fidel Castellanos Diaz
//! A Vector Telemetry Research (VTR) open-source tool
//! Licensed under Apache-2.0

use clap::{Parser, Subcommand};

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
    /// Scan a PCAP file or X.509 certificate for crypto weaknesses
    Scan {
        #[arg(long)]
        pcap: Option<String>,
        #[arg(long)]
        cert: Option<String>,
        #[arg(long, default_value = "text")]
        format: String,
    },
}

fn print_attribution() {
    println!("cryptofault {}", VERSION);
    println!("Copyright (C) 2026 {}", AUTHOR);
    println!("{}", PROJECT);
    println!("{}", WEBSITE);
    println!("Licensed under Apache-2.0");
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { pcap, cert, format } => {
            print_attribution();
            println!();

            if pcap.is_none() && cert.is_none() {
                eprintln!("error: provide --pcap or --cert (or both)");
                std::process::exit(1);
            }

            if let Some(path) = &pcap {
                println!("[INFO] PCAP target: {}", path);
                println!("[TODO] PCAP analysis not yet implemented — v0.2.0");
            }

            if let Some(path) = &cert {
                println!("[INFO] Certificate target: {}", path);
                println!("[TODO] Certificate analysis not yet implemented — v0.2.0");
            }

            let _ = format;
            Ok(())
        }
    }
}

mod detectors;
mod schema;
mod output;
mod scanner;
