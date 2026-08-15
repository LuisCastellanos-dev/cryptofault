//! Plaintext session detector for OT/ICS protocols
//!
//! Detects unencrypted sessions on well-known OT/ICS ports.
//! References: IEC 62443-3-3 SR 4.1, NERC CIP-007-6

use crate::schema::{Category, Finding, Severity};

#[derive(Debug, Clone)]
pub struct OtPort {
    pub port: u16,
    pub protocol: &'static str,
    pub reference: &'static str,
}

pub const OT_PORTS: &[OtPort] = &[
    OtPort { port: 502,   protocol: "Modbus/TCP",   reference: "IEC 62443-3-3 SR 4.1" },
    OtPort { port: 20000, protocol: "DNP3",         reference: "IEC 62443-3-3 SR 4.1" },
    OtPort { port: 44818, protocol: "EtherNet/IP",  reference: "IEC 62443-3-3 SR 4.1" },
    OtPort { port: 102,   protocol: "S7/ISO-TSAP",  reference: "IEC 62443-3-3 SR 4.1" },
    OtPort { port: 4840,  protocol: "OPC-UA (TCP)", reference: "IEC 62443-3-3 SR 4.1" },
    OtPort { port: 1962,  protocol: "PCWorx",       reference: "IEC 62443-3-3 SR 4.1" },
    OtPort { port: 2455,  protocol: "WAGO Modbus",  reference: "IEC 62443-3-3 SR 4.1" },
    OtPort { port: 9600,  protocol: "OMRON FINS",   reference: "IEC 62443-3-3 SR 4.1" },
];

#[derive(Debug)]
pub struct PlaintextSession {
    pub src: String,
    pub dst: String,
    pub port: u16,
    pub protocol: String,
    pub reference: String,
}

pub fn is_ot_port(port: u16) -> Option<&'static OtPort> {
    OT_PORTS.iter().find(|p| p.port == port)
}

pub fn build_finding(id: usize, session: &PlaintextSession) -> Finding {
    Finding {
        id: format!("CF-{:03}", id),
        severity: Severity::High,
        category: Category::PlaintextSession,
        description: format!(
            "Unencrypted {} session detected on port {}",
            session.protocol, session.port
        ),
        src: Some(session.src.clone()),
        dst: Some(session.dst.clone()),
        port: Some(session.port),
        evidence: format!(
            "plaintext {}:{} -> {}",
            session.protocol, session.src, session.port
        ),
        reference: session.reference.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_modbus_port() {
        let p = is_ot_port(502);
        assert!(p.is_some());
        assert_eq!(p.unwrap().protocol, "Modbus/TCP");
    }

    #[test]
    fn recognizes_dnp3_port() {
        let p = is_ot_port(20000);
        assert!(p.is_some());
        assert_eq!(p.unwrap().protocol, "DNP3");
    }

    #[test]
    fn ignores_https_port() {
        assert!(is_ot_port(443).is_none());
    }

    #[test]
    fn ignores_ssh_port() {
        assert!(is_ot_port(22).is_none());
    }

    #[test]
    fn finding_severity_is_high() {
        let session = PlaintextSession {
            src: "10.0.0.5".to_string(),
            dst: "10.0.0.1".to_string(),
            port: 502,
            protocol: "Modbus/TCP".to_string(),
            reference: "IEC 62443-3-3 SR 4.1".to_string(),
        };
        let f = build_finding(1, &session);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.port, Some(502));
    }

    #[test]
    fn all_ot_ports_have_references() {
        for p in OT_PORTS {
            assert!(!p.reference.is_empty());
            assert!(!p.protocol.is_empty());
        }
    }
}
