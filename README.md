# cryptofault

**Legacy crypto weakness detector for OT/ICS environments.**

```
cryptofault 0.1.0
Copyright (C) 2026 Luis Fidel Castellanos Diaz
A Vector Telemetry Research (VTR) open-source tool
https://vectortelemetryresearch.com
Licensed under Apache-2.0
```

## What it does

`cryptofault` reads packet captures (PCAP) and X.509 certificates and
reports cryptographic weaknesses commonly found in legacy industrial
environments:

- TLS 1.0 / TLS 1.1 ClientHello handshakes
- RSA keys under 2048 bits
- MD5 and SHA-1 certificate signatures
- Plaintext protocol sessions (no encryption detected)

It does **not** modify traffic, inject packets, or perform active
remediation. Output only.

## Usage

```sh
# Analyze a PCAP file
cryptofault scan --pcap capture.pcap

# Analyze an X.509 certificate
cryptofault scan --cert server.pem

# JSON output for pipeline integration
cryptofault scan --pcap capture.pcap --format json
```

## Example output

```
[WARN] TLS 1.0 ClientHello — src 10.0.0.5 → dst 10.0.0.1
[WARN] RSA 1024 — CN=legacy-plc.local (expires 2027-03-01)
[WARN] SHA-1 signature — CN=scada-root-ca
[INFO] 3 unencrypted sessions detected on port 502 (Modbus)
```

## Installation

```sh
cargo install cryptofault
```

Or build from source:

```sh
git clone https://github.com/LuisCastellanos-dev/cryptofault
cd cryptofault
cargo build --release
```

## License

Apache-2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Contributions require DCO sign-off — see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Author

Luis Fidel Castellanos Diaz ([@LuisCastellanos-dev](https://github.com/LuisCastellanos-dev))  
Founder, [Vector Telemetry Research (VTR)](https://vectortelemetryresearch.com)

## Known limitations

- **`src` field semantics**: for `tls_version` and `plaintext_session` findings, `src` is an IP address; for `weak_key`, `weak_signature`, and `certificate_expiry` findings, `src` is a file path. A dedicated `src_kind` field will be added to the schema when a third external consumer requires it (tracked as technical debt).
