# Contributing to cryptofault

Thank you for your interest in contributing to cryptofault.

## Developer Certificate of Origin (DCO)

All contributions must be signed off using the DCO. Add a
`Signed-off-by` line to every commit message:

```
git commit -s -m "fix: description of your change"
```

This certifies that you have the right to submit the contribution
under the Apache-2.0 license. See [DCO](./DCO) for the full text.

## License Audit Requirement

Before introducing any new dependency, verify its license:

1. Run `cargo deny check licenses`
2. Confirm the dependency is NOT under GPLv2 strict (without "or later")
3. Document the result in the PR description as HECHO before merging

GPLv2-strict dependencies are incompatible with Apache-2.0 and will
be rejected regardless of functionality.

## Contribution Guidelines

- Follow existing code style
- Add tests for any new detection logic
- Update `docs/` if adding new detection categories
- Reference relevant RFCs or CVEs in code comments where applicable

## What This Project Does NOT Cover

This tool detects and reports weaknesses. It does not implement
translation, key management, or crypto-agility shim logic.
Contributions that introduce active remediation logic are out of scope
for this repository.
