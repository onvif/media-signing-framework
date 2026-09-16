# Future Work

These topics are deliberately outside the Phase 0 demo. Their presence here does
not imply partial implementation.

- Formal media-parser sandboxing, resource limits, and unprivileged execution
- Evidence-directory allow-lists and stderr sanitization
- Signing and private-key or HSM integration
- Metadata inspection as a cheap pre-validation operation
- Authenticated remote HTTP, multi-user scoping, and audit logging
- A reproducible signed-and-trimmed fixture for `integrity_warning`, followed by
  a stable tamper corpus and CI integration
- Docker or Dev Container distribution for clean-machine setup
- Production packaging and versioning
- Chain-of-custody, legal admissibility, and broader video-forensics claims
- Any upstream `--json` feature proposal to the Media Signing Framework

See the [Phase 0 design](../spec.md) for the implemented boundary and the
[explanation](explanation.md) for the current trust model.
