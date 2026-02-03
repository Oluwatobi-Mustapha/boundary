# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to Semantic Versioning.

---

## [0.1.0] — 2026-02-03

### Added
- End-to-end request lifecycle simulation via `demo.py`.
- Mock AWS Adapter support for full Engine testing without live AWS dependencies.
- Dual output support:
  - Human-readable console output
  - Machine-readable JSON audit logs
- Structured evaluation context captured in decision output:
  - Matched OU paths
  - Matched account tags
  - Selector used for rule resolution
- Engine metadata included in output:
  - `engine_version`
  - `rules_processed`
- Cryptographic policy integrity:
  - SHA-256 hash of `access_rules.yaml` embedded in every audit log entry (`policy_hash`).

### Changed
- Timestamp serialization standardized to ISO 8601 (`Z`) format for audit readability.
- Console output redesigned to use structured grid tables and consistent section headers.
- Permission Set display enhanced to include both human-readable name and full ARN.

### Fixed
- Enforced fail-closed behavior on invalid or malformed request timestamps.
- Improved determinism and traceability of policy evaluation decisions.

### Security
- Established immutable chain-of-custody for policy decisions via policy hashing.
- Ensured all executions produce durable, verifiable audit artifacts.

---

