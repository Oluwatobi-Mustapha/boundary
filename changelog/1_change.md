# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to Semantic Versioning.

---

## [1.0.0] — 2026-02-25

### Added
- Frozen v1 contract documentation and constants:
  - `docs/v1_contract.md`
  - `src/contracts.py`
- Read API contract test suite to prevent breaking response/schema drift:
  - `tests/test_v1_contract.py`
- Role-matrix smoke script for API/dashboard caller validation:
  - `scripts/smoke_audit_role_matrix.sh`
- Per-role least-privilege API invoke IAM policies for:
  - `security_admin`
  - `auditor`
  - `viewer`
- Additional Terraform outputs for role-specific invoke policy ARNs.

### Changed
- Read API responses now include `X-Boundary-Contract-Version`.
- `GET /api/requests`, `GET /api/metrics`, and CSV export headers are generated from frozen contract constants.
- Audit API principal mapping now defaults to explicit caller ARNs only.
  Wildcard principal mapping is disabled unless explicitly enabled for bootstrap.
- Dev environment docs expanded with:
  - role-matrix smoke guidance
  - dashboard access flow
  - principal mapping and wildcard behavior

### Fixed
- Janitor Lambda import path issue in AWS Organizations adapter (`src` import path mismatch).

### Security
- Hardened audit API authorization posture:
  - deny-by-default for unmapped principals
  - explicit opt-in for wildcard principal mapping
  - least-privilege invoke policies separated by caller role

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
