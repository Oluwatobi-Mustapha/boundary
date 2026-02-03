# Threat Model

**Last Updated:** 2026-02-03  
**Scope:** Core Policy Engine, AWS Adapters, and State Management

---

## 1. Trust Boundaries

### Boundary A — User / Input
- The interface (Slack / CLI) submitting an `AccessRequest`.
- The Identity Provider (Slack Auth) is trusted.
- The request payload (e.g., duration, account ID) is treated as **untrusted input**.

### Boundary B — Infrastructure
- The connection between the Engine and AWS APIs.
- AWS Control Plane is assumed secure.
- Network reliability, API availability, and data consistency are considered fallible.

### Boundary C — Configuration
- The `access_rules.yaml` file on disk.
- Treated as the **root of trust** for all access decisions.

---

## 2. Identified Threats & Mitigations

### A. Spoofing (Impersonation)

**Threat:**  
A user requests access to an unauthorized account by guessing or supplying an incorrect OU ID.

**Mitigations (Implemented):**
- **Contextual Validation:**  
  The Engine does not trust user-supplied environment or OU claims.  
  It fetches the authoritative OU path via `AWSOrganizationsAdapter`.
- **Principal Mapping:**  
  Uses immutable Identity Store IDs (`principal_id`) instead of mutable usernames.

---

### B. Tampering (Integrity)

**Threat:**  
A rogue administrator modifies `access_rules.yaml` to allow unauthorized access and later reverts the change to conceal activity.

**Mitigations (Implemented):**
- **Cryptographic Binding:**  
  The Engine computes `SHA256(access_rules.yaml)` at startup.
- **Immutable Evidence:**  
  The resulting `policy_hash` is embedded in every JSON audit log and database record.
  - Mismatches between logs and Git history are detectable.

---

### C. Repudiation (Denial of Action)

**Threat:**  
A user claims they did not request access or that the system granted access erroneously.

**Mitigations (Implemented):**
- **Durable Artifacts:**  
  Every evaluation produces a timestamped JSON artifact in `audit_logs/`.
- **Dual-Identifier Logging:**  
  Logs both:
  - Human-readable names (e.g., `ReadOnly`)
  - Immutable identifiers (e.g., `arn:aws:sso:::permissionSet/...`)
  - Prevents ambiguity if names are reused.

---

### D. Information Disclosure

**Threat:**  
Sensitive data (credentials, internal stack traces) is leaked through logs or UI output.

**Mitigations (Implemented):**
- **Controlled UI Rendering:**  
  Output is strictly formatted via `printer.py`.
- **Fail-Closed Error Handling:**  
  Infrastructure errors return a generic `Infrastructure Error` status.
  - Raw Python stack traces and partial AWS details are not exposed.

---

### E. Denial of Service (Availability)

**Threat:**  
AWS API throttling or outages cause the system to crash or hang, leaving access grants in an inconsistent state.

**Mitigations (Implemented):**
- **Caching:**  
  Permission Set name lookups are cached to reduce API calls.
- **Pagination Support:**  
  Tag retrieval supports pagination to prevent memory exhaustion.
- **Fail-Closed Logic:**  
  If AWS is unreachable:
  - The workflow catches the exception
  - The request is denied
  - The system remains stable (secure but unavailable)

---

## 3. Residual Risks (Accepted / To Be Addressed)

### DynamoDB / Storage Failures
- Current implementation writes audit logs to JSON files.
- Disk exhaustion could result in log loss.

**Future Mitigation:**
- Offload audit artifacts to S3 or DynamoDB.

---

### Race Conditions
- A user removed from a group during evaluation may still receive access within a sub-second window.

**Accepted Risk:**
- AWS IAM propagation delays exceed this window.
- Considered acceptable given platform constraints.

---
