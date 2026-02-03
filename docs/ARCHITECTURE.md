# Architecture Decision Records (ADR)

---

## ADR-001: Runtime API vs. Infrastructure as Code for Access Grants

**Status:** Accepted  
**Date:** 2026-01-28

### Context

We need to grant ephemeral (temporary) access to AWS accounts. Two approaches were considered:

- **GitOps / Terraform**
  - Commit a change to a `.tf` file and wait for CI/CD to apply it.
- **Direct API Integration**
  - The application calls AWS APIs directly to grant and revoke access.

### Decision

We will use **Direct API Integration** (AWS Identity Center APIs) for granting and revoking access.

Terraform will be used **only** to provision baseline infrastructure:
- Permission Sets
- Accounts
- Static assignments

### Consequences

**Positive:**
- Access grants are near-instant (seconds).
- Revocation failures do not corrupt Terraform state files.
- Eliminates state-locking issues when multiple engineers request access simultaneously.

**Negative:**
- Loss of Git-based history for access grants.
- Requires compensating controls:
  - Durable audit logs (JSON / DynamoDB)
  - Clear access lifecycle tracking (who, what, when)

---

## ADR-002: High-Integrity Structured Audit Outputs & Fail-Closed UI

**Status:** Accepted  
**Date:** 2026-02-03

### Context

Security tooling often suffers from two extremes:

- Verbose, unstructured text logs that are difficult to parse.
- Silent or ambiguous failures that are difficult to debug.

In regulated or compliance-focused environments, a simple “Allowed” or “Denied” verdict is insufficient.  
The system must prove **why** a decision was made and **what inputs** were used.

### Decision

We will adopt an **Evidence-Based, Fail-Closed** architecture for all access evaluations.

#### Dual Output Requirement

- Every execution **MUST** produce a structured JSON audit artifact containing:
  - Request
  - Result
  - Decision Context (evidence)
- Console output is treated as a **view** of this data:
  - Styled to match industry-standard forensic tools (e.g., Prowler, Kali-style output)

#### Cryptographic Policy Binding

- The Policy Engine **MUST** compute a SHA-256 hash of the policy configuration file at initialization.
- This hash **MUST** be embedded in every audit JSON record.

**Reasoning:**
- Ensures non-repudiation.
- Allows auditors to verify that the policy file on disk matches the policy used for historical decisions.

#### Strict Exit Codes (Fail-Closed)

The CLI will enforce deterministic exit codes:

- `0` — ALLOW (policy approval)
- `2` — DENY (policy rejection)
- `3` — ERROR (infrastructure or dependency failure)

**Reasoning:**
- Enables safe integration with CI/CD pipelines (e.g., GitHub Actions).
- Infrastructure failures must result in a secure state.
- The system must deny access if AWS or dependencies are unreachable (fail closed).

#### Forensic Visibility (UI Decision)

- The UI must display **full AWS ARNs** alongside human-readable names.
- While friendly names improve readability, ARNs are the only immutable identifiers for forensic investigation.
- Visual minimalism is intentionally sacrificed in favor of audit accuracy.

### Consequences

**Positive:**
- The tool is audit-ready by default.
- End-to-end traceability is built into every execution.
- Decisions are explainable, verifiable, and reproducible.

**Negative:**
- Increased complexity in `src/ui` to support dual rendering (human + forensic).
