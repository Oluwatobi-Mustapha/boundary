# Architecture Decision Records (ADR)

## ADR-001: Runtime API vs. Infrastructure as Code for Access Grants

**Date:** 2026-01-28

### Context
We need to grant ephemeral (temporary) access to AWS accounts. We considered two approaches:
1.  **GitOps/Terraform:** Commit a change to a `.tf` file, wait for CI/CD to apply.
2.  **Direct API:** The application calls AWS APIs directly to grant access.

### Decision
We will use **Direct API Integration** (AWS Identity Center APIs) for granting and revoking access. Terraform will only be used to provision the baseline Permission Sets and Accounts.

### Consequences
* **Positive:** Granting access is near-instant (seconds).
* **Positive:** Revocation failures do not corrupt Terraform state files.
* **Positive:** Eliminates "State Locking" issues when multiple engineers request access simultaneously.
* **Negative:** We lose the "Git History" of access. We must compensate by building a robust Audit Log (DynamoDB) to track who had access and when.


## ADR-002: High-Integrity Structured Audit Outputs

**Date:** 2026-02-03

### Context
Security tools often output unstructured text logs, making it difficult to ingest into SIEMs (Splunk, Datadog) or verify later during an audit. Furthermore, if a policy changes, it is often impossible to prove *which version* of the policy was active when a specific access decision was made.

### Decision
1.  **Dual Output:** The system will support both Human-Readable tables (for UX) and Structured JSON (for machines/audit).
2.  **Integrity Hashing:** The Policy Engine will calculate and store the SHA256 hash of the loaded YAML configuration on startup. This hash must be included in every evaluation result log.
3.  **Fail-Closed Exit Codes:** We will standardize exit codes (0=ALLOW, 2=DENY, 3=ERROR) to allow safe integration with CI/CD pipelines.

### Consequences
* **Positive:** Provides an irrefutable cryptographic link between a decision and the policy version used.
* **Positive:** Enables automated pipeline gates via exit codes.

* **Negative:** Requires stricter file handling (binary mode) in the Engine initialization.
