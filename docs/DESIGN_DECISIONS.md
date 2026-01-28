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

