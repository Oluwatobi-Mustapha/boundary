# Architecture Decision Records (ADR)

## ADR-001: Runtime API vs. Infrastructure as Code for Access Grants

**Date:** 2026-01-28

### 1st Context

We need to grant ephemeral (temporary) access to AWS accounts. We considered two approaches:

1. **GitOps/Terraform:** Commit a change to a `.tf` file, wait for CI/CD to apply.
2. **Direct API:** The application calls AWS APIs directly to grant access.

### 1st Decision

We will use **Direct API Integration** (AWS Identity Center APIs) for granting and revoking access. Terraform will only be used to provision the baseline Permission Sets and Accounts.

### 1st Consequences

* **Positive:** Granting access is near-instant (seconds).
* **Positive:** Revocation failures do not corrupt Terraform state files.
* **Positive:** Eliminates "State Locking" issues when multiple engineers request access simultaneously.
* **Negative:** We lose the "Git History" of access. We must compensate by building a robust Audit Log (DynamoDB) to track who had access and when.

## ADR-002: High-Integrity Structured Audit Outputs

**Date:** 2026-02-03

### 2nd Context

Security tools often output unstructured text logs, making it difficult to ingest into SIEMs (Splunk, Datadog) or verify later during an audit. Furthermore, if a policy changes, it is often impossible to prove *which version* of the policy was active when a specific access decision was made.

### 2nd Decision

1. **Dual Output:** The system will support both Human-Readable tables (for UX) and Structured JSON (for machines/audit).
2. **Integrity Hashing:** The Policy Engine will calculate and store the SHA256 hash of the loaded YAML configuration on startup. This hash must be included in every evaluation result log.
3. **Fail-Closed Exit Codes:** We will standardize exit codes (0=ALLOW, 2=DENY, 3=ERROR) to allow safe integration with CI/CD pipelines.

### 2nd Consequences

* **Positive:** Provides an irrefutable cryptographic link between a decision and the policy version used.
* **Positive:** Enables automated pipeline gates via exit codes.

* **Negative:** Requires stricter file handling (binary mode) in the Engine initialization.

## ADR-003: Out-of-Band Bootstrapping for Third-Party Secrets

**Date:** 2026-02-20

### 3rd Context

To integrate with Slack, our system requires highly sensitive third-party API credentials (the Slack Signing Secret and the OAuth Bot Token). Passing these secrets through Terraform variables (`.tfvars`) causes them to be stored in plaintext within the `terraform.tfstate` file in our S3 state bucket, creating a severe security vulnerability.

### 3rd Decision

We will employ **Out-of-Band Bootstrapping**. Engineers must manually inject these secrets directly into AWS Systems Manager (SSM) Parameter Store as KMS-encrypted `SecureString` parameters via the AWS CLI (Day 0 configuration). Terraform will strictly manage the IAM permissions (`ssm:GetParameter`) to allow Lambda to read these secrets at runtime.

### 3rd Consequences

* **Positive:** `terraform.tfstate` remains completely sanitized of third-party API keys.
* **Positive:** Secret lifecycle and rotation are decoupled from infrastructure deployments.
* **Negative:** Introduces a manual "Day 0" setup step that cannot be fully automated via standard CI/CD pipelines without introducing heavier external tooling (e.g., HashiCorp Vault).

## ADR-004: Application-Layer HMAC Signature Verification

**Date:** 2026-02-20

### 4th Context

The API Gateway webhook is publicly accessible. We must guarantee that only Slack can invoke the Policy Engine and prevent malicious actors from submitting spoofed access requests.  

### 4th Decision

Rather than attempting to IP-allowlist Slack's massive and dynamic IP ranges at the WAF/Gateway layer, we will implement **Application-Layer Cryptographic Verification** inside the Lambda function. The function will use the `x-slack-signature` and `x-slack-request-timestamp` headers to compute an HMAC-SHA256 hash using the bootstrapped Slack Signing Secret.

### 4th Consequences

* **Positive:** Mathematically guarantees the payload originated from our specific Slack app.
* **Positive:** Inherently mitigates replay attacks by strictly enforcing a 5-minute maximum clock drift window on the request timestamp.
* **Negative:** Malicious requests still trigger Lambda execution (and SSM/KMS fetches on cold starts) before being dropped, potentially incurring minor compute costs during a DDoS event.

## ADR-005: Slack-to-AWS Identity Translation Chain

**Date:** 2026-02-20

### 5th Context

Slack users are identified by opaque IDs (e.g., `U1234ABCD`), while AWS Identity Center requires the user's Principal ID (UUID format). We need a reliable, performant way to translate Slack user IDs into AWS Identity Store User IDs to provision access. A naive approach would tightly couple Slack API calls with AWS API calls in a single monolithic function, making testing difficult and violating the Single Responsibility Principle.

### 5th Decision

We will implement a **Two-Adapter Identity Translation Chain**:

1. **SlackAdapter** (`src/adapters/slack_adapter.py`): Maps Slack User ID → Email via Slack Web API (`users.info`).
2. **IdentityStoreAdapter** (`src/adapters/identity_store_adapter.py`): Maps Email → AWS Principal ID via AWS Identity Store API (`ListUsers` with email filter).
3. **SlackWorkflow** (`src/workflows/access_workflow.py`): Orchestrates the chain and handles errors.

Both adapters implement:
- **Bounded LRU Cache** (max 1000 entries) using OrderedDict to prevent memory exhaustion in long-running Lambda functions.
- **Exponential Backoff with Jitter** (0-50% random jitter) to handle rate limits (Slack HTTP 429, AWS ThrottlingException) and prevent thundering herd.
- **PII Protection**: All emails and user IDs are logged at DEBUG level only, never at INFO/WARNING in production logs.

### 5th Consequences

* **Positive:** Decoupled adapters enable independent unit testing (mock Slack without AWS, and vice versa).
* **Positive:** Bounded cache prevents memory leaks while maintaining sub-millisecond lookup performance for repeat requests.
* **Positive:** Jittered retry logic prevents cascading failures during API rate limit events.
* **Negative:** Two sequential API calls add ~200-500ms latency compared to a hypothetical direct Slack-to-AWS mapping (which doesn't exist).
* **Negative:** Cache invalidation is time-based only (5-minute TTL); if a user's email changes in Slack or AWS, stale data may be served until cache expires.
