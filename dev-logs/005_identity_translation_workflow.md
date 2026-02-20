# Phase 5: Identity Translation Chain & Access Workflow Orchestration

**Date:** 2026-02-20

---

## Overview

Phase 5 implements the complete identity translation pipeline from Slack user IDs to AWS Identity Store Principal IDs, along with the orchestration layer that ties together identity mapping, policy evaluation, and asynchronous Slack notifications.

---

## SlackAdapter Implementation

Built `src/adapters/slack_adapter.py` to map Slack User IDs to email addresses.

### Core Functionality

- `get_user_email(user_id: str) -> str`: Calls Slack Web API `users.info` endpoint
- Returns the user's primary email address from their Slack profile

### Resilience Features

- **HTTP 429 Handling:** Automatic exponential backoff with 0-50% jitter on rate limit errors
- **Bounded LRU Cache:** Max 1000 entries using OrderedDict to prevent memory exhaustion
- **Input Validation:** Slack user IDs validated against format `^U[A-Z0-9]{10}$`
- **Timeout Protection:** 10-second timeout on all HTTP requests
- **Custom Exceptions:** SlackAPIError and SlackRateLimitError for granular error handling

### Security Controls

- PII Protection: Email addresses logged at DEBUG level only
- URL Validation: Slack API base URL validated before requests
- TLS Enforcement: All requests use HTTPS with certificate validation

---

## IdentityStoreAdapter Implementation

Built `src/adapters/identity_store_adapter.py` to map email addresses to AWS Identity Store User IDs.

### Core Functionality

- `get_user_id_by_email(email: str) -> str`: Calls AWS Identity Store `ListUsers` API with email filter
- Returns the immutable AWS Principal ID (UUID format)

### Resilience Features

- **ThrottlingException Handling:** Exponential backoff with jitter on AWS rate limits
- **Bounded LRU Cache:** Max 1000 entries to prevent memory leaks in long-running Lambda functions
- **Email Validation:** Regex validation before API calls
- **Pagination Support:** Handles paginated responses (though email should return single result)

### Security Controls

- PII Protection: Email and Principal ID logged at DEBUG level only
- Fail-Closed Logic: Raises IdentityStoreError if user not found (prevents silent failures)

---

## SlackWorkflow Orchestration

Built `src/workflows/access_workflow.py` to orchestrate end-to-end Slack access requests.

### Architecture

Implements the complete request lifecycle:

1. **Identity Translation Chain:** Slack User ID → Email → AWS Principal ID
2. **Command Parsing:** Extract Permission Set and duration from Slack command text
3. **Policy Evaluation:** (STUB - to be integrated with existing `src/workflow.py`)
4. **Provisioning:** (STUB - to be integrated with SSO adapter)
5. **Asynchronous Notification:** Send success/error messages back to Slack via response_url webhook

### Security Hardening

- **URL Validation:** `response_url` validated against `https://hooks.slack.com/` prefix BEFORE try block
- **PII Protection:** All error messages are generic ("Unable to map your identity") with no PII exposure
- **Type Safety:** MyPy type narrowing enforced (explicit None checks instead of `all()`)
- **Fail-Open Notifications:** If Slack webhook fails, workflow continues (doesn't crash access grant)

### Error Handling Strategy

Four-tier exception handling:

1. **SlackAPIError:** "Unable to retrieve your Slack profile. Please try again."
2. **IdentityStoreError:** "Unable to map your identity to AWS. Please contact your administrator."
3. **WorkflowError:** Safe to expose message directly (no PII)
4. **Unexpected Exceptions:** Generic message + full logging with `exc_info=True`

---

## Bugfixes & Linting

### Fixed During Implementation

- **F841 Unused Variables:** Removed unused `response`, `e`, and `aws_principal_id` variables
- **MyPy arg-type Errors:** Changed `if not all([x, y])` to `if not x or not y` for type narrowing
- **Unreachable Code:** Simplified exception handler by removing unreachable `else` branch

### CI/CD Integration

All code passes:

- Ruff linting (with E501 ignored for long lines)
- MyPy strict type checking
- Bandit security scanning

---

## Design Decisions

### Two-Adapter Pattern

**Decision:** Separate SlackAdapter and IdentityStoreAdapter instead of single monolithic mapper.

**Rationale:**

- Independent unit testing (mock Slack without AWS, and vice versa)
- Single Responsibility Principle (each adapter has one job)
- Reusability (IdentityStoreAdapter can be used by CLI workflows)

**Trade-off:** Adds ~200-500ms latency due to two sequential API calls.

### Bounded LRU Cache

**Decision:** Enforce max 1000 entries with OrderedDict-based LRU eviction.

**Rationale:**

- Prevents memory exhaustion in long-running Lambda functions
- Maintains sub-millisecond lookup performance for repeat requests
- Validated at initialization (cache_max_size must be > 0)

**Trade-off:** Cache invalidation is time-based only (5-minute TTL); stale data possible if user email changes.

### Jittered Retry Logic

**Decision:** Exponential backoff with 0-50% random jitter on all retries.

**Rationale:**

- Prevents thundering herd during rate limit events
- Standard pattern: `sleep(backoff + random.uniform(0, backoff * 0.5))`

**Trade-off:** Adds unpredictable latency during retry scenarios.

---

## Integration Points

### With Existing Code

- **src/workflow.py:** Policy evaluation engine (to be integrated in Phase 6)
- **src/validators.py:** Duration validation already integrated via `validate_duration()`
- **DynamoDB Schema:** Slack fields (`slack_user_id`, `slack_response_url`) now actively used

### Future Work

- Integrate with SSO adapter for actual account assignment provisioning
- Connect SlackWorkflow to existing policy evaluation engine
- Implement Janitor for automatic revocation with Slack DM notifications

---

## Phase 5 Complete: Identity Translation & Workflow Orchestration

The identity translation chain is production-ready with full security hardening.

Next Phase:

**End-to-End Integration**  
Connect SlackWorkflow to the existing Policy Engine and SSO provisioning adapters to enable full access grant lifecycle.
