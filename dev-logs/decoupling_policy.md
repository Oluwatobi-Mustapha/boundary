# Entry: Decoupling Policy Logic from AWS Side-Effects

**Note:**  
Decided to keep the `PolicyEngine` *pure*. Introduced an AWS Adapter pattern where the engine receives an `AWSAccountContext` object containing pre-fetched AWS facts (e.g., Tags, OU IDs) instead of calling `boto3` directly.  
This design keeps policy evaluation fast, deterministic, and easy to unit test, while cleanly separating decision logic from AWS I/O.

---

## Entry: Implementing Target Selection Logic

**Note:**  
Added the `_match_target` helper to encapsulate rule target evaluation logic.  
Supports both:

- OU-based hierarchical matching
- Tag-based attribute matching  

Uses short-circuiting logic (`any()`) to optimize performance and fail fast on non-matching targets.

---

### Entry: Implementing Target Resolution

**Note:**  
Integrated `AWSAccountContext` into the main policy evaluation loop.  
Wired `_match_target` into rule processing to enable both hierarchical (OU) and attribute-based (Tag) authorization decisions, ensuring rules are only evaluated when their target scope matches the request context.
