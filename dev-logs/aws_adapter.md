## **Phase 2: AWS Adapter (Organizations) — Context Fact Gathering + Hardening**

**Date: 01-02-26**

### **Goal**

Build the “Hands” of the system: a thin adapter that talks to AWS APIs and returns a clean `AWSAccountContext` (OU path + tags) so the `PolicyEngine` stays pure and deterministic.

---

### **1) Created the Organizations Adapter Skeleton**

* **Added `src/adapters/aws_orgs.py`** and introduced `AWSOrganizationsAdapter`.
* **Used dependency injection in `__init__`**:

  * Accepts optional `orgs_client` / `sso_client`
  * Defaults to `boto3.client("organizations")` and `boto3.client("sso-admin")`
* **Why:** makes AWS integration code testable (mock clients) and keeps AWS calls at the edge of the system.

**Suggested commit title/message**

* `feat(adapters): add AWSOrganizationsAdapter with DI clients`

---

### **2) Implemented `get_ou_path(account_id)` using `organizations.list_parents` (iterative climb)**

* Implemented OU/root chain discovery:

  * Start at `current_id = account_id`
  * Call `list_parents(ChildId=current_id)`
  * Move upward by setting `current_id = parent_id`
  * Stop when parent `Type == "ROOT"`
* **Stored the OU/root path in root-first order** by using `ou_path_ids.insert(0, p_id)`
* **Why:** engine rules can match any OU level; root-first ordering matches how we reason about OU hierarchy in policy evaluation.

---

### **3) Production-hardening: fail-closed on broken hierarchy**

Added strict consistency checks to prevent “partial facts” from leaking into security decisions:

* **Raise if `Parents` is empty before ROOT**

  * Treat this as a broken or incomplete Organizations view.
* **Validate parent response shape**

  * `p_id` and `p_type` must exist, else raise.
* **Validate allowed parent types**

  * Only accept `{"ROOT", "ORGANIZATIONAL_UNIT"}`; raise on unexpected types.
* **Added `hit_root` sanity check**

  * Ensures traversal truly reached ROOT before returning.
* **Why:** partial OU paths can cause incorrect allow/deny decisions (security risk). In IAM-style systems, **crash the request > guess**.

---

### **4) Implemented `get_account_tags(account_id)` with dictionary transformation**

* Called `organizations.list_tags_for_resource(ResourceId=account_id)`
* Converted AWS tag format:

  * Input: `[{"Key": "Env", "Value": "Prod"}]`
  * Output: `{"Env": "Prod"}`
* **Why:** engine does O(1) tag matching with `context.tags.get(key)` and stays pure.

---

### **5) Added pagination support for tags**

* Implemented `NextToken` loop to gather all tag pages into `all_tags`
* Returned normalized dict only after loop completes
* **Why:** without pagination you risk incomplete tags → wrong policy matches.

---

### **6) Implemented safer AWS error handling for tags**

* Imported and handled `botocore.exceptions.ClientError`
* Behavior:

  * **AccessDeniedException ⇒ return `{}`**

    * Engine will fail-safe for tag selectors (no tag match → deny).
  * **Other errors ⇒ re-raise**

    * Don’t silently convert session/auth/throttling into “no tags” (that hides real failures).
* **Why:** distinguish “no permission to read tags” (safe to treat as no tags) from “system broken” (must crash).

---

### **7) Added `build_account_context(account_id)` orchestration method**

* New convenience entry point:

  * Calls `get_ou_path(account_id)`
  * Calls `get_account_tags(account_id)`
  * Returns `AWSAccountContext(ou_path_ids=..., tags=...)`
* **Why:** prevents adapter consumers from juggling multiple calls and keeps “facts building” consistent.

---

## **Phase 2 Status**

✅ Adapter can now produce a complete `AWSAccountContext` from live AWS Organizations data  
✅ Hierarchy logic is fail-closed to avoid decisions on partial facts  
✅ Tag retrieval supports pagination and handles AccessDenied safely  
➡️ Next gap: **Permission Set Name resolution** via `sso-admin.describe_permission_set`
