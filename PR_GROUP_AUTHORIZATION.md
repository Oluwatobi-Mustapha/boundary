# PR: Implement Group-Based Authorization

## Summary
This PR implements group-based authorization by fetching user group memberships from AWS Identity Store and evaluating policies against groups instead of individual users. This enables scalable, role-based access control (RBAC) that aligns with enterprise security best practices.

## Problem Statement
The previous implementation passed individual User IDs to the policy engine with `principal_type="USER"`, but the policy rules in `access_rules.yaml` only authorize groups (`principal_type: GROUP`). This caused all requests to be denied with "User not in authorized groups."

## Solution
1. Fetch the user's group memberships from Identity Store after identity translation
2. Evaluate the policy for each group the user belongs to
3. Grant access if ANY group authorizes the request
4. Include the authorizing group in audit logs

## Changes Made

### 1. **src/adapters/identity_store_adapter.py**
Added `get_user_group_memberships(user_id)` method:
- Fetches all group IDs a user belongs to using AWS Identity Store API
- Implements pagination for users in many groups
- Includes retry logic with exponential backoff for throttling
- Returns empty list if user has no group memberships

### 2. **src/workflows/access_workflow.py**
Updated `process_request()` method:
- Fetch user's group memberships after identity translation
- Fail fast if user has no group memberships
- Iterate through each group and evaluate policy
- Grant access on first ALLOW decision
- Log which group authorized the access for audit trail
- Provide clear error message if no groups authorize the request

### 3. **terraform/modules/boundary-bot/workflow.tf**
Added IAM permission:
- `identitystore:ListGroupMembershipsForMember` - Required to fetch user's groups

## Benefits

### Scalability
- **Before**: Need a policy rule for every user (doesn't scale)
- **After**: One rule per group covers all members

### Simplified Management
- Add user to group → Instant access (no code changes)
- Remove from group → Automatic revocation
- HR/IT manages groups, not YAML files

### Security & Compliance
- Follows AWS IAM best practices (group-based authorization)
- Clear audit trail: "Access granted by Admins group"
- Least privilege: Users with no groups → Denied
- Automatic revocation when users leave groups

### Flexibility
- Support multiple groups per user
- Different groups → Different permissions
- Easy to add approval workflows per group later

## Example Flow

### Before (Broken)
```
User requests access
→ Fetch User ID: "92671234-5678-..."
→ Evaluate policy with principal_type="USER"
→ Policy checks for principal_type="GROUP"
→ ❌ DENY: "User not in authorized groups"
```

### After (Working)
```
User requests access
→ Fetch User ID: "92671234-5678-..."
→ Fetch Groups: ["a4671234-...-admins", "b5671234-...-developers"]
→ Evaluate policy for "admins" group
→ ✅ ALLOW: "Admins group authorized"
→ Grant access with audit log
```

## Testing Instructions

### Prerequisites
Ensure your AWS Identity Store user is a member of at least one group that's authorized in `config/access_rules.yaml`.

### Steps
1. Apply Terraform changes:
   ```bash
   cd terraform/live/envs/dev
   terraform apply
   ```

2. Test in Slack:
   ```
   /boundary request <AccountID> ReadOnlyAccess 2
   ```

### Expected Results

**If you're in an authorized group:**
```
✅ Access Granted!
Account: 123456789012
Role: ReadOnlyAccess
Duration: 2 hours
Status: Provisioning... (WIP)
```

**If you're not in any groups:**
```
⚠️ You are not a member of any authorized groups.
```

**If your groups aren't authorized for this request:**
```
❌ Access Denied
Reason: None of your groups are authorized for this request.
```

## Architecture Notes

### Policy Evaluation Strategy
The workflow uses an "ANY group allows" strategy:
- Iterates through user's groups in order
- Stops on first ALLOW decision
- Only denies if ALL groups deny (or no groups exist)

This matches AWS IAM's behavior: explicit ALLOW wins.

### Performance Considerations
- Group membership lookup adds ~100-200ms latency
- Results could be cached in future optimization
- Pagination handles users in 100+ groups

### Audit Trail
Logs include:
- Number of groups user belongs to
- Which group authorized the access
- Clear denial reasons if no groups match

## Security Considerations
- Group IDs are UUIDs (not sensitive)
- No PII logged (group names not fetched)
- IAM permission scoped to minimum required actions
- Fail-closed: No groups = Denied

## Breaking Changes
None. This is backward compatible:
- Existing policy rules continue to work
- Only changes internal authorization logic
- No API or command format changes

## Future Enhancements
This enables:
- Per-group approval workflows
- Per-group duration limits
- Per-group MFA requirements
- Group-based compliance reporting

## Related Issues
Fixes the "User not in authorized groups" error introduced in the previous PR.

## Checklist
- [x] Code follows project style guidelines
- [x] Added retry logic with exponential backoff
- [x] Error messages are user-friendly (no PII)
- [x] IAM permissions follow least-privilege
- [x] Logging includes audit trail information
- [x] No breaking changes to existing functionality
