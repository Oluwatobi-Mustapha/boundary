# PR: Integrate PolicyEngine and AWS Context into Workflow

## Summary
This PR integrates the PolicyEngine and AWS Organizations adapter into the access workflow, replacing stub policy evaluation with real policy decisions based on AWS account context.

## Changes Made

### 1. **src/workflows/access_workflow.py**
- Added PolicyEngine and AWSOrganizationsAdapter integration
- Implemented SSM Parameter Store caching for Slack bot token (warm start optimization)
- Updated command format from 2 to 3 parameters: `<AccountID> <PermissionSet> <Hours>`
- Added lambda_handler function for SQS event processing
- Replaced stub policy evaluation with real engine.evaluate() calls
- Added UUID-based request ID generation to prevent collisions
- Added AWSResourceNotFoundError exception handling
- Made config path configurable via ACCESS_RULES_PATH environment variable

### 2. **terraform/modules/boundary-bot/workflow.tf**
- Added IDENTITY_STORE_ID environment variable
- Added SSO_INSTANCE_ARN environment variable
- Added IAM policy for SSM Parameter Store access (`ssm:GetParameter`)
- Added IAM policy for Identity Store access (`identitystore:DescribeUser`, `identitystore:ListUsers`)
- Added IAM policy for Organizations access (`organizations:DescribeAccount`, `organizations:ListTagsForResource`)

## Testing Instructions

### Prerequisites
Ensure the following are configured in `terraform/live/envs/dev/main.tf`:
- `identity_store_id` is passed to the boundary_bot module
- `sso_instance_arn` is passed to the boundary_bot module

### Steps
1. Apply Terraform changes:
   ```bash
   cd terraform/live/envs/dev
   terraform apply
   ```

2. Test the new command format in Slack:
   ```
   /boundary request <Your_AWS_Account_ID> ReadOnlyAccess 2
   ```

### Expected Behavior
The Slack bot will acknowledge the request ("Got it!"), and the workflow Lambda will:
1. Fetch your Slack email
2. Map it to an AWS Identity Store User ID
3. Fetch AWS account context (tags, OU path)
4. Evaluate the request against `config/access_rules.yaml`
5. Send a Slack DM with the decision

### Known Issue (Intentional)
The policy engine will likely return: `❌ Access Denied: User not in authorized groups.`

This is expected because:
- The workflow passes `principal_type="USER"` (an Identity Store User ID)
- The `access_rules.yaml` file checks for `principal_type: GROUP`
- Individual users are not directly authorized; only groups are

This architectural mismatch is intentional for learning purposes and will be addressed in a follow-up PR.

## Architecture Notes

### Warm Start Optimization
The SSM parameter for the Slack bot token is cached globally to avoid repeated API calls on warm Lambda invocations.

### Request ID Generation
Changed from timestamp-based (`req-{int(time.time())}`) to UUID-based (`req-{uuid.uuid4().hex[:16]}`) to prevent collisions when multiple requests occur in the same second.

### Config Path Flexibility
The access rules config path defaults to `config/access_rules.yaml` but can be overridden via the `ACCESS_RULES_PATH` environment variable for testing or alternative deployments.

## Security Considerations
- SSM parameter access is scoped to `/boundary/*` prefix
- Identity Store and Organizations permissions use least-privilege actions
- No PII is logged (email/user details logged at DEBUG level only)
- Response URL validation prevents webhook injection attacks

## Dependencies
This PR assumes the following modules/adapters exist:
- `src.adapters.aws_orgs.AWSOrganizationsAdapter`
- `src.core.engine.PolicyEngine`
- `src.models.request.AccessRequest`
- `config/access_rules.yaml`

## Next Steps
After testing and observing the "User not in authorized groups" error, investigate:
1. How to resolve the USER vs GROUP principal type mismatch
2. Whether to fetch user group memberships in the workflow
3. Whether to modify the policy engine to support user-level authorization
