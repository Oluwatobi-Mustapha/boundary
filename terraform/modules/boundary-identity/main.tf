# ------------------------------------------------------------------------------
# DATA LOOKUPS
# ------------------------------------------------------------------------------
# Automatically find the Single Sign-On Instance ARN and Identity Store ID.
# We select the Identity Center instance owned by the *current* AWS account.
data "aws_ssoadmin_instances" "this" {}
data "aws_caller_identity" "current" {}

locals {
  matching_instances = [
    for idx, owner in data.aws_ssoadmin_instances.this.owner_account_ids : {
      instance_arn      = data.aws_ssoadmin_instances.this.arns[idx]
      identity_store_id = data.aws_ssoadmin_instances.this.identity_store_ids[idx]
      owner_account_id  = owner
    }
    if owner == data.aws_caller_identity.current.account_id
  ]

  # Safe extraction (avoids invalid index) + deterministic selection by owner account
  sso_instance_arn  = try(local.matching_instances[0].instance_arn, null)
  identity_store_id = try(local.matching_instances[0].identity_store_id, null)
}

# Fail fast with a clear message if we can't deterministically select the right instance.
resource "null_resource" "require_identity_center" {
  lifecycle {
    precondition {
      condition     = length(local.matching_instances) == 1
      error_message = <<-EOT
        Unable to select a unique IAM Identity Center instance for this AWS account.

        Current account: ${data.aws_caller_identity.current.account_id}
        Matching instances found: ${length(local.matching_instances)}

        Fix:
        - Run Terraform from the account that administers IAM Identity Center (management or delegated admin), OR
        - Remove/disable extra Identity Center instances so exactly one is owned by this account.
      EOT
    }
  }
}

# ------------------------------------------------------------------------------
# 1. PERMISSION SETS
# ------------------------------------------------------------------------------
resource "aws_ssoadmin_permission_set" "this" {
  for_each = var.permission_sets

  name             = each.key
  description      = each.value.description
  instance_arn     = local.sso_instance_arn
  session_duration = each.value.session_duration

  # Re-provision if the duration or description changes
  tags = {
    ManagedBy = "Terraform"
    Module    = "boundary-identity"
  }
}

# ------------------------------------------------------------------------------
# 2. MANAGED POLICY ATTACHMENTS
# ------------------------------------------------------------------------------
# Flatten the nested structure (Permission Set -> List of Policies) 
# into a flat list of pairs for Terraform iteration.
locals {
  managed_policy_attachments = flatten([
    for ps_name, ps_config in var.permission_sets : [
      for policy_arn in ps_config.managed_policies : {
        ps_name    = ps_name
        policy_arn = policy_arn
      }
    ]
  ])
}

resource "aws_ssoadmin_managed_policy_attachment" "this" {
  # Create a unique key for each attachment: "PermissionSetName.PolicyARN"
  for_each = {
    for item in local.managed_policy_attachments : 
    "${item.ps_name}.${item.policy_arn}" => item
  }

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.ps_name].arn
  managed_policy_arn = each.value.policy_arn
}

# ------------------------------------------------------------------------------
# 3. GROUPS
# ------------------------------------------------------------------------------
resource "aws_identitystore_group" "this" {
  for_each = toset(var.groups)

  display_name      = each.key
  description       = "Managed by Terraform (Boundary)"
  identity_store_id = local.identity_store_id
}