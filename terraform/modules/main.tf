# ------------------------------------------------------------------------------
# DATA LOOKUPS
# ------------------------------------------------------------------------------
# Automatically find the Single Sign-On Instance ARN and Identity Store ID.
# We assume there is only one instance (standard for AWS Organizations).
data "aws_ssoadmin_instances" "this" {}

locals {
  sso_instance_arn  = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]
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