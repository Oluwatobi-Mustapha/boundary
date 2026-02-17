output "permission_set_arns" {
  description = "Map of Permission Set Names to their ARNs"
  value       = { for k, v in aws_ssoadmin_permission_set.this : k => v.arn }
}

output "group_ids" {
  description = "Map of Group Names to their Identity Store IDs"
  value       = { for k, v in aws_identitystore_group.this : k => v.group_id }
}

# --- NEW OUTPUTS FOR THE BOT ---

output "sso_instance_arn" {
  description = "The ARN of the SSO Instance found by this module"
  value       = local.sso_instance_arn
}

output "identity_store_id" {
  description = "The Identity Store ID found by this module"
  value       = local.identity_store_id
}