output "permission_set_arns" {
  description = "Map of Permission Set Names to their ARNs"
  value       = { for k, v in aws_ssoadmin_permission_set.this : k => v.arn }
}

output "group_ids" {
  description = "Map of Group Names to their Identity Store IDs"
  value       = { for k, v in aws_identitystore_group.this : k => v.group_id }
}