output "permission_set_arns" {
  description = "Permission Set ARNs (Update config/access_rules.yaml with these)"
  value       = module.boundary_identity.permission_set_arns
}

output "group_ids" {
  description = "Group IDs (Update config/access_rules.yaml with these)"
  value       = module.boundary_identity.group_ids
}