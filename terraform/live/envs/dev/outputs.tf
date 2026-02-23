output "permission_set_arns" {
  description = "Permission Set ARNs (Update config/access_rules.yaml with these)"
  value       = module.boundary_identity.permission_set_arns
}

output "group_ids" {
  description = "Group IDs (Update config/access_rules.yaml with these)"
  value       = module.boundary_identity.group_ids
}

output "dynamodb_table_name" {
  description = "The DynamoDB Table for State Persistence"
  value       = module.boundary_state.table_name
}

output "slack_webhook_url" {
  value       = module.boundary_bot.slack_webhook_url
  description = "The public webhook URL for the Slack App"
}

output "audit_api_base_url" {
  value       = module.boundary_bot.audit_api_base_url
  description = "Base URL for the read-only audit API"
}

output "audit_dashboard_url" {
  value       = module.boundary_bot.audit_dashboard_url
  description = "Entry URL for the read-only audit dashboard"
}

output "audit_read_invoke_policy_arn" {
  value       = module.boundary_bot.audit_read_invoke_policy_arn
  description = "Managed policy ARN to attach on audit API/dashboard caller roles"
}
