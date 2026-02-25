output "lambda_function_arn" {
  description = "ARN of the Janitor Lambda Function"
  value       = aws_lambda_function.janitor.arn
}

output "lambda_role_name" {
  description = "Name of the IAM Role used by the Janitor"
  value       = aws_iam_role.janitor_execution.name
}

# --- NEW OUTPUT ---
output "sns_topic_arn" {
  description = "SNS Topic for Boundary Alerts (Subscribe your email here)"
  value       = aws_sns_topic.alerts.arn
}

output "audit_api_base_url" {
  description = "Base URL for the read-only audit API"
  value       = "${aws_apigatewayv2_api.slack_api.api_endpoint}/api"
}

output "audit_dashboard_url" {
  description = "Entry URL for the read-only audit dashboard"
  value       = "${aws_apigatewayv2_api.slack_api.api_endpoint}/dashboard"
}

output "audit_read_invoke_policy_arn" {
  description = "Legacy broad policy for audit API/dashboard callers (kept for compatibility)"
  value       = aws_iam_policy.audit_read_invoke.arn
}

output "audit_security_admin_invoke_policy_arn" {
  description = "Attach to security_admin caller role(s): requests + metrics + exports + dashboard"
  value       = aws_iam_policy.audit_read_invoke_security_admin.arn
}

output "audit_auditor_invoke_policy_arn" {
  description = "Attach to auditor caller role(s): read-only requests + metrics + exports + dashboard"
  value       = aws_iam_policy.audit_read_invoke_auditor.arn
}

output "audit_viewer_invoke_policy_arn" {
  description = "Attach to viewer caller role(s): requests + dashboard only"
  value       = aws_iam_policy.audit_read_invoke_viewer.arn
}

output "audit_invoke_policy_arns_by_role" {
  description = "Role-keyed invoke policy ARNs for security_admin, auditor, and viewer"
  value = {
    security_admin = aws_iam_policy.audit_read_invoke_security_admin.arn
    auditor        = aws_iam_policy.audit_read_invoke_auditor.arn
    viewer         = aws_iam_policy.audit_read_invoke_viewer.arn
  }
}

# NOTE: Once applied, go to the AWS Console -> Amazon SNS -> Topics. 
# Find the boundary-dev-boundary-alerts topic, click Create subscription, select Email, and type your email address. 
# You will get a confirmation link.
