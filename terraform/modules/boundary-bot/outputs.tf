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
  description = "Attach this managed policy to IAM caller roles that should access audit API/dashboard"
  value       = aws_iam_policy.audit_read_invoke.arn
}

# NOTE: Once applied, go to the AWS Console -> Amazon SNS -> Topics. 
# Find the boundary-dev-boundary-alerts topic, click Create subscription, select Email, and type your email address. 
# You will get a confirmation link.
