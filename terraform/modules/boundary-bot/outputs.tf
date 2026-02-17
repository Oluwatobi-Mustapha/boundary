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