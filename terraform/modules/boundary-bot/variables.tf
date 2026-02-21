variable "project_name" {
  description = "Project name prefix"
  type        = string
  default     = "boundary"
}

variable "environment" {
  description = "Deployment environment (e.g., dev)"
  type        = string
}

variable "dynamodb_table_name" {
  description = "The DynamoDB table containing active access requests"
  type        = string
}

variable "dynamodb_table_arn" {
  description = "The ARN of the DynamoDB table (for IAM policy scoping)"
  type        = string
}

variable "identity_store_id" {
  description = "The SSO Identity Store ID (for scoping permissions)"
  type        = string
}

variable "sso_instance_arn" {
  description = "The SSO Instance ARN"
  type        = string
}

variable "schedule_expression" {
  description = "How often the Janitor runs"
  type        = string
  default     = "rate(1 minute)"
}

variable "extra_env_vars" {
  description = "Map of additional environment variables to pass to the Lambda (e.g., config secrets)"
  type        = map(string)
  default     = {}
}

variable "slack_bot_token_parameter_name" {
  description = "SSM Parameter Store path for the Slack bot token used by workflow manager"
  type        = string
  default     = "/boundary/slack/bot_token"
}
