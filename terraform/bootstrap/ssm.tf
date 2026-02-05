# ------------------------------------------------------------------------------
# SSM Parameter Store Exports
# These allow "Live" roots to discover bootstrap resources without copy-paste.
# ------------------------------------------------------------------------------

resource "aws_ssm_parameter" "ci_role_arn" {
  name        = "/${var.project_name}/bootstrap/ci_role_arn"
  description = "ARN of the IAM Role for GitHub Actions CI/CD"
  type        = "String"
  value       = aws_iam_role.ci_ro.arn
}

resource "aws_ssm_parameter" "state_bucket" {
  name        = "/${var.project_name}/bootstrap/state_bucket_name"
  description = "Name of the S3 bucket storing Terraform state"
  type        = "String"
  value       = aws_s3_bucket.terraform_state.id
}

resource "aws_ssm_parameter" "lock_table" {
  name        = "/${var.project_name}/bootstrap/lock_table_name"
  description = "Name of the DynamoDB table for Terraform state locking"
  type        = "String"
  value       = aws_dynamodb_table.terraform_locks.name
}