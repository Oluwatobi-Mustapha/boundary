# These outputs are strictly for human verification and the Genesis setup.
# Downstream automation will use the SSM parameters defined in ssm.tf.

output "state_bucket_name" {
  description = "The name of the S3 bucket created for Terraform state. COPY THIS for backend.tf."
  value       = aws_s3_bucket.terraform_state.id
}

output "dynamodb_table_name" {
  description = "The name of the DynamoDB table created for state locking. COPY THIS for backend.tf."
  value       = aws_dynamodb_table.terraform_locks.name
}

output "ci_role_arn" {
  description = "The ARN of the IAM role created for GitHub Actions."
  value       = aws_iam_role.ci_ro.arn
}