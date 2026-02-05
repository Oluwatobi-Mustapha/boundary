variable "aws_region" {
  description = "The AWS region where bootstrap resources (S3, DynamoDB) will be created."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project identifier used for naming resources (e.g., boundary)."
  type        = string
  default     = "boundary"
}

variable "github_org" {
  description = "The GitHub Organization name for OIDC trust (e.g., your-username)."
  type        = string
}

variable "github_repo" {
  description = "The GitHub Repository name for OIDC trust (e.g., boundary)."
  type        = string
}