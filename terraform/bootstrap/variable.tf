variable "aws_region" {
  description = "The AWS region where resources will be deployed."
  type        = string
  default     = "us-east-1" # Defaults to N. Virginia, but easily overridable
}