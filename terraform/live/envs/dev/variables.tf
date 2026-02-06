variable "aws_region" {
  description = "AWS Region for this environment"
  type        = string
  default     = "us-east-1"
}

variable "groups" {
  description = "List of groups to create"
  type        = list(string)
}

variable "permission_sets" {
  description = "Configuration for Permission Sets"
  type = map(object({
    description      = string
    session_duration = string
    managed_policies = list(string)
  }))
}