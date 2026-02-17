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

# --- NEW: SECRETS PASS-THROUGH ---
variable "boundary_secrets" {
  description = "Map of configuration secrets (Group IDs, OU IDs) to pass to the Lambda environment"
  type        = map(string)
  default     = {}
  sensitive   = true # Hides values from CLI output (Plan/Apply logs)
}