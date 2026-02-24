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

variable "boundary_group_name_map" {
  description = "Maps logical Boundary roles to Identity Store group display names."
  type = object({
    developers      = string
    auditors        = string
    security_admins = string
  })
  default = {
    developers      = "Boundary-Developers"
    auditors        = "Boundary-Auditors"
    security_admins = "Boundary-Security-Admins"
  }

  validation {
    condition = (
      length(trimspace(var.boundary_group_name_map.developers)) > 0 &&
      length(trimspace(var.boundary_group_name_map.auditors)) > 0 &&
      length(trimspace(var.boundary_group_name_map.security_admins)) > 0
    )
    error_message = "All boundary_group_name_map values must be non-empty group display names."
  }
}

# --- NEW: SECRETS PASS-THROUGH ---
variable "boundary_secrets" {
  description = "Map of configuration secrets (Group IDs, OU IDs) to pass to the Lambda environment"
  type        = map(string)
  default     = {}
  sensitive   = true # Hides values from CLI output (Plan/Apply logs)
}
