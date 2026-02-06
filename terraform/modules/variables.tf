variable "groups" {
  description = "List of Group names to create in the Identity Store (e.g., ['Boundary-Devs', 'Boundary-Sec'])"
  type        = list(string)
  default     = []
}

variable "permission_sets" {
  description = "Map of Permission Set definitions. Key is the name."
  type = map(object({
    description      = string
    session_duration = string       # ISO 8601 format, e.g., PT2H
    managed_policies = list(string) # List of AWS Managed Policy ARNs
  }))
  default = {}
}