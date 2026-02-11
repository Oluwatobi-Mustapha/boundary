variable "project_name" {
  description = "Project name prefix (e.g., boundary)"
  type        = string
  default     = "boundary"
}

variable "environment" {
  description = "Deployment environment (e.g., dev, prod)"
  type        = string
}
