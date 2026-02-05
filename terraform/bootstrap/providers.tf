provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "Boundary"
      Layer     = "Bootstrap"
      ManagedBy = "Terraform"
      Owner     = "PlatformSecurity"
    }
  }
}