provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "Boundary"
      Environment = "Dev"
      ManagedBy   = "Terraform"
      Owner       = "PlatformEngineering"
    }
  }
}