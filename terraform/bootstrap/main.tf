terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "boundary"
      ManagedBy = "Terraform"
      Owner     = "OpenSource"
    }
  }
}

# We need to look up the SSO Instance to get the ARN and Store ID.
data "aws_ssoadmin_instances" "this" {}

locals {
  # Automatically grabs the ARN of your Identity Center instance
  sso_instance_arn = tolist(data.aws_ssoadmin_instances.this.arns)[0]

  # Automatically grabs the Identity Store ID (Required to create groups)
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]
}
