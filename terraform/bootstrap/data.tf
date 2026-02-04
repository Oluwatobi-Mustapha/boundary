# Find the existing IAM Identity Center (SSO) instance
data "aws_ssoadmin_instances" "this" {}

locals {
  # The ARN of your SSO Instance
  sso_instance_arn = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  # The ID of your Identity Store (where Users/Groups live)
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]
}