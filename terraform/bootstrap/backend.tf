# ------------------------------------------------------------------------------
# Backend Configuration
# INSTRUCTIONS:
# 1. Comment this entire block out for the FIRST "terraform apply" (Genesis).
# 2. Run "terraform apply".
# 3. Get the bucket name and table name from the outputs.
# 4. Uncomment this block and fill in the values.
# 5. Run "terraform init -migrate-state".
# ------------------------------------------------------------------------------

# terraform {
#   backend "s3" {
#     # REPLACE WITH YOUR BUCKET NAME FROM OUTPUTS
#     bucket         = "boundary-tf-state-REPLACE-ME"
#     key            = "bootstrap/terraform.tfstate"
#     region         = "us-east-1"
#
#     # REPLACE WITH YOUR TABLE NAME FROM OUTPUTS
#     dynamodb_table = "boundary-tf-locks"
#     encrypt        = true
#   }
# }