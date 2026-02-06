# ------------------------------------------------------------------------------
# REMOTE STATE CONFIGURATION (Pattern A)
# ------------------------------------------------------------------------------
# Update 'bucket' and 'dynamodb_table' with the outputs from your Bootstrap phase.
# The 'key' ensures this state file is isolated to the Dev environment.
# ------------------------------------------------------------------------------

terraform {
  backend "s3" {
    bucket         = "REPLACE_WITH_BOOTSTRAP_BUCKET_NAME"
    key            = "envs/dev/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "REPLACE_WITH_BOOTSTRAP_LOCK_TABLE_NAME"
    encrypt        = true
  }
}