
# REMOTE STATE CONFIGURATION (Pattern A)

# Update 'bucket' and 'dynamodb_table' with the outputs from your Bootstrap phase.
# The 'key' ensures this state file is isolated to the Dev environment.


terraform {
  backend "s3" {
    bucket         = "boundary-tf-state-20260206225739329700000001"
    key            = "envs/dev/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "boundary-tf-locks"
    encrypt        = true
  }
}   
