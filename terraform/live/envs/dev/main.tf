# ------------------------------------------------------------------------------
# BOUNDARY IDENTITY MODULE (The Body)
# ------------------------------------------------------------------------------
module "boundary_identity" {
  source = "../../../modules/boundary-identity"

  groups          = var.groups
  permission_sets = var.permission_sets
}

# ------------------------------------------------------------------------------
# BOUNDARY STATE MODULE (The Memory)
# ------------------------------------------------------------------------------
module "boundary_state" {
  source = "../../../modules/boundary-state"

  project_name = "boundary"
  environment  = "dev"
}

# ------------------------------------------------------------------------------
# BOUNDARY BOT (The Janitor)
# ------------------------------------------------------------------------------
module "boundary_bot" {
  source = "../../../modules/boundary-bot"

  project_name = "boundary"
  environment  = "dev"

  # Wiring State (Memory) -> Bot
  dynamodb_table_name = module.boundary_state.table_name
  dynamodb_table_arn  = module.boundary_state.table_arn

  # Wiring Identity (Body) -> Bot
  sso_instance_arn  = module.boundary_identity.sso_instance_arn
  identity_store_id = module.boundary_identity.identity_store_id

  # Wiring Secrets (Config) -> Bot
  # Pass the secrets from tfvars down to the Lambda
  extra_env_vars = var.boundary_secrets

  # Schedule
  schedule_expression = "rate(1 minute)"
}