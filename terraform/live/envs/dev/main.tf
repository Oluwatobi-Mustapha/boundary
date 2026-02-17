
# BOUNDARY IDENTITY MODULE

module "boundary_identity" {
  source = "../../../modules/boundary-identity"

  groups          = var.groups
  permission_sets = var.permission_sets
}


# BOUNDARY STATE MODULE (New)
module "boundary_state" {
  source = "../../../modules/boundary-state"

  project_name = "boundary"
  environment  = "dev"
}

# BOUNDARY BOT (The Janitor) - NEW
module "boundary_bot" {
  source = "../../../modules/boundary-bot"

  project_name = "boundary"
  environment  = "dev"

  # Wiring State (Memory) -> Bot
  dynamodb_table_name = module.boundary_state.table_name
  dynamodb_table_arn  = module.boundary_state.table_arn

  # Wiring Identity (Body) -> Bot
  # These inputs rely on the updated outputs.tf in boundary-identity
  sso_instance_arn  = module.boundary_identity.sso_instance_arn
  identity_store_id = module.boundary_identity.identity_store_id

  # Schedule
  schedule_expression = "rate(1 minute)"
}