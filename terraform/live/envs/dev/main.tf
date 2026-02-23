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

  # Wiring Secrets + Identity outputs (Config) -> Bot
  extra_env_vars = merge(
    var.boundary_secrets,
    {
      BOUNDARY_DEVELOPERS_ID      = module.boundary_identity.group_ids[var.boundary_group_name_map.developers]
      BOUNDARY_AUDITORS_ID        = module.boundary_identity.group_ids[var.boundary_group_name_map.auditors]
      BOUNDARY_SECURITY_ADMINS_ID = module.boundary_identity.group_ids[var.boundary_group_name_map.security_admins]
    },
    module.boundary_identity.permission_set_arns
  )

  # Schedule
  schedule_expression = "rate(1 minute)"
}
