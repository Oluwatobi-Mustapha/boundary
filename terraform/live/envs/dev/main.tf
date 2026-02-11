# ------------------------------------------------------------------------------
# BOUNDARY IDENTITY MODULE
# ------------------------------------------------------------------------------
module "boundary_identity" {
  source = "../../../modules/boundary-identity"

  groups          = var.groups
  permission_sets = var.permission_sets
}

# ------------------------------------------------------------------------------
# BOUNDARY STATE MODULE (New)
# ------------------------------------------------------------------------------
module "boundary_state" {
  source = "../../../modules/boundary-state"

  project_name = "boundary"
  environment  = "dev"
}