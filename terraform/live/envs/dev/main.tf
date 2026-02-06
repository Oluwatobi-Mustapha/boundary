# ------------------------------------------------------------------------------
# BOUNDARY IDENTITY MODULE
# ------------------------------------------------------------------------------
module "boundary_identity" {
  source = "../../../modules/boundary-identity"

  groups          = var.groups
  permission_sets = var.permission_sets
}