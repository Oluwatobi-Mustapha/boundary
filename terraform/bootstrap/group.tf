# 1. Developers
resource "aws_identitystore_group" "developers" {
  display_name      = "Boundary-Developers"
  description       = "Standard application developers"
  identity_store_id = local.identity_store_id
}

# 2. Security Admins
resource "aws_identitystore_group" "security_admins" {
  display_name      = "Boundary-SecurityAdmins"
  description       = "Cloud Security team (Approvers)"
  identity_store_id = local.identity_store_id
}

# 3. Auditors
resource "aws_identitystore_group" "auditors" {
  display_name      = "Boundary-Auditors"
  description       = "External or Internal Compliance Auditors"
  identity_store_id = local.identity_store_id
}