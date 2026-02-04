# 1. ViewOnly (Strict Audit)
resource "aws_ssoadmin_permission_set" "view_only" {
  name             = "ViewOnly"
  description      = "Strict auditing access. Cannot read data content (S3), only metadata."
  instance_arn     = local.sso_instance_arn
  session_duration = "PT12H"
}
resource "aws_ssoadmin_managed_policy_attachment" "view_only_attach" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.view_only.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# 2. ReadOnly (Standard Dev)
resource "aws_ssoadmin_permission_set" "read_only" {
  name             = "ReadOnlyAccess"
  description      = "Standard read access for developers."
  instance_arn     = local.sso_instance_arn
  session_duration = "PT12H"
}
resource "aws_ssoadmin_managed_policy_attachment" "read_only_attach" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.read_only.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# 3. PowerUser (Sandbox Builder)
resource "aws_ssoadmin_permission_set" "power_user" {
  name             = "PowerUserAccess"
  description      = "Builder access. Can create resources but cannot change networking or IAM."
  instance_arn     = local.sso_instance_arn
  session_duration = "PT4H" # Shorter duration for higher risk
}
resource "aws_ssoadmin_managed_policy_attachment" "power_user_attach" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.power_user.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# 4. Administrator (Break Glass)
resource "aws_ssoadmin_permission_set" "admin" {
  name             = "AdministratorAccess"
  description      = "Full access. RESTRICTED USE ONLY."
  instance_arn     = local.sso_instance_arn
  session_duration = "PT1H" # Very short duration
}
resource "aws_ssoadmin_managed_policy_attachment" "admin_attach" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.admin.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}