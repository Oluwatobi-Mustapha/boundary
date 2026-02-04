output "sso_instance_arn" {
  value = local.sso_instance_arn
}

output "group_ids" {
  value = {
    developers      = aws_identitystore_group.developers.group_id
    security_admins = aws_identitystore_group.security_admins.group_id
    auditors        = aws_identitystore_group.auditors.group_id
  }
}

output "permission_set_arns" {
  value = {
    readonly   = aws_ssoadmin_permission_set.read_only.arn
    power_user = aws_ssoadmin_permission_set.power_user.arn
    admin      = aws_ssoadmin_permission_set.admin.arn
    view_only  = aws_ssoadmin_permission_set.view_only.arn
  }
}