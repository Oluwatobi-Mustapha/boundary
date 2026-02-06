# ------------------------------------------------------------------------------
# INFRASTRUCTURE DISCOVERY
# ------------------------------------------------------------------------------
# This looks up the CI/CD Role ARN exported by the Bootstrap phase.
# It prevents us from having to copy-paste the ARN manually.

data "aws_ssm_parameter" "ci_role_arn" {
  name = "/boundary/bootstrap/ci_role_arn"
}

# Example usage: You might use this ARN if you were creating a trust policy
# for a local resource that the CI pipeline needs to assume.