# ------------------------------------------------------------------------------
# IAM EXECUTION ROLE
# ------------------------------------------------------------------------------
resource "aws_iam_role" "janitor_execution" {
  name = "${var.project_name}-${var.environment}-janitor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# ------------------------------------------------------------------------------
# IAM POLICIES
# ------------------------------------------------------------------------------

# 1. Logging (Standard Lambda requirement)
resource "aws_iam_role_policy_attachment" "basic_execution" {
  role       = aws_iam_role.janitor_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# 2. Application Logic (DynamoDB + SSO)
resource "aws_iam_role_policy" "janitor_logic" {
  name = "boundary-janitor-permissions"
  role = aws_iam_role.janitor_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DynamoDBAccess"
        Effect   = "Allow"
        Action   = [
          "dynamodb:Query",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem"
        ]
        Resource = [
          var.dynamodb_table_arn,
          "${var.dynamodb_table_arn}/index/*" # Allow GSI queries
        ]
      },
      {
        Sid      = "SSOAccess"
        Effect   = "Allow"
        Action   = [
          "sso:DeleteAccountAssignment",
          "sso:DescribePermissionSet", # Required for adapter init
          "sso:ListTagsForResource"    # Required for adapter init
        ]
        Resource = "*" # SSO actions often require wildcard scope, or specific Instance ARN
      },
      {
        Sid      = "OrgsAccess"
        Effect   = "Allow"
        Action   = [
          "organizations:ListParents",
          "organizations:ListTagsForResource"
        ]
        Resource = "*" # Organizations calls are global/root scoped
      }
    ]
  })
}