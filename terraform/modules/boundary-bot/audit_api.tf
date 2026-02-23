# ------------------------------------------------------------------------------
# AUDIT API IAM ROLE
# ------------------------------------------------------------------------------
resource "aws_iam_role" "audit_api_execution" {
  name = "boundary-${var.environment}-audit-api-role"

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

resource "aws_iam_role_policy_attachment" "audit_api_basic_logs" {
  role       = aws_iam_role.audit_api_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "audit_api_dynamodb" {
  name = "boundary-audit-api-dynamodb-${var.environment}"
  role = aws_iam_role.audit_api_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyBoundaryState"
        Effect = "Allow"
        Action = [
          "dynamodb:Query",
          "dynamodb:GetItem"
        ]
        Resource = [
          var.dynamodb_table_arn,
          "${var.dynamodb_table_arn}/index/*"
        ]
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# AUDIT API LAMBDA
# ------------------------------------------------------------------------------
resource "aws_lambda_function" "audit_api" {
  function_name = "boundary-${var.environment}-audit-api"
  role          = aws_iam_role.audit_api_execution.arn
  handler       = "audit_api.lambda_handler"
  runtime       = "python3.11"
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  environment {
    variables = merge(
      {
        DYNAMODB_TABLE          = var.dynamodb_table_name
        LOG_LEVEL               = "INFO"
        AUDIT_API_MAX_PAGE_SIZE = "200"
      },
      var.extra_env_vars
    )
  }
}

# ------------------------------------------------------------------------------
# AUDIT API ROUTES (Read-only, authenticated via AWS IAM)
# ------------------------------------------------------------------------------
resource "aws_apigatewayv2_integration" "audit_api_integration" {
  api_id             = aws_apigatewayv2_api.slack_api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.audit_api.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "audit_requests_route" {
  api_id             = aws_apigatewayv2_api.slack_api.id
  route_key          = "GET /api/requests"
  target             = "integrations/${aws_apigatewayv2_integration.audit_api_integration.id}"
  authorization_type = "AWS_IAM"
}

resource "aws_apigatewayv2_route" "audit_request_by_id_route" {
  api_id             = aws_apigatewayv2_api.slack_api.id
  route_key          = "GET /api/requests/{request_id}"
  target             = "integrations/${aws_apigatewayv2_integration.audit_api_integration.id}"
  authorization_type = "AWS_IAM"
}

resource "aws_apigatewayv2_route" "audit_metrics_route" {
  api_id             = aws_apigatewayv2_api.slack_api.id
  route_key          = "GET /api/metrics"
  target             = "integrations/${aws_apigatewayv2_integration.audit_api_integration.id}"
  authorization_type = "AWS_IAM"
}

resource "aws_apigatewayv2_route" "audit_exports_route" {
  api_id             = aws_apigatewayv2_api.slack_api.id
  route_key          = "GET /api/exports.csv"
  target             = "integrations/${aws_apigatewayv2_integration.audit_api_integration.id}"
  authorization_type = "AWS_IAM"
}

resource "aws_lambda_permission" "api_gw_invoke_audit_api" {
  statement_id  = "AllowAPIGatewayInvokeAuditApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.audit_api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.slack_api.execution_arn}/*/*/api/*"
}

# ------------------------------------------------------------------------------
# CALLER POLICY OUTPUT: read-only invoke rights for API + dashboard
# ------------------------------------------------------------------------------
resource "aws_iam_policy" "audit_read_invoke" {
  name        = "boundary-${var.environment}-audit-read-invoke"
  description = "Read-only invoke policy for Boundary audit API and dashboard routes"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AuditReadInvoke"
        Effect = "Allow"
        Action = ["execute-api:Invoke"]
        Resource = [
          "${aws_apigatewayv2_api.slack_api.execution_arn}/*/GET/api/*",
          "${aws_apigatewayv2_api.slack_api.execution_arn}/*/GET/dashboard*"
        ]
      }
    ]
  })
}
