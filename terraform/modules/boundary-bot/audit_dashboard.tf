# ------------------------------------------------------------------------------
# AUDIT DASHBOARD LAMBDA (Read-only HTML views)
# ------------------------------------------------------------------------------
resource "aws_lambda_function" "audit_dashboard" {
  function_name = "boundary-${var.environment}-audit-dashboard"
  role          = aws_iam_role.audit_api_execution.arn
  handler       = "audit_dashboard.lambda_handler"
  runtime       = "python3.11"
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  environment {
    variables = merge(
      {
        DYNAMODB_TABLE = var.dynamodb_table_name
        LOG_LEVEL      = "INFO"
      },
      var.extra_env_vars
    )
  }
}

resource "aws_apigatewayv2_integration" "audit_dashboard_integration" {
  api_id             = aws_apigatewayv2_api.slack_api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.audit_dashboard.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "audit_dashboard_home_route" {
  api_id             = aws_apigatewayv2_api.slack_api.id
  route_key          = "GET /dashboard"
  target             = "integrations/${aws_apigatewayv2_integration.audit_dashboard_integration.id}"
  authorization_type = "AWS_IAM"
}

resource "aws_apigatewayv2_route" "audit_dashboard_proxy_route" {
  api_id             = aws_apigatewayv2_api.slack_api.id
  route_key          = "GET /dashboard/{proxy+}"
  target             = "integrations/${aws_apigatewayv2_integration.audit_dashboard_integration.id}"
  authorization_type = "AWS_IAM"
}

resource "aws_lambda_permission" "api_gw_invoke_audit_dashboard" {
  statement_id  = "AllowAPIGatewayInvokeAuditDashboard"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.audit_dashboard.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.slack_api.execution_arn}/*/GET/dashboard*"
}
