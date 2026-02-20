# ------------------------------------------------------------------------------
# 1. SLACK BOT IAM ROLE (Separation of Duties)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "slack_bot_execution" {
  name = "boundary-${var.environment}-slack-bot-role"

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

# Add Basic Lambda Execution (CloudWatch Logs)
resource "aws_iam_role_policy_attachment" "slack_bot_basic_logs" {
  role       = aws_iam_role.slack_bot_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Grab the current AWS Account ID and Region dynamically
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ------------------------------------------------------------------------------
# 1.5 SLACK BOT IAM POLICY (The Vault Badge)
# ------------------------------------------------------------------------------
resource "aws_iam_role_policy" "slack_bot_ssm" {
  name = "slack-bot-ssm-policy"
  role = aws_iam_role.slack_bot_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "ssm:GetParameter"
        # We strictly limit this to ONLY the Slack signing secret
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/boundary/slack/signing_secret"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 2. SLACK BOT LAMBDA FUNCTION
# ------------------------------------------------------------------------------
resource "aws_lambda_function" "slack_bot" {
  function_name = "boundary-${var.environment}-slack-bot"
  role          = aws_iam_role.slack_bot_execution.arn
  handler       = "slack_bot.lambda_handler" # We will create this python file next
  runtime       = "python3.11"
  timeout       = 10 # Slack requires a response within 3 seconds!

  # We reuse the exact same zip file we built in main.tf
  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE = var.dynamodb_table_name
      LOG_LEVEL      = "INFO"
    }
  }
}

# ------------------------------------------------------------------------------
# 3. HTTP API GATEWAY (v2)
# ------------------------------------------------------------------------------
resource "aws_apigatewayv2_api" "slack_api" {
  name          = "boundary-${var.environment}-slack-api"
  protocol_type = "HTTP"
}

# The Stage acts as our deployment environment (default routes everything)
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.slack_api.id
  name        = "$default"
  auto_deploy = true
}

# Connect the API Gateway to our Lambda Function
resource "aws_apigatewayv2_integration" "slack_bot_integration" {
  api_id             = aws_apigatewayv2_api.slack_api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.slack_bot.invoke_arn
  integration_method = "POST"
}

# Create the specific /webhook route
resource "aws_apigatewayv2_route" "slack_webhook_route" {
  api_id    = aws_apigatewayv2_api.slack_api.id
  route_key = "POST /webhook"
  target    = "integrations/${aws_apigatewayv2_integration.slack_bot_integration.id}"
}

# ------------------------------------------------------------------------------
# 4. RESOURCE-BASED POLICY (The "Door Pass")
# ------------------------------------------------------------------------------
resource "aws_lambda_permission" "api_gw_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_bot.function_name
  principal     = "apigateway.amazonaws.com"

  # Only allow THIS specific API Gateway to trigger the Lambda
  source_arn = "${aws_apigatewayv2_api.slack_api.execution_arn}/*/*"
}

# Output the URL so we can copy/paste it into the Slack Developer Portal later
output "slack_webhook_url" {
  value       = "${aws_apigatewayv2_api.slack_api.api_endpoint}/webhook"
  description = "The public URL to paste into the Slack API portal"
}