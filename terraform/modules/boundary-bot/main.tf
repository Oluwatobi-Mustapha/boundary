# ------------------------------------------------------------------------------
# 1. CODE PACKAGING
# ------------------------------------------------------------------------------
data "archive_file" "lambda_package" {
  type        = "zip"
  source_dir  = "${path.module}/../../.."
  output_path = "${path.module}/build/boundary_bot.zip"

  excludes = [
    ".git", ".github", ".gitignore", "terraform", "audit_logs",
    "tests", "venv", "__pycache__", "Makefile", ".DS_Store"
  ]
}

# ------------------------------------------------------------------------------
# 2. LAMBDA FUNCTION
# ------------------------------------------------------------------------------
resource "aws_lambda_function" "janitor" {
  function_name = "${var.project_name}-${var.environment}-janitor"
  role          = aws_iam_role.janitor_execution.arn
  handler       = "src.janitor.lambda_handler"
  runtime       = "python3.11"
  timeout       = 60
  memory_size   = 128

  # CRITICAL: Publish a new version on every code change
  publish = true

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

  tags = {
    Name = "Boundary Janitor"
  }
}

# ------------------------------------------------------------------------------
# 2b. LAMBDA ALIAS (The Stable Pointer)
# ------------------------------------------------------------------------------
resource "aws_lambda_alias" "janitor_prod" {
  name             = "prod"
  description      = "Production alias for the Janitor"
  function_name    = aws_lambda_function.janitor.function_name
  function_version = aws_lambda_function.janitor.version
}

# ------------------------------------------------------------------------------
# 3. LOGGING
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "janitor" {
  name              = "/aws/lambda/${aws_lambda_function.janitor.function_name}"
  retention_in_days = 14
}