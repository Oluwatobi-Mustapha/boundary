# ------------------------------------------------------------------------------
# 1. CODE PACKAGING
# ------------------------------------------------------------------------------
# We zip the Project Root but exclude infrastructure and git files.
# This preserves the 'src/' folder structure so imports work in Lambda.
data "archive_file" "lambda_package" {
  type        = "zip"
  source_dir  = "${path.module}/../../.." # Project Root
  output_path = "${path.module}/build/boundary_bot.zip"

  excludes = [
    ".git",
    ".github",
    ".gitignore",
    "terraform",       # Don't include the infra in the app code
    "audit_logs",      # Don't include local logs
    "tests",
    "venv",
    "__pycache__",
    "Makefile",
    ".DS_Store"
  ]
}

# ------------------------------------------------------------------------------
# 2. LAMBDA FUNCTION
# ------------------------------------------------------------------------------
resource "aws_lambda_function" "janitor" {
  function_name = "${var.project_name}-${var.environment}-janitor"
  role          = aws_iam_role.janitor_execution.arn
  handler       = "src.janitor.lambda_handler" # Points to src/janitor.py
  runtime       = "python3.11"
  timeout       = 60 # Fail fast if it hangs
  memory_size   = 128

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE = var.dynamodb_table_name
      LOG_LEVEL      = "INFO"
    }
  }

  tags = {
    Name = "Boundary Janitor"
  }
}

# ------------------------------------------------------------------------------
# 3. LOGGING
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "janitor" {
  name              = "/aws/lambda/${aws_lambda_function.janitor.function_name}"
  retention_in_days = 14
}