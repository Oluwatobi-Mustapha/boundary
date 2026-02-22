# ------------------------------------------------------------------------------
# 0. BUILD LAMBDA PACKAGE
# ------------------------------------------------------------------------------
resource "null_resource" "install_dependencies" {
  triggers = {
    requirements = filemd5("${path.module}/../../../requirements.txt")
    config_file  = filemd5("${path.module}/../../../config/access_rules.yaml")
  }

  provisioner "local-exec" {
    command = <<EOT
      rm -rf ${path.module}/build/package
      mkdir -p ${path.module}/build/package
      cp -r ${path.module}/../../../src/* ${path.module}/build/package/
      pip3 install -r ${path.module}/../../../requirements.txt -t ${path.module}/build/package/
      cp ${path.module}/../../../config/access_rules.yaml ${path.module}/build/package/
    EOT
  }
}

# ------------------------------------------------------------------------------
# 1. CODE PACKAGING
# ------------------------------------------------------------------------------
data "archive_file" "lambda_package" {
  type        = "zip"
  source_dir  = "${path.module}/build/package"
  output_path = "${path.module}/build/boundary_bot.zip"

  depends_on = [null_resource.install_dependencies]
}

# ------------------------------------------------------------------------------
# 2. LAMBDA FUNCTION
# ------------------------------------------------------------------------------
resource "aws_lambda_function" "janitor" {
  function_name = "${var.project_name}-${var.environment}-janitor"
  role          = aws_iam_role.janitor_execution.arn
  handler       = "janitor.lambda_handler"
  runtime       = "python3.11"
  timeout       = 60
  memory_size   = 128
  publish       = true

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

# ------------------------------------------------------------------------------
# 2b. LAMBDA ALIAS
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