resource "aws_lambda_function" "workflow_manager" {
  function_name = "boundary-workflow-manager-${var.environment}"
  role          = aws_iam_role.workflow_execution_role.arn
  handler       = "workflows.access_workflow.lambda_handler"
  runtime       = "python3.11"
  timeout       = 60

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT       = var.environment
      DYNAMODB_TABLE    = var.dynamodb_table_name
      LOG_LEVEL         = "INFO"
      IDENTITY_STORE_ID = var.identity_store_id
      SSO_INSTANCE_ARN  = var.sso_instance_arn
    }
  }
}

resource "aws_lambda_event_source_mapping" "sqs_trigger" {
  event_source_arn = aws_sqs_queue.workflow_queue.arn
  function_name    = aws_lambda_function.workflow_manager.arn
  batch_size       = 1
}

resource "aws_iam_role" "workflow_execution_role" {
  name = "boundary-workflow-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "workflow_basic_execution" {
  role       = aws_iam_role.workflow_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
}

resource "aws_iam_role_policy" "workflow_dynamodb" {
  name = "workflow-dynamodb-access"
  role = aws_iam_role.workflow_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:Query",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem"
        ]
        Resource = [
          var.dynamodb_table_arn,
          "${var.dynamodb_table_arn}/index/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "workflow_aws_services" {
  name = "workflow-aws-services-access"
  role = aws_iam_role.workflow_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMParameterAccess"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/boundary/*"
      },
      {
        Sid    = "IdentityStoreAccess"
        Effect = "Allow"
        Action = [
          "identitystore:DescribeUser",
          "identitystore:ListUsers",
          "identitystore:ListGroupMembershipsForMember"
        ]
        Resource = "*"
      },
      {
        Sid    = "OrganizationsAccess"
        Effect = "Allow"
        Action = [
          "organizations:DescribeAccount",
          "organizations:ListTagsForResource"
        ]
        Resource = "*"
      }
    ]
  })
}
