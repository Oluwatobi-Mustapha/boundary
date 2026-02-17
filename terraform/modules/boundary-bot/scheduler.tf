
# EVENTBRIDGE SCHEDULER

# Note: We use the newer "aws_scheduler_schedule" resource (EventBridge Scheduler)
# instead of the older CloudWatch Events Rule, as it is the modern standard.

resource "aws_iam_role" "scheduler" {
  name = "${var.project_name}-${var.environment}-scheduler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "scheduler.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler_invoke_lambda" {
  name = "invoke-janitor"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.janitor.arn
    }]
  })
}

resource "aws_scheduler_schedule" "janitor_tick" {
  name       = "${var.project_name}-${var.environment}-janitor-tick"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = var.schedule_expression

  target {
    arn      = aws_lambda_function.janitor.arn
    role_arn = aws_iam_role.scheduler.arn
  }
}