# ------------------------------------------------------------------------------
# EVENTBRIDGE SCHEDULER
# ------------------------------------------------------------------------------

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
      # CRITICAL: We must allow invoking the SPECIFIC ALIAS (:prod)
      Resource = "${aws_lambda_function.janitor.arn}:prod"
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
    # CRITICAL: Point to the ALIAS, not the function
    # This ensures the scheduler always triggers the stable 'prod' version
    arn      = aws_lambda_alias.janitor_prod.arn 
    role_arn = aws_iam_role.scheduler.arn
  }
}