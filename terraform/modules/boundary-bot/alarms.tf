# ------------------------------------------------------------------------------
# NOTIFICATION CHANNEL (SNS)
# ------------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-${var.environment}-boundary-alerts"
}

# ------------------------------------------------------------------------------
# CLOUDWATCH ALARM
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "janitor_errors" {
  alarm_name          = "${var.project_name}-${var.environment}-janitor-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2 # Wait for 2 failures
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60 # Check every 1 minute
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Triggers if the Janitor fails to run 2 times in a row. Potential Security Risk: Zombie Access."

  # Connect to the specific Lambda Function
  dimensions = {
    FunctionName = aws_lambda_function.janitor.function_name
  }

  # Send notification to SNS
  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn] # Notify when fixed
}