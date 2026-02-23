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

# ------------------------------------------------------------------------------
# LOG-BASED METRIC: SLACK REVOCATION NOTIFICATION FAILURES
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "janitor_slack_notify_failures" {
  name           = "${var.project_name}-${var.environment}-janitor-slack-notify-failures"
  log_group_name = aws_cloudwatch_log_group.janitor.name

  # Matches janitor warnings like:
  # "Revoked req-..., but failed to send Slack revocation notification: ..."
  pattern = "failed to send Slack revocation notification"

  metric_transformation {
    name      = "SlackRevocationNotificationFailures"
    namespace = "Boundary/Janitor"
    value     = "1"
  }
}

# ------------------------------------------------------------------------------
# CLOUDWATCH ALARM: SLACK REVOCATION NOTIFICATION FAILURES
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "janitor_slack_notify_failures" {
  alarm_name          = "${var.project_name}-${var.environment}-janitor-slack-notify-failures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "SlackRevocationNotificationFailures"
  namespace           = "Boundary/Janitor"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_description   = "Triggers when Janitor revokes access but fails to notify requester in Slack."

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]
}

# ------------------------------------------------------------------------------
# SAVED LOGS INSIGHTS QUERY: QUICK TRIAGE FOR JANITOR SLACK FAILURES
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_query_definition" "janitor_slack_notify_failures" {
  name = "${var.project_name}-${var.environment}-janitor-slack-notify-failures"

  log_group_names = [
    aws_cloudwatch_log_group.janitor.name
  ]

  query_string = <<-EOT
    fields @timestamp, @message
    | filter @message like /failed to send Slack revocation notification/
    | parse @message /Revoked (?<request_id>req-[^,]+), but failed to send Slack revocation notification: (?<error>.*)/
    | sort @timestamp desc
    | limit 100
  EOT
}
