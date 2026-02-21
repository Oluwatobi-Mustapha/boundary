resource "aws_sqs_queue" "workflow_dlq" {
  name                      = "boundary-workflow-dlq-${var.environment}"
  message_retention_seconds = 1209600  # 14 days for forensics
  sqs_managed_sse_enabled   = true

  tags = {
    Environment = var.environment
    Component   = "AccessWorkflow"
  }
}

resource "aws_sqs_queue" "workflow_queue" {
  name                       = "boundary-workflow-queue-${var.environment}"
  visibility_timeout_seconds = 300  # 5 minutes (6x Lambda timeout)
  message_retention_seconds  = 86400  # 1 day
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.workflow_dlq.arn
    maxReceiveCount     = 3
  })

  tags = {
    Environment = var.environment
    Component   = "AccessWorkflow"
  }
}
