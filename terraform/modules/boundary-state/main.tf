resource "aws_dynamodb_table" "active_requests" {
  name         = "${var.project_name}-${var.environment}-active-requests"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "request_id"

  # Attribute definitions (Only for keys and indexes)
  attribute {
    name = "request_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "expires_at"
    type = "N"
  }

  attribute {
    name = "created_at"
    type = "N"
  }

  attribute {
    name = "account_id"
    type = "S"
  }

  attribute {
    name = "requester_slack_user_id"
    type = "S"
  }

  attribute {
    name = "permission_set_name"
    type = "S"
  }

  # The Janitor's Index: Find ACTIVE requests that have expired
  global_secondary_index {
    name            = "ExpirationIndex"
    hash_key        = "status"
    range_key       = "expires_at"
    projection_type = "ALL"
  }

  # API Query Index: Filter by status and time range
  global_secondary_index {
    name            = "StatusCreatedAtIndex"
    hash_key        = "status"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # API Query Index: Filter by account and time range
  global_secondary_index {
    name            = "AccountCreatedAtIndex"
    hash_key        = "account_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # API Query Index: Filter by requester (Slack user) and time range
  global_secondary_index {
    name            = "RequesterCreatedAtIndex"
    hash_key        = "requester_slack_user_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # API Query Index: Filter by role/permission set and time range
  global_secondary_index {
    name            = "RoleCreatedAtIndex"
    hash_key        = "permission_set_name"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # Auto-delete records (e.g., 90 days after expiry)
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name        = "Boundary Active Requests"
    Environment = var.environment
  }
}
