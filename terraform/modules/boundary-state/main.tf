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

  # The Janitor's Index: Find ACTIVE requests that have expired
  global_secondary_index {
    name               = "ExpirationIndex"
    hash_key           = "status"
    range_key          = "expires_at"
    projection_type    = "ALL"
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