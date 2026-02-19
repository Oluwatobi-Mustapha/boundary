# ------------------------------------------------------------------------------
# 1. Terraform State Storage (S3)
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "terraform_state" {
  # Naming convention: project-tf-state-random_suffix
  # We use a prefix so AWS assigns a unique name, avoiding global naming conflicts
  bucket_prefix = "${var.project_name}-tf-state-"
  force_destroy = false

  lifecycle {
    prevent_destroy = false
  }

  tags = {
    Name = "Terraform State Store"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------------------------------------------
# 2. State Locking (DynamoDB)
# ------------------------------------------------------------------------------
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "${var.project_name}-tf-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name = "Terraform State Lock Table"
  }
}

# ------------------------------------------------------------------------------
# 3. GitHub Actions Trust (OIDC)
# ------------------------------------------------------------------------------
# Retrieves the generic GitHub certificate thumbprint
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]
}

# ------------------------------------------------------------------------------
# 4. CI/CD IAM Role
# ------------------------------------------------------------------------------
# This role allows GitHub Actions to assume identity in this account
# strictly scoped to the repository defined in variables.tf
resource "aws_iam_role" "ci_ro" {
  name = "${var.project_name}-ci-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Condition = {
          StringLike = {
            # Only allow this specific repository to assume the role
            "token.actions.githubusercontent.com:sub" : "repo:${var.github_org}/${var.github_repo}:*"
          }
        }
      }
    ]
  })
}

# Attach AdministratorAccess to the CI role so it can provision resources.
# In a stricter environment, we would scope this down, but for a Bootstrap 
# role that manages infrastructure, Admin is standard practice.
resource "aws_iam_role_policy_attachment" "ci_admin" {
  role       = aws_iam_role.ci_ro.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}