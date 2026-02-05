# Boundary Infrastructure: Bootstrap Layer

## Scope

This directory contains the **rarely changed** foundation of the infrastructure.

## Ownership

### **Platform Engineering / Security Team**

## Purpose

This Terraform root provisions the prerequisites required to run Terraform securely and automatically:

- **State Storage:** S3 bucket (encrypted, versioned) to store `terraform.tfstate`
- **State Locking:** DynamoDB table to prevent concurrent `terraform apply` runs
- **Trust Anchor:** OpenID Connect (OIDC) provider for GitHub Actions (enables keyless CI/CD)

---

## The "Genesis" Protocol (First Run Only)

Terraform cannot store its state in an S3 bucket that does not exist yet.  
During the first deployment, you must follow this exact order.

---

### Step 1: Local State Initialization

Ensure `backend.tf` has the `backend "s3" { ... }` block **commented out**.

Run initialization:

```bash
terraform init
