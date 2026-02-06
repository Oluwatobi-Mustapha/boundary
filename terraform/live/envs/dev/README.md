# Development Environment (Dev)

This is the sandbox for the **Boundary Access System**.

All changes to **Permission Sets**, **Groups**, or **Policies** must be applied here first before promotion to higher environments.

---

## Purpose

This environment exists to:

- Validate Terraform module changes.
- Test new IAM policies without affecting production workloads.
- Verify the Python Policy Engine integration.

---

## Configuration

This root expects a `terraform.tfvars` file.

A safe template is provided:

- `terraform.tfvars.example` (committed)

To run locally:

```bash
cp terraform.tfvars.example terraform.tfvars
```

***Then edit `terraform.tfvars` to match your environment. This file is ignored by Git and should not be committed.***

---

## Apply Instructions

Run Terraform in the following order:

### 1) Initialize

```bash
terraform init
```

### 2) Plan

```bash
terraform plan -out=tfplan
```

### 3) Apply

```bash
terraform apply tfplan
```

---

## State Backends

- This environment uses the S3 backend bucket provisioned during the Bootstrap phase.

- Ensure `backend.tf` is configured with the correct bucket name.
