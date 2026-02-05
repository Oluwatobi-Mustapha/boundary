# Boundary Identity Module

This module manages the **nouns** of AWS IAM Identity Center (SSO):

- **Permission Sets**: Define what a user can do (for example: `ReadOnly`, `Administrator`).
- **Groups**: Define who users are grouped as (for example: `Developers`, `Security`).

---

## Usage

```hcl
module "identity" {
  source = "../../modules/boundary-identity"

  # 1) Define Groups to create in the Identity Store
  groups = ["Boundary-Developers", "Boundary-Admins"]

  # 2) Define Permission Sets and their properties
  permission_sets = {
    "ReadOnly" = {
      description      = "Read-only access to resources"
      session_duration = "PT2H" # 2 Hours
      managed_policies = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
    },
    "Administrator" = {
      description      = "Full administrative access"
      session_duration = "PT1H" # 1 Hour
      managed_policies = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    }
  }
}
```

## Requirements

- **AWS IAM Identity Center (SSO)** must be enabled in the region where this module is applied.
- The Terraform principal must have permissions to manage Identity Center:
  - `sso-admin:*`
  - `identitystore:*`


## Inputs

| Name | Type | Description |
|------|------|-------------|
| `groups` | `list(string)` | A list of group names to create in the Identity Store. |
| `permission_sets` | `map(object)` | A map defining permission sets, session durations, and attached policies. |



## Outputs

| Name | Type | Description |
|------|------|-------------|
| `permission_set_arns` | `map(string)` | Map of Permission Set Name → ARN. |
| `group_ids` | `map(string)` | Map of Group Name → Identity Store ID. |
