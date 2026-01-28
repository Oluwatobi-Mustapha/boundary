# Architecture Reference

## 1. High-Level Design
The system operates on a strict separation of concerns between **Infrastructure Configuration** (Design Time) and **Access Orchestration** (Runtime).

### The "Split-Brain" Model
* **Static (Terraform):** Defines *what is possible*. It creates Permission Sets, Account assignments, and broadly scoped IAM Roles. It defines the "shape" of the security landscape.
* **Dynamic (The Bot):** Defines *who has access right now*. It utilizes the AWS Identity Center (SSO) API to grant and revoke time-bound access.

## 2. Component Diagram

```mermaid
graph TD
    User[User (Slack)] -->|1. Request Access| Bot[Access Control Bot]
    
    subgraph "Control Plane"
        Bot -->|2. Validate Policy| OPA[Policy Engine (YAML)]
        Bot -->|3. Log Audit| DB[(Audit Log / DynamoDB)]
        Bot -->|4. Request Approval| Approver[Human Approver]
    end
    
    subgraph "AWS Infrastructure (Terraform Managed)"
        IC[AWS Identity Center]
        PermSet[Permission Sets]
        TargetAcc[Target AWS Accounts 0..1000]
    end
    
    Approver -->|5. Approve| Bot
    Bot -->|6. Grant Access (API Call)| IC
    IC -.->|7. Federate| TargetAcc
    
    Bot -->|8. Revoke Timer (TTL)| IC
