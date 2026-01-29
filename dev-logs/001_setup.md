
## 2026-01-29 

**Phase 0: Architecture & Data Design**

### The "Split-Brain" Decision
- **Decision:** We chose a "Split-Brain" model.
- **Reasoning:** Terraform is too slow (45+ mins) for ephemeral access across 1,000 accounts. We will use AWS Identity Center APIs for runtime grants and Terraform only for baseline architecture.

### The "Bot Crash" Problem
- **Solution:** We designed a DynamoDB schema with a Global Secondary Index (GSI) on `status + expires_at`.
- **Benefit:** The bot can wake up, run one query (find active requests where time < now), and revoke them. It is stateless and crash-recoverable.

### Configuration Strategy
- **Design:** We created `access_rules.yaml`.
- **Key Learnings:** Listing Account IDs is a scaling bottleneck. We implemented selectors (OUs and Tags) to ensure the bot works automatically as new accounts are added.