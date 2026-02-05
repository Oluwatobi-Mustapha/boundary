# Interface Strategy: CLI, Slack, and Web

Access requests happen in different places depending on who’s working and how urgent it is. This project supports three interfaces, all backed by the same policy engine and audit log.

- **CLI** for automation and repeatable validation in CI
- **Slack** for fast requests when engineers are in the middle of work
- **Web** for oversight, review, and reporting

No matter the interface, the flow stays the same: evaluate policy, record the decision with context, then manage the access lifecycle.

---

## 🧰 CLI

**Who it’s for:** DevOps engineers, platform teams, CI pipelines  
**Where it fits:** local debugging, automated checks, repeatable workflows

The CLI exists because some workflows are best handled as code. Teams often want to validate policy decisions before applying changes, run checks in CI, or execute bulk operations during migrations. A CLI is the most reliable way to make the system scriptable and composable.

Design choices:
- Output is structured so it can be read by humans and also piped into other tools.
- The CLI focuses on deterministic results and clear reasoning, so policy behavior can be reviewed during development and incident response.
- It keeps dependencies minimal, which makes it easier to run in different environments.

---

## 💬 Slack

**Who it’s for:** application engineers, on call responders  
**Where it fits:** requesting temporary access while actively working

Slack is the “front door” for most day to day requests because it reduces steps. If an engineer needs short lived access to debug an issue, the fastest path is usually inside the tool they already have open. This is less about convenience and more about reliability under pressure.

Design choices:
- Commands and forms should be short and predictable.
- The bot should return a clear decision and the next step, without requiring users to understand policy internals.
- Slack is also a good place to enforce consistency: required fields, approvals, ticket links, and time bounds.


---

## 📊 Web

**Who it’s for:** security engineers, managers, auditors  
**Where it fits:** visibility, review, reporting, and operational control

Some tasks are hard to do well in chat or terminal output, especially when the questions are about trends and history. A web interface helps answer operational and audit questions like:

- Who has active access right now?
- What changed over the last 30 days?
- Which requests were denied and why?
- Can we revoke access quickly and document the reason?

Design choices:
- The web UI should reflect the system of record (for example, DynamoDB backed state and audit events).
- It should support filtering, searching, and exporting for review cycles.
- It should include controlled actions like revoke, with strong logging and guardrails.

---

## Why keep all three

Using three interfaces is a practical response to how access requests happen in real teams:

- The **CLI** supports automation and repeatability.
- **Slack** supports speed and adoption for everyday requests.
- The **Web** supports oversight and audit workflows.

***Keeping them separate at the interface layer, while sharing the same policy engine and audit pipeline, helps prevent policy drift and reduces maintenance. The user experience changes, but the decision logic stays the same.***
