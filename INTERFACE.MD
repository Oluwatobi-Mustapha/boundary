# Interface Strategy

> Access requests happen in different places depending on who’s working and how urgent it is. This Security product supports three interfaces, all backed by the same policy engine and audit log.


## 🧰 CLI

**Who it’s for:** _DevOps engineers, platform teams, CI pipelines_

**Where it fits:** _local debugging, automated checks, repeatable workflows_

The CLI exists because some workflows are best handled as code. Teams often want to validate policy decisions before applying changes, run checks in CI, or execute bulk operations during migrations. A CLI is the most reliable way to make the system scriptable and composable.

---

## 💬 Slack

**Who it’s for:** _Application engineers, on call responders_  

**Where it fits:** _requesting temporary access while actively working_

Slack is the “front door” for most day to day requests because it reduces steps. If an engineer needs short lived access to debug an issue, the fastest path is usually inside the tool they already have open. This is less about convenience and more about reliability under pressure.

---

## 📊 Web

**Who it’s for:** _Security engineers, managers, auditors_  

**Where it fits:** _visibility, review, reporting, and operational control_

Some tasks are hard to do well in chat or terminal output, especially when the questions are about trends and history. A web interface helps answer operational and audit questions like:

- Who has active access right now?
- What changed over the last 30 days?
- Which requests were denied and why?
- Can we revoke access quickly and document the reason?

---

***Keeping them separate at the interface layer, while sharing the same policy engine and audit pipeline, helps prevent policy drift and reduces maintenance. The user experience changes, but the decision logic stays the same.***
