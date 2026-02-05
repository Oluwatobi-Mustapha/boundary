# Interface Strategy

> Access requests happen in different places depending on who’s working and how urgent it is. This project supports three interfaces, all backed by the same policy engine and audit log.

* **CLI** for automation and repeatable validation in CI
* **Slack** for fast requests when engineers are in the middle of work
* **Web** for oversight, review, and reporting

No matter the interface, the flow stays the same: evaluate policy, record the decision with context, then manage the access lifecycle.

---

## 🧰 CLI

**Who it’s for:** DevOps engineers, platform teams, CI pipelines  
**Where it fits:** local debugging, automated checks, repeatable workflows

The CLI exists because some workflows are best handled as code. Teams often want to validate policy decisions before applying changes, run checks in CI, or execute bulk operations during migrations. A CLI is the most reliable way to make the system scriptable and composable.

---

## 💬 Slack

**Who it’s for:** application engineers, on call responders  
**Where it fits:** requesting temporary access while actively working

Slack is the “front door” for most day to day requests because it reduces steps. If an engineer needs short lived access to debug an issue, the fastest path is usually inside the tool they already have open. This is less about convenience and more about reliability under pressure.

---

## 📊 Web

**Who it’s for:** security engineers, managers, auditors  
**Where it fits:** visibility, review, reporting, and operational control

Some tasks are hard to do well in chat or terminal output, especially when the questions are about trends and history. A web interface helps answer operational and audit questions like:

- Who has active access right now?
- What changed over the last 30 days?
- Which requests were denied and why?
- Can we revoke access quickly and document the reason?

---

***Keeping them separate at the interface layer, while sharing the same policy engine and audit pipeline, helps prevent policy drift and reduces maintenance. The user experience changes, but the decision logic stays the same.***
