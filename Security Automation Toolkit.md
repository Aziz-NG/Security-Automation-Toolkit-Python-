# 🔧 Security Automation Toolkit (Python)

> A small collection of Python scripts that automate practical security tasks against Microsoft Entra ID and Sentinel — built to extend my existing Azure IAM and SIEM projects with scripting rather than portal clicks.

![Python](https://img.shields.io/badge/Language-Python-blue)
![Azure](https://img.shields.io/badge/Cloud-Microsoft%20Azure-blue)
![Security](https://img.shields.io/badge/Focus-Security%20Automation-red)

---

## 📌 Why This Exists

Most of my other projects use Azure-native tools (Sentinel, Logic Apps, Purview) configured through the portal. This toolkit demonstrates the other half of practical security work: scripting the repetitive, manual parts of governance and monitoring that don't need a full SOAR pipeline — the kind of thing a security analyst reaches for when a task needs doing once, or on a schedule, without building a whole automation platform around it.

---

## 🛠️ Scripts

### 1. [mfa_stale_role_audit.py](https://github.com/Aziz-NG/Security-Automation-Toolkit-Python-/blob/main/repo/mfa_stale_role_audit.py) ✅ Built
Authenticates to Microsoft Graph via an Entra ID app registration (client credentials flow) and runs two checks:

- **Accounts without MFA registered** — checks each user's registered authentication methods directly; flags any account with only a password and no additional factor.
- **Standing (permanent) privileged role assignments** — lists every account holding a directory role assignment on a standing basis, rather than through time-bound activation.

Both findings are written to [audit_report.csv](https://github.com/Aziz-NG/Security-Automation-Toolkit-Python-/blob/main/repo/audit_report.csv).

**Known limitation, documented honestly:** the original plan was to flag privileged roles *unused* for 90+ days, using PIM's activation history. That data lives behind Microsoft Graph endpoints (`roleAssignmentScheduleInstances`, and the MFA registration *report* endpoint) that both require **Entra ID P2 or Governance licensing** — this tenant doesn't have it, and the script correctly surfaces that via Graph's own error messages rather than failing silently. The script was adjusted to flag **standing/permanent assignments instead of usage staleness** — arguably still a legitimate finding on its own, since permanent privileged access is exactly the anti-pattern PIM's just-in-time model exists to prevent, but it's a narrower check than originally scoped, and worth being upfront about if asked.

**Security benefit:** surfaces exactly the kind of access hygiene gaps that show up in real audits — accounts without MFA, and privileged access held on a standing basis rather than activated only when needed.

### 2. [ca_policy_export.py](https://github.com/Aziz-NG/Security-Automation-Toolkit-Python-/blob/main/repo/ca_policy_export.py) ✅ Built
Authenticates to Microsoft Graph and exports all Conditional Access policies into a readable CSV report, rather than reviewing them one by one in the portal. For each policy, captures the display name, enabled/disabled state, required grant controls (e.g., MFA, block), and included users.

[ca_policy_report.csv](https://github.com/Aziz-NG/Security-Automation-Toolkit-Python-/blob/main/repo/ca_policy_report.csv)

**Note:** some policies target access entirely through role assignment (`includeRoles`) rather than named users or groups — for those, the "Included Users" field will legitimately be blank. This isn't missing data; it reflects how the policy is actually scoped. A future enhancement would add a separate "Included Roles" column to capture this explicitly.

**Security benefit:** makes periodic CA policy review actually practical — this is the kind of governance task that gets skipped when it requires manually opening a dozen policies in a UI.

### 3. `sentinel-incident-summary.py` ⏳ Not yet built
Pulls recent high-severity Sentinel incidents via the API and generates a plain-text summary report — incident count by severity, top affected accounts, oldest unresolved incident.

**Security benefit:** a lightweight reporting layer on top of Sentinel, useful for a quick status check without opening the full portal dashboard.

---

## 🔐 Authentication

All scripts authenticate to Microsoft Graph / Azure using an app registration with least-privilege API permissions scoped to read-only access — no script in this repo writes to or modifies tenant data.

**Application permissions required:**
- `User.Read.All` — for `mfa_stale_role_audit.py`
- `UserAuthenticationMethod.Read.All` — for `mfa_stale_role_audit.py`
- `RoleManagement.Read.Directory` — for `mfa_stale_role_audit.py`
- `AuditLog.Read.All` — for `mfa_stale_role_audit.py`; added after an initial `403` error revealed this was required for the MFA authentication-methods endpoint, beyond what `UserAuthenticationMethod.Read.All` alone covers
- `Policy.Read.All` — for `ca_policy_export.py`

Admin consent must be granted for all four in the Entra ID app registration before the script will run successfully.

## ⚙️ Setup

1. Create an app registration in Entra ID, add the four permissions above, and grant admin consent.
2. Generate a client secret and copy its value immediately (shown only once).
3. Copy `config.example.json` to a new file named `config.json` in the project root, and fill in your real tenant ID, client ID, and client secret.
4. `config.json` is listed in `.gitignore` and will never be committed to this repo — it should only ever exist locally.

---

## 🚀 Requirements

```
pip install requests msal
```

Each script expects a `config.json` (not committed) with your tenant ID, app registration client ID, and client secret — see `config.example.json` for the expected format.

---

## 📌 What This Demonstrates

- Practical scripting ability beyond point-and-click portal work
- Comfort with the Microsoft Graph API and OAuth-based authentication
- Applying the same governance mindset from my IAM/SIEM projects, just via code instead of Azure-native automation

---
