
# Power BI Extractor

`powerbi_extractor.py` is a **fully open-source auditing and exploration tool** for **Microsoft Power BI** environments.  
Designed for **red teams**, **security auditors**, and **data analysts**, it performs deep metadata extraction, access control validation, user-role mapping, and optional DAX/report export operations — all from the command line.

[![GitHub Stars](https://img.shields.io/github/stars/nemmusu/powerbi-extractor?style=social)](https://github.com/nemmusu/powerbi-extractor/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/nemmusu/powerbi-extractor?style=social)](https://github.com/nemmusu/powerbi-extractor/forks)
[![GitHub Issues](https://img.shields.io/github/issues/nemmusu/powerbi-extractor)](https://github.com/nemmusu/powerbi-extractor/issues)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/nemmusu/powerbi-extractor)](https://github.com/nemmusu/powerbi-extractor/commits/main)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📌 Why Power BI Extractor?

Microsoft Power BI is a widely adopted business intelligence platform — yet security misconfigurations are common.  
`powerbi_extractor.py` enables structured discovery and validation of:

- 🔐 Access Control Lists (ACLs)
- 📊 Report + Dataset mapping
- 👤 Role-Based Access Control (RBAC)
- 📤 Export-to behavior
- 🔎 Data exposure via DAX
- 🧑‍💼 User enumeration and role visibility
- 🧠 AAD Group lookups (optional via Microsoft Graph)

---

## 🚀 Features

- ✅ List accessible workspaces
- ✅ Extract report metadata and export tokens
- ✅ Dump datasets and DAX output (when permitted)
- ✅ Perform ACL and RBAC checks
- ✅ Enumerate workspace users and roles (opt-in)
- ✅ Map users → workspaces → permissions
- ✅ Save audit logs, summaries, and vulnerabilities
- ✅ Optional integration with Microsoft Graph

---

## ⚙️ Installation

```bash
git clone https://github.com/nemmusu/powerbi-extractor.git
cd powerbi-extractor
pip install -r requirements.txt
```

Requirements (in `requirements.txt`):

```txt
requests
tabulate
pandas
```

---

## 🧪 Usage

```bash
python3 powerbi_extractor.py --token <BEARER_TOKEN> [--enum-users] [--audit] [--output OUTPUT_DIR]
```

### Arguments

- `--token`: Required. A Power BI access token.
- `--enum-users`: List users and roles for each workspace.
- `--audit`: Trigger ACL and export token validation.
- `--output`: Destination directory. Defaults to `output/YYYYMMDD_HHMMSS`.

---

## Output

### Terminal Output (Example)

```
[=] Workspace: Finance_Dept
    → Your role: Contributor
    ↪ Report: Quarterly_Summary
    ├─ [✓] Fetched reportId: 7a1df76...
    ├─ ⚙️ Checking embed token...
    ├─ [✓] Embed token generated (HTTP 200)
    ├─ [✓] Sent ExportTo request → jobId: 3a1f...
    ├─ [✓] Export succeeded
    [✔] DAX OK: FinancialsDataset (24 columns)

    ↪ Report: Forecast_2024
    ├─ [✓] Fetched reportId: 9bbff3e...
    ├─ ⚙️ Checking embed token...
    ├─ [✓] Embed token generated (HTTP 200)
    ├─ [✓] Sent ExportTo request → jobId: 8ab7...
    ├─ [✘] Polling attempt 1 → HTTP 404
    └─ [✘] Export job valid but PDF missing

[=] Workspace: HR_Team
    → Your role: Unknown (not in list)
    ↪ Report: Employee_Stats
    ├─ [✘] Embed token failed → HTTP 403
    ↪ Report: Headcount_Report
    ├─ [✓] Fetched reportId: b821ffe...
    ├─ ⚙️ Checking embed token...
    ├─ [✓] Embed token generated (HTTP 200)
    ├─ [✓] Sent ExportTo request → jobId: c771...
    ├─ [✘] Export job failed

[✔] DAX OK: FinancialsDataset (24 columns)
[✘] DAX FAIL: HR_Dataset (HTTP 403)

🧑‍💼 Users Summary:
╭────────────────────────────┬────────────────────────────┬──────────────┬──────────╮
│ displayName                │ emailAddress               │ identifier   │ role     │
├────────────────────────────┼────────────────────────────┼──────────────┼──────────┤
│ Alice Admin                │ alice@contoso.com          │ ...          │ Admin    │
│ Bob Viewer                 │ bob@contoso.com            │ ...          │ Viewer   │
│ Carol Contributor          │ carol@contoso.com          │ ...          │ Contributor│
╰────────────────────────────┴────────────────────────────┴──────────────┴──────────╯

📌 User → Workspace Mapping (with roles):
╭────────────────────┬──────────────────────────────────────────────╮
│ User               │ Workspaces (Role)                            │
├────────────────────┼──────────────────────────────────────────────┤
│ alice@contoso.com  │ Finance_Dept (Admin), HR_Team (Viewer)       │
│ bob@contoso.com    │ Finance_Dept (Viewer)                        │
│ carol@contoso.com  │ HR_Team (Contributor)                        │
╰────────────────────┴──────────────────────────────────────────────╯

[✓] Summary saved to output/20250509_172302/summary.txt
[✓] Full output saved to output/20250509_172302/full_output_summary.txt

🚨 Vulnerabilities Detected: 3
╭─────────────┬─────────────────────────────────────────────────────────────╮
│ Type        │ Vulnerability                                               │
├─────────────┼─────────────────────────────────────────────────────────────┤
│ 🔴 VULN     │ Embed token can be generated for: Quarterly_Summary         │
│ 🔴 VULN     │ Dataset executed without error or RLS: FinancialsDataset    │
│ 🔴 VULN     │ Export job valid but PDF missing: Forecast_2024             │
╰─────────────┴─────────────────────────────────────────────────────────────╯
```

---

### Example `summary.txt`

```
📊 Workspace: Finance_Dept
  📄 Reports:
    [✔] Quarterly_Summary         → exported
    [✘] Annual_Overview           → failed_403
    [✘] Legacy_Budget             → export_failed_404
  🧬 Datasets:
    [✔] FinancialsDataset         → DAX OK, 24 col
    [✘] HR_Dataset                → FAIL (fail_403)

📊 Workspace: HR_Team
  📄 Reports:
    [✘] Employee_Stats            → failed_403
    [✘] Salary_Overview           → export_failed
  🧬 Datasets:
    [✘] StaffData                 → FAIL (fail_403)

📋 Enumerated Users:

| displayName     | emailAddress          | identifier | role       |
|-----------------|-----------------------|------------|------------|
| Alice Admin     | alice@contoso.com     | ...        | Admin      |
| Bob Viewer      | bob@contoso.com       | ...        | Viewer     |
| Eve External    | eve@external.com      | ...        | Contributor|

=== USERS → WORKSPACES MAP ===
╭────────────────────┬────────────────────────────────────────────────────────╮
│ User               │ Workspaces (Role)                                      │
├────────────────────┼────────────────────────────────────────────────────────┤
│ alice@contoso.com  │ Finance_Dept (Admin), HR_Team (Contributor)            │
│ bob@contoso.com    │ Finance_Dept (Viewer)                                  │
│ eve@external.com   │ HR_Team (Contributor)                                  │
╰────────────────────┴────────────────────────────────────────────────────────╯

=== AUDIT VULNERABILITY SUMMARY ===
╭─────────────┬──────────────────────────────────────────────────────────────╮
│ Type        │ Vulnerability                                                │
├─────────────┼──────────────────────────────────────────────────────────────┤
│ 🔴 VULN     │ Embed token can be generated for: Quarterly_Summary          │
│ 🔴 VULN     │ Dataset executed without error or RLS: FinancialsDataset     │
│ 🔴 VULN     │ Export job valid but PDF missing: Legacy_Budget (jobId: ...) │
╰─────────────┴──────────────────────────────────────────────────────────────╯
```

---

### Example `full_output_summary.txt`

```
======================================================================
SUMMARY
======================================================================
📊 Workspace: Finance_Dept
  📄 Reports:
    [✔] Quarterly_Summary         → exported
    [✘] Annual_Overview           → failed_403
    [✘] Legacy_Budget             → export_failed_404
  🧬 Datasets:
    [✔] FinancialsDataset         → DAX OK, 24 col
    [✘] HR_Dataset                → FAIL (fail_403)

📊 Workspace: HR_Team
  📄 Reports:
    [✘] Employee_Stats            → failed_403
    [✘] Salary_Overview           → export_failed
  🧬 Datasets:
    [✘] StaffData                 → FAIL (fail_403)

📋 Enumerated Users:

| displayName     | emailAddress          | identifier | role       |
|-----------------|-----------------------|------------|------------|
| Alice Admin     | alice@contoso.com     | ...        | Admin      |
| Bob Viewer      | bob@contoso.com       | ...        | Viewer     |
| Eve External    | eve@external.com      | ...        | Contributor|

=== USERS → WORKSPACES MAP ===
╭────────────────────┬────────────────────────────────────────────────────────╮
│ User               │ Workspaces (Role)                                      │
├────────────────────┼────────────────────────────────────────────────────────┤
│ alice@contoso.com  │ Finance_Dept (Admin), HR_Team (Contributor)            │
│ bob@contoso.com    │ Finance_Dept (Viewer)                                  │
│ eve@external.com   │ HR_Team (Contributor)                                  │
╰────────────────────┴────────────────────────────────────────────────────────╯

=== AUDIT VULNERABILITY SUMMARY ===
╭─────────────┬──────────────────────────────────────────────────────────────╮
│ Type        │ Vulnerability                                                │
├─────────────┼──────────────────────────────────────────────────────────────┤
│ 🔴 VULN     │ Embed token can be generated for: Quarterly_Summary          │
│ 🔴 VULN     │ Dataset executed without error or RLS: FinancialsDataset     │
│ 🔴 VULN     │ Export job valid but PDF missing: Legacy_Budget (jobId: ...) │
╰─────────────┴──────────────────────────────────────────────────────────────╯

======================================================================
REPORT LOGS
======================================================================

📄 Quarterly_Summary.log
--------------------------------------------------
Report Name: Quarterly_Summary
Workspace: Finance_Dept
Group ID: GID-FIN-001
Report ID: RPT-123
Dataset ID: DS-456
EmbedTokenCheck: HTTP 200
EmbedToken: eyJ0eXAi...
Job ID: JOB-789

📄 Legacy_Budget.log
--------------------------------------------------
Report Name: Legacy_Budget
Workspace: Finance_Dept
Group ID: GID-FIN-001
Report ID: RPT-LEG-333
Dataset ID: DS-LEGACY
EmbedTokenCheck: HTTP 200
EmbedToken: eyJ0eXAi...
Job ID: JOB-XYZ
Polling: 404 NOT FOUND

📄 Salary_Overview.log
--------------------------------------------------
Report Name: Salary_Overview
Workspace: HR_Team
Group ID: GID-HR-002
Report ID: RPT-SAL
Dataset ID: DS-HR-02
EmbedTokenCheck: HTTP 200
Job ID: JOB-FAIL
Status: FAILED

======================================================================
AUDIT FINDINGS
======================================================================
[OK] Token context → service_principal=False, guest=False, admin=False
[INFO] Embed URL detected: https://app.powerbi.com/reportEmbed?reportId=...
[OK] Token subject explicitly in report ACL: Quarterly_Summary
[VULN] Embed token can be generated for: Quarterly_Summary
[VULN] Dataset executed without error or RLS: FinancialsDataset (cols: 24)
[OK] RLS roles defined for dataset: FinancialsDataset
[OK] RLS enforcement confirmed: FinancialsDataset
[VULN] Export job valid but PDF missing: Legacy_Budget (jobId: JOB-XYZ)
```

---

## 🗂 Output Structure

- `reports/<workspace>/`: Exported report PDFs (if accessible)
- `dax/<workspace>/`: Dataset output in JSON format
- `logs/<workspace>/`: Detailed logs for each export
- `users.csv` / `users.json`: Workspace user listings (if enabled)
- `summary.txt`: Human-readable summary
- `full_output_summary.txt`: Full logs + findings

## Notes

- Tokens must be valid for the Power BI REST API. Microsoft Graph access (e.g., AAD group resolution) requires additional scopes but is optional.
- Export and DAX operations do not guarantee access — HTTP errors are logged and reported.

## ⚠️ Disclaimer

This tool is released for educational and authorized assessment purposes only.  
It is always distributed as **Python source code**.  
**⚠️ Beware of `.exe` versions: they are unofficial and potentially malicious.**

---

## 📫 Contact
GitHub: [nemmusu/powerbi-extractor](https://github.com/nemmusu/powerbi-extractor)