# PowerBI Scanner

Minimalistic scanner for auditing Power BI assets.

## What it does

- Enumerates all accessible Power BI workspaces
- Extracts report metadata and exports to PDF
- Executes basic DAX queries on datasets
- Checks Row-Level Security (RLS) definitions and enforcement
- Verifies ACLs (including Azure AD group memberships if available)
- Optionally enumerates users in each workspace
- Outputs clean summary files and logs

## Requirements

- Python 3.6+
- Bearer token from Power BI (standard user access is enough)
- Optional: token must work with Microsoft Graph to resolve AAD group memberships (for deeper ACL checks)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
./powerbi_scanner.py --token "<BEARER_TOKEN>" [--enum-users] [--audit] [--output <dir>]
```

- `--token`        : Required. Power BI Bearer token.
- `--enum-users`   : Optional. Lists workspace users and maps them to roles.
- `--audit`        : Optional. Enables detailed audit checks and vulnerability logging.
- `--output`       : Optional. Custom output folder (default: output/<timestamp>)

## Output

- PDF exports under `reports/`
- DAX output under `dax/`
- Logs under `logs/`
- `summary.txt` and `full_output_summary.txt`
- `users.csv` and `users.json` if `--enum-users` is used

## Example

```bash
./powerbi_scanner.py --token "eyJ0eXAiOiJKV..." --enum-users --audit
```

## License

MIT
