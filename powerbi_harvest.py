#!/usr/bin/env python3
import requests
import os
import json
import datetime
import base64
from time import sleep
from pathlib import Path
from argparse import ArgumentParser
from difflib import SequenceMatcher
from tabulate import tabulate

API = "https://api.powerbi.com/v1.0/myorg"
GRAPH_API = "https://graph.microsoft.com/v1.0"
HEADERS = {}
SESSION = requests.Session()
MAP = {}
ENUM_USERS = False
AUDIT_MODE = False
MY_ID = None
USERS_SEEN = {}
AUDIT_LOGS = []
USER_WORKSPACE_MAP = {}

def decode_jwt_payload(token):
    try:
        payload = token.split('.')[1]
        payload += '=' * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except:
        return {}

def decode_token_sub(token):
    """Extract oid or sub from JWT."""
    payload = decode_jwt_payload(token)
    return payload.get("oid") or payload.get("sub")

def identify_token_context(token):
    p = decode_jwt_payload(token)
    is_sp = bool(p.get("appid") and not p.get("upn"))
    roles = p.get("roles", [])
    is_guest = "Guest" in roles or p.get("idp") == "live.com"
    is_admin = any(r.lower().endswith("administrator") for r in roles)
    audit(f"[OK] Token context → service_principal={is_sp}, guest={is_guest}, admin={is_admin}")
    return is_sp, is_guest, is_admin

def get_json(url):
    r = SESSION.get(url, headers=HEADERS)
    if r.status_code in (401, 403):
        print(f"[!] {r.status_code}: {r.text.strip()}")
        exit(1)
    if r.status_code != 200:
        print(f"[!] GET {url} failed with HTTP {r.status_code}")
        return None
    return r.json()

def post_json(url, data):
    r = SESSION.post(url, headers=HEADERS, json=data)
    if r.status_code not in (200, 202):
        return None
    return r.json()

def write_log(logfile, lines):
    logfile.parent.mkdir(parents=True, exist_ok=True)
    with open(logfile, "w") as f:
        f.write("\n".join(lines))

def audit(message):
    if AUDIT_MODE:
        AUDIT_LOGS.append(message)
        print(message)


def get_report_permissions(group_id, report_id):
    url = f"{API}/groups/{group_id}/reports/{report_id}/permissions"
    return get_json(url)

def get_dataset_permissions(group_id, dataset_id):
    url = f"{API}/groups/{group_id}/datasets/{dataset_id}/permissions"
    return get_json(url)

def get_dataset_roles(group_id, dataset_id):
    url = f"{API}/groups/{group_id}/datasets/{dataset_id}/roles"
    return get_json(url)

def simulate_rls_check(group_id, dataset_id):
    test_query = {"queries":[{"query":"EVALUATE FILTER( {VALUES(1)}, FALSE )"}]}
    r = SESSION.post(f"{API}/groups/{group_id}/datasets/{dataset_id}/executeQueries",
                     headers=HEADERS, json=test_query)
    return r.status_code != 200

def get_user_azure_groups(user_id):
    url = f"{GRAPH_API}/users/{user_id}/memberOf?$select=id"
    r = SESSION.get(url, headers=HEADERS)
    if r.status_code == 200:
        return {g["id"] for g in r.json().get("value", [])}
    return set()


def check_embed_token(report_id, group_id=None):
    if group_id:
        url = f"{API}/groups/{group_id}/reports/{report_id}/GenerateToken"
    else:
        url = f"{API}/reports/{report_id}/GenerateToken"
    payload = {"accessLevel": "view"}
    r = SESSION.post(url, headers=HEADERS, json=payload)
    if r.status_code == 200:
        return 200, r.json().get("token")
    else:
        return r.status_code, r.text.strip()

def export_report(group_id, report, outdir, logdir):
    name       = report['name'].replace(" ", "_")
    report_id  = report["id"]
    dataset_id = report.get("datasetId", "N/A")
    workspace  = report.get("workspace", "Unknown")
    embed_url  = report.get("embedUrl", "")

    log_lines = [
        f"Report Name: {name}",
        f"Workspace: {workspace}",
        f"Group ID: {group_id}",
        f"Report ID: {report_id}",
        f"Dataset ID: {dataset_id}"
    ]

    print(f"    ↪ Report: {name}")
    print(f"    ├─ [✓] Fetched reportId: {report_id}")

    if AUDIT_MODE:
        print(f"    ├─ ⚙️ Checking embed token...")
        status, info = check_embed_token(report_id, group_id)
        log_lines.append(f"EmbedTokenCheck: HTTP {status}")
        if status == 200:
            log_lines.append(f"EmbedToken: {info}")
            print(f"    ├─ [✓] Embed token generated (HTTP 200)")
            audit(f"[VULN] Embed token can be generated for: {name}")
        else:
            log_lines.append(f"EmbedTokenError: {info}")
            print(f"    ├─ [✘] Embed token failed → HTTP {status}")

    if AUDIT_MODE:
        if dataset_id == "N/A":
            audit(f"[WARN] Report exported without dataset: {name}")
        if embed_url.startswith("https://"):
            audit(f"[INFO] Embed URL detected: {embed_url}")

    if AUDIT_MODE:
        perms = get_report_permissions(group_id, report_id)
        if perms and "value" in perms:
            direct_ids = {e.get("identifier") for e in perms["value"]}
            user_groups = get_user_azure_groups(MY_ID)
            if MY_ID in direct_ids:
                audit(f"[OK] Token subject explicitly in report ACL: {name}")
            elif direct_ids & user_groups:
                audit(f"[OK] Token subject in report ACL via AAD group(s): {name} " +
                      f"(groups: {', '.join(direct_ids & user_groups)})")
            else:
                fallback = decode_jwt_payload(token).get("preferred_username","").lower()
                for e in perms["value"]:
                    dn = e.get("displayName","").lower()
                    ratio = SequenceMatcher(None, fallback, dn).ratio()
                    if ratio > 0.8:
                        audit(f"[INFO] Fuzzy match '{fallback}'~'{dn}' ratio {ratio:.2f}")
                audit(f"[WARN] Token subject not in report ACL: {name}")

    res = SESSION.post(f"{API}/groups/{group_id}/reports/{report_id}/ExportTo",
                       headers=HEADERS, json={"format":"PDF"})
    if res.status_code != 202:
        print(f"    ├─ [✘] ExportTo request failed → HTTP {res.status_code}")
        log_lines += ["ExportTo: FAILED", f"HTTP {res.status_code}"]
        write_log(logdir / f"{name}.log", log_lines)
        return {"name": name, "status": f"failed_{res.status_code}"}

    job_id = res.json().get("id")
    print(f"    ├─ [✓] Sent ExportTo request → jobId: {job_id}")
    log_lines.append(f"Job ID: {job_id}")

    for i in range(20):
        sleep(3)
        poll = SESSION.get(f"{API}/reports/exportTo/{job_id}", headers=HEADERS)
        if poll.status_code == 404:
            print(f"    ├─ [✘] Polling attempt {i+1} → HTTP 404")
            audit(f"[WARN] Export job valid but PDF missing: {name} (jobId: {job_id})")
            log_lines.append("Polling: 404 NOT FOUND")
            write_log(logdir / f"{name}.log", log_lines)
            return {"name": name, "status": "export_failed_404"}
        if poll.status_code != 200:
            continue
        status = poll.json()
        if status.get("status") == "Succeeded":
            pdf_url = status.get("reportStreamUrl")
            if pdf_url:
                outdir.mkdir(parents=True, exist_ok=True)
                with open(outdir / f"{name}.pdf", "wb") as f:
                    f.write(SESSION.get(pdf_url).content)
                print(f"    ├─ [✓] Export succeeded")
                write_log(logdir / f"{name}.log", log_lines)
                return {"name": name, "status": "exported"}
        elif status.get("status") == "Failed":
            print(f"    └─ [✘] Export job failed")
            log_lines.append("Status: FAILED")
            write_log(logdir / f"{name}.log", log_lines)
            return {"name": name, "status": "export_failed"}

    print(f"    └─ [✘] Export polling timed out")
    log_lines.append("Status: TIMEOUT")
    write_log(logdir / f"{name}.log", log_lines)
    return {"name": name, "status": "timeout"}
def extract_dax(group_id, dataset_id, outdir, name):
    query = {"queries":[{"query":"EVALUATE { 1 }"}]}
    r = SESSION.post(f"{API}/groups/{group_id}/datasets/{dataset_id}/executeQueries",
                     headers=HEADERS, json=query)
    if r.status_code == 200:
        j = r.json()
        tables = j.get("results",[{}])[0].get("tables",[])
        cols = len(tables[0].get("columns",[])) if tables else 0
        if tables:
            outdir.mkdir(parents=True, exist_ok=True)
            with open(outdir / f"{name}.json","w") as f:
                json.dump(j, f, indent=2)
            if AUDIT_MODE:
                audit(f"[VULN] Dataset executed without error or RLS: {name} (cols: {cols})")
                if cols > 20:
                    audit(f"[!] Large schema detected (cols: {cols}): {name}")

        print(f"    [✔] DAX OK: {name} ({cols} columns)")

        if AUDIT_MODE:
            roles = get_dataset_roles(group_id, dataset_id)
            if roles and roles.get("value"):
                audit(f"[OK] RLS roles defined for dataset: {name}")
                enforced = simulate_rls_check(group_id, dataset_id)
                if enforced:
                    audit(f"[OK] RLS enforcement confirmed: {name}")
                else:
                    audit(f"[VULN] RLS defined but not enforced: {name}")
            else:
                audit(f"[VULN] No RLS roles defined for dataset: {name}")

            ds_perms = get_dataset_permissions(group_id, dataset_id)
            if ds_perms and "value" in ds_perms:
                direct_ds_ids = {e.get("identifier") for e in ds_perms["value"]}
                user_groups = get_user_azure_groups(MY_ID)
                if MY_ID in direct_ds_ids:
                    audit(f"[OK] Token subject in dataset ACL: {name}")
                elif direct_ds_ids & user_groups:
                    audit(f"[OK] Token subject in dataset ACL via AAD group(s): {name} " +
                          f"(groups: {', '.join(direct_ds_ids & user_groups)})")
                else:
                    audit(f"[WARN] Token subject not in dataset ACL: {name}")

        return {"name": name, "dax": "ok", "columns": cols}
    else:
        print(f"    [✘] DAX FAIL: {name} (HTTP {r.status_code})")
        return {"name": name, "dax": f"fail_{r.status_code}"}

def enum_workspace_users(group_id, output_dir, workspace):
    users = get_json(f"{API}/groups/{group_id}/users")
    if not users:
        print(f"    [!] Cannot list users for workspace {workspace}")
        return "Unknown (API failure)", None

    user_table = []
    my_role    = None
    payload    = decode_jwt_payload(token)
    fallback   = payload.get("preferred_username","").lower() or payload.get("upn","").lower()

    for u in users.get("value",[]):
        uid    = u.get("identifier")
        email  = u.get("emailAddress","").lower()
        role   = u.get("groupUserAccessRight","?")

        if uid == MY_ID:
            my_role = role
        elif not my_role and fallback == email:
            my_role = role

        if uid and uid not in USERS_SEEN:
            USERS_SEEN[uid] = u
            user_table.append(u)

        dn = u.get("displayName","").lower()
        if fallback and dn:
            ratio = SequenceMatcher(None, fallback, dn).ratio()
            if ratio > 0.8:
                audit(f"[INFO] Fuzzy match '{fallback}'~'{dn}' ratio {ratio:.2f}")

        key = email or uid
        USER_WORKSPACE_MAP.setdefault(key,[]).append(f"{workspace} ({role})")

    if AUDIT_MODE and user_table:
        audit(f"[INFO] Workspace '{workspace}': {len(user_table)} users enumerated")

    if not my_role:
        my_role = "Unknown (not in list)"
        audit(f"[WARN] Token subject not found in workspace users")

    return my_role, user_table

def summarize_user_workspace_map():
    table = [(u, ", ".join(ws)) for u, ws in USER_WORKSPACE_MAP.items()]
    return tabulate(table,
                    headers=["User","Workspaces (Role)"],
                    tablefmt="rounded_grid",
                    maxcolwidths=[None,80])

def summarize_vuln_findings():
    vuln = [("🔴 VULN", log[7:].strip()) for log in AUDIT_LOGS if log.startswith("[VULN]")]
    if not vuln:
        return None, 0
    tbl = tabulate(vuln,
                   headers=["Type","Vulnerability"],
                   tablefmt="rounded_grid",
                   maxcolwidths=[None,80])
    return tbl, len(vuln)

def write_summary(outdir, mapdata, user_table):
    from pandas import DataFrame

    summary_lines, full_output = [], []

    for ws, data in mapdata.items():
        summary_lines.append(f"\n📊 Workspace: {ws}")
        summary_lines.append("  📄 Reports:")
        for r in data["reports"]:
            icon = "✔" if r["status"]=="exported" else "✘"
            summary_lines.append(f"    [{icon}] {r['name']:<24} → {r['status']}")
        summary_lines.append("  🧬 Datasets:")
        for d in data["datasets"]:
            icon = "✔" if d["dax"]=="ok" else "✘"
            detail = (f"DAX OK, {d['columns']} col" if d["dax"]=="ok"
                      else f"FAIL ({d['dax']})")
            summary_lines.append(f"    [{icon}] {d['name']:<24} → {detail}")

    if user_table:
        df = DataFrame(user_table)
        summary_lines.append("\n📋 Enumerated Users:\n")
        summary_lines.append(df.to_markdown(index=False))

    summary_path = outdir/"summary.txt"
    outdir.mkdir(parents=True, exist_ok=True)
    with open(summary_path,"w") as f:
        f.write("\n".join(summary_lines))
        if USER_WORKSPACE_MAP:
            f.write("\n\n=== USERS → WORKSPACES MAP ===\n")
            f.write(summarize_user_workspace_map())
        if AUDIT_MODE:
            vt,count = summarize_vuln_findings()
            if vt:
                f.write("\n\n=== AUDIT VULNERABILITY SUMMARY ===\n")
                f.write(vt)
                f.write("\n\n")

    full_output += ["="*70,"SUMMARY","="*70] + summary_lines

    if USER_WORKSPACE_MAP:
        full_output += ["\n","="*70,"USERS → WORKSPACES MAP","="*70]
        full_output.append(summarize_user_workspace_map())
    if AUDIT_MODE:
        vt,count = summarize_vuln_findings()
        if vt:
            full_output += ["\n","="*70,"AUDIT VULNERABILITY SUMMARY","="*70]
            full_output.append(vt)
            full_output += ["\n"]
    full_output += ["\n","="*70,"REPORT LOGS","="*70]
    for root, _, files in os.walk(outdir/"logs"):
        for file in files:
            if file.endswith(".log"):
                p = Path(root)/file
                full_output.append(f"\n📄 {file}")
                full_output.append("-"*50)
                full_output += open(p).read().splitlines()
    if AUDIT_MODE and AUDIT_LOGS:
        full_output += ["\n","="*70,"AUDIT FINDINGS","="*70]
        full_output += AUDIT_LOGS

    full_path = outdir/"full_output_summary.txt"
    with open(full_path,"w") as f:
        f.write("\n".join(full_output))

    return summary_path, full_path

def main():
    global HEADERS, ENUM_USERS, AUDIT_MODE, MY_ID, token

    parser = ArgumentParser()
    parser.add_argument("--token",    required=True)
    parser.add_argument("--output",   help="Custom output directory")
    parser.add_argument("--enum-users", action="store_true",
                        help="Enumerate users in each workspace")
    parser.add_argument("--audit", action="store_true",
                        help="Enable vulnerability audit")
    args = parser.parse_args()

    token      = args.token
    HEADERS    = {"Authorization":f"Bearer {token}","Content-Type":"application/json"}
    ENUM_USERS = args.enum_users
    AUDIT_MODE = args.audit
    MY_ID      = decode_token_sub(token)

    identify_token_context(token)

    base = Path(args.output) if args.output else Path(
        f"output/{datetime.datetime.now():%Y%m%d_%H%M%S}")
    MAP.clear()
    user_table_all = []

    groups = get_json(f"{API}/groups")
    if not groups or not groups.get("value"):
        print("[!] No groups returned.")
        return

    for g in groups["value"]:
        gid, gname = g["id"], g["name"].replace(" ","_")
        print(f"\n[=] Workspace: {gname}")
        rep_dir, dax_dir, log_dir = base/"reports"/gname, base/"dax"/gname, base/"logs"/gname
        MAP[gname] = {"reports": [], "datasets": []}

        if ENUM_USERS:
            role, users = enum_workspace_users(gid, base, gname)
            print(f"    → Your role: {role or 'Unknown'}")
            if users:
                user_table_all.extend(users)

        reports = get_json(f"{API}/groups/{gid}/reports") or {"value":[]}
        if not reports["value"] and AUDIT_MODE:
            audit(f"[INFO] Empty workspace: {gname} (accessible but no visible assets)")
        for r in reports["value"]:
            r["workspace"]=gname
            res = export_report(gid, r, rep_dir, log_dir)
            if res: MAP[gname]["reports"].append(res)

        datasets = get_json(f"{API}/groups/{gid}/datasets") or {"value":[]}
        for d in datasets["value"]:
            dname = d["name"].replace(" ","_")
            res = extract_dax(gid, d["id"], dax_dir, dname)
            if res: MAP[gname]["datasets"].append(res)

    if ENUM_USERS and user_table_all:
        import pandas as pd
        df = pd.DataFrame(USERS_SEEN.values())
        df.to_csv(base/"users.csv", index=False)
        df.to_json(base/"users.json", indent=2)
        print("\n🧑‍💼 Users Summary:")
        print(tabulate(df, headers="keys", tablefmt="rounded_grid", showindex=False))

    s_path, f_path = write_summary(
        base, MAP,
        list(USERS_SEEN.values()) if ENUM_USERS else None
    )
    print(f"\n[✓] Summary saved to {s_path}")
    print(f"[✓] Full output saved to {f_path}")

    if AUDIT_MODE:
        vt, count = summarize_vuln_findings()
        if vt:
            print(f"\n🚨 Vulnerabilities Detected: {count}")
            print(vt)

    if ENUM_USERS and USER_WORKSPACE_MAP:
        print("\n📌 User → Workspace Mapping (with roles):")
        print(summarize_user_workspace_map())

if __name__ == "__main__":
    main()
