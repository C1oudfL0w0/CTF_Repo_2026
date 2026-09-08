#!/usr/bin/env python3
"""Build FINAL-v2 submission: fine-grained per-event graph (104 edges) + 35-step timeline."""
import csv, json, re, shutil
from datetime import datetime, timezone
from pathlib import Path

BASE = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-final")
S1 = BASE / "team54-pro/../../team54/build/submission"
S1 = Path("/Users/mashiro/Downloads/CISCN2026Final/team54/build/submission")
S2 = BASE / "submission-new"
OUT = BASE / "submission-final"

# ---------- load event timestamps ----------
def load_times():
    out = {}
    logs = BASE / "build/build选手附件/logs"
    for path in logs.rglob("*.jsonl"):
        for line in path.open(encoding="utf-8"):
            line = line.strip()
            if not line: continue
            try: o = json.loads(line)
            except Exception: continue
            if o.get("event_id"): out[o["event_id"]] = o.get("timestamp","")
    for path in logs.rglob("*.csv"):
        for row in csv.DictReader(path.open(encoding="utf-8", newline="")):
            if row.get("event_id"): out[row["event_id"]] = row.get("timestamp","")
    pat = re.compile(r"event_id=(\S+).*?time=([^ ]+)")
    for path in logs.rglob("*.log"):
        for line in path.open(encoding="utf-8"):
            m = pat.search(line)
            if m: out[m.group(1)] = m.group(2)
    idx = BASE / "build/build选手附件/artifacts/artifact_event_index.csv"
    for row in csv.DictReader(idx.open(encoding="utf-8", newline="")):
        if row.get("event_id"): out[row["event_id"]] = row.get("timestamp","")
    return out

TIMES = load_times()

# evidence id -> event_id, stage
EV = {}
for row in csv.DictReader(open(S2 / "evidence.csv")):
    EV[row["evidence_id"]] = (row["event_id"], row["stage"])

def eids(*evids):
    return [f"E{i:03d}" for i in evids] if False else None

# map evidence number -> E id
def E(n):
    return f"E{n:03d}"

# per-event edges: (evidence numbers, from, to, action, stage)
PER_EVENT = [
    # recon
    (1, "ip:198.51.100.77", "host:web-prod-01", "scan", "recon"),
    (2, "ip:198.51.100.77", "host:web-prod-01", "scan", "recon"),
    (3, "ip:198.51.100.77", "host:web-prod-01", "scan", "recon"),
    (4, "ip:198.51.100.77", "host:web-prod-01", "scan", "recon"),
    (5, "ip:198.51.100.77", "host:web-prod-01", "scan", "recon"),
    (6, "ip:198.51.100.77", "host:web-prod-01", "scan", "recon"),
    (7, "ip:198.51.100.77", "host:web-prod-01", "scan", "recon"),
    (8, "ip:198.51.100.77", "host:web-prod-01", "scan", "recon"),
    (9, "ip:198.51.100.77", "host:web-prod-01", "scan", "recon"),
    (10, "ip:198.51.100.77", "host:web-prod-01", "scan", "recon"),
    # ssrf
    (11, "ip:198.51.100.77", "host:web-prod-01", "exploit_public_service", "initial_access"),
    (12, "ip:198.51.100.77", "host:web-prod-01", "exploit_public_service", "initial_access"),
    (13, "ip:198.51.100.77", "host:web-prod-01", "exploit_public_service", "initial_access"),
    (14, "ip:198.51.100.77", "host:web-prod-01", "exploit_public_service", "initial_access"),
    # a.sh
    (15, "host:web-prod-01", "ip:203.0.113.60", "command_execution", "execution"),
    (16, "host:web-prod-01", "ip:203.0.113.60", "command_execution", "execution"),
    (17, "host:web-prod-01", "ip:203.0.113.60", "command_execution", "execution"),
    # c2
    (18, "host:web-prod-01", "ip:198.51.100.77", "command_and_control", "execution"),
    (19, "host:web-prod-01", "ip:198.51.100.77", "command_and_control", "execution"),
    # webshell
    (20, "host:web-prod-01", "file:/var/www/oa/public/.cache.php", "webshell_upload", "persistence"),
    (21, "ip:198.51.100.77", "host:web-prod-01", "webshell_upload", "persistence"),
    (22, "host:web-prod-01", "file:/var/www/oa/public/.cache.php", "webshell_upload", "persistence"),
    # web discovery
    (23, "host:web-prod-01", "host:web-prod-01", "host_discovery", "discovery"),
    (24, "host:web-prod-01", "host:web-prod-01", "host_discovery", "discovery"),
    (25, "host:web-prod-01", "host:web-prod-01", "host_discovery", "discovery"),
    (26, "host:web-prod-01", "host:web-prod-01", "host_discovery", "discovery"),
    (27, "host:web-prod-01", "host:web-prod-01", "host_discovery", "discovery"),
    # web credential dump
    (28, "host:web-prod-01", "account:deploy", "credential_dump", "credential_access"),
    (29, "host:web-prod-01", "account:deploy", "credential_dump", "credential_access"),
    (30, "host:web-prod-01", "account:deploy", "credential_dump", "credential_access"),
    # ssh lateral
    (31, "account:deploy", "host:ops-jump-01", "lateral_movement", "lateral_movement"),
    (32, "account:deploy", "host:ops-jump-01", "lateral_movement", "lateral_movement"),
    (33, "account:deploy", "host:ops-jump-01", "lateral_movement", "lateral_movement"),
    (34, "account:deploy", "host:ops-jump-01", "lateral_movement", "lateral_movement"),
    # jump discovery
    (35, "host:ops-jump-01", "host:win-admin-01", "host_discovery", "discovery"),
    (36, "host:ops-jump-01", "host:win-admin-01", "host_discovery", "discovery"),
    (37, "host:ops-jump-01", "database:pgsql-bi-01", "database_discovery", "discovery"),
    # mysql login
    (38, "account:crm_ro", "database:mysql-core-01", "credential_use", "credential_use"),
    (39, "host:web-prod-01", "database:mysql-core-01", "credential_use", "credential_use"),
    # mysql discovery
    (40, "account:crm_ro", "database:mysql-core-01", "database_discovery", "discovery"),
    (41, "account:crm_ro", "database:mysql-core-01", "database_discovery", "discovery"),
    (42, "account:crm_ro", "database:mysql-core-01", "database_discovery", "discovery"),
    (43, "account:crm_ro", "database:mysql-core-01", "database_discovery", "discovery"),
    # windows creds
    (44, "host:ops-jump-01", "account:CORP\\svc_backup", "credential_dump", "credential_access"),
    (45, "host:ops-jump-01", "account:CORP\\svc_backup", "credential_dump", "credential_access"),
    (46, "host:ops-jump-01", "account:CORP\\svc_backup", "credential_dump", "credential_access"),
    # bi creds from sys_config
    (47, "host:web-prod-01", "account:bi_sync", "credential_dump", "credential_access"),
    (48, "host:web-prod-01", "account:bi_sync", "credential_dump", "credential_access"),
    # git creds
    (49, "host:ops-jump-01", "account:svc_deploy", "credential_dump", "credential_access"),
    # pat login
    (50, "account:svc_deploy", "host:gitlab-01", "credential_use", "credential_use"),
    # ldap
    (51, "host:ops-jump-01", "host:ad-dc-01", "network_discovery", "discovery"),
    # ad logon
    (52, "account:CORP\\svc_backup", "host:ad-dc-01", "credential_use", "credential_use"),
    (53, "account:CORP\\svc_backup", "host:ad-dc-01", "credential_use", "credential_use"),
    (54, "account:CORP\\svc_backup", "host:ad-dc-01", "credential_use", "credential_use"),
    (55, "account:CORP\\svc_backup", "host:ad-dc-01", "credential_use", "credential_use"),
    # gitlab discovery
    (56, "account:svc_deploy", "host:gitlab-01", "devops_discovery", "discovery"),
    (57, "account:svc_deploy", "host:gitlab-01", "devops_discovery", "discovery"),
    (58, "account:svc_deploy", "host:gitlab-01", "devops_discovery", "discovery"),
    # bi login
    (59, "account:bi_sync", "database:pgsql-bi-01", "credential_use", "credential_use"),
    (60, "host:ops-jump-01", "database:pgsql-bi-01", "credential_use", "credential_use"),
    # domain enum
    (61, "account:CORP\\svc_backup", "host:ad-dc-01", "domain_discovery", "discovery"),
    (62, "account:CORP\\svc_backup", "host:ad-dc-01", "domain_discovery", "discovery"),
    (63, "account:CORP\\svc_backup", "host:ad-dc-01", "domain_discovery", "discovery"),
    # pipeline
    (64, "host:gitlab-01", "host:jenkins-01", "ci_pipeline_execution", "execution"),
    (66, "host:gitlab-01", "host:jenkins-01", "ci_pipeline_execution", "execution"),
    # BI copy
    (65, "account:bi_sync", "database:pgsql-bi-01", "data_collection", "collection"),
    (67, "account:bi_sync", "database:pgsql-bi-01", "data_collection", "collection"),
    (68, "account:bi_sync", "database:pgsql-bi-01", "data_collection", "collection"),
    # rdp
    (69, "account:CORP\\svc_backup", "host:win-admin-01", "lateral_movement", "lateral_movement"),
    (70, "account:CORP\\svc_backup", "host:win-admin-01", "lateral_movement", "lateral_movement"),
    # privesc
    (71, "account:CORP\\svc_backup", "host:win-admin-01", "credential_use", "privilege_escalation"),
    # ci.sh
    (72, "host:ci-runner-01", "ip:203.0.113.60", "command_execution", "execution"),
    (73, "host:ci-runner-01", "ip:203.0.113.60", "command_execution", "execution"),
    # lsass
    (74, "host:win-admin-01", "file:C:\\Windows\\Temp\\ls.dmp", "credential_dump", "credential_access"),
    (75, "host:win-admin-01", "file:C:\\Windows\\Temp\\ls.dmp", "credential_dump", "credential_access"),
    (76, "host:win-admin-01", "file:C:\\Windows\\Temp\\ls.dmp", "credential_dump", "credential_access"),
    # k8s token
    (77, "host:ci-runner-01", "token:system:serviceaccount:prod:ci-runner", "credential_dump", "credential_access"),
    (78, "token:system:serviceaccount:prod:ci-runner", "cluster:k8s-master-01", "credential_use", "credential_use"),
    (79, "token:system:serviceaccount:prod:ci-runner", "cluster:k8s-master-01", "credential_dump", "credential_access"),
    (80, "token:system:serviceaccount:prod:ci-runner", "cluster:k8s-master-01", "cloud_discovery", "discovery"),
    (81, "token:system:serviceaccount:prod:ci-runner", "cluster:k8s-master-01", "cloud_discovery", "discovery"),
    # finance collection
    (82, "host:win-admin-01", "host:file-srv-01", "data_collection", "collection"),
    (83, "host:win-admin-01", "host:file-srv-01", "data_collection", "collection"),
    (84, "host:win-admin-01", "host:file-srv-01", "data_collection", "collection"),
    # assume role
    (85, "token:system:serviceaccount:prod:ci-runner", "token:role/oss-backup-reader", "credential_use", "credential_use"),
    # bucket discovery
    (86, "token:role/oss-backup-reader", "bucket:prod-backup", "cloud_discovery", "discovery"),
    # staging
    (87, "host:win-admin-01", "file:C:\\Temp\\finance_q2.7z", "data_staging", "collection"),
    (88, "host:win-admin-01", "host:ops-jump-01", "data_staging", "collection"),
    # exfil bi
    (89, "host:ops-jump-01", "domain:archive-sync-bkt.storage.example", "exfiltration", "exfiltration"),
    (90, "host:ops-jump-01", "ip:203.0.113.210", "exfiltration", "exfiltration"),
    # erp get
    (91, "token:role/oss-backup-reader", "bucket:prod-backup", "cloud_collection", "collection"),
    # erp upload
    (92, "host:ci-runner-01", "domain:archive-sync-bkt.storage.example", "exfiltration", "exfiltration"),
    # staging full
    (93, "host:ops-jump-01", "file:/tmp/.cache/.stage/full.tar", "data_staging", "collection"),
    (94, "host:ops-jump-01", "file:/tmp/.cache/.stage/full.tar", "data_staging", "collection"),
    (95, "host:ops-jump-01", "file:/tmp/.cache/.stage/full.tar", "data_staging", "collection"),
    # cleanup
    (96, "host:ops-jump-01", "host:ops-jump-01", "cleanup", "defense_evasion"),
    (97, "host:ops-jump-01", "host:ops-jump-01", "cleanup", "defense_evasion"),
    (98, "host:ops-jump-01", "host:ops-jump-01", "cleanup", "defense_evasion"),
    # final exfil
    (99, "host:ops-jump-01", "domain:cdn-sync.example", "exfiltration", "exfiltration"),
    (100, "host:ops-jump-01", "domain:cdn-sync.example", "exfiltration", "exfiltration"),
    (101, "host:ops-jump-01", "ip:203.0.113.77", "exfiltration", "exfiltration"),
    (102, "host:ops-jump-01", "domain:cdn-sync.example", "exfiltration", "exfiltration"),
    (103, "host:ops-jump-01", "ip:203.0.113.77", "exfiltration", "exfiltration"),
    (104, "host:ops-jump-01", "ip:203.0.113.77", "exfiltration", "exfiltration"),
]

assert len(PER_EVENT) == 104, len(PER_EVENT)
assert sorted(e[0] for e in PER_EVENT) == list(range(1, 105))

# ---------- attack_graph.json ----------
nodes = {}
edges = []
for i, (n, f, t, act, stg) in enumerate(PER_EVENT):
    eid = E(n)
    event_id, ev_stage = EV[eid]
    ts = TIMES[event_id]
    nodes[f] = f.split(":", 1)
    nodes[t] = t.split(":", 1)
    edges.append({
        "id": f"EDGE{n:03d}",
        "from": f,
        "to": t,
        "action": act,
        "stage": stg,
        "time_start": ts,
        "time_end": ts,
        "evidence_ids": [eid],
    })

node_list = [{"id": ty + ":" + val, "type": ty, "label": val} for ty, val in nodes.values()]
node_list.sort(key=lambda x: x["id"])

graph = {
    "schema_version": "1.0",
    "incident_id": "team54-build-final-2026",
    "nodes": node_list,
    "edges": edges,
}
(OUT / "attack_graph.json").write_text(json.dumps(graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

# ---------- timeline.csv: 35 rows (4 merges) ----------
TL = [
    ("recon", "09:05:00", "09:05:49", [1,2,3,4,5,6,7,8,9,10]),
    ("initial_access", "09:14:22", "09:14:24", [11,12,13,14]),
    ("execution", "09:16:10", "09:16:30", [15,16,17,18,19]),
    ("persistence", "09:20:05", "09:20:17", [20,21,22]),
    ("discovery", "09:24:00", "09:24:44", [23,24,25,26,27]),
    ("credential_access", "09:31:00", "09:31:48", [28,29,30]),
    ("lateral_movement", "09:39:15", "09:39:19", [31,32,33,34]),
    ("discovery", "09:45:00", "09:45:32", [35,36,37]),
    ("credential_use", "09:51:00", "09:51:01", [38,39]),
    ("discovery", "09:55:00", "09:55:45", [40,41,42,43]),
    ("credential_access", "10:02:00", "10:02:34", [44,45,46]),
    ("credential_access", "10:03:00", "10:03:05", [47,48]),
    ("credential_access", "10:05:00", "10:05:00", [49]),
    ("credential_use", "10:05:18", "10:05:18", [50]),
    ("discovery", "10:08:00", "10:08:00", [51]),
    ("credential_use", "10:08:06", "10:08:11", [52,53,54,55]),
    ("discovery", "10:10:00", "10:10:24", [56,57,58]),
    ("credential_use", "10:12:00", "10:12:01", [59,60]),
    ("discovery", "10:13:00", "10:13:40", [61,62,63]),
    ("execution", "10:18:00", "10:19:20", [64,65,66,67,68]),
    ("privilege_escalation", "10:22:00", "10:22:03", [69,70,71]),
    ("execution", "10:24:00", "10:24:05", [72,73]),
    ("credential_access", "10:27:00", "10:27:02", [74,75,76]),
    ("credential_use", "10:28:00", "10:28:12", [77,78]),
    ("credential_access", "10:34:00", "10:34:00", [79]),
    ("discovery", "10:34:12", "10:34:24", [80,81]),
    ("collection", "10:41:00", "10:41:04", [82,83,84]),
    ("credential_use", "10:42:00", "10:42:09", [85,86]),
    ("collection", "10:49:00", "10:49:30", [87,88]),
    ("exfiltration", "11:08:00", "11:08:01", [89,90]),
    ("collection", "11:15:00", "11:15:00", [91]),
    ("exfiltration", "11:15:30", "11:15:30", [92]),
    ("collection", "11:35:00", "11:35:50", [93,94,95]),
    ("defense_evasion", "11:42:00", "11:42:22", [96,97,98]),
    ("exfiltration", "11:50:00", "11:50:18", [99,100,101,102,103,104]),
]
D = "2026-07-06"
with (OUT / "timeline.csv").open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["step","stage","time_start","time_end","evidence_ids"])
    for i, (stg, ts, te, nums) in enumerate(TL, 1):
        w.writerow([i, stg, f"{D}T{ts}+08:00", f"{D}T{te}+08:00", ";".join(E(n) for n in nums)])

# ---------- evidence.csv / ioc.csv / manifest ----------
shutil.copy(S2 / "evidence.csv", OUT / "evidence.csv")
shutil.copy("/Users/mashiro/Downloads/CISCN2026Final/team54-final/analysis/_ioc_s1_remapped.csv", OUT / "ioc.csv")
manifest = {
    "team_id": "team54",
    "schema_version": "1.0",
    "created_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
}
(OUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

print("nodes:", len(node_list), "edges:", len(edges), "timeline rows:", len(TL))
