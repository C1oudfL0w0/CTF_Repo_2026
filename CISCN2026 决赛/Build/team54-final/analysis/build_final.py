#!/usr/bin/env python3
"""Build the FINAL (3rd) submission for team54.

Decisions (reasoned in analysis):
1. evidence.csv / timeline.csv: keep exactly the 2nd submission (evidence 25/25, timeline 12.01).
   - Evidence F1 is computed on (event_id, stage) pairs: S2 = 25.00 means all 104 stages correct.
2. attack_graph.json: rebuild on S2's 41-edge skeleton with these changes:
   - credential_use edges use the ACCOUNT as source (raw logs emphasize the stolen account):
       crm_ro -> database:mysql-core-01 (E038/E039 login; E040-E043 discovery)
       bi_sync -> database:pgsql-bi-01 (E059/E060 login; E065/E067/E068 collection)
   - credential_dump E047/E048 (sys_config '%bi%'): host:web-prod-01 -> account:bi_sync
   - egress targets use the planted DOMAINS (pcap Host headers, proxy URLs, DNS query):
       a.sh  -> domain:update-cache.example (pcap 72073 Host header)
       bi exfil -> domain:archive-sync-bkt.storage.example  (single edge, E089+E090)
       final   -> domain:cdn-sync.example (single edge, E099..E104; DNS evidence supports domain)
   - E091 get_object: token:role/oss-backup-reader -> bucket:prod-backup (actor->target)
   - drop ip:203.0.113.{60,210,77} / account:gitlab-runner / token:pat/deploy-token nodes
     (they remain IOC entries); add account:bi_sync node.
   - no cleanup edge (target unknowable, skip).
3. ioc.csv: revert to submission-1 rows (scored 7.10 > 6.71) but remap evidence ids to S2 numbering.
"""
import csv
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

BASE = Path("/Users/mashiro/Downloads/CISCN2026Final")
S1 = BASE / "team54/build/submission"
S2 = BASE / "team54-final/submission-new"
OUT = BASE / "team54-final/submission-final"

D = "2026-07-06"
TZ = "+08:00"
def t(hms):
    return f"{D}T{hms}{TZ}"

OUT.mkdir(parents=True, exist_ok=True)

# ---------- 1. evidence.csv & timeline.csv & manifest ----------
shutil.copy(S2 / "evidence.csv", OUT / "evidence.csv")
shutil.copy(S2 / "timeline.csv", OUT / "timeline.csv")
manifest = {
    "team_id": "team54",
    "schema_version": "1.0",
    "created_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
}
(OUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

# ---------- 2. attack_graph.json ----------
NODES = [
    ("ip", "198.51.100.77"),
    ("host", "web-prod-01"),
    ("domain", "update-cache.example"),
    ("file", "/var/www/oa/public/.cache.php"),
    ("account", "deploy"),
    ("host", "ops-jump-01"),
    ("account", "crm_ro"),
    ("account", "bi_sync"),
    ("database", "mysql-core-01"),
    ("database", "pgsql-bi-01"),
    ("account", "CORP\\svc_backup"),
    ("account", "svc_deploy"),
    ("host", "gitlab-01"),
    ("host", "ad-dc-01"),
    ("host", "win-admin-01"),
    ("host", "jenkins-01"),
    ("host", "ci-runner-01"),
    ("host", "file-srv-01"),
    ("file", "C:\\Windows\\Temp\\ls.dmp"),
    ("token", "system:serviceaccount:prod:ci-runner"),
    ("cluster", "k8s-master-01"),
    ("token", "role/oss-backup-reader"),
    ("bucket", "prod-backup"),
    ("domain", "archive-sync-bkt.storage.example"),
    ("domain", "cdn-sync.example"),
    ("file", "/tmp/.cache/.stage/full.tar"),
]
nodes = [{"id": f"{ty}:{v}", "type": ty, "label": v} for ty, v in NODES]

SA = "token:system:serviceaccount:prod:ci-runner"
ROLE = "token:role/oss-backup-reader"

EDGES = [
    # recon
    ("ip:198.51.100.77", "host:web-prod-01", "scan", "recon", "09:05:00", "09:05:49",
     "E001;E002;E003;E004;E005;E006;E007;E008;E009;E010"),
    # initial access SSRF
    ("ip:198.51.100.77", "host:web-prod-01", "exploit_public_service", "initial_access", "09:14:22", "09:14:24",
     "E011;E012;E013;E014"),
    # execution: a.sh download (pcap Host: update-cache.example)
    ("host:web-prod-01", "domain:update-cache.example", "command_execution", "execution", "09:16:10", "09:16:14",
     "E015;E016;E017"),
    # C2 callback
    ("host:web-prod-01", "ip:198.51.100.77", "command_and_control", "execution", "09:16:26", "09:16:30",
     "E018;E019"),
    # webshell
    ("host:web-prod-01", "file:/var/www/oa/public/.cache.php", "webshell_upload", "persistence", "09:20:05", "09:20:17",
     "E020;E021;E022"),
    # host discovery commands on web-prod-01 (id / hostname / ip route / etc hosts / env)
    ("host:web-prod-01", "host:web-prod-01", "host_discovery", "discovery", "09:24:00", "09:24:44",
     "E023;E024;E025;E026;E027"),
    # credential dump on web (deploy key etc.)
    ("host:web-prod-01", "account:deploy", "credential_dump", "credential_access", "09:31:00", "09:31:48",
     "E028;E029;E030"),
    # ssh to jump as deploy
    ("account:deploy", "host:ops-jump-01", "lateral_movement", "lateral_movement", "09:39:15", "09:39:19",
     "E031;E032;E033;E034"),
    # discovery on jump: ansible inventory -> win-admin-01; db.yml -> pgsql
    ("host:ops-jump-01", "host:win-admin-01", "host_discovery", "discovery", "09:45:00", "09:45:16",
     "E035;E036"),
    ("host:ops-jump-01", "database:pgsql-bi-01", "database_discovery", "discovery", "09:45:32", "09:45:32",
     "E037"),
    # mysql login as crm_ro
    ("account:crm_ro", "database:mysql-core-01", "credential_use", "credential_use", "09:51:00", "09:51:01",
     "E038;E039"),
    # mysql discovery as crm_ro
    ("account:crm_ro", "database:mysql-core-01", "database_discovery", "discovery", "09:55:00", "09:55:45",
     "E040;E041;E042;E043"),
    # svc_backup creds from ansible vault
    ("host:ops-jump-01", "account:CORP\\svc_backup", "credential_dump", "credential_access", "10:02:00", "10:02:34",
     "E044;E045;E046"),
    # bi_sync creds from mysql sys_config
    ("host:web-prod-01", "account:bi_sync", "credential_dump", "credential_access", "10:03:00", "10:03:05",
     "E047;E048"),
    # gitlab PAT from git-credentials
    ("host:ops-jump-01", "account:svc_deploy", "credential_dump", "credential_access", "10:05:00", "10:05:00",
     "E049"),
    # PAT login to gitlab
    ("account:svc_deploy", "host:gitlab-01", "credential_use", "credential_use", "10:05:18", "10:05:18",
     "E050"),
    # ldap enumeration
    ("host:ops-jump-01", "host:ad-dc-01", "network_discovery", "discovery", "10:08:00", "10:08:00",
     "E051"),
    # svc_backup logon to DC
    ("account:CORP\\svc_backup", "host:ad-dc-01", "credential_use", "credential_use", "10:08:06", "10:08:11",
     "E052;E053;E054;E055"),
    # gitlab API discovery
    ("account:svc_deploy", "host:gitlab-01", "devops_discovery", "discovery", "10:10:00", "10:10:24",
     "E056;E057;E058"),
    # bi_sync login to pgsql
    ("account:bi_sync", "database:pgsql-bi-01", "credential_use", "credential_use", "10:12:00", "10:12:01",
     "E059;E060"),
    # domain enumeration on DC
    ("account:CORP\\svc_backup", "host:ad-dc-01", "domain_discovery", "discovery", "10:13:00", "10:13:40",
     "E061;E062;E063"),
    # pipeline creation gitlab -> jenkins
    ("host:gitlab-01", "host:jenkins-01", "ci_pipeline_execution", "execution", "10:18:00", "10:18:21",
     "E064;E066"),
    # jenkins -> ci-runner executes poisoned script
    ("host:jenkins-01", "host:ci-runner-01", "ci_pipeline_execution", "execution", "10:24:00", "10:24:05",
     "E072;E073"),
    # BI data copy out
    ("account:bi_sync", "database:pgsql-bi-01", "data_collection", "collection", "10:18:00", "10:19:20",
     "E065;E067;E068"),
    # RDP to win-admin-01
    ("account:CORP\\svc_backup", "host:win-admin-01", "lateral_movement", "lateral_movement", "10:22:00", "10:22:00",
     "E069;E070"),
    # 4672 special privileges
    ("account:CORP\\svc_backup", "host:win-admin-01", "credential_use", "privilege_escalation", "10:22:03", "10:22:03",
     "E071"),
    # lsass dump
    ("host:win-admin-01", "file:C:\\Windows\\Temp\\ls.dmp", "credential_dump", "credential_access", "10:27:00", "10:27:02",
     "E074;E075;E076"),
    # k8s SA token theft
    ("host:ci-runner-01", SA, "credential_dump", "credential_access", "10:28:00", "10:28:00",
     "E077"),
    # SA token use
    (SA, "cluster:k8s-master-01", "credential_use", "credential_use", "10:28:12", "10:28:12",
     "E078"),
    # k8s secrets
    (SA, "cluster:k8s-master-01", "credential_dump", "credential_access", "10:34:00", "10:34:00",
     "E079"),
    # k8s discovery
    (SA, "cluster:k8s-master-01", "cloud_discovery", "discovery", "10:34:12", "10:34:24",
     "E080;E081"),
    # finance share collection
    ("host:win-admin-01", "host:file-srv-01", "data_collection", "collection", "10:41:00", "10:41:04",
     "E082;E083;E084"),
    # assume oss role
    (SA, ROLE, "credential_use", "credential_use", "10:42:00", "10:42:00",
     "E085"),
    # list bucket
    (ROLE, "bucket:prod-backup", "cloud_discovery", "discovery", "10:42:09", "10:42:09",
     "E086"),
    # staging 7z + smb to jump
    ("host:win-admin-01", "host:ops-jump-01", "data_staging", "collection", "10:49:00", "10:49:30",
     "E087;E088"),
    # exfil bi part
    ("host:ops-jump-01", "domain:archive-sync-bkt.storage.example", "exfiltration", "exfiltration", "11:08:00", "11:08:01",
     "E089;E090"),
    # get erp backup from bucket
    (ROLE, "bucket:prod-backup", "cloud_collection", "collection", "11:15:00", "11:15:00",
     "E091"),
    # exfil erp backup
    ("host:ci-runner-01", "domain:archive-sync-bkt.storage.example", "exfiltration", "exfiltration", "11:15:30", "11:15:30",
     "E092"),
    # staging full.tar
    ("host:ops-jump-01", "file:/tmp/.cache/.stage/full.tar", "data_staging", "collection", "11:35:00", "11:35:50",
     "E093;E094;E095"),
    # cleanup traces (delete scripts, history -c, purge logs)
    ("host:ops-jump-01", "host:ops-jump-01", "cleanup", "defense_evasion", "11:42:00", "11:42:22",
     "E096;E097;E098"),
    # final exfil via cdn-sync
    ("host:ops-jump-01", "domain:cdn-sync.example", "exfiltration", "exfiltration", "11:50:00", "11:50:18",
     "E099;E100;E101;E102;E103;E104"),
]

edges = []
for i, (f, to, act, stg, ts, te, ev) in enumerate(EDGES, 1):
    edges.append({
        "id": f"EDGE{i:03d}",
        "from": f,
        "to": to,
        "action": act,
        "stage": stg,
        "time_start": t(ts),
        "time_end": t(te),
        "evidence_ids": ev.split(";"),
    })

graph = {
    "schema_version": "1.0",
    "incident_id": "team54-build-final-2026",
    "nodes": nodes,
    "edges": edges,
}
(OUT / "attack_graph.json").write_text(json.dumps(graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

# ---------- 3. ioc.csv: S1 rows remapped to S2 evidence numbering ----------
# build event_id -> S2 number
s2_by_event = {}
with (S2 / "evidence.csv").open() as f:
    for row in csv.DictReader(f):
        s2_by_event[row["event_id"]] = row["evidence_id"]
s1_by_id = {}
with (S1 / "evidence.csv").open() as f:
    for row in csv.DictReader(f):
        s1_by_id[row["evidence_id"]] = row["event_id"]

def remap(refs):
    out = []
    for r in refs.split(";"):
        r = r.strip()
        if not r:
            continue
        ev = s1_by_id[r]          # S1 event_id
        out.append(s2_by_event[ev])  # S2 evidence id
    return ";".join(out)

with (S1 / "ioc.csv").open() as f:
    s1_ioc = list(csv.DictReader(f))

with (OUT / "ioc.csv").open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["type", "value", "first_seen", "last_seen", "related_asset", "evidence_ids"])
    for row in s1_ioc:
        w.writerow([
            row["type"], row["value"], row["first_seen"], row["last_seen"],
            row["related_asset"], remap(row["evidence_ids"]),
        ])

print("nodes:", len(nodes), "edges:", len(edges), "ioc rows:", len(s1_ioc))
