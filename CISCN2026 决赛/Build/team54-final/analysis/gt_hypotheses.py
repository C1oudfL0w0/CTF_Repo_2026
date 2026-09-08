#!/usr/bin/env python3
"""GT hypotheses for the attack graph."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from sim import run, E1, E2, E3, q, score

D = "2026-07-06"
T = lambda hms: f"{D}T{hms}+08:00"

# evidence id sets by group (final submission-new numbering)
EVID = {
 "scan": "E001;E002;E003;E004;E005;E006;E007;E008;E009;E010",
 "ssrf": "E011;E012;E013;E014",
 "ash":  "E015;E016;E017",
 "c2":   "E018;E019",
 "wshell":"E020;E021;E022",
 "webdis":"E023;E024;E025;E026;E027",
 "webcred":"E028;E029;E030",
 "ssh":  "E031;E032;E033;E034",
 "jumpdis":"E035;E036;E037",
 "mysqllogin":"E038;E039",
 "mysqldis":"E040;E041;E042;E043",
 "wincred":"E044;E045;E046",
 "sysconf":"E047;E048",
 "gitcred":"E049",
 "pat":  "E050",
 "ldap": "E051",
 "adlogon":"E052;E053;E054;E055",
 "gitdis":"E056;E057;E058",
 "bilogin":"E059;E060",
 "domdis":"E061;E062;E063",
 "pipeline":"E064;E066",
 "cicopy":"E065;E067;E068",
 "rdp":  "E069;E070",
 "priv": "E071",
 "cish": "E072;E073",
 "lsass":"E074;E075;E076",
 "satoken":"E077",
 "satuse":"E078",
 "secrets":"E079",
 "k8sdis":"E080;E081",
 "finance":"E082;E083;E084",
 "assume":"E085",
 "bucketdis":"E086",
 "stage7z":"E087;E088",
 "biupl": "E089;E090",
 "erpget":"E091",
 "erpupl":"E092",
 "stagefull":"E093;E094;E095",
 "clean":"E096;E097;E098",
 "final": "E099;E100;E101;E102;E103;E104",
}

def es(s):
    return frozenset(s.split(";"))

def gtA():
    g = []
    g.append(("ip:198.51.100.77","host:web-prod-01","scan","recon",T("09:05:00"),T("09:05:49"),es(EVID["scan"])))
    g.append(("ip:198.51.100.77","host:web-prod-01","exploit_public_service","initial_access",T("09:14:22"),T("09:14:24"),es(EVID["ssrf"])))
    g.append(("host:web-prod-01","domain:update-cache.example","command_execution","execution",T("09:16:10"),T("09:16:14"),es(EVID["ash"])))
    g.append(("host:web-prod-01","ip:198.51.100.77","command_and_control","execution",T("09:16:26"),T("09:16:30"),es(EVID["c2"])))
    g.append(("host:web-prod-01","file:/var/www/oa/public/.cache.php","webshell_upload","persistence",T("09:20:05"),T("09:20:17"),es(EVID["wshell"])))
    g.append(("host:web-prod-01","account:deploy","credential_dump","credential_access",T("09:31:00"),T("09:31:48"),es(EVID["webcred"])))
    g.append(("account:deploy","host:ops-jump-01","lateral_movement","lateral_movement",T("09:39:15"),T("09:39:19"),es(EVID["ssh"])))
    g.append(("host:ops-jump-01","host:win-admin-01","host_discovery","discovery",T("09:45:00"),T("09:45:16"),es("E035;E036")))
    g.append(("host:ops-jump-01","database:pgsql-bi-01","database_discovery","discovery",T("09:45:32"),T("09:45:32"),es("E037")))
    g.append(("account:crm_ro","database:mysql-core-01","credential_use","credential_use",T("09:51:00"),T("09:51:01"),es(EVID["mysqllogin"])))
    g.append(("account:crm_ro","database:mysql-core-01","database_discovery","discovery",T("09:55:00"),T("09:55:45"),es(EVID["mysqldis"])))
    g.append(("host:ops-jump-01","account:CORP\\svc_backup","credential_dump","credential_access",T("10:02:00"),T("10:02:34"),es(EVID["wincred"])))
    g.append(("account:crm_ro","database:mysql-core-01","credential_dump","credential_access",T("10:03:00"),T("10:03:05"),es(EVID["sysconf"])))
    g.append(("host:ops-jump-01","account:svc_deploy","credential_dump","credential_access",T("10:05:00"),T("10:05:00"),es(EVID["gitcred"])))
    g.append(("account:svc_deploy","host:gitlab-01","credential_use","credential_use",T("10:05:18"),T("10:05:18"),es(EVID["pat"])))
    g.append(("host:ops-jump-01","host:ad-dc-01","network_discovery","discovery",T("10:08:00"),T("10:08:00"),es(EVID["ldap"])))
    g.append(("account:CORP\\svc_backup","host:ad-dc-01","credential_use","credential_use",T("10:08:06"),T("10:08:11"),es(EVID["adlogon"])))
    g.append(("account:svc_deploy","host:gitlab-01","devops_discovery","discovery",T("10:10:00"),T("10:10:24"),es(EVID["gitdis"])))
    g.append(("account:bi_sync","database:pgsql-bi-01","credential_use","credential_use",T("10:12:00"),T("10:12:01"),es(EVID["bilogin"])))
    g.append(("account:CORP\\svc_backup","host:ad-dc-01","domain_discovery","discovery",T("10:13:00"),T("10:13:40"),es(EVID["domdis"])))
    g.append(("host:gitlab-01","host:jenkins-01","ci_pipeline_execution","execution",T("10:18:00"),T("10:18:21"),es(EVID["pipeline"])))
    g.append(("host:jenkins-01","host:ci-runner-01","ci_pipeline_execution","execution",T("10:24:00"),T("10:24:05"),es(EVID["cish"])))
    g.append(("account:bi_sync","database:pgsql-bi-01","data_collection","collection",T("10:18:00"),T("10:19:20"),es(EVID["cicopy"])))
    g.append(("account:CORP\\svc_backup","host:win-admin-01","lateral_movement","lateral_movement",T("10:22:00"),T("10:22:00"),es(EVID["rdp"])))
    g.append(("host:win-admin-01","file:C:\\Windows\\Temp\\ls.dmp","credential_dump","credential_access",T("10:27:00"),T("10:27:02"),es(EVID["lsass"])))
    g.append(("host:ci-runner-01","token:system:serviceaccount:prod:ci-runner","credential_dump","credential_access",T("10:28:00"),T("10:28:00"),es(EVID["satoken"])))
    g.append(("token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","credential_use","credential_use",T("10:28:12"),T("10:28:12"),es(EVID["satuse"])))
    g.append(("token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","credential_dump","credential_access",T("10:34:00"),T("10:34:00"),es(EVID["secrets"])))
    g.append(("token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","cloud_discovery","discovery",T("10:34:12"),T("10:34:24"),es(EVID["k8sdis"])))
    g.append(("host:win-admin-01","host:file-srv-01","data_collection","collection",T("10:41:00"),T("10:41:04"),es(EVID["finance"])))
    g.append(("token:system:serviceaccount:prod:ci-runner","token:role/oss-backup-reader","credential_use","credential_use",T("10:42:00"),T("10:42:00"),es(EVID["assume"])))
    g.append(("token:role/oss-backup-reader","bucket:prod-backup","cloud_discovery","discovery",T("10:42:09"),T("10:42:09"),es(EVID["bucketdis"])))
    g.append(("host:win-admin-01","host:ops-jump-01","data_staging","collection",T("10:49:00"),T("10:49:30"),es(EVID["stage7z"])))
    g.append(("host:ops-jump-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration",T("11:08:00"),T("11:08:01"),es(EVID["biupl"])))
    g.append(("bucket:prod-backup","host:ci-runner-01","cloud_collection","collection",T("11:15:00"),T("11:15:00"),es(EVID["erpget"])))
    g.append(("host:ci-runner-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration",T("11:15:30"),T("11:15:30"),es(EVID["erpupl"])))
    g.append(("host:ops-jump-01","file:/tmp/.cache/.stage/full.tar","data_staging","collection",T("11:35:00"),T("11:35:50"),es(EVID["stagefull"])))
    g.append(("host:ops-jump-01","file:/tmp/a.sh","cleanup","defense_evasion",T("11:42:00"),T("11:42:22"),es(EVID["clean"])))
    g.append(("host:ops-jump-01","domain:cdn-sync.example","exfiltration","exfiltration",T("11:50:00"),T("11:50:18"),es(EVID["final"])))
    return g

def gtB():
    """A without priv edge; add priv as separate; cleanup target ops-jump self removed."""
    g = gtA()
    g.append(("account:CORP\\svc_backup","host:win-admin-01","credential_use","privilege_escalation",T("10:22:03"),T("10:22:03"),es(EVID["priv"])))
    # replace cleanup edge target
    g = [e for e in g if e[4] != T("11:42:00")]
    g.append(("host:ops-jump-01","file:/tmp/a.sh","cleanup","defense_evasion",T("11:42:00"),T("11:42:22"),es(EVID["clean"])))
    return g

def gtC():
    """host-from variants: a.sh -> ip:203.0.113.60; mysql from web-prod; pgsql from ops-jump; E047/48 from web."""
    g = []
    g.append(("ip:198.51.100.77","host:web-prod-01","scan","recon",T("09:05:00"),T("09:05:49"),es(EVID["scan"])))
    g.append(("ip:198.51.100.77","host:web-prod-01","exploit_public_service","initial_access",T("09:14:22"),T("09:14:24"),es(EVID["ssrf"])))
    g.append(("host:web-prod-01","ip:203.0.113.60","command_execution","execution",T("09:16:10"),T("09:16:14"),es(EVID["ash"])))
    g.append(("host:web-prod-01","ip:198.51.100.77","command_and_control","execution",T("09:16:26"),T("09:16:30"),es(EVID["c2"])))
    g.append(("host:web-prod-01","file:/var/www/oa/public/.cache.php","webshell_upload","persistence",T("09:20:05"),T("09:20:17"),es(EVID["wshell"])))
    g.append(("host:web-prod-01","account:deploy","credential_dump","credential_access",T("09:31:00"),T("09:31:48"),es(EVID["webcred"])))
    g.append(("account:deploy","host:ops-jump-01","lateral_movement","lateral_movement",T("09:39:15"),T("09:39:19"),es(EVID["ssh"])))
    g.append(("host:ops-jump-01","host:win-admin-01","host_discovery","discovery",T("09:45:00"),T("09:45:16"),es("E035;E036")))
    g.append(("host:ops-jump-01","database:pgsql-bi-01","database_discovery","discovery",T("09:45:32"),T("09:45:32"),es("E037")))
    g.append(("host:web-prod-01","database:mysql-core-01","credential_use","credential_use",T("09:51:00"),T("09:51:01"),es(EVID["mysqllogin"])))
    g.append(("host:web-prod-01","database:mysql-core-01","database_discovery","discovery",T("09:55:00"),T("09:55:45"),es(EVID["mysqldis"])))
    g.append(("host:ops-jump-01","account:CORP\\svc_backup","credential_dump","credential_access",T("10:02:00"),T("10:02:34"),es(EVID["wincred"])))
    g.append(("host:web-prod-01","database:mysql-core-01","credential_dump","credential_access",T("10:03:00"),T("10:03:05"),es(EVID["sysconf"])))
    g.append(("host:ops-jump-01","account:svc_deploy","credential_dump","credential_access",T("10:05:00"),T("10:05:00"),es(EVID["gitcred"])))
    g.append(("account:svc_deploy","host:gitlab-01","credential_use","credential_use",T("10:05:18"),T("10:05:18"),es(EVID["pat"])))
    g.append(("host:ops-jump-01","host:ad-dc-01","network_discovery","discovery",T("10:08:00"),T("10:08:00"),es(EVID["ldap"])))
    g.append(("account:CORP\\svc_backup","host:ad-dc-01","credential_use","credential_use",T("10:08:06"),T("10:08:11"),es(EVID["adlogon"])))
    g.append(("account:svc_deploy","host:gitlab-01","devops_discovery","discovery",T("10:10:00"),T("10:10:24"),es(EVID["gitdis"])))
    g.append(("host:ops-jump-01","database:pgsql-bi-01","credential_use","credential_use",T("10:12:00"),T("10:12:01"),es(EVID["bilogin"])))
    g.append(("account:CORP\\svc_backup","host:ad-dc-01","domain_discovery","discovery",T("10:13:00"),T("10:13:40"),es(EVID["domdis"])))
    g.append(("host:gitlab-01","host:jenkins-01","ci_pipeline_execution","execution",T("10:18:00"),T("10:18:21"),es(EVID["pipeline"])))
    g.append(("host:jenkins-01","host:ci-runner-01","ci_pipeline_execution","execution",T("10:24:00"),T("10:24:05"),es(EVID["cish"])))
    g.append(("host:ops-jump-01","database:pgsql-bi-01","data_collection","collection",T("10:18:00"),T("10:19:20"),es(EVID["cicopy"])))
    g.append(("account:CORP\\svc_backup","host:win-admin-01","lateral_movement","lateral_movement",T("10:22:00"),T("10:22:00"),es(EVID["rdp"])))
    g.append(("account:CORP\\svc_backup","host:win-admin-01","credential_use","privilege_escalation",T("10:22:03"),T("10:22:03"),es(EVID["priv"])))
    g.append(("host:win-admin-01","file:C:\\Windows\\Temp\\ls.dmp","credential_dump","credential_access",T("10:27:00"),T("10:27:02"),es(EVID["lsass"])))
    g.append(("host:ci-runner-01","token:system:serviceaccount:prod:ci-runner","credential_dump","credential_access",T("10:28:00"),T("10:28:00"),es(EVID["satoken"])))
    g.append(("token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","credential_use","credential_use",T("10:28:12"),T("10:28:12"),es(EVID["satuse"])))
    g.append(("token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","credential_dump","credential_access",T("10:34:00"),T("10:34:00"),es(EVID["secrets"])))
    g.append(("token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","cloud_discovery","discovery",T("10:34:12"),T("10:34:24"),es(EVID["k8sdis"])))
    g.append(("host:win-admin-01","host:file-srv-01","data_collection","collection",T("10:41:00"),T("10:41:04"),es(EVID["finance"])))
    g.append(("token:system:serviceaccount:prod:ci-runner","token:role/oss-backup-reader","credential_use","credential_use",T("10:42:00"),T("10:42:00"),es(EVID["assume"])))
    g.append(("token:role/oss-backup-reader","bucket:prod-backup","cloud_discovery","discovery",T("10:42:09"),T("10:42:09"),es(EVID["bucketdis"])))
    g.append(("host:win-admin-01","host:ops-jump-01","data_staging","collection",T("10:49:00"),T("10:49:30"),es(EVID["stage7z"])))
    g.append(("host:ops-jump-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration",T("11:08:00"),T("11:08:01"),es(EVID["biupl"])))
    g.append(("bucket:prod-backup","host:ci-runner-01","cloud_collection","collection",T("11:15:00"),T("11:15:00"),es(EVID["erpget"])))
    g.append(("host:ci-runner-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration",T("11:15:30"),T("11:15:30"),es(EVID["erpupl"])))
    g.append(("host:ops-jump-01","file:/tmp/.cache/.stage/full.tar","data_staging","collection",T("11:35:00"),T("11:35:50"),es(EVID["stagefull"])))
    g.append(("host:ops-jump-01","file:/tmp/a.sh","cleanup","defense_evasion",T("11:42:00"),T("11:42:22"),es(EVID["clean"])))
    g.append(("host:ops-jump-01","domain:cdn-sync.example","exfiltration","exfiltration",T("11:50:00"),T("11:50:18"),es(EVID["final"])))
    return g

if __name__ == "__main__":
    for name, g in [("A", gtA()), ("B", gtB()), ("C", gtC())]:
        run(g, name)
