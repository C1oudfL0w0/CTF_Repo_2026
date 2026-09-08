#!/usr/bin/env python3
"""Grid search GT graph structure to reproduce observed edge scores 7.18 (S1) / 7.49 (S2)."""
import itertools
from sim import E1, E2, E3, q

D = "2026-07-06"
T = lambda hms: f"{D}T{hms}+08:00"
es = lambda s: frozenset(s.split(";"))

EV = {
 "scan": "E001;E002;E003;E004;E005;E006;E007;E008;E009;E010",
 "ssrf": "E011;E012;E013;E014",
 "ash":  "E015;E016;E017",
 "c2":   "E018;E019",
 "wshell":"E020;E021;E022",
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

def build(ash_tgt, mysql_from, pgsql_from, sysconf_from, lsass_to, jumpdis_mode, priv_mode, exfil_mode, clean_mode, stage_from, erp_from, bucketdis_from, assume_edge, pipeline_split):
    g = []
    def add(f, t, a, s, ts, te, ev):
        g.append((f, t, a, s, ts, te, es(ev)))
    add("ip:198.51.100.77","host:web-prod-01","scan","recon",T("09:05:00"),T("09:05:49"),EV["scan"])
    add("ip:198.51.100.77","host:web-prod-01","exploit_public_service","initial_access",T("09:14:22"),T("09:14:24"),EV["ssrf"])
    add("host:web-prod-01",ash_tgt,"command_execution","execution",T("09:16:10"),T("09:16:14"),EV["ash"])
    add("host:web-prod-01","ip:198.51.100.77","command_and_control","execution",T("09:16:26"),T("09:16:30"),EV["c2"])
    add("host:web-prod-01","file:/var/www/oa/public/.cache.php","webshell_upload","persistence",T("09:20:05"),T("09:20:17"),EV["wshell"])
    add("host:web-prod-01","account:deploy","credential_dump","credential_access",T("09:31:00"),T("09:31:48"),EV["webcred"])
    add("account:deploy","host:ops-jump-01","lateral_movement","lateral_movement",T("09:39:15"),T("09:39:19"),EV["ssh"])
    if jumpdis_mode == "win+pgsql":
        add("host:ops-jump-01","host:win-admin-01","host_discovery","discovery",T("09:45:00"),T("09:45:16"),"E035;E036")
        add("host:ops-jump-01","database:pgsql-bi-01","database_discovery","discovery",T("09:45:32"),T("09:45:32"),"E037")
    elif jumpdis_mode == "one":
        add("host:ops-jump-01","host:win-admin-01","host_discovery","discovery",T("09:45:00"),T("09:45:32"),"E035;E036;E037")
    add(mysql_from,"database:mysql-core-01","credential_use","credential_use",T("09:51:00"),T("09:51:01"),EV["mysqllogin"])
    add(mysql_from,"database:mysql-core-01","database_discovery","discovery",T("09:55:00"),T("09:55:45"),EV["mysqldis"])
    add("host:ops-jump-01","account:CORP\\svc_backup","credential_dump","credential_access",T("10:02:00"),T("10:02:34"),EV["wincred"])
    add(sysconf_from,"database:mysql-core-01","credential_dump","credential_access",T("10:03:00"),T("10:03:05"),EV["sysconf"])
    add("host:ops-jump-01","account:svc_deploy","credential_dump","credential_access",T("10:05:00"),T("10:05:00"),EV["gitcred"])
    add("account:svc_deploy","host:gitlab-01","credential_use","credential_use",T("10:05:18"),T("10:05:18"),EV["pat"])
    add("host:ops-jump-01","host:ad-dc-01","network_discovery","discovery",T("10:08:00"),T("10:08:00"),EV["ldap"])
    add("account:CORP\\svc_backup","host:ad-dc-01","credential_use","credential_use",T("10:08:06"),T("10:08:11"),EV["adlogon"])
    add("account:svc_deploy","host:gitlab-01","devops_discovery","discovery",T("10:10:00"),T("10:10:24"),EV["gitdis"])
    add(pgsql_from,"database:pgsql-bi-01","credential_use","credential_use",T("10:12:00"),T("10:12:01"),EV["bilogin"])
    add("account:CORP\\svc_backup","host:ad-dc-01","domain_discovery","discovery",T("10:13:00"),T("10:13:40"),EV["domdis"])
    if pipeline_split:
        add("host:gitlab-01","host:jenkins-01","ci_pipeline_execution","execution",T("10:18:00"),T("10:18:21"),EV["pipeline"])
        add("host:jenkins-01","host:ci-runner-01","ci_pipeline_execution","execution",T("10:24:00"),T("10:24:05"),EV["cish"])
    else:
        add("host:gitlab-01","host:jenkins-01","ci_pipeline_execution","execution",T("10:18:00"),T("10:18:21"),EV["pipeline"])
        add("host:jenkins-01","host:ci-runner-01","ci_pipeline_execution","execution",T("10:18:00"),T("10:24:05"),EV["pipeline"]+";"+EV["cish"])
    add(pgsql_from,"database:pgsql-bi-01","data_collection","collection",T("10:18:00"),T("10:19:20"),EV["cicopy"])
    add("account:CORP\\svc_backup","host:win-admin-01","lateral_movement","lateral_movement",T("10:22:00"),T("10:22:00"),EV["rdp"])
    if priv_mode == "edge":
        add("account:CORP\\svc_backup","host:win-admin-01","credential_use","privilege_escalation",T("10:22:03"),T("10:22:03"),EV["priv"])
    elif priv_mode == "fold":
        # fold E071 into lsass edge
        add("host:win-admin-01",lsass_to,"credential_dump","credential_access",T("10:27:00"),T("10:27:02"),EV["lsass"]+";"+EV["priv"])
        lsass_to = None
    if lsass_to:
        add("host:win-admin-01",lsass_to,"credential_dump","credential_access",T("10:27:00"),T("10:27:02"),EV["lsass"])
    add("host:ci-runner-01","token:system:serviceaccount:prod:ci-runner","credential_dump","credential_access",T("10:28:00"),T("10:28:00"),EV["satoken"])
    add("token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","credential_use","credential_use",T("10:28:12"),T("10:28:12"),EV["satuse"])
    add("token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","credential_dump","credential_access",T("10:34:00"),T("10:34:00"),EV["secrets"])
    add("token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","cloud_discovery","discovery",T("10:34:12"),T("10:34:24"),EV["k8sdis"])
    add("host:win-admin-01","host:file-srv-01","data_collection","collection",T("10:41:00"),T("10:41:04"),EV["finance"])
    if assume_edge == "sa-role":
        add("token:system:serviceaccount:prod:ci-runner","token:role/oss-backup-reader","credential_use","credential_use",T("10:42:00"),T("10:42:00"),EV["assume"])
    elif assume_edge == "k8s-bucket":
        add("cluster:k8s-master-01","bucket:prod-backup","credential_use","credential_use",T("10:42:00"),T("10:42:00"),EV["assume"])
    add(bucketdis_from,"bucket:prod-backup","cloud_discovery","discovery",T("10:42:09"),T("10:42:09"),EV["bucketdis"])
    add(stage_from,"host:ops-jump-01","data_staging","collection",T("10:49:00"),T("10:49:30"),EV["stage7z"])
    if exfil_mode == "single":
        add("host:ops-jump-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration",T("11:08:00"),T("11:08:01"),EV["biupl"])
    else:
        add("host:ops-jump-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration",T("11:08:00"),T("11:08:00"),"E089")
        add("host:ops-jump-01","ip:203.0.113.210","exfiltration","exfiltration",T("11:08:01"),T("11:08:01"),"E090")
    add(erp_from,"host:ci-runner-01","cloud_collection","collection",T("11:15:00"),T("11:15:00"),EV["erpget"])
    add("host:ci-runner-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration",T("11:15:30"),T("11:15:30"),EV["erpupl"])
    add("host:ops-jump-01","file:/tmp/.cache/.stage/full.tar","data_staging","collection",T("11:35:00"),T("11:35:50"),EV["stagefull"])
    if clean_mode == "file":
        add("host:ops-jump-01","file:/tmp/a.sh","cleanup","defense_evasion",T("11:42:00"),T("11:42:22"),EV["clean"])
    elif clean_mode == "self":
        add("host:ops-jump-01","host:ops-jump-01","cleanup","defense_evasion",T("11:42:00"),T("11:42:22"),EV["clean"])
    if exfil_mode == "single":
        add("host:ops-jump-01","domain:cdn-sync.example","exfiltration","exfiltration",T("11:50:00"),T("11:50:18"),EV["final"])
    else:
        add("host:ops-jump-01","domain:cdn-sync.example","exfiltration","exfiltration",T("11:50:00"),T("11:50:12"),"E099;E100;E102")
        add("host:ops-jump-01","ip:203.0.113.77","exfiltration","exfiltration",T("11:50:12"),T("11:50:18"),"E101;E103;E104")
    return g

def evals(ours, g, ev_mode="frac", time_mode="exact"):
    used = set(); tq = 0.0
    for ge in g:
        cands = [i for i, o in enumerate(ours) if i not in used and o[0] == ge[0] and o[1] == ge[1]]
        if not cands: continue
        best = max(cands, key=lambda i: q(ours[i], ge, 0.5, time_mode, ev_mode))
        used.add(best); tq += q(ours[best], ge, 0.5, time_mode, ev_mode)
    return tq, len(used), len(g)

def f1_score(ours, g, ev_mode="frac", time_mode="exact", mode="f1"):
    tq, nm, ng = evals(ours, g, ev_mode, time_mode)
    if mode == "f1":
        P = tq / len(ours); R = tq / ng
        return 2 * P * R / (P + R) * 20 if P + R else 0
    if mode == "recall":
        return tq / ng * 20
    if mode == "f1count":
        P = nm / len(ours); R = nm / ng
        f1 = 2 * P * R / (P + R) if P + R else 0
        avgq = tq / nm if nm else 0
        return f1 * avgq * 20
    if mode == "f1count_raw":
        P = nm / len(ours); R = nm / ng
        f1 = 2 * P * R / (P + R) if P + R else 0
        return f1 * 20
    if mode == "pq":
        # precision = sumq/n_ours, recall = sumq/n_gt -> f1
        P = tq / len(ours); R = tq / ng
        return 2 * P * R / (P + R) * 20 if P + R else 0

if __name__ == "__main__":
    combos = list(itertools.product(
        ["domain:update-cache.example", "ip:203.0.113.60"],      # ash_tgt
        ["account:crm_ro", "host:web-prod-01"],                  # mysql_from
        ["account:bi_sync", "host:ops-jump-01"],                 # pgsql_from
        ["account:crm_ro", "host:web-prod-01"],                  # sysconf_from
        ["file:C:\\Windows\\Temp\\ls.dmp", "account:CORP\\svc_backup", "host:win-admin-01"],  # lsass_to
        ["win+pgsql", "one", "none"],                            # jumpdis
        ["edge", "fold", "none"],                                # priv
        ["single", "split"],                                     # exfil
        ["file", "self", "none"],                                # clean
        ["host:win-admin-01", "host:file-srv-01"],               # stage_from
        ["bucket:prod-backup", "token:role/oss-backup-reader"],  # erp_from
        ["token:role/oss-backup-reader", "token:system:serviceaccount:prod:ci-runner", "cluster:k8s-master-01"],  # bucketdis_from
        ["sa-role", "k8s-bucket", "none"],                       # assume
        [True, False],                                           # pipeline_split
    ))
    best = []
    for c in combos:
        pass
        g = build(*c)
        for ev_mode in ("frac", "exact"):
            for tm in ("exact", "overlap"):
                for m in ("f1", "recall", "f1count", "f1count_raw"):
                    s1 = f1_score(E1, g, ev_mode, tm, m)
                    s2 = f1_score(E2, g, ev_mode, tm, m)
                    d1 = abs(s1 - 7.18); d2 = abs(s2 - 7.49)
                    if d1 < 0.25 and d2 < 0.25:
                        best.append((d1 + d2, s1, s2, ev_mode, tm, m, c))
    best.sort()
    print(len(best), "candidates")
    for b in best[:12]:
        print(f"S1={b[1]:.2f} S2={b[2]:.2f} ev={b[3]} tm={b[4]} mode={b[5]}")
        print("   ", b[6])
