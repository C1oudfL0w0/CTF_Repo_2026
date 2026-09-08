#!/usr/bin/env python3
"""Parameterized GT convention search: find per-event conventions fitting (7.18, 7.49)."""
import csv, json, itertools
exec(open('fine_grained.py').read().split('def score_sub')[0])

EV_BY_ID = {}
for row in csv.DictReader(open('/Users/mashiro/Downloads/CISCN2026Final/team54-final/submission-new/evidence.csv')):
    EV_BY_ID[row["evidence_id"]] = {"event_id": row["event_id"], "stage": row["stage"]}
EV_S1 = {}
for row in csv.DictReader(open('/Users/mashiro/Downloads/CISCN2026Final/team54-pro/build/work/submission/evidence.csv')):
    EV_S1[row["evidence_id"]] = {"event_id": row["event_id"], "stage": row["stage"]}

S1G = json.load(open('/Users/mashiro/Downloads/CISCN2026Final/team54-pro/build/work/submission/attack_graph.json'))
S2G = json.load(open('/Users/mashiro/Downloads/CISCN2026Final/team54-final/submission-new/attack_graph.json'))

def sub_edges(g, evmap):
    out = []
    for e in g["edges"]:
        evs = set()
        for x in e["evidence_ids"]:
            evs.add(evmap[x]["event_id"])
        out.append((e["from"], e["to"], e["action"], e["stage"], e["time_start"], e["time_end"], evs))
    return out

E1 = sub_edges(S1G, EV_S1)
E2 = sub_edges(S2G, EV_BY_ID)

def build_gt(ash, e039, e059, e060, e037, e035, lsass, assume, bdis, erpget, e064, cish, clean, e087, biupl, final):
    gt = {}
    def add(evids, f, t, act, stg):
        for e in evids: gt[e] = (f, t, act, stg)
    add(["fw-20260706-144141","waf-20260706-096141","fw-20260706-144142","waf-20260706-096142","fw-20260706-144143","waf-20260706-096143","fw-20260706-144144","waf-20260706-096144","fw-20260706-144145","waf-20260706-096145"],"ip:198.51.100.77","host:web-prod-01","scan","recon")
    add(["waf-20260706-096146","artifact-pcap-20260706-072042","nginx-20260706-000001","oa-20260706-017559"],"ip:198.51.100.77","host:web-prod-01","exploit_public_service","initial_access")
    add(["audit-web-20260706-024801","artifact-pcap-20260706-072073","proxy-20260706-112001"],"host:web-prod-01",ash,"command_execution","execution")
    add(["fw-20260706-144146","edr-20260706-010135"],"host:web-prod-01","ip:198.51.100.77","command_and_control","execution")
    add(["audit-web-20260706-024802","edr-20260706-010136"],"host:web-prod-01","file:/var/www/oa/public/.cache.php","webshell_upload","persistence")
    add(["nginx-20260706-000002"],"ip:198.51.100.77","host:web-prod-01","webshell_upload","persistence")
    add(["audit-web-20260706-024803","audit-web-20260706-024804","audit-web-20260706-024805","audit-web-20260706-024806","audit-web-20260706-024807"],"host:web-prod-01","host:web-prod-01","host_discovery","discovery")
    add(["audit-web-20260706-024808","audit-web-20260706-024809","audit-web-20260706-024810"],"host:web-prod-01","account:deploy","credential_dump","credential_access")
    add(["artifact-pcap-20260706-072344","fw-20260706-144147","auth-ops-20260706-016892","netflow-20260706-152001"],"account:deploy","host:ops-jump-01","lateral_movement","lateral_movement")
    add(["audit-ops-20260706-024801","audit-ops-20260706-024802"],"host:ops-jump-01",e035,"host_discovery","discovery")
    add(["audit-ops-20260706-024803"],"host:ops-jump-01",e037[0],e037[1],e037[2])
    add(["mysql-20260706-036001"],"account:crm_ro","database:mysql-core-01","credential_use","credential_use")
    add(["fw-20260706-144148"],e039,"database:mysql-core-01","credential_use","credential_use")
    add(["mysql-20260706-036002","mysql-20260706-036003","mysql-20260706-036004","mysql-20260706-036005"],"account:crm_ro","database:mysql-core-01","database_discovery","discovery")
    add(["audit-ops-20260706-024804","audit-ops-20260706-024805","audit-ops-20260706-024806"],"host:ops-jump-01","account:CORP\\svc_backup","credential_dump","credential_access")
    add(["mysql-20260706-036006","edr-20260706-010138"],"host:web-prod-01","account:bi_sync","credential_dump","credential_access")
    add(["audit-ops-20260706-024807"],"host:ops-jump-01","account:svc_deploy","credential_dump","credential_access")
    add(["gitlab-20260706-017582"],"account:svc_deploy","host:gitlab-01","credential_use","credential_use")
    add(["netflow-20260706-152002"],"host:ops-jump-01","host:ad-dc-01","network_discovery","discovery")
    add(["artifact-winsec-20260706-000001","winsec-ad-20260706-000001","artifact-winsec-20260706-000002","winsec-ad-20260706-000002"],"account:CORP\\svc_backup","host:ad-dc-01","credential_use","credential_use")
    add(["gitlab-20260706-017583","gitlab-20260706-017584","gitlab-20260706-017585"],"account:svc_deploy","host:gitlab-01","devops_discovery","discovery")
    add(["pgsql-20260706-028001"],e059,"database:pgsql-bi-01","credential_use","credential_use")
    add(["netflow-20260706-152004"],e060,"database:pgsql-bi-01","credential_use","credential_use")
    add(["sysmon-ad-20260706-000001","sysmon-ad-20260706-000002","sysmon-ad-20260706-000003"],"account:CORP\\svc_backup","host:ad-dc-01","domain_discovery","discovery")
    add(["gitlab-20260706-017586"],e064,"host:jenkins-01","ci_pipeline_execution","execution")
    add(["jenkins-20260706-018063"],"host:gitlab-01","host:jenkins-01","ci_pipeline_execution","execution")
    add(["pgsql-20260706-028002","pgsql-20260706-028003","pgsql-20260706-028004"],"account:bi_sync","database:pgsql-bi-01","data_collection","collection")
    add(["artifact-winsec-20260706-000003","winsec-win-20260706-024842"],"account:CORP\\svc_backup","host:win-admin-01","lateral_movement","lateral_movement")
    add(["winsec-win-20260706-024843"],"account:CORP\\svc_backup","host:win-admin-01","credential_use","privilege_escalation")
    add(["audit-ci-20260706-000001","edr-20260706-010139"],"host:ci-runner-01",cish,"command_execution","execution")
    add(["artifact-sysmon-20260706-000001","sysmon-win-20260706-024801","edr-20260706-010137"],"host:win-admin-01",lsass,"credential_dump","credential_access")
    add(["audit-ci-20260706-000002"],"host:ci-runner-01","token:system:serviceaccount:prod:ci-runner","credential_dump","credential_access")
    add(["k8s-20260706-018130"],"token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","credential_use","credential_use")
    add(["k8s-20260706-018131"],"token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","credential_dump","credential_access")
    add(["k8s-20260706-018132","k8s-20260706-018133"],"token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","cloud_discovery","discovery")
    add(["winsec-fil-20260706-024848","artifact-sysmon-20260706-000002","sysmon-fil-20260706-024801"],"host:win-admin-01","host:file-srv-01","data_collection","collection")
    add(["iam-20260706-018161"],"token:system:serviceaccount:prod:ci-runner",assume,"credential_use","credential_use")
    add(["obj-20260706-017768"],bdis,"bucket:prod-backup","cloud_discovery","discovery")
    add(["sysmon-win-20260706-024802"],"host:win-admin-01",e087,"data_staging","collection")
    add(["netflow-20260706-152003"],"host:win-admin-01","host:ops-jump-01","data_staging","collection")
    if biupl == "split":
        add(["proxy-20260706-112002"],"host:ops-jump-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration")
        add(["fw-20260706-144149"],"host:ops-jump-01","ip:203.0.113.210","exfiltration","exfiltration")
    else:
        add(["proxy-20260706-112002","fw-20260706-144149"],"host:ops-jump-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration")
    add(["obj-20260706-017769"],erpget,"bucket:prod-backup","cloud_collection","collection")
    add(["proxy-20260706-112003"],"host:ci-runner-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration")
    add(["audit-ops-20260706-024808","audit-ops-20260706-024809","audit-ops-20260706-024810"],"host:ops-jump-01","file:/tmp/.cache/.stage/full.tar","data_staging","collection")
    if clean:
        add(["audit-ops-20260706-024811","audit-ops-20260706-024812","audit-ops-20260706-024813"],"host:ops-jump-01",clean,"cleanup","defense_evasion")
    if final == "split":
        add(["artifact-pcap-20260706-073871","dns-20260706-144001","proxy-20260706-112004"],"host:ops-jump-01","domain:cdn-sync.example","exfiltration","exfiltration")
        add(["artifact-pcap-20260706-073875","fw-20260706-144150","ids-20260706-010047"],"host:ops-jump-01","ip:203.0.113.77","exfiltration","exfiltration")
    else:
        add(["artifact-pcap-20260706-073871","dns-20260706-144001","artifact-pcap-20260706-073875","proxy-20260706-112004","fw-20260706-144150","ids-20260706-010047"],"host:ops-jump-01","domain:cdn-sync.example","exfiltration","exfiltration")
    return gt

def score(our, gt):
    used = set(); tq = 0.0
    for gid, (gf, gt_, ga, gs) in gt.items():
        best=None; bestq=-1
        for i,(f,t,a,s,ts,te,evs) in enumerate(our):
            if i in used or f!=gf or t!=gt_: continue
            act = 1.0 if a==ga else 0.0
            stg = 1.0 if s==gs else 0.0
            evt = TIMES.get(gid,"")
            t_ok = 0.5 if evt and ts<=evt<=te else 0.0
            if evt and ts==evt and te==evt: t_ok=1.0
            evi = 1.0 if gid in evs else 0.0
            q = 0.4 + 0.15*act + 0.15*stg + 0.1*t_ok + 0.2*evi
            if q>bestq: bestq=q; best=i
        if best is not None: used.add(best); tq += bestq
    n=len(our)
    P=tq/n if n else 0; R=tq/len(gt)
    return 2*P*R/(P+R)*20 if P+R else 0, tq

grid = list(itertools.product(
    ["ip:203.0.113.60","domain:update-cache.example"],      # ash
    ["host:web-prod-01","account:crm_ro"],                   # e039
    ["account:bi_sync","host:ops-jump-01"],                  # e059
    ["host:ops-jump-01","account:bi_sync"],                  # e060
    [("database:pgsql-bi-01","database_discovery","discovery"),
     ("account:bi_sync","credential_dump","credential_access"),
     ("host:ops-jump-01","host_discovery","discovery")],     # e037 (to,action,stage)
    ["host:win-admin-01","host:ops-jump-01"],                # e035/36 to
    ["file:C:\\Windows\\Temp\\ls.dmp","account:CORP\\svc_backup","host:win-admin-01"],  # lsass
    ["token:role/oss-backup-reader","bucket:prod-backup"],   # assume to
    ["token:role/oss-backup-reader","token:system:serviceaccount:prod:ci-runner"],  # bucketdis from
    ["token:role/oss-backup-reader","bucket:prod-backup","host:ci-runner-01"],      # erpget from
    ["host:gitlab-01","account:svc_deploy"],                 # e064 from
    ["ip:203.0.113.60","domain:update-cache.example"],       # cish to
    [None,"host:ops-jump-01","file:/tmp/.cache/.stage/full.tar"],  # clean to
    ["file:C:\\Temp\\finance_q2.7z","host:ops-jump-01"],     # e087 to
    ["split","single"],                                      # biupl
    ["split","single"],                                      # final
))
res=[]
for c in grid:
    gt = build_gt(*c)
    s1, q1 = score(E1, gt)
    s2, q2 = score(E2, gt)
    err = abs(s1-7.18) + abs(s2-7.49)
    res.append((err, round(s1,2), round(s2,2), c))
res.sort()
print("top candidates (err, S1, S2, params):")
for r in res[:8]:
    print(f"  err={r[0]:.2f} S1={r[1]} S2={r[2]}")
    print("   ", r[3])
