#!/usr/bin/env python3
"""Fine-grained per-event GT edge model simulation.

Hypothesis: GT has ~104 edges (one per evidence event), with from/to derived from
each event's own fields (actor/src -> target/dst). Our grouped submissions match
at most one GT edge per (from,to) pair, explaining the observed low scores.
"""
import csv, json, itertools
from pathlib import Path
from datetime import datetime

BASE = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-final")

# event_id -> timestamp (from logs)
def load_times():
    out = {}
    import re
    logs = BASE / "build/build选手附件/logs"
    for path in logs.rglob("*.jsonl"):
        for line in path.open(encoding="utf-8"):
            line=line.strip()
            if not line: continue
            try: o=json.loads(line)
            except Exception: continue
            if o.get("event_id"): out[o["event_id"]]=o.get("timestamp","")
    for path in logs.rglob("*.csv"):
        for row in csv.DictReader(path.open(encoding="utf-8", newline="")):
            if row.get("event_id"): out[row["event_id"]]=row.get("timestamp","")
    pat=re.compile(r"event_id=(\S+).*?time=([^ ]+)")
    for path in logs.rglob("*.log"):
        for line in path.open(encoding="utf-8"):
            m=pat.search(line)
            if m: out[m.group(1)]=m.group(2)
    idx = BASE/"build/build选手附件/artifacts/artifact_event_index.csv"
    for row in csv.DictReader(idx.open(encoding="utf-8", newline="")):
        if row.get("event_id"): out[row["event_id"]]=row.get("timestamp","")
    return out

TIMES = load_times()

# per-event GT edges: event_id -> (from, to, action, stage)
def build_gt():
    gt = {}
    def add(evids, f, t, act, stg):
        for e in evids:
            gt[e] = (f, t, act, stg)
    add(["fw-20260706-144141","waf-20260706-096141","fw-20260706-144142","waf-20260706-096142",
         "fw-20260706-144143","waf-20260706-096143","fw-20260706-144144","waf-20260706-096144",
         "fw-20260706-144145","waf-20260706-096145"],
        "ip:198.51.100.77","host:web-prod-01","scan","recon")
    add(["waf-20260706-096146","artifact-pcap-20260706-072042","nginx-20260706-000001","oa-20260706-017559"],
        "ip:198.51.100.77","host:web-prod-01","exploit_public_service","initial_access")
    add(["audit-web-20260706-024801","artifact-pcap-20260706-072073","proxy-20260706-112001"],
        "host:web-prod-01","ip:203.0.113.60","command_execution","execution")
    add(["fw-20260706-144146","edr-20260706-010135"],
        "host:web-prod-01","ip:198.51.100.77","command_and_control","execution")
    add(["audit-web-20260706-024802","edr-20260706-010136"],
        "host:web-prod-01","file:/var/www/oa/public/.cache.php","webshell_upload","persistence")
    add(["nginx-20260706-000002"],
        "ip:198.51.100.77","host:web-prod-01","webshell_upload","persistence")
    add(["audit-web-20260706-024803","audit-web-20260706-024804","audit-web-20260706-024805",
         "audit-web-20260706-024806","audit-web-20260706-024807"],
        "host:web-prod-01","host:web-prod-01","host_discovery","discovery")
    add(["audit-web-20260706-024808","audit-web-20260706-024809","audit-web-20260706-024810"],
        "host:web-prod-01","account:deploy","credential_dump","credential_access")
    add(["artifact-pcap-20260706-072344","fw-20260706-144147","auth-ops-20260706-016892","netflow-20260706-152001"],
        "account:deploy","host:ops-jump-01","lateral_movement","lateral_movement")
    add(["audit-ops-20260706-024801","audit-ops-20260706-024802"],
        "host:ops-jump-01","host:win-admin-01","host_discovery","discovery")
    add(["audit-ops-20260706-024803"],
        "host:ops-jump-01","database:pgsql-bi-01","database_discovery","discovery")
    add(["mysql-20260706-036001"],
        "account:crm_ro","database:mysql-core-01","credential_use","credential_use")
    add(["fw-20260706-144148"],
        "host:web-prod-01","database:mysql-core-01","credential_use","credential_use")
    add(["mysql-20260706-036002","mysql-20260706-036003","mysql-20260706-036004","mysql-20260706-036005"],
        "account:crm_ro","database:mysql-core-01","database_discovery","discovery")
    add(["audit-ops-20260706-024804","audit-ops-20260706-024805","audit-ops-20260706-024806"],
        "host:ops-jump-01","account:CORP\\svc_backup","credential_dump","credential_access")
    add(["mysql-20260706-036006","edr-20260706-010138"],
        "host:web-prod-01","account:bi_sync","credential_dump","credential_access")
    add(["audit-ops-20260706-024807"],
        "host:ops-jump-01","account:svc_deploy","credential_dump","credential_access")
    add(["gitlab-20260706-017582"],
        "account:svc_deploy","host:gitlab-01","credential_use","credential_use")
    add(["netflow-20260706-152002"],
        "host:ops-jump-01","host:ad-dc-01","network_discovery","discovery")
    add(["artifact-winsec-20260706-000001","winsec-ad-20260706-000001",
         "artifact-winsec-20260706-000002","winsec-ad-20260706-000002"],
        "account:CORP\\svc_backup","host:ad-dc-01","credential_use","credential_use")
    add(["gitlab-20260706-017583","gitlab-20260706-017584","gitlab-20260706-017585"],
        "account:svc_deploy","host:gitlab-01","devops_discovery","discovery")
    add(["pgsql-20260706-028001"],
        "account:bi_sync","database:pgsql-bi-01","credential_use","credential_use")
    add(["netflow-20260706-152004"],
        "host:ops-jump-01","database:pgsql-bi-01","credential_use","credential_use")
    add(["sysmon-ad-20260706-000001","sysmon-ad-20260706-000002","sysmon-ad-20260706-000003"],
        "account:CORP\\svc_backup","host:ad-dc-01","domain_discovery","discovery")
    add(["gitlab-20260706-017586"],
        "account:svc_deploy","host:gitlab-01","ci_pipeline_execution","execution")
    add(["jenkins-20260706-018063"],
        "host:gitlab-01","host:jenkins-01","ci_pipeline_execution","execution")
    add(["pgsql-20260706-028002","pgsql-20260706-028003","pgsql-20260706-028004"],
        "account:bi_sync","database:pgsql-bi-01","data_collection","collection")
    add(["artifact-winsec-20260706-000003","winsec-win-20260706-024842"],
        "account:CORP\\svc_backup","host:win-admin-01","lateral_movement","lateral_movement")
    add(["winsec-win-20260706-024843"],
        "account:CORP\\svc_backup","host:win-admin-01","credential_use","privilege_escalation")
    add(["audit-ci-20260706-000001","edr-20260706-010139"],
        "host:ci-runner-01","ip:203.0.113.60","command_execution","execution")
    add(["artifact-sysmon-20260706-000001","sysmon-win-20260706-024801","edr-20260706-010137"],
        "host:win-admin-01","file:C:\\Windows\\Temp\\ls.dmp","credential_dump","credential_access")
    add(["audit-ci-20260706-000002"],
        "host:ci-runner-01","token:system:serviceaccount:prod:ci-runner","credential_dump","credential_access")
    add(["k8s-20260706-018130"],
        "token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","credential_use","credential_use")
    add(["k8s-20260706-018131"],
        "token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","credential_dump","credential_access")
    add(["k8s-20260706-018132","k8s-20260706-018133"],
        "token:system:serviceaccount:prod:ci-runner","cluster:k8s-master-01","cloud_discovery","discovery")
    add(["winsec-fil-20260706-024848","artifact-sysmon-20260706-000002","sysmon-fil-20260706-024801"],
        "host:win-admin-01","host:file-srv-01","data_collection","collection")
    add(["iam-20260706-018161"],
        "token:system:serviceaccount:prod:ci-runner","token:role/oss-backup-reader","credential_use","credential_use")
    add(["obj-20260706-017768"],
        "token:role/oss-backup-reader","bucket:prod-backup","cloud_discovery","discovery")
    add(["sysmon-win-20260706-024802"],
        "host:win-admin-01","file:C:\\Temp\\finance_q2.7z","data_staging","collection")
    add(["netflow-20260706-152003"],
        "host:win-admin-01","host:ops-jump-01","data_staging","collection")
    add(["proxy-20260706-112002"],
        "host:ops-jump-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration")
    add(["fw-20260706-144149"],
        "host:ops-jump-01","ip:203.0.113.210","exfiltration","exfiltration")
    add(["obj-20260706-017769"],
        "token:role/oss-backup-reader","bucket:prod-backup","cloud_collection","collection")
    add(["proxy-20260706-112003"],
        "host:ci-runner-01","domain:archive-sync-bkt.storage.example","exfiltration","exfiltration")
    add(["audit-ops-20260706-024808","audit-ops-20260706-024809","audit-ops-20260706-024810"],
        "host:ops-jump-01","file:/tmp/.cache/.stage/full.tar","data_staging","collection")
    add(["audit-ops-20260706-024811","audit-ops-20260706-024812","audit-ops-20260706-024813"],
        "host:ops-jump-01","host:ops-jump-01","cleanup","defense_evasion")
    add(["artifact-pcap-20260706-073871","dns-20260706-144001","proxy-20260706-112004"],
        "host:ops-jump-01","domain:cdn-sync.example","exfiltration","exfiltration")
    add(["artifact-pcap-20260706-073875","fw-20260706-144150","ids-20260706-010047"],
        "host:ops-jump-01","ip:203.0.113.77","exfiltration","exfiltration")
    return gt

GT = build_gt()
assert len(GT) == 104, len(GT)

def score_sub(path):
    g = json.load(open(path))
    our = []
    for e in g["edges"]:
        for ev in e["evidence_ids"]:
            # find event time
            evrow = EV_BY_ID.get(ev, {})
            our.append((e["from"], e["to"], e["action"], e["stage"], evrow.get("event_id"), e["time_start"], e["time_end"]))
    # match 1:1 by (from,to) greedy max q
    gt_items = [(k, v[0], v[1], v[2], v[3]) for k, v in GT.items()]
    used = set()
    total_q = 0.0
    for gi, (gid, gf, gt_, ga, gs) in enumerate(gt_items):
        best = None; bestq = -1
        for i, (f, t, a, s, eid, ts, te) in enumerate(our):
            if i in used or f != gf or t != gt_:
                continue
            # q: from/to 0.4, action 0.15, stage 0.15, time 0.1 (exact event time == our range?), evi 0.2
            ft = 1.0
            act = 1.0 if a == ga else 0.0
            stg = 1.0 if s == gs else 0.0
            # time: our edge time window vs event timestamp
            evt = TIMES.get(gid, "")
            t_ok = 0.0
            if evt:
                if ts == evt and te == evt: t_ok = 1.0
                elif ts <= evt <= te: t_ok = 0.5
            evi = 1.0
            q = 0.4*ft + 0.15*act + 0.15*stg + 0.1*t_ok + 0.2*evi
            if q > bestq:
                bestq = q; best = i
        if best is not None:
            used.add(best)
            total_q += bestq
    n = len(our)
    P = total_q / n if n else 0
    R = total_q / len(gt_items)
    f1 = 2*P*R/(P+R) if P+R else 0
    return f1*20, n

if __name__ == "__main__":
    import csv as _csv
    EV_BY_ID = {}
    for row in _csv.DictReader(open(BASE/"submission-new/evidence.csv")):
        EV_BY_ID[row["evidence_id"]] = {"event_id": row["event_id"], "stage": row["stage"]}
    for label, p in [
        ("S1", BASE/"team54-pro/../../team54/build/submission/attack_graph.json"),
    ]:
        pass
    # normalize paths
    paths = {
        "S1": "/Users/mashiro/Downloads/CISCN2026Final/team54/build/submission/attack_graph.json",
        "S2": "/Users/mashiro/Downloads/CISCN2026Final/team54-final/submission-new/attack_graph.json",
        "FINAL": "/Users/mashiro/Downloads/CISCN2026Final/team54-final/submission-final/attack_graph.json",
    }
    for label, p in paths.items():
        s, n = score_sub(p)
        print(f"{label}: score={s:.2f} (want S1=7.18 S2=7.49)")
