#!/usr/bin/env python3
"""Distinct command distribution per host/day from auditd; print cmdlines sorted by time."""
import json, sys
from pathlib import Path
from collections import Counter

BASE = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-pro/build/build选手附件")
LOGS = BASE / "logs"

def main():
    host = sys.argv[1]
    day = sys.argv[2] if len(sys.argv) > 2 else "2026-07-06"
    p = LOGS / "linux" / f"{host}_auditd.jsonl"
    rows = []
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            ts = rec.get("timestamp", "")
            if day in ts:
                rows.append((ts, rec))
    rows.sort(key=lambda x: x[0])
    cnt = Counter()
    interesting = []
    for ts, rec in rows:
        cmd = rec.get("cmdline", "")
        cnt[(rec.get("exe"), cmd, rec.get("user"))] += 1
    print(f"=== {host} {day}: distinct commands (exe, cmd, user, count) ===")
    for (exe, cmd, user), n in sorted(cnt.items(), key=lambda x: x[1], reverse=True):
        print(f"{n:5d}  {user:14s} {exe:12s} {cmd}")
    print(f"\n=== timeline of suspicious (non-journalctl etc) ===")
    for ts, rec in rows:
        cmd = rec.get("cmdline", "")
        exe = rec.get("exe", "")
        if any(k in cmd for k in ("curl", "wget", "nc ", "ncat", "python", "bash -", "sh -c", "whoami", "id", "cat /etc", "tar", "zip", "scp", "rsync", "mysqldump", "pg_dump", "redis", "chmod", "chown", "useradd", "crontab", "base64", "gopher", "tunnel", "proxychains", "nmap", "masscan", "hydra", "john", "mimikatz", "hashdump", "kubectl", "docker exec", "minio", "aws", "mc ")) or "journalctl" not in cmd:
            print(ts, f"user={rec.get('user')}", f"exe={exe}", f"cmd={cmd}", f"result={rec.get('result')}", f"evid={rec.get('event_id')}")

if __name__ == "__main__":
    main()
