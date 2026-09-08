#!/usr/bin/env python3
"""Dump 07-06 activity of a given linux host from auditd + auth logs."""
import json, re, sys
from pathlib import Path

BASE = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-pro/build/build选手附件")
LOGS = BASE / "logs"

def iter_jsonl(path):
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

def main():
    host = sys.argv[1]
    day = sys.argv[2] if len(sys.argv) > 2 else "2026-07-06"
    t0 = sys.argv[3] if len(sys.argv) > 3 else ""
    events = []
    for name, loader in [("auditd", iter_jsonl), ("auth", iter_jsonl)]:
        p = LOGS / "linux" / f"{host}_{name}.jsonl"
        if name == "auth":
            p = LOGS / "linux" / f"{host}_auth.log"
        if not p.exists():
            print(f"missing {p}")
            continue
        if p.suffix == ".log":
            rows = []
            with p.open() as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    kv = dict(re.findall(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', line))
                    for k, v in kv.items():
                        if v.startswith('"'):
                            kv[k] = v.strip('"')
                    rows.append(kv)
            loader_iter = iter(rows)
        else:
            loader_iter = loader(p)
        for rec in loader_iter:
            ts = rec.get("timestamp") or rec.get("time", "")
            if day in ts and (not t0 or ts >= t0):
                events.append((ts, name, rec))
    events.sort(key=lambda x: x[0])
    print(f"{host} events on {day} from {t0}: {len(events)}")
    for ts, name, rec in events:
        if name == "auth":
            raw = rec.get("raw", "")
            print(ts, "| auth |", raw[:200])
        else:
            print(ts, "| auditd |", f"user={rec.get('user')} exe={rec.get('exe')} cmd={rec.get('cmdline')} result={rec.get('result')} evid={rec.get('event_id')}")
    print()

if __name__ == "__main__":
    main()
