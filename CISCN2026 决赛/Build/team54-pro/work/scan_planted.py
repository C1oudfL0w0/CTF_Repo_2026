#!/usr/bin/env python3
"""Scan all logs for planted evidence: event_ids with low/sequential numbering."""
import json, re, csv
from pathlib import Path

BASE = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-pro/build/build选手附件")
LOGS = BASE / "logs"

PAT = re.compile(r'-(\d{6})$')

def scan_jsonl(path):
    out = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            eid = r.get("event_id", "")
            m = PAT.search(eid)
            if m and int(m.group(1)) <= 30000:
                out.append((r.get("timestamp",""), path.name, eid, r))
    return out

def scan_csv(path):
    out = []
    with path.open() as f:
        for row in csv.DictReader(f):
            eid = row.get("event_id", "")
            m = PAT.search(eid)
            if m and int(m.group(1)) <= 30000:
                out.append((row.get("timestamp",""), path.name, eid, row))
    return out

def scan_log(path):
    out = []
    with path.open() as f:
        for line in f:
            m = re.search(r'event_id=(\S+)', line)
            if not m:
                continue
            eid = m.group(1)
            mm = PAT.search(eid)
            if mm and int(mm.group(1)) <= 30000:
                tm = re.search(r'time=(\S+)', line)
                out.append((tm.group(1) if tm else "", path.name, eid, line.strip()))
    return out

def main():
    hits = []
    for sub in sorted(LOGS.iterdir()):
        if not sub.is_dir():
            continue
        for p in sorted(sub.iterdir()):
            if not p.is_file():
                continue
            if p.suffix == ".jsonl":
                hits += scan_jsonl(p)
            elif p.suffix == ".csv":
                hits += scan_csv(p)
            elif p.suffix == ".log":
                hits += scan_log(p)
    hits.sort(key=lambda x: x[0])
    print(f"total planted-looking events: {len(hits)}")
    for ts, src, eid, rec in hits:
        if isinstance(rec, dict):
            detail = {k: v for k, v in rec.items() if k not in ("raw", "source")}
            print(ts, "|", src, "|", eid, "|", json.dumps(detail, ensure_ascii=False))
        else:
            print(ts, "|", src, "|", eid, "|", rec[:200])

if __name__ == "__main__":
    main()
