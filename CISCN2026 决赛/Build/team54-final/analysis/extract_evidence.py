#!/usr/bin/env python3
"""Extract full details of all evidence events from logs/artifacts."""
import csv
import json
import re
import sys
from pathlib import Path

BUILD = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-final/build/build选手附件")
LOGS = BUILD / "logs"
ARTIFACTS = BUILD / "artifacts"

EVID = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-final/submission-new/evidence.csv")

def load_evidence_ids():
    ids = []
    with EVID.open() as f:
        for row in csv.DictReader(f):
            ids.append(row["event_id"])
    return ids

def scan():
    wanted = set(load_evidence_ids())
    found = {}
    # JSONL
    for path in LOGS.rglob("*.jsonl"):
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                eid = obj.get("event_id")
                if eid in wanted and eid not in found:
                    found[eid] = ("jsonl", str(path.relative_to(BUILD)), obj)
    # CSV
    for path in LOGS.rglob("*.csv"):
        with path.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                eid = row.get("event_id")
                if eid in wanted and eid not in found:
                    found[eid] = ("csv", str(path.relative_to(BUILD)), dict(row))
    # .log (plain text)
    pat = re.compile(r"\bevent_id=([^\s]+)")
    for path in LOGS.rglob("*.log"):
        with path.open(encoding="utf-8") as f:
            for line in f:
                m = pat.search(line)
                if m:
                    eid = m.group(1)
                    if eid in wanted and eid not in found:
                        found[eid] = ("log", str(path.relative_to(BUILD)), line.strip())
    # artifacts index
    idx = ARTIFACTS / "artifact_event_index.csv"
    if idx.exists():
        with idx.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                eid = row.get("event_id")
                if eid in wanted and eid not in found:
                    found[eid] = ("artifact", str(idx.relative_to(BUILD)), dict(row))
    # pcap manifest
    man = ARTIFACTS / "pcap" / "pcap_manifest.csv"
    if man.exists():
        with man.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                eid = row.get("event_id")
                if eid in wanted and eid not in found:
                    found[eid] = ("pcap", str(man.relative_to(BUILD)), dict(row))
    return wanted, found

def main():
    wanted, found = scan()
    for eid in sorted(wanted):
        if eid in found:
            kind, src, payload = found[eid]
            print(f"=== {eid} [{kind}] {src}")
            if isinstance(payload, dict):
                print(json.dumps(payload, ensure_ascii=False))
            else:
                print(payload)
        else:
            print(f"=== {eid} NOT FOUND")
    missing = [e for e in wanted if e not in found]
    print("\nMissing:", missing)

if __name__ == "__main__":
    main()
