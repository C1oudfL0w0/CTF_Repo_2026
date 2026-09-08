#!/usr/bin/env python3
"""Track a given IP across all log sources; dump its activity sorted by time."""
import json, re, sys
from pathlib import Path
import polars as pl

BASE = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-pro/build/build选手附件")
LOGS = BASE / "logs"
TARGET_IPS = set(sys.argv[1].split(",")) if len(sys.argv) > 1 else {"198.51.100.77"}

def load_source(path: Path):
    if path.suffix == ".jsonl":
        rows = []
        with path.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return pl.DataFrame(rows)
    if path.suffix == ".csv":
        return pl.read_csv(path)
    if path.suffix == ".log":
        rows = []
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                kv = dict(re.findall(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', line))
                for k, v in kv.items():
                    if v.startswith('"'):
                        kv[k] = v.strip('"')
                rows.append(kv)
        return pl.DataFrame(rows)
    return None

def main():
    hits = []
    for sub in sorted(LOGS.iterdir()):
        if not sub.is_dir():
            continue
        for p in sorted(sub.iterdir()):
            if not p.is_file():
                continue
            df = load_source(p)
            if df is None:
                continue
            ipcols = [c for c in df.columns if "ip" in c.lower() and c in ("src_ip","dst_ip","client_ip","client","src","assigned_ip")]
            mask = None
            for c in ipcols:
                m = df[c].cast(pl.Utf8).is_in(TARGET_IPS)
                mask = m if mask is None else (mask | m)
            if mask is None:
                continue
            sub_df = df.filter(mask)
            if sub_df.height == 0:
                continue
            tcol = "timestamp" if "timestamp" in df.columns else "time"
            for row in sub_df.iter_rows(named=True):
                hits.append((row.get(tcol, ""), p.name, row))
    hits.sort(key=lambda x: x[0])
    print(f"total hits for {TARGET_IPS}: {len(hits)}")
    for t, src, row in hits:
        # compact view
        print(t, "|", src)
        for k, v in row.items():
            if k in ("raw", "timestamp", "time", "source", "event_type"):
                continue
            print(f"     {k}={v}")
        print()

if __name__ == "__main__":
    main()
