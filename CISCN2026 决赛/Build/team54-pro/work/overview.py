#!/usr/bin/env python3
"""Overview: per-source row counts on 2026-07-06 and activity of suspicious IPs."""
import json, re, sys
from pathlib import Path
import polars as pl

BASE = Path("/Users/mashiro/Downloads/CISCN2026Final/team54-pro/build/build选手附件")
LOGS = BASE / "logs"

def ts_col(df: pl.DataFrame) -> pl.Series:
    if "timestamp" in df.columns:
        return pl.col("timestamp")
    return pl.col("time")

def load_jsonl(path: Path):
    rows = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return pl.DataFrame(rows)

def load_csv(path: Path):
    return pl.read_csv(path)

def load_log_txt(path: Path):
    # key=value text log
    rows = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            kv = dict(re.findall(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', line))
            # strip quotes
            for k, v in kv.items():
                if v.startswith('"'):
                    kv[k] = v.strip('"')
            rows.append(kv)
    return pl.DataFrame(rows)

def load_source(path: Path):
    if path.suffix == ".jsonl":
        return load_jsonl(path)
    if path.suffix == ".csv":
        return load_csv(path)
    if path.suffix == ".log":
        return load_log_txt(path)
    return None

def main():
    print("=== per-source stats ===")
    for sub in sorted(LOGS.iterdir()):
        if not sub.is_dir():
            continue
        for p in sorted(sub.iterdir()):
            if not p.is_file():
                continue
            try:
                df = load_source(p)
            except Exception as e:
                print(f"{p.name}: LOAD ERROR {e}")
                continue
            tcol = "timestamp" if "timestamp" in df.columns else ("time" if "time" in df.columns else None)
            total = df.height
            if tcol:
                day = df.filter(pl.col(tcol).str.contains("2026-07-06"))
                n_day = day.height
            else:
                n_day = -1
            print(f"{sub.name}/{p.name}: total={total} day06={n_day}")

if __name__ == "__main__":
    main()
