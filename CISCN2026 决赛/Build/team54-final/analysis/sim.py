#!/usr/bin/env python3
"""Simulate edge scoring under various GT hypotheses and matching rules."""
import json
import itertools
from pathlib import Path

BASE = Path("/Users/mashiro/Downloads/CISCN2026Final")
S1 = json.load(open(BASE / "team54/build/submission/attack_graph.json"))
S2 = json.load(open(BASE / "team54-final/submission-new/attack_graph.json"))
S3 = json.load(open(BASE / "team54-pro/build/work/submission/attack_graph.json"))

def edges(g):
    return [(e["from"], e["to"], e["action"], e["stage"], e["time_start"], e["time_end"], frozenset(e["evidence_ids"])) for e in g["edges"]]

E1, E2, E3 = edges(S1), edges(S2), edges(S3)

def q(ours, gt, ft_split=0.5, time_mode="exact", evi_mode="frac"):
    f, t, a, s, ts, te, ev = ours
    gf, gt_, ga, gs, gts, gte, gev = gt
    ft = 0.0
    if f == gf:
        ft += ft_split
    if t == gt_:
        ft += 1.0 - ft_split
    act = 1.0 if a == ga else 0.0
    stg = 1.0 if s == gs else 0.0
    if time_mode == "exact":
        time = 0.5 * (1.0 if ts == gts else 0.0) + 0.5 * (1.0 if te == gte else 0.0)
    else:  # overlap: ours within gt window
        s_ok = gts <= ts <= gte
        e_ok = gts <= te <= gte
        time = 0.5 * (1.0 if s_ok else 0.0) + 0.5 * (1.0 if e_ok else 0.0)
    if evi_mode == "frac":
        evi = len(ev & gev) / len(gev) if gev else 1.0
    else:
        evi = 1.0 if ev == gev else 0.0
    return 0.4 * ft + 0.15 * act + 0.15 * stg + 0.10 * time + 0.20 * evi

def score(ours, gt_edges, ft_split=0.5, time_mode="exact", evi_mode="frac"):
    # greedy matching: for each GT edge, prefer our edge with same from/to maximizing q
    used = set()
    total_q = 0.0
    n_gt = len(gt_edges)
    for gi, g in enumerate(gt_edges):
        cands = [i for i, o in enumerate(ours) if i not in used and o[0] == g[0] and o[1] == g[1]]
        if not cands:
            continue
        best = max(cands, key=lambda i: q(ours[i], g, ft_split, time_mode, evi_mode))
        used.add(best)
        total_q += q(ours[best], g, ft_split, time_mode, evi_mode)
    P = total_q / len(ours) if ours else 0.0
    R = total_q / n_gt if n_gt else 0.0
    f1 = 2 * P * R / (P + R) if P + R > 0 else 0.0
    return f1 * 20

def run(gt, label):
    for ft_split in (0.5,):
        for tm in ("exact", "overlap"):
            for ev in ("frac", "exact"):
                s1 = score(E1, gt, ft_split, tm, ev)
                s2 = score(E2, gt, ft_split, tm, ev)
                s3 = score(E3, gt, ft_split, tm, ev)
                print(f"{label} | tm={tm} ev={ev} | S1={s1:.2f} S2={s2:.2f} S3={s3:.2f}  (want 7.18/7.49)")

if __name__ == "__main__":
    import sys
    # GT defined inline by caller via import; keep placeholder
    print("load gt variants from gt_hypotheses.py")
