#!/usr/bin/env python3
"""Render an attack_graph.json as a layered topology diagram (PNG + SVG)."""
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

# ---- node type colors -----------------------------------------------------
TYPE_COLORS = {
    "ip":       "#e74c3c",  # red      - attacker / external
    "domain":   "#e67e22",  # orange   - c2 / exfil infra
    "host":     "#3498db",  # blue     - internal hosts
    "database": "#9b59b6",  # purple   - databases
    "account":  "#1abc9c",  # teal     - accounts
    "token":    "#16a085",  # dark teal - tokens/roles
    "cluster":  "#2c3e50",  # dark     - k8s cluster
    "bucket":   "#f39c12",  # yellow   - object storage
    "file":     "#95a5a6",  # gray     - files
    "network":  "#7f8c8d",
    "process":  "#7f8c8d",
    "service":  "#7f8c8d",
}

STAGE_COLORS = {
    "recon":              "#bdc3c7",
    "initial_access":     "#e74c3c",
    "execution":          "#e67e22",
    "persistence":        "#d35400",
    "privilege_escalation":"#8e44ad",
    "defense_evasion":    "#34495e",
    "credential_access":  "#16a085",
    "credential_use":     "#1abc9c",
    "discovery":          "#f39c12",
    "lateral_movement":   "#2980b9",
    "collection":         "#9b59b6",
    "exfiltration":       "#c0392b",
    "impact":             "#c0392b",
}

# ---- layered layout (column = stage flow, row = branch) -------------------
# explicit coordinates: node -> (x, y)
LAYOUT = {
    # external / entry (left)
    "ip:198.51.100.77":            (0, 5.5),
    "domain:update-cache.example": (0, 4.0),
    # web layer
    "host:web-prod-01":            (1.6, 5.2),
    "file:/var/www/oa/public/.cache.php": (2.4, 6.4),
    # jump layer
    "host:ops-jump-01":            (3.2, 5.2),
    "account:deploy":              (2.4, 4.6),
    "account:svc_deploy":          (3.2, 3.4),
    # db / id / devops layer
    "database:mysql-core-01":      (4.8, 6.4),
    "database:pgsql-bi-01":        (4.8, 4.4),
    "host:ad-dc-01":               (4.8, 3.2),
    "host:gitlab-01":              (4.8, 2.0),
    "account:CORP\\svc_backup":    (4.0, 3.8),
    # windows / ci layer
    "host:win-admin-01":           (6.4, 4.6),
    "file:C:\\Windows\\Temp\\ls.dmp": (7.4, 5.6),
    "host:jenkins-01":             (6.4, 2.0),
    "host:file-srv-01":            (7.4, 3.6),
    "host:ci-runner-01":           (8.0, 1.2),
    "token:system:serviceaccount:prod:ci-runner": (8.8, 0.4),
    "token:role/oss-backup-reader":(9.6, 0.0),
    # cloud layer
    "cluster:k8s-master-01":       (10.2, 0.8),
    "bucket:prod-backup":          (10.2, 1.8),
    # exfil (right)
    "domain:archive-sync-bkt.storage.example": (10.4, 4.0),
    "ip:203.0.113.210":            (10.6, 5.2),
    "ip:203.0.113.77":             (10.6, 2.8),
    "domain:cdn-sync.example":     (10.2, 2.2),
}

def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "/Users/mashiro/Downloads/submission-new/attack_graph.json")
    out_png = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/attack_topology.png")
    graph = json.loads(path.read_text())

    nodes = {n["id"]: n for n in graph["nodes"]}
    edges = graph["edges"]

    fig, ax = plt.subplots(figsize=(24, 13))
    ax.set_xlim(-0.6, 11.8)
    ax.set_ylim(-1.2, 7.6)
    ax.axis("off")

    # fallback placement for nodes missing from LAYOUT
    auto_x = 6.0
    for i, n in enumerate(graph["nodes"]):
        if n["id"] not in LAYOUT:
            LAYOUT[n["id"]] = (auto_x, 6.6 - (i % 8) * 0.9)

    # draw edges first (under nodes)
    for e in edges:
        src = LAYOUT[e["from"]]
        dst = LAYOUT[e["to"]]
        color = STAGE_COLORS.get(e["stage"], "#7f8c8d")
        arrow = FancyArrowPatch(
            src, dst, connectionstyle="arc3,rad=0.12",
            arrowstyle="-|>", mutation_scale=16,
            color=color, lw=2.0, alpha=0.85, zorder=1)
        ax.add_patch(arrow)
        mid = ((src[0] + dst[0]) / 2, (src[1] + dst[1]) / 2 + 0.18)
        ax.text(mid[0], mid[1], f"{e['action']} ({e['stage']})",
                fontsize=6.2, color=color, ha="center", va="bottom",
                bbox=dict(boxstyle="round,pad=0.12", fc="white", ec=color, lw=0.6, alpha=0.9),
                zorder=3)

    # draw nodes
    for nid, (x, y) in LAYOUT.items():
        if nid not in nodes:
            continue
        n = nodes[nid]
        c = TYPE_COLORS.get(n["type"], "#7f8c8d")
        label = n["label"] if n["label"] else nid.split(":", 1)[1]
        box = FancyBboxPatch((x - 0.62, y - 0.26), 1.24, 0.52,
                             boxstyle="round,pad=0.06", fc=c, ec="white",
                             lw=1.2, zorder=4)
        ax.add_patch(box)
        ax.text(x, y, label, ha="center", va="center", fontsize=8.2,
                color="white", fontweight="bold", zorder=5)
        ax.text(x, y - 0.40, n["type"], ha="center", va="center", fontsize=6.0,
                color=c, style="italic", zorder=5)

    # legend
    from matplotlib.lines import Line2D
    handles = [Line2D([0], [0], marker="s", color="w", markerfacecolor=c,
                      markersize=11, label=t)
               for t, c in [("ip (external)", "#e74c3c"), ("domain (c2/exfil)", "#e67e22"),
                            ("host (internal)", "#3498db"), ("database", "#9b59b6"),
                            ("account", "#1abc9c"), ("token/role", "#16a085"),
                            ("cluster", "#2c3e50"), ("bucket", "#f39c12"), ("file", "#95a5a6")]]
    ax.legend(handles=handles, loc="upper left", fontsize=9, framealpha=0.9,
              title="Node types", title_fontsize=10)

    ax.set_title("CISCN 2026 build-final · Attack topology (submission-new)\n"
                 "edge label = action (stage); edge color = kill-chain stage",
                 fontsize=13, pad=12)
    fig.tight_layout()
    fig.savefig(out_png, dpi=170, bbox_inches="tight", facecolor="white")
    fig.savefig(str(out_png.with_suffix(".svg")), bbox_inches="tight", facecolor="white")
    print(f"saved {out_png} and {out_png.with_suffix('.svg')}")
    print(f"nodes: {len(nodes)}, edges: {len(edges)}")

if __name__ == "__main__":
    main()
