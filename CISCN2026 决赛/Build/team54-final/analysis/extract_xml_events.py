#!/usr/bin/env python3
"""Extract the 5 attack artifact XML events fully."""
import re
from pathlib import Path

WANT = {
    "artifact-winsec-20260706-000001",
    "artifact-winsec-20260706-000002",
    "artifact-winsec-20260706-000003",
    "artifact-sysmon-20260706-000001",
    "artifact-sysmon-20260706-000002",
}

for name, path in [
    ("security_selected.evtx.xml", Path("build/build选手附件/artifacts/windows_event_exports/security_selected.evtx.xml")),
    ("sysmon_selected.evtx.xml", Path("build/build选手附件/artifacts/windows_event_exports/sysmon_selected.evtx.xml")),
]:
    text = path.read_text(encoding="utf-8", errors="replace")
    # split events on "<Event "
    events = text.split("<Event ")
    for ev in events:
        m = re.search(r"ArtifactEventId\">([^<]+)<", ev)
        if m and m.group(1) in WANT:
            print(f"===== {m.group(1)} [{name}] =====")
            print("<Event " + ev.strip()[:3000])
            print()
