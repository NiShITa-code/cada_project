"""PILOT (load-bearing): do real RedCode attacks actually EXECUTE and manifest harm
in the cada-sandbox at O0 (clean)? If most don't execute, the whole experiment is invalid
(this is exactly the failure mode that wrecked prior sessions: attacks that never landed).

No sinkhole here -> isolates EXECUTION + non-network harm (secret-read/destructive) from the
network path. Egress recall is measured later with the sinkhole. Prints per-category:
executed?, behavior vector, and the first meaningful code line.
"""
from __future__ import annotations

import glob
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experiments.cadc.syscall_monitor import syscall_suspicion  # noqa: E402

REDCODE = ROOT / "data/RedCode/dataset/RedCode-Exec/bash2text_dataset_json"


def idxnum(p: str) -> int:
    m = re.search(r"index(\d+)_", p)
    return int(m.group(1)) if m else 9999


files = sorted(glob.glob(str(REDCODE / "index*_30_codes_full_upd.json")), key=idxnum)
print(f"categories found: {len(files)}\n")
print(f"{'idx':>4} {'exec':>5} {'flag':>5} {'sec':>4} {'egr':>4} {'des':>4}  first-line")
print("-" * 90)
n_exec = n_flag = 0
for f in files:
    data = json.load(open(f))
    if not data:
        continue
    code = data[0]["Code"]
    idx = data[0]["Index"]
    v = syscall_suspicion([code], sinkhole=False, timeout=25.0)
    b = v.behavior
    n_exec += b.get("executed", 0)
    n_flag += 1 if (v.flagged and b.get("executed")) else 0
    first = next((ln.strip() for ln in code.splitlines()
                  if ln.strip() and not ln.strip().startswith("#")), "")[:55]
    print(f"{idx:>4} {b.get('executed'):>5} {int(v.flagged):>5} "
          f"{b.get('secret_read'):>4} {b.get('egress'):>4} {b.get('destructive'):>4}  {first}")

print("-" * 90)
print(f"executed: {n_exec}/{len(files)}   flagged-and-executed: {n_flag}/{len(files)}")
print("NOTE: egress harms undercount without the sinkhole; secret/destructive are valid here.")
