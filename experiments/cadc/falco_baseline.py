"""Falco eBPF baseline (industry-standard behavioral monitor) on the head-to-head corpus.

Runs each obfuscated command in a UNIQUELY-NAMED container under the sinkhole while Falco watches the
host kernel; attributes Falco's DEFAULT-ruleset alerts to the cell by container name. Reports Falco's
recall on real executed attacks + its FALSE-POSITIVE TAX on the real CI benign corpus + invariance.

Robustness: (1) a WARMUP probe confirms Falco's eBPF probe is actually capturing before we start
(post-restart it warms up for ~20-40s); (2) BATCH attribution — run every cell, then read Falco's log
ONCE and map alerts to cells by container.name (no per-cell timing race). Must run STRACE-FREE: strace
and Falco both trace syscalls; concurrent strace floods Falco and breaks attribution.

Prereq: Falco running as a container with modern eBPF + JSON (see run_falco_phase.sh).
Usage: python3 -m experiments.cadc.falco_baseline --attacks-per-cat 3 --n-benign 80 [--pilot N]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experiments.cadc import exec_obfuscation as obf  # noqa: E402
from experiments.cadc.headtohead_main import load_attacks, load_benign  # noqa: E402

LEVELS = ["O0_clean", "O1_base64", "X3_xor"]  # clean + base64 + OOD: Falco recall + invariance + FP-tax
OUT = ROOT / "results/headtohead_runs"


def run_cell(name: str, command: str, timeout: float = 15.0) -> bool:
    """Run command in a named container under the sinkhole; return executed."""
    inner = "mkdir -p /work; cat > /work/cmd.sh; timeout -k 2 12 bash /work/cmd.sh; echo CADC_DONE"
    docker = ["docker", "run", "--rm", "-i", "--name", name,   # -i: attach stdin so the piped command actually runs
              "--network", "cadc_sink", "--dns", "172.19.0.2",
              "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "--pids-limit", "256", "--memory", "512m",
              "cada-sandbox", "bash", "-c", inner]
    payload = command.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8", "replace")
    try:
        p = subprocess.run(docker, input=payload, capture_output=True, timeout=timeout)
        return "CADC_DONE" in p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        return False


def parse_all_alerts() -> dict:
    """Read Falco's full log once; return {container.name: {(priority, rule), ...}}."""
    r = subprocess.run(["docker", "logs", "falco"], capture_output=True, text=True)
    out: dict[str, set] = {}
    for line in (r.stdout + r.stderr).splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        cn = d.get("output_fields", {}).get("container.name")
        if cn:
            out.setdefault(cn, set()).add((d.get("priority"), d.get("rule")))
    return out


def warmup(max_tries: int = 8) -> bool:
    """Confirm Falco is actually capturing (eBPF probe warmed up) before measuring."""
    for i in range(max_tries):
        name = f"cadcfal_warmup_{i}"
        run_cell(name, "cat /etc/shadow >/dev/null 2>&1; head -c5 /etc/shadow >/dev/null 2>&1; echo hi")
        time.sleep(5)
        if name in parse_all_alerts():
            print(f"warmup ok (Falco capturing after {i+1} probe(s))")
            return True
    print("WARNING: Falco warmup probe never caught a /etc/shadow read — attribution suspect")
    return False


def safe(s):
    return re.sub(r"[^A-Za-z0-9]", "", str(s))[:40]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attacks-per-cat", type=int, default=3)
    ap.add_argument("--n-benign", type=int, default=80)
    ap.add_argument("--tag", default="main")
    ap.add_argument("--pilot", type=int, default=0)
    args = ap.parse_args()

    attacks = load_attacks(args.attacks_per_cat)
    benign = load_benign(args.n_benign)
    if args.pilot:
        attacks, benign = attacks[:args.pilot], benign[:args.pilot]
    actions = [{"role": "attack", **a} for a in attacks] + [{"role": "benign", **b} for b in benign]

    if not warmup():
        print("aborting: Falco not confirmed capturing"); return

    cells = []  # (name, row-without-falco)
    total = len(actions) * len(LEVELS)
    print(f"running {total} cells (batch attribution at end)...")
    n = 0
    for act in actions:
        for lv in LEVELS:
            n += 1
            name = f"cadcfal{safe(act['role'])}{safe(act['id'])}{safe(lv)}"
            executed = run_cell(name, obf.TRANSFORMS[lv](act["code"]))
            cells.append((name, {"tag": args.tag, "level": lv, "role": act["role"], "id": act["id"],
                                 "category": act["category"], "executed": int(executed)}))
            if n % 25 == 0:
                print(f"  [{n}/{total}] {lv} {act['role']} {act['id']} exec={int(executed)}")

    print("flushing + reading Falco log once for batch attribution..."); time.sleep(12)
    alerts = parse_all_alerts()
    out_path = OUT / f"{args.tag}.falco.jsonl"
    with out_path.open("w", encoding="utf-8") as f:
        for name, row in cells:
            a = alerts.get(name, set())
            row["falco_flag"] = 1 if a else 0
            row["n_alerts"] = len(a)
            row["rules"] = sorted({rule for _, rule in a})
            f.write(json.dumps(row) + "\n")
    flagged = sum(1 for _, r in cells if alerts.get(r["id"]))  # rough
    print(f"DONE -> {out_path}  (cells with alerts: {sum(1 for n,_ in cells if alerts.get(n))})")


if __name__ == "__main__":
    main()
