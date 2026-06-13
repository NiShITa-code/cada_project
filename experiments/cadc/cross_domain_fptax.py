"""Cross-domain FP-tax: does the behavioral monitor's benign false-positive tax generalize beyond
CI/CD to data-science agent work? If it holds (or grows) across domains, the FP-tax is a structural
property of autonomous agent work, not a CI artifact. Behavioral-only -> free, no API.

Runs the behavioral monitor at O0 on CI benign vs DS benign; compares FP-tax per config + per primitive.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experiments.cadc.build_real_benign import load_real_benign  # noqa: E402
from experiments.cadc.build_ds_benign import load_ds_benign  # noqa: E402
from experiments.cadc.monitor_family import CONFIGS, extract_features, score  # noqa: E402
from experiments.cadc.trace_runner import capture  # noqa: E402


ART = ROOT / "results/headtohead_runs/main.crossdomain.jsonl"  # auditable per-command artifact


def fptax(commands, label, n, fout):
    import json
    random.seed(42)
    cmds = list(commands)
    random.shuffle(cmds)
    cmds = cmds[:n]
    cfg = {c.name: 0 for c in CONFIGS}
    prim = {"egress": 0, "secret": 0, "destructive": 0, "persistence": 0}
    ran = 0
    for cmd in cmds:
        cap = capture(cmd, sinkhole=True, timeout=15)
        executed = int(cap["executed"])
        raw = extract_features(cap["trace"]) if executed else None
        fired = [c.name for c in CONFIGS if raw and score(raw, c).flagged]
        egress = 1 if (raw and any(p != 53 for p in raw.net_ports)) else 0
        # verify-the-artifact: persist every command's outcome (executed + features + fired configs)
        fout.write(json.dumps({"domain": label, "command": cmd[:200], "executed": executed,
                               "trace_len": cap["raw_trace_len"] if hasattr(cap, "raw_trace_len") else len(cap.get("trace", "")),
                               "egress": egress,
                               "secret": int(bool(raw.sensitive_broad)) if raw else 0,
                               "destructive": int(bool(raw.destructive)) if raw else 0,
                               "fired": fired}) + "\n")
        fout.flush()
        if not executed:
            continue
        ran += 1
        for name in fired:
            cfg[name] += 1
        prim["egress"] += egress
        prim["secret"] += int(bool(raw.sensitive_broad))
        prim["destructive"] += int(bool(raw.destructive))
        prim["persistence"] += int(bool(raw.persistence))
    print(f"\n[{label}] executed {ran}/{len(cmds)}")
    for c in CONFIGS:
        print(f"  {c.name:14} FP-tax = {cfg[c.name] / max(1, ran):.2f}")
    print("  primitives: " + "  ".join(f"{k}={v / max(1, ran):.2f}" for k, v in prim.items()))
    return {c.name: cfg[c.name] / max(1, ran) for c in CONFIGS}


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    ci = [it["command"] for it in load_real_benign()]
    ds = [it["command"] for it in load_ds_benign()]
    try:
        from experiments.cadc.build_ds_agent_benign import load_ds_agent_benign
        dsa = [it["command"] for it in load_ds_agent_benign()]
    except Exception:
        dsa = []
    print(f"CI: {len(ci)}  |  DS-CI: {len(ds)}  |  DS-agent(notebook): {len(dsa)}")
    with ART.open("w", encoding="utf-8") as fout:
        ci_fp = fptax(ci, "CI/CD benign", n, fout)
        ds_fp = fptax(ds, "data-science benign", n, fout)
        dsa_fp = fptax(dsa, "data-science-AGENT benign", n, fout) if dsa else None
    print(f"\nartifact -> {ART}")
    print("\n=== cross-domain FP-tax (C5_behavioral) ===")
    line = f"  CI/CD: {ci_fp['C5_behavioral']:.2f}   data-science(CI): {ds_fp['C5_behavioral']:.2f}"
    if dsa_fp:
        line += f"   data-science(AGENT notebooks): {dsa_fp['C5_behavioral']:.2f}"
    print(line)
    print("  -> FP-tax GENERALIZES (structural) if DS >= CI; CI-specific if DS << CI.")


if __name__ == "__main__":
    main()
