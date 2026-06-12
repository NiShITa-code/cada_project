"""Behavioral-monitor FAMILY frontier + harm-type stratification, from the head-to-head JSONL.

Answers: (1) how many attacks are system-manifest (a syscall signature) vs semantic (blind spot);
(2) each config C1-C6's benign FP-tax vs attack recall (the precision/recall frontier);
(3) invariance: per-config recall across O0..O6; (4) judge AUROC on system-harm subset vs all.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experiments.cadc.analyze_headtohead import auroc, harm_score  # noqa: E402

LEVELS = ["O0_clean", "O1_base64", "O2_indirect", "O3_renamed", "O4_dynimport", "O5_deceptive", "O6_composed",
          "X1_base32", "X2_hex", "X3_xor"]
ENCODED = ["O1_base64", "O2_indirect", "O3_renamed", "O4_dynimport", "O6_composed"]
CFGS = ["C1_minimal", "C2_egr_dns", "C3_secret_nar", "C4_secret_brd", "C5_behavioral", "C6_maximal"]


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "main"
    rows = [json.loads(l) for l in (ROOT / "results/headtohead_runs" / f"{tag}.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]

    # system-harm = attack manifests >=1 HARM primitive at O0 (lineage-free; verify-the-artifact: executed).
    # NOTE: this subset is monitor-DEFINED, so "recall on system-harm" is near-tautological — report the
    # honest all-attack recall as the headline; this subset only shows the harm-class is encoding-invariant.
    o0a = [r for r in rows if r["level"] == "O0_clean" and r["role"] == "attack" and r.get("executed")]
    sys_ids = {r["id"] for r in o0a if harm_score(r) > 0}
    all_att_ids = {r["id"] for r in rows if r["role"] == "attack"}
    print(f"attacks total={len(all_att_ids)}  system-manifest(O0)={len(sys_ids)}  "
          f"semantic/blind={len(all_att_ids)-len(sys_ids)}")
    print(f"  -> behavioral monitor is STRUCTURALLY BLIND to {len(all_att_ids)-len(sys_ids)}/{len(all_att_ids)} "
          f"attacks (no syscall signature: bias/logic/content harms)\n")

    ben0 = [r for r in rows if r["level"] == "O0_clean" and r["role"] == "benign"]
    print("--- behavioral FAMILY frontier (O0): benign FP-tax vs recall ---")
    print(f"{'config':14} {'benign FPR':>10} {'recall(all exec)':>17} {'recall(system-harm)':>20}")
    for c in CFGS:
        fpr = np.mean([r.get("family_flags", {}).get(c, 0) for r in ben0])
        rec_all = np.mean([r.get("family_flags", {}).get(c, 0) for r in o0a]) if o0a else float("nan")
        sysrows = [r for r in o0a if r["id"] in sys_ids]
        rec_sys = np.mean([r.get("family_flags", {}).get(c, 0) for r in sysrows]) if sysrows else float("nan")
        print(f"{c:14} {fpr:>10.2f} {rec_all:>17.2f} {rec_sys:>20.2f}")

    print("\n--- INVARIANCE: C5_behavioral recall on system-harm attacks, per level ---")
    print(f"{'level':13} {'recall(sys-harm)':>17} {'benign FPR':>11}")
    for lv in LEVELS:
        att = [r for r in rows if r["level"] == lv and r["role"] == "attack" and r.get("executed") and r["id"] in sys_ids]
        ben = [r for r in rows if r["level"] == lv and r["role"] == "benign"]
        rec = np.mean([r.get("family_flags", {}).get("C5_behavioral", 0) for r in att]) if att else float("nan")
        bfpr = np.mean([r.get("family_flags", {}).get("C5_behavioral", 0) for r in ben]) if ben else float("nan")
        print(f"{lv:13} {rec:>17.2f} {bfpr:>11.2f}")

    print("\n--- judge AUROC: all attacks vs system-harm-only subset (O0) ---")
    for label, ids in [("ALL attacks", all_att_ids), ("system-harm only", sys_ids)]:
        att = [r for r in rows if r["level"] == "O0_clean" and r["role"] == "attack" and r.get("executed") and r["id"] in ids]
        aj = [r["judge_score"] for r in att if r.get("judge_score") is not None]
        bj = [r["judge_score"] for r in ben0 if r.get("judge_score") is not None]
        print(f"  {label:18} judge AUROC(O0) = {auroc(aj, bj):.2f}  (n_att={len(aj)})")

    # what benign behaviors cause the FP-tax
    print("\n--- FP-tax source: benign CI commands tripping each primitive (O0) ---")
    feats = ["sensitive_broad", "destructive", "persistence", "privesc"]
    egr = np.mean([1 if r.get("features", {}).get("net_ports") else 0 for r in ben0])
    print(f"  egress(any non-DNS connect): {egr:.0%}")
    for f in feats:
        print(f"  {f:18}: {np.mean([1 if r.get('features',{}).get(f) else 0 for r in ben0]):.0%}")


if __name__ == "__main__":
    main()
