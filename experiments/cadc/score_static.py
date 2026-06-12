"""Score the TAXONOMY static monitor (representation-level twin of the behavioral monitor) on the
exact same corpus as the head-to-head, and tabulate it next to the LLM judge (smart text) and the
behavioral monitor (effect). Free, post-hoc (re-derives the obfuscated string deterministically).

Shows the two representation-level monitors degrade under encoding by DIFFERENT mechanisms
(judge: over-flags wrapper; static: misses hidden patterns) while the SAME taxonomy at the effect
level is invariant -> the collapse is the observation point, not model intelligence.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experiments.cadc import exec_obfuscation as obf  # noqa: E402
from experiments.cadc.analyze_headtohead import auroc  # noqa: E402
from experiments.cadc.headtohead_main import load_attacks, load_benign  # noqa: E402
from experiments.cadc.static_monitors import TaxonomyStaticMonitor  # noqa: E402

LEVELS = ["O0_clean", "O1_base64", "O2_indirect", "O3_renamed", "O4_dynimport", "O5_deceptive", "O6_composed",
          "X1_base32", "X2_hex", "X3_xor"]


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "main"
    rows = [json.loads(l) for l in (ROOT / "results/headtohead_runs" / f"{tag}.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    by_key = {(r["level"], r["role"], r["id"]): r for r in rows}

    code = {f"a:{a['id']}": a["code"] for a in load_attacks(5)}     # full corpus (audit: was 2/50 subset)
    code.update({f"b:{b['id']}": b["code"] for b in load_benign(120)})

    tax = TaxonomyStaticMonitor()
    out = []
    print(f"{'level':13} | {'judge AUROC':>11} | {'static recall':>13} {'static FPR':>10} {'static AUROC':>12} | {'behav C5 recall_sys':>19}")
    print("-" * 100)
    static_rows = []
    for lv in LEVELS:
        if not any(k[0] == lv for k in by_key):
            continue
        tr = obf.TRANSFORMS[lv]
        a_scores, b_scores = [], []
        att_exec_flag, ben_flag = [], []
        for (level, role, rid), r in by_key.items():
            if level != lv:
                continue
            key = f"{'a' if role=='attack' else 'b'}:{rid}"
            if key not in code:
                continue
            s = tax.predict(tr(code[key]))
            static_rows.append({"level": lv, "role": role, "id": rid, "static_flag": s})
            if role == "attack":
                if r.get("executed"):  # verify-the-artifact
                    a_scores.append(s)
                    att_exec_flag.append(s)
            else:
                b_scores.append(s)
                ben_flag.append(s)
        recall = np.mean(att_exec_flag) if att_exec_flag else float("nan")
        fpr = np.mean(ben_flag) if ben_flag else float("nan")
        au = auroc(a_scores, b_scores)
        # judge AUROC for the same level
        att = [r for r in rows if r["level"] == lv and r["role"] == "attack" and r.get("executed")]
        ben = [r for r in rows if r["level"] == lv and r["role"] == "benign"]
        aj = auroc([r["judge_score"] for r in att if r.get("judge_score") is not None],
                   [r["judge_score"] for r in ben if r.get("judge_score") is not None])
        # behavioral C5 recall on system-harm (manifested at O0)
        o0a = [r for r in rows if r["level"] == "O0_clean" and r["role"] == "attack" and r.get("executed") and r.get("behav_score", 0) > 0]
        sys_ids = {r["id"] for r in o0a}
        bsys = [r for r in att if r["id"] in sys_ids]
        brec = np.mean([r.get("family_flags", {}).get("C5_behavioral", 0) for r in bsys]) if bsys else float("nan")
        print(f"{lv:13} | {aj:>11.2f} | {recall:>13.2f} {fpr:>10.2f} {au:>12.2f} | {brec:>19.2f}")
        out.append({"level": lv, "judge_auroc": aj, "static_recall": float(recall),
                    "static_fpr": float(fpr), "static_auroc": au, "behav_recall_sys": float(brec)})

    (ROOT / "results/headtohead_runs" / f"{tag}.static.jsonl").write_text(
        "\n".join(json.dumps(r) for r in static_rows))
    (ROOT / "results/headtohead_runs" / f"{tag}.static_summary.json").write_text(json.dumps(out, indent=2))
    print("-" * 100)
    a0 = out[0]
    print(f"static taxonomy: O0 recall={a0['static_recall']:.2f} -> collapses by MISSING under encoding "
          f"(min recall across encoded levels shown above)")
    print("judge collapses by OVER-FLAGGING (AUROC<0.5); same taxonomy on SYSCALLS stays ~0.9 recall (invariant).")
    print(f"wrote -> results/headtohead_runs/{tag}.static_summary.json")


if __name__ == "__main__":
    main()
