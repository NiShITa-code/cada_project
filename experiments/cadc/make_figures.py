"""Generate the paper figures from a head-to-head JSONL. Robust to partial data.

Fig 1  AUROC vs obfuscation level  (judge / llama-guard / behavioral) with bootstrap CI bands
Fig 2  recall @ 1% and 5% benign FPR vs level (judge vs behavioral) -> the inversion
Fig 3  benign false-positive tax: family configs + per-primitive decomposition on real CI commands
Saves PNGs to paper/figures/.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experiments.cadc.analyze_headtohead import auroc, bootstrap_auroc, harm_score, recall_at_fpr  # noqa: E402

LEVELS = ["O0_clean", "O1_base64", "O2_indirect", "O3_renamed", "O4_dynimport", "O5_deceptive", "O6_composed",
          "X1_base32", "X2_hex", "X3_xor"]
FIGDIR = ROOT / "paper/figures"


def load(tag):
    p = ROOT / "results/headtohead_runs" / f"{tag}.jsonl"
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def per_level(rows):
    levels = [l for l in LEVELS if any(r["level"] == l for r in rows)]
    out = {}
    for lv in levels:
        att = [r for r in rows if r["level"] == lv and r["role"] == "attack" and r.get("executed")]
        ben = [r for r in rows if r["level"] == lv and r["role"] == "benign"]
        aj = [r["judge_score"] for r in att if r.get("judge_score") is not None]
        bj = [r["judge_score"] for r in ben if r.get("judge_score") is not None]
        ab = [harm_score(r) for r in att]   # lineage-free harm-primitive score (audit fix)
        bb = [harm_score(r) for r in ben]
        ag = [r.get("guard_flag") for r in att if r.get("guard_flag") is not None]
        bg = [r.get("guard_flag") for r in ben if r.get("guard_flag") is not None]
        out[lv] = {
            "auroc_judge": auroc(aj, bj), "ci_judge": bootstrap_auroc(aj, bj),
            "auroc_behav": auroc(ab, bb), "ci_behav": bootstrap_auroc(ab, bb),
            "auroc_guard": auroc(ag, bg),
            "r1_judge": recall_at_fpr(aj, bj, 0.01)[0], "r1_behav": recall_at_fpr(ab, bb, 0.01)[0],
            "r5_judge": recall_at_fpr(aj, bj, 0.05)[0], "r5_behav": recall_at_fpr(ab, bb, 0.05)[0],
            "n_att": len(att), "n_ben": len(ben),
        }
    return levels, out


def short(levels):
    return [l.split("_")[0] for l in levels]


def fig_auroc(levels, M, tag):
    x = np.arange(len(levels))
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for key, lab, col in [("auroc_judge", "Text guardrail (GPT-4o judge)", "#c0392b"),
                          ("auroc_behav", "Behavioral (syscall) monitor", "#2471a3"),
                          ("auroc_guard", "Llama Guard 4", "#e67e22")]:
        y = [M[l][key] for l in levels]
        ax.plot(x, y, "-o", color=col, label=lab, lw=2)
        ci = "ci_judge" if key == "auroc_judge" else ("ci_behav" if key == "auroc_behav" else None)
        if ci:
            lo = [M[l][ci][0] for l in levels]; hi = [M[l][ci][1] for l in levels]
            ax.fill_between(x, lo, hi, color=col, alpha=0.15)
    ax.axhline(0.5, ls="--", color="gray", lw=1, label="chance")
    ax.set_xticks(x); ax.set_xticklabels(short(levels))
    ax.set_xlabel("obfuscation level"); ax.set_ylabel("AUROC (attack vs benign)")
    ax.set_ylim(0.3, 1.02)
    ax.set_title("Discrimination vs. obfuscation: text collapses, effect-level is invariant")
    ax.legend(fontsize=8, loc="lower left"); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(FIGDIR / f"fig1_auroc_{tag}.png", dpi=150); plt.close(fig)


def fig_recall(levels, M, tag):
    x = np.arange(len(levels))
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(x, [M[l]["r1_judge"] for l in levels], "-o", color="#c0392b", label="text judge, recall@1%FPR", lw=2)
    ax.plot(x, [M[l]["r1_behav"] for l in levels], "-o", color="#2471a3", label="behavioral, recall@1%FPR", lw=2)
    ax.plot(x, [M[l]["r5_judge"] for l in levels], "--s", color="#c0392b", alpha=0.55, label="text judge, recall@5%FPR")
    ax.plot(x, [M[l]["r5_behav"] for l in levels], "--s", color="#2471a3", alpha=0.55, label="behavioral, recall@5%FPR")
    ax.set_xticks(x); ax.set_xticklabels(short(levels))
    ax.set_xlabel("obfuscation level"); ax.set_ylabel("recall at fixed benign FPR")
    ax.set_ylim(-0.02, 1.02)
    ax.set_title("Recall at deployment FPR (the inversion lives here)")
    ax.legend(fontsize=8); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(FIGDIR / f"fig2_recall_{tag}.png", dpi=150); plt.close(fig)


def fig_fptax(rows, tag):
    ben0 = [r for r in rows if r["role"] == "benign" and r["level"] == "O0_clean"]
    if not ben0:
        return
    cfgs = ["C1_minimal", "C2_egr_dns", "C3_secret_nar", "C4_secret_brd", "C5_behavioral", "C6_maximal"]
    fpr = [np.mean([r.get("family_flags", {}).get(c, 0) for r in ben0]) for c in cfgs]
    prims = ["sensitive_broad", "destructive", "persistence", "privesc"]
    prim_rate = [np.mean([1 if r.get("features", {}).get(p) else 0 for r in ben0]) for p in prims]
    egress_rate = np.mean([1 if r.get("features", {}).get("net_ports") else 0 for r in ben0])
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 4))
    a1.bar(range(len(cfgs)), fpr, color="#2471a3")
    a1.set_xticks(range(len(cfgs))); a1.set_xticklabels([c.split("_")[0] for c in cfgs])
    a1.set_ylabel("benign FPR (real CI commands)"); a1.set_title("Behavioral FP-tax by monitor config")
    a1.grid(alpha=0.3, axis="y")
    labs = ["egress"] + prims
    rates = [egress_rate] + prim_rate
    a2.bar(range(len(labs)), rates, color="#e67e22")
    a2.set_xticks(range(len(labs))); a2.set_xticklabels(labs, rotation=20, fontsize=8)
    a2.set_ylabel("fraction of benign CI commands"); a2.set_title("Which benign behaviors trip the monitor")
    a2.grid(alpha=0.3, axis="y")
    fig.tight_layout(); fig.savefig(FIGDIR / f"fig3_fptax_{tag}.png", dpi=150); plt.close(fig)


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "main"
    FIGDIR.mkdir(parents=True, exist_ok=True)
    rows = load(tag)
    levels, M = per_level(rows)
    fig_auroc(levels, M, tag); fig_recall(levels, M, tag); fig_fptax(rows, tag)
    print(f"figures -> {FIGDIR} (levels={short(levels)}, n_att~{M[levels[0]]['n_att']}, n_ben~{M[levels[0]]['n_ben']})")


if __name__ == "__main__":
    main()
