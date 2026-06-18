"""Extra publication figures (from existing local data, no compute):
 fig4_armsrace   — GPT-4o vs Claude-4.6 judge AUROC across encodings (the decoding arms race)
 fig5_crossdomain — behavioral FP-tax: CI vs DS-project-CI vs DS-AGENT (8% -> 9% -> 38%)
 fig6_vise       — the precision/recall vise: text (clean) / behavioral family / Falco on one plot
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
import sys  # noqa: E402
sys.path.insert(0, str(ROOT))
from experiments.cadc.analyze_headtohead import auroc, harm_score  # noqa: E402

R = ROOT / "results/headtohead_runs"
FIG = ROOT / "paper/figures"
FIG.mkdir(parents=True, exist_ok=True)


def load(name):
    return [json.loads(l) for l in (R / name).read_text(encoding="utf-8").splitlines() if l.strip()]


def fig_armsrace():
    g = load("main.jsonl")
    c = {(r["level"], r["role"], r["id"]): r["claude_score"] for r in load("main.claude.jsonl")}
    levels = ["O0_clean", "O1_base64", "O5_deceptive", "X3_xor"]
    xlab = ["clean", "base64", "comment\n(control)", "XOR"]
    gpt, cla = [], []
    for lv in levels:
        att = [r for r in g if r["level"] == lv and r["role"] == "attack" and r.get("executed")]
        ben = [r for r in g if r["level"] == lv and r["role"] == "benign"]
        gpt.append(auroc([r["judge_score"] for r in att], [r["judge_score"] for r in ben]))
        ca = [c[(lv, "attack", r["id"])] for r in att if (lv, "attack", r["id"]) in c]
        cb = [c[(lv, "benign", r["id"])] for r in ben if (lv, "benign", r["id"]) in c]
        cla.append(auroc(ca, cb))
    x = np.arange(len(levels))
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(x, gpt, "-o", color="#c0392b", lw=2, label="GPT-4o judge")
    ax.plot(x, cla, "-s", color="#8e44ad", lw=2, label="Claude-4.6 judge (frontier)")
    ax.axhline(0.5, ls="--", color="gray", lw=1, label="chance")
    ax.set_xticks(x); ax.set_xticklabels(xlab)
    ax.set_ylabel("AUROC (attack vs benign)"); ax.set_ylim(0.2, 1.0)
    ax.set_title("Decoding arms race: a frontier judge resists base64 but loses to XOR")
    ax.legend(fontsize=8, loc="lower left"); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(FIG / "fig4_armsrace.png", dpi=150); plt.close(fig)
    print("fig4:", dict(zip(levels, [(round(a, 2), round(b, 2)) for a, b in zip(gpt, cla)])))


def fig_crossdomain():
    rows = load("main.crossdomain.jsonl")
    doms = ["CI/CD benign", "data-science benign", "data-science-AGENT benign"]
    lab = ["CI/CD", "DS project-CI", "DS AGENT\n(notebooks)"]
    fp = []
    for d in doms:
        rs = [r for r in rows if r["domain"] == d and r["executed"]]
        fp.append(sum(1 for r in rs if "C5_behavioral" in r["fired"]) / max(1, len(rs)))
    fig, ax = plt.subplots(figsize=(6, 4.2))
    bars = ax.bar(range(len(doms)), fp, color=["#2471a3", "#2980b9", "#e67e22"])
    ax.axhline(0.01, ls="--", color="red", lw=1, label="1% deployment FPR target")
    for b, v in zip(bars, fp):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.01, f"{v:.0%}", ha="center", fontsize=11, fontweight="bold")
    ax.set_xticks(range(len(doms))); ax.set_xticklabels(lab)
    ax.set_ylabel("behavioral monitor false-positive rate"); ax.set_ylim(0, 0.45)
    ax.set_title("The FP-tax scales with autonomy: legit agent work looks like attacks")
    ax.legend(fontsize=8); ax.grid(alpha=0.3, axis="y")
    fig.tight_layout(); fig.savefig(FIG / "fig5_crossdomain.png", dpi=150); plt.close(fig)
    print("fig5:", dict(zip(lab, [round(v, 2) for v in fp])))


def fig_vise():
    g = load("main.jsonl")
    o0a = [r for r in g if r["level"] == "O0_clean" and r["role"] == "attack" and r.get("executed")]
    ben0 = [r for r in g if r["level"] == "O0_clean" and r["role"] == "benign"]
    sys_ids = {r["id"] for r in o0a if harm_score(r) > 0}
    cfgs = ["C1_minimal", "C3_secret_nar", "C5_behavioral", "C6_maximal"]
    pts = []
    for c in cfgs:
        fpr = np.mean([r.get("family_flags", {}).get(c, 0) for r in ben0])
        rec = np.mean([r.get("family_flags", {}).get(c, 0) for r in o0a])  # all-attack recall
        pts.append((fpr, rec))
    falco = load("main.falco.jsonl")
    f_fpr = np.mean([r["falco_flag"] for r in falco if r["role"] == "benign" and r["level"] == "O0_clean"])
    f_rec = np.mean([r["falco_flag"] for r in falco if r["role"] == "attack" and r["level"] == "O0_clean"])
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    fx, fy = zip(*pts)
    ax.plot(fx, fy, "-o", color="#2471a3", lw=2, label="behavioral family (ours)")
    ax.plot([f_fpr], [f_rec], "D", color="#27ae60", ms=10, label="Falco (industry, default)")
    ax.axvline(0.01, ls="--", color="red", lw=1, label="1% deployment FPR")
    ax.set_xlabel("benign false-positive rate (real CI)"); ax.set_ylabel("all-attack recall")
    ax.set_title("The vise: no behavioral config is deployable at 1% FPR")
    ax.set_xlim(-0.01, 0.15); ax.set_ylim(0, 0.4); ax.legend(fontsize=8); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(FIG / "fig6_vise.png", dpi=150); plt.close(fig)
    print(f"fig6: behavioral pts={[(round(a,3),round(b,2)) for a,b in pts]}  falco=({f_fpr:.3f},{f_rec:.2f})")


def fig_promptablation():
    """fig7 — steelman decode-prompt vs original judge across encodings (the prompt lever)."""
    s = json.loads((R / "main.ablation_strong.summary.json").read_text(encoding="utf-8"))
    order = ["O0_clean", "O1_base64", "X3_xor"]
    lab = ["clean", "base64\n(decodable)", "XOR\n(not decodable)"]
    rows = {r["level"]: r for r in s["levels"]}
    weak = [rows[l]["auroc_weak"] for l in order]
    strong = [rows[l]["auroc_strong"] for l in order]
    x = np.arange(len(order)); w = 0.36
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    ax.bar(x - w / 2, weak, w, color="#95a5a6", label="original judge prompt")
    ax.bar(x + w / 2, strong, w, color="#c0392b", label="steelman decode-prompt")
    ax.axhline(0.5, ls="--", color="gray", lw=1, label="chance")
    for i, (a, b) in enumerate(zip(weak, strong)):
        ax.text(i - w / 2, a + 0.01, f"{a:.2f}", ha="center", fontsize=9)
        ax.text(i + w / 2, b + 0.01, f"{b:.2f}", ha="center", fontsize=9, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels(lab)
    ax.set_ylabel("AUROC (attack vs benign)"); ax.set_ylim(0.2, 1.0)
    ax.set_title("Prompt lever: a steelman decode-prompt recovers base64 but is\ndefeated by XOR (collapses to chance)")
    ax.legend(fontsize=8, loc="lower left"); ax.grid(alpha=0.3, axis="y")
    fig.tight_layout(); fig.savefig(FIG / "fig7_promptablation.png", dpi=150); plt.close(fig)
    print("fig7:", {l: (w_, s_) for l, w_, s_ in zip(order, weak, strong)})


def fig_capability():
    """fig8 — capability ladder: base64 AUROC rises with capability, XOR stays flat for all."""
    s = json.loads((R / "main.ladder.summary.json").read_text(encoding="utf-8"))
    L = s["ladder"]  # Haiku, GPT-4o, Sonnet (ascending within-family for the H/S pair)
    names = [r["model"] for r in L]
    x = np.arange(len(names))
    clean = [r["O0_clean"] for r in L]
    b64 = [r["O1_base64"] for r in L]
    xor = [r["X3_xor"] for r in L]
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(x, clean, "-o", color="#27ae60", lw=2, label="clean")
    ax.plot(x, b64, "-s", color="#c0392b", lw=2, label="base64 (decodable)")
    ax.plot(x, xor, "-^", color="#2471a3", lw=2, label="XOR (not decodable)")
    ax.axhline(0.5, ls="--", color="gray", lw=1, label="chance")
    for xi, v in zip(x, b64):
        ax.annotate(f"{v:.2f}", (xi, v), textcoords="offset points", xytext=(0, -14), ha="center", fontsize=8, color="#c0392b")
    for xi, v in zip(x, xor):
        ax.annotate(f"{v:.2f}", (xi, v), textcoords="offset points", xytext=(0, 7), ha="center", fontsize=8, color="#2471a3")
    ax.set_xticks(x); ax.set_xticklabels(names)
    ax.set_ylabel("judge AUROC (attack vs benign)"); ax.set_ylim(0.2, 1.0)
    ax.set_title("Capability lifts base64 resistance (0.56→0.82) but NOT XOR (flat ~0.74)\n"
                 "Haiku-4.5↔Sonnet-4.6 = within-family; GPT-4o = cross-family reference")
    ax.legend(fontsize=8, loc="lower left"); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(FIG / "fig8_capability.png", dpi=150); plt.close(fig)
    print("fig8:", {r["model"]: (r["O1_base64"], r["X3_xor"]) for r in L})


if __name__ == "__main__":
    fig_armsrace(); fig_crossdomain(); fig_vise(); fig_promptablation(); fig_capability()
    print("wrote fig4..fig8 ->", FIG)
