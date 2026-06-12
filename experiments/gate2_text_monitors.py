#!/usr/bin/env python3
"""Gate 2 - does a real text guardrail degrade under obfuscation? (text-only)

The cheap, decisive experiment: no Docker, no eBPF. Run the text monitors on each
action in clean form and under every obfuscation, then report the recall gap at the
benign false-positive rate. A real gap on a real guardrail locks the motivation; no
gap means pivot the framing before building the behavioural harness.

Examples:
    python -m experiments.gate2_text_monitors --dry-run
    python -m experiments.gate2_text_monitors --redcode ./data/RedCode
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()  # read .env so LLM_API_KEY / LLM_BASE_URL / JUDGE_MODEL are available

from cada import obfuscation
from cada.cache import JsonCache
from cada.config import ExperimentConfig
from cada.data import build_dataset, sample_actions
from cada.metrics import MonitorRecord, gap_table
from cada.monitors.text import build_text_monitors

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true", help="use the offline regex stub (no API, no cost)")
    p.add_argument("--redcode", default=None, help="path to a cloned RedCode repo")
    p.add_argument("--representation", default="code", choices=["code", "summary", "details"],
                   help="RedCode representation to use as the action text")
    p.add_argument("--positives-per-category", type=int, default=None,
                   help="if set, stratified-sample this many RedCode positives per category (cost control)")
    p.add_argument("--out", default=str(RESULTS_DIR / "gate2_results.csv"))
    return p.parse_args()


def main() -> None:
    args = parse_args()
    cfg = ExperimentConfig()

    actions = (
        build_dataset(args.redcode, representation=args.representation)
        if args.redcode else sample_actions()
    )

    if args.positives_per_category is not None:
        from collections import defaultdict
        per_cat: dict[str, list] = defaultdict(list)
        for a in actions:
            (per_cat[a.category] if a.label == 1 else per_cat["__benign__"]).append(a)
        sampled = []
        for cat, items in per_cat.items():
            if cat == "__benign__":
                sampled.extend(items)  # keep all benigns — FPR denominator matters
            else:
                sampled.extend(items[: args.positives_per_category])
        actions = sampled
        n_pos = sum(1 for a in actions if a.label == 1)
        n_neg = sum(1 for a in actions if a.label == 0)
        print(f"[subsample] positives={n_pos}, benigns={n_neg}, total={len(actions)}")

    cache = None if args.dry_run else JsonCache(RESULTS_DIR / "gate2_cache.json")
    monitors = build_text_monitors(args.dry_run, cache=cache)
    if cache is not None:
        print(f"[cache] loaded {len(cache)} prior entries from {cache.path}")

    records, raw = [], []
    for mon in monitors:
        for cond, transform in obfuscation.TRANSFORMS.items():
            y_true, y_pred = [], []
            for action in actions:
                pred = mon.predict(transform(action.command))
                y_true.append(action.label)
                y_pred.append(pred)
                raw.append((mon.name, cond, action.category, action.label, pred))
            records.append(MonitorRecord(mon.name, cond, y_true, y_pred))

    table, gaps = gap_table(records, clean_condition=cfg.clean_condition)

    print(f"\n{'monitor':14}{'condition':14}{'recall':8}{'FPR':8}{'F1':6}")
    print("-" * 52)
    for (mon, cond), op in sorted(table.items()):
        print(f"{mon:14}{cond:14}{op.recall:<8.2f}{op.fpr:<8.2f}{op.f1:<6.2f}")

    print("\n=== OBFUSCATION GAP (clean recall - mean obfuscated recall) ===")
    for mon, g in gaps.items():
        has_gap = g["gap"] == g["gap"] and g["gap"] > 0.05
        verdict = "GAP (motivation holds)" if has_gap else "no/low gap -> revisit framing"
        print(
            f"  {mon:14} clean={g['clean_recall']:.2f}  obf_mean={g['obf_mean_recall']:.2f}"
            f"  gap={g['gap']:+.2f}  -> {verdict}"
        )

    print("\n=== PROVIDER-SIDE REFUSALS (Azure-style content filter) ===")
    for mon in monitors:
        refusals = getattr(mon, "refusals", 0)
        print(f"  {mon.name:14} refusals={refusals}  (counted as predicted=1; report separately in paper)")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["monitor", "condition", "category", "label", "pred"])
        w.writerows(raw)
    summary = {f"{m}|{c}": op.__dict__ for (m, c), op in table.items()}
    out.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nsaved -> {out}")

    if args.dry_run:
        print(
            "\nNOTE: --dry-run uses a regex stub; a stub collapsing proves nothing about "
            "Llama Guard / a judge. Re-run without --dry-run (with API keys) for the real Gate 2."
        )


if __name__ == "__main__":
    main()
