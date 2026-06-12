#!/usr/bin/env bash
# ONE-STEP regeneration: rebuild every analysis + figure + hash from the final main.jsonl, atomically,
# so summaries can never go stale vs the data (audit 2026-06-12). Run from repo root after the grid run.
set -u
cd "$(dirname "$0")/../.." || exit 1
export PATH="$HOME/.local/bin:$PATH"
R=results/headtohead_runs

echo "== analyze (recall@5% and @1% FPR, with bootstrap CIs) =="
python3 -m experiments.cadc.analyze_headtohead main 0.05 --boot | tee "$R/analysis_5pct.txt"
python3 -m experiments.cadc.analyze_headtohead main 0.01 --boot | tee "$R/analysis_1pct.txt"
echo "== behavioral family frontier + harm-type stratification =="
python3 -m experiments.cadc.frontier_report main | tee "$R/frontier.txt"
echo "== static (representation-level) baseline =="
python3 -m experiments.cadc.score_static main
echo "== figures =="
python3 -m experiments.cadc.make_figures main
echo "== artifact SHA256 (provenance manifest) =="
( for f in "$R/main.jsonl" "$R/main.falco.jsonl" "$R/main.static.jsonl" "$R/main.textcache.json" data/benign_real_corpus.json; do
    [ -f "$f" ] && (sha256sum "$f" 2>/dev/null || shasum -a 256 "$f"); done ) | tee "$R/ARTIFACT_HASHES.txt"
echo "== done — all summaries regenerated from the current main.jsonl =="
