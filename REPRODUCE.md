# REPRODUCE — cada head-to-head (representation- vs effect-level monitoring under obfuscation)

This manifest lets a third party (or us, later) regenerate every number in `paper/cada_paper.md` from the
raw inputs. It records the exact environment, commands, seeds, model, data hashes, expected numbers, and the
known sources of non-determinism with their mitigations. (Artifact-evaluation style — USENIX/S&P/NeurIPS.)

> STATUS: numbers + hashes are finalized after the n=100-attack/120-benign regeneration. Sections marked
> ⟦FINALIZE⟧ are filled by `make_all.sh` at the end of the run.

## 1. Environment (exact versions used)
- **Compute:** Azure `Standard_D4s_v3` (4 vCPU / 16 GB), x86_64. (Also runs on any Linux Docker host; the local
  Windows Docker Desktop run is bit-compatible for the deterministic parts but see §5 timing non-determinism.)
- **OS:** Ubuntu 22.04.5 LTS · **kernel:** 6.8.0-1052-azure
- **Docker:** 29.5.3 · **Falco:** 0.44.1 (default ruleset, modern-eBPF engine)
- **Python:** 3.10.12 · deps pinned in `experiments/cadc/requirements.lock.txt`:
  `openai==2.41.1 numpy==2.2.6 scipy==1.15.3 scikit-learn==1.7.2 matplotlib==3.10.9 python-dotenv==1.2.2 requests==2.25.1 PyYAML==5.4.1`
- **Sandbox image:** `sandbox/Dockerfile` (`FROM ubuntu:22.04` + strace/python3/curl). ⚠️ NOT pinned by digest;
  for byte-exact repro pin `ubuntu:22.04@sha256:<digest>` and record apt versions. Build: `docker build -t cada-sandbox sandbox/`.

## 2. Data provenance
- **Attacks:** RedCode-Exec bash dataset (AI-secure/RedCode), `data/RedCode/dataset/RedCode-Exec/bash2text_dataset_json/index*_30_codes_full_upd.json`. Loaded deterministically: `k` per category, category order numeric (`headtohead_main.load_attacks`).
- **Benign:** `data/benign_real_corpus.json` — mechanically extracted verbatim CI/Dockerfile commands from 14 public OSS repos with provenance (`build_real_benign.py`). Sampled with `random.seed(42)` (`headtohead_main.load_benign`).
- **Obfuscation:** deterministic pure functions (`exec_obfuscation.TRANSFORMS`, O0–O6 + X1–X3).
- **SHA256 (final, n=100/120 run, 2026-06-12):**
  - `main.jsonl` (2200 rows) `df588c193a5735db…`
  - `main.falco.jsonl` (60-attack subset) `ceb525f6475aa37d…`
  - `main.static.jsonl` `6e0873ddb3920589…`
  - `main.textcache.json` `70b1c9fcde32c59a…`
  - `benign_real_corpus.json` `c9de5c05404731f2…`

## 3. Models
- **Text judge:** `openai/gpt-4o` via OpenRouter, `temperature=0`, graded 0–100 prompt (`graded_monitors.GradedJudgeMonitor`). **Llama Guard:** `meta-llama/llama-guard-4-12b`.
- **REPRODUCIBILITY:** all 1,260 judge/guard responses are **cached** in `results/headtohead_runs/main.textcache.json` (keyed by sha256(model,prompt)); re-running with this cache reproduces the text numbers **exactly, with no API calls**. For a *fresh* reproduction without the cache, pin a snapshot (`openai/gpt-4o-2024-08-06`) — the floating `gpt-4o` tag may drift.

## 4. Commands (regenerate everything)
```bash
# 0. setup (on a Linux Docker host)
docker build -t cada-sandbox sandbox/
bash experiments/cadc/setup_sinkhole.sh                 # egress sinkhole (cadc_sink / 172.19.0.2)
cp .env.example .env  &&  edit .env                     # LLM_API_KEY, JUDGE_MODEL, LLAMAGUARD_MODEL
# 1. head-to-head grid (behavioral + judge + guard), JSONL-resumable, verify-the-artifact
python3 -m experiments.cadc.headtohead_main --attacks-per-cat 5 --n-benign 120 --tag main
# 2. metrics + CIs (judge vs behavioral, per encoding)
python3 -m experiments.cadc.analyze_headtohead main 0.05 --boot
python3 -m experiments.cadc.analyze_headtohead main 0.01 --boot
# 3. behavioral family frontier + harm-type stratification
python3 -m experiments.cadc.frontier_report main
# 4. static (representation-level) baseline
python3 -m experiments.cadc.score_static main
# 5. industry eBPF baseline (Falco running; strace-free system) — see run_falco_phase.sh
python3 -m experiments.cadc.falco_baseline --attacks-per-cat 5 --n-benign 120 --tag main
# 6. adaptive behavioral-evasion (null space), sinkhole-verified
python3 -m experiments.cadc.evasion_probe
# 7. figures
python3 -m experiments.cadc.make_figures main
```

## 5. Known non-determinism + mitigations (honest)
| source | effect | mitigation |
|---|---|---|
| LLM judge (temp 0 ≠ fully deterministic; floating model tag) | judge_score can drift on fresh runs | **ship the cache** (exact repro); pin `gpt-4o-2024-08-06` for fresh runs |
| syscall **timeout races** (blocking-curl attacks time out, level-correlated) | `executed` flag varies run-to-run | report exec% per level; compute OOD comparison on the **level-matched** executed subset; timeout raised 15→25s |
| Falco version / default ruleset evolves | recall/FP can shift | pin Falco 0.44.1 + default ruleset (recorded) |
| sandbox image (ubuntu:22.04 tag + unpinned apt) | syscall trace edges | pin base image by digest; record apt versions |

## 6. Expected headline numbers (final, n=100 attacks / 120 benign, audited code)
Reproduce within bootstrap tolerance (`analyze_headtohead main 0.05 --boot`):
- **judge AUROC** O0 = **0.81 [0.74,0.87]** → base64 = **0.30 [0.24,0.37]** (CIs non-overlapping; base64 below 0.5). O5_deceptive control = 0.79. O6_composed = 0.58 (NOT below chance). X3_xor = 0.74.
- **behavioral AUROC (harm-primitive, lineage-free)** = **0.60 [0.55,0.65] at every level, spread 0.01**.
- judge benign **raw FPR → 1.00** on every encoded level; **recall@1%FPR** 0.70 → ~0; recall@5%FPR 0.70 → ≤0.23.
- behavioral **blind to 74/100 (74%)** of attacks; **all-attack behavioral recall (C5) = 0.27 at 7% FP-tax**; no family config below 4% FPR (cannot run at 1%). "system-harm recall = 1.00" is by-construction (subset = attacks the monitor fires on) — report all-attack recall as the headline.
- **static-taxonomy** recall 0.42 (clean/O5) → 0.00 (every encoded level). **Falco** recall 0.083, FP-tax 0.000 (on the 60-attack subset).

## 7. Version control
`git init` at repo root; `.gitignore` excludes `.env` (secret), nested dataset `.git` dirs, caches, `__pycache__`.
Commit the code + `results/headtohead_runs/*.jsonl` + this manifest so code, data, and expected numbers are versioned together.
