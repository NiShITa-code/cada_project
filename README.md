# CADA v2 — Behavioral vs. Textual Monitoring of LLM Code-Agents under Obfuscation

> **Note on this branch.** This `redesign-v2` branch supersedes the Stage-0 design on
> `main`. During a feasibility audit we found three design-level confounds in the original
> text+sandbox *fusion* plan and corrected them (see **What changed & why** below). The
> corrected work is a **control evaluation**, not a fusion-vs-GPT-4o leaderboard chase.

**Author:** Nishita Jain · **Status:** feasibility validated, motivation experiment in progress · **License:** MIT

---

## The question
On a real-execution code-agent benchmark, does a kernel-level (**eBPF**) **behavioral**
monitor detect programmatically-obfuscated malicious actions that **text** guardrails
(Llama Guard 4, judges) miss — at what false-positive cost — and where does an adaptive,
**sandbox-aware** agent defeat it?

Hypotheses: **H1** text degrades under obfuscation · **H2** behavior is obfuscation-invariant ·
**H3 (key)** the behavioral advantage collapses under sandbox-aware evasion · **H4** a cheap
text→detonation cascade recovers most detection at a fraction of the cost.

## What changed & why (vs. `main` / Stage-0)
| Stage-0 (deprecated) | Problem | v2 correction |
|---|---|---|
| Obfuscate only *unsafe* actions | **Label leakage** — marker ≡ label | Obfuscate **both** classes; oracle labels |
| R-Judge / AgentDojo as behavioral substrate | Static transcripts / simulated tools → **no syscalls** | **RedCode-Exec** (real Docker execution) |
| "Fusion matches GPT-4o", raw F1 | Ignores detonation cost; F1 ill-defined on all-positive | **Recall @ fixed FPR**; judges = cost ceiling |
| 28-feature Phi via strace | Hand-rolled, fragile | **eBPF (Tetragon/Falco)**; strace validated the mechanism |
| (none) | Strawman adversary | **Adaptive sandbox-aware red team** = the contribution |

## Status — feasibility result (Gate 0/1, real syscall traces)
Behavioral recall **1.00** vs. text **0.50** on the obfuscated-malicious set, **0** false
positives, with the syscall feature invariant across all 6 obfuscations. Validates the
*mechanism* (H1+H2). Caveat: strace proxy, micro-scale, keyword stub — the real numbers
come from Gates 2/3/0-real below.

## Install
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env          # add your OpenRouter (or other) LLM key
pytest && ruff check .        # 22 tests, lint clean
```

## Data
```bash
git clone https://github.com/AI-secure/RedCode  data/RedCode    # risky actions (positives)
git clone https://github.com/Lordog/R-Judge      data/R-Judge    # Gate-3 anchor
```
RedCode-Exec is *all-risky*; benign negatives come from `cada.data.benign_actions()` so the
false-positive rate is measurable.

## Kill-gate order (run in this order)
```bash
# Gate 3 — validate the judge harness against R-Judge GPT-4o = 74.45% F1
python -m experiments.gate3_rjudge_repro --rjudge data/R-Judge --limit 20

# Gate 2 — THE motivation run: does Llama Guard 4 degrade under obfuscation?
python -m experiments.gate2_text_monitors --redcode data/RedCode

# Gate 0-real — eBPF + RedCode execution (privileged Linux VM; strace path runs anywhere)
python -m experiments.gate0_runner
```

## Layout
```
cada/            installable package
  obfuscation.py   both-class transform suite (+ held-out family)
  metrics.py       fixed-FPR operating points + obfuscation-gap table
  data.py          RedCode loader + benign negatives + Action type
  rjudge.py        faithful R-Judge protocol (loader, prompts, parsing)
  monitors/        text.py (Llama Guard 4 / judge / stub) · behavioral.py (strace + eBPF hook)
experiments/       gate2 (text gap) · gate3 (R-Judge anchor) · gate0_runner (behavioral)
methodology/       full plan, threat model, failure atlas, kill-gates
tests/             22 unit tests
```

## Compute
Gates 2 & 3 need **one API key, no GPU** (OpenRouter serves Llama Guard 4 + judges). The eBPF
phase needs a **root Linux VM** (not a rootless Vast/Lightning container); a GPU is only needed
to self-host open guardrails. Whole thing fits a ~$200 grant.

## Reproducibility
Code, prompts, configs, raw outputs released MIT — **regardless of result direction**.

Cite via `CITATION.cff`.
