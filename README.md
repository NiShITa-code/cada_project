# cada — Can you monitor a capable AI agent? (text guardrails vs. syscall monitors, under obfuscation)

**A head-to-head of representation-level (text/LLM-judge) vs. effect-level (syscall/eBPF) monitoring of LLM
code-agents, on real executed attacks under an obfuscation ladder.** Short answer: **neither is deployable.**

*Author: Nishita Jain · solo BlueDot project · MIT · everything below reproduces from this repo.*

📄 Paper: [`paper/cada_paper.md`](paper/cada_paper.md) · 📝 Blog: [`paper/blog_lesswrong.md`](paper/blog_lesswrong.md) · 🔁 Repro: [`REPRODUCE.md`](REPRODUCE.md)

---

## The question
As LLM agents get real privileges (shell, credentials), the standard safety mechanism is a **monitor**. Two
families: read what the agent *says* (a text/LLM-judge guardrail) or watch what it *does* (a syscall monitor).
The common intuition — "obfuscation fools text guardrails, so just watch the syscalls" — turns out to be wrong.
We measured it.

## Findings (n = 100 real attacks / 120 real benign, executed under `strace` + an egress sinkhole)
- **Text guardrails are in a *decoding arms race*.** GPT-4o's discrimination collapses **0.81 → 0.30 AUROC**
  under one line of `base64`; a frontier model (Claude 4.6) decodes base64 (0.82) but loses to **XOR**,
  over-flags 80% of benign, and refuses ~15%. The adversary just picks an encoding the model can't decode.
- **Syscall monitors are decode-free but blind and noisy.** Invariant to obfuscation, but **blind to ~51%** of
  harms (no syscall signature), can't run below **4% FPR**, and the false-positive rate hits **38% on real
  data-science-agent commands** — legit dataset downloads are syscall-indistinguishable from exfiltration.
- **A frontier LLM bypasses the syscall monitor autonomously in ~1 turn** (DNS-tunnel; 5/5, 0 refusals,
  exfiltration verified at the sink).

![arms race](paper/figures/fig4_armsrace.png)
![FP-tax scales with autonomy](paper/figures/fig5_crossdomain.png)

**Net:** at a 1% deployment FPR there is no single deployable monitor. Relevance to AI safety: the *AI-control*
plan for deploying untrusted agents rests on monitoring — this maps where the monitoring holes actually are.

## Reproduce
```bash
pip install -r experiments/cadc/requirements.lock.txt      # pinned deps
# the LLM-monitor numbers reproduce from the shipped cache with ZERO API calls:
python -m experiments.cadc.analyze_headtohead main 0.05 --boot
python -m experiments.cadc.frontier_report main
python -m experiments.cadc.make_figures main && python -m experiments.cadc.make_figures2
# full from-scratch run (needs a Linux Docker host; see REPRODUCE.md):
bash experiments/cadc/make_all.sh
```
Raw per-attack data: `results/headtohead_runs/main.jsonl` (2200 cells). Every number has an artifact + an
independent recompute. **Verify-the-artifact:** 98% of attacks provably executed (0 phantom catches).

## What's here
```
paper/        cada_paper.md (the write-up) · blog_lesswrong.md · figures/
experiments/cadc/
  headtohead_main.py    run the grid (behavioral + GPT-4o + Llama Guard)
  graded_monitors.py    graded LLM judge · static_monitors.py (regex twin)
  blue_team.py monitor_family.py   syscall behavioral monitor (C1..C6 configs)
  falco_baseline.py     industry eBPF baseline · evasion_autonomous.py (LLM red-team)
  cross_domain_fptax.py build_ds_agent_benign.py   the FP-tax-vs-autonomy result
  analyze_headtohead.py frontier_report.py make_figures*.py   metrics + figures
results/      AUDIT_FINDINGS.md (the integrity audit) · headtohead_runs/*.jsonl
methodology/  PREREG_next_level.md (pre-registered next experiments)
```

## Honest status & limitations
- Modest scale (n=100/120, single seed, one obfuscator); behavioral coverage uses `strace` (misses io_uring/raw
  sockets); "74% blind" is ~51% structural + ~22% unmanifested in our generic sandbox. We do **not** claim agents
  are "fundamentally unmonitorable" — only the measured trends. (One early over-claim — that the text collapse was
  universal — was caught by an audit and corrected to "model-dependent"; see `results/AUDIT_FINDINGS.md`.)
- **The hybrid fix (built + pre-registered):** a monitor that feeds an LLM judge the *decoded runtime arguments*
  from the trace escapes the obfuscation arms race (invariant) **and** the FP-tax (DS-agent 44%→3%, `RESULTS_exp_h.md`),
  but inherits the semantic blind spot (all-attack recall 0.34; 0.81 on attacks that actually execute harm).
- **It's the only observation point that resists an adaptive adversary (`RESULTS_exp_e.md`):** an autonomous
  GPT-4o/Claude attacker told the monitor's design evades the syscall monitor **5/5** (DNS-tunnel) but the hybrid
  **0/16** (incl. that DNS-tunnel). So the hybrid is obfuscation-robust **+** FP-deployable **+** evasion-resistant
  — combined, not transcended. (Both experiments adversarially audited before running: `results/EXPH_DESIGN_REVIEW.md`.)

Feedback / "you're wrong because…" very welcome — the repo runs in one command and I'd love someone to break the
hybrid before I build it.
