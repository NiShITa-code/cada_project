# cada — Monitoring LLM Code-Agents Under Obfuscation and Adaptive Evasion

A head-to-head study of three ways to monitor an untrusted LLM code-agent — a **text** guardrail, a **syscall** monitor, and a **hybrid** — evaluated on *real, executed* attacks under an obfuscation ladder and an adaptive attacker.

**Short version:** text monitoring dies to obfuscation; syscall monitoring drowns in false alarms on real agent work; a hybrid that judges the *decoded runtime arguments* fixes both and resists adaptive evasion — with one bounded blind spot.

*Nishita Jain · BlueDot Impact project · MIT (code) / CC BY 4.0 (figures & docs).*

---

## The question

As LLM agents gain real privileges (a shell, credentials, package managers), the standard safety mechanism is a **monitor** that watches the agent and flags dangerous actions. You can build one in two places — read what the agent *says* (a text/LLM-judge guardrail) or watch what it *does* (a syscall monitor). The common intuition is *"obfuscation fools text guardrails, so just watch the syscalls."* This project tests that on attacks that actually run, and adds an adaptive attacker.

## Key findings

Evaluated on 100–300 real RedCode-Exec attacks and 120 provenance-tracked benign commands, executed under `strace` in a network-isolated sandbox with an egress sinkhole (98–99% of attacks verifiably execute).

1. **Text monitoring is a decoding arms race.** A GPT-4o judge separates attacks from benign commands well (AUROC 0.81) but collapses to **0.30** (below chance) under one line of `base64`. A stronger model or prompt only changes *which* encoding wins — the limit is structural.
2. **Syscall monitoring is obfuscation-proof but has a false-positive tax that scales with autonomy.** It flags **8% → 44%** of legitimate commands as the workload shifts from CI to genuine data-science-agent work, because a benign `pip install` is syscall-indistinguishable from exfiltration. Neither pure monitor is deployable at a usable alarm rate.
3. **A hybrid fixes both.** Feeding an LLM judge the *decoded runtime arguments* from the trace (the real command, resolved destination, files touched) is obfuscation-invariant **and** cuts the agent false-positive tax from **44% → 3%**.
4. **The hybrid resists an adaptive attacker.** An autonomous GPT-4o/Claude attacker, told the monitor's design, evades the syscall monitor **5/5** (a DNS-tunnel) but the hybrid **0/16** — including that same DNS-tunnel. Its one limit is structural: it cannot see harm that never reaches the kernel (pair it with a content check).

![Text monitors collapse under obfuscation](paper/figures/fig4_armsrace.png)
![The false-positive tax scales with autonomy](paper/figures/fig5_crossdomain.png)

**Relevance to AI safety.** The AI-control agenda for deploying untrusted agents rests on monitoring catching bad actions against an evading agent. This maps where the monitoring holes are, and gives a monitor design that closes most of them.

## Quickstart

```bash
pip install -r requirements.txt
```

## Reproduce

The headline numbers replay from a shipped response cache — **no API calls, no VM required**:

```bash
python -m experiments.cadc.exp_h_analyze --report          # hybrid: FP-tax 44%->3%, evasion baselines
python -m experiments.cadc.judge_prompt_ablation --report  # the text-monitor decoding arms race
python -m experiments.cadc.make_figures2                    # regenerate the figures
```

A full from-scratch run (re-executing attacks under `strace`) needs a Linux Docker host; see [`REPRODUCE.md`](REPRODUCE.md). Every reported number has a committed artifact under `results/headtohead_runs/` and an independent recompute.

## Repository layout

```
experiments/cadc/   the experiments
  headtohead_main.py        the text vs. syscall grid
  blue_team.py, monitor_family.py   the syscall behavioral monitor
  graded_monitors.py        the LLM-judge text monitor
  exp_h.py, exp_h_analyze.py        the hybrid (decoded-runtime-argument) monitor
  exp_e.py, exp_e_verify.py         adaptive evasion of the hybrid
  judge_prompt_ablation.py, model_ladder.py   robustness ablations
cada/               shared library (cache, monitor clients)
results/            findings docs + per-attack data, caches, and traces (for reproduction)
paper/figures/      the figures
REPRODUCE.md        full reproduction manifest
```

## Status and limitations

This is a single-author project; the findings are measured trends, not universal claims. Specifically:

- **Partial fix.** The hybrid is blind to harm with no syscall signature (≈ content/logic harm); it is the *runtime* half of a defense. All-attack recall is 0.34 (0.81 on attacks that actually execute harm — the rest are benchmark code-pattern tasks with nothing to catch at runtime; see [`results/RESULTS_blindspot.md`](results/RESULTS_blindspot.md)).
- **Evasion test caveat.** Some attacker attempts failed to deliver for environmental reasons, so the claim is "no attempt that *actually delivered* the secret evaded." Temporal-splitting evasion and a more reliable exfil harness are the next stress tests.
- **Scope.** One attack benchmark, single seed for headline numbers, single judge model per arm, `strace` coverage gaps (io_uring/raw sockets).
- **Rigor.** Each experiment was pre-registered and adversarially reviewed before its results were trusted; an integrity audit caught and fixed real confounds. See [`results/AUDIT_FINDINGS.md`](results/AUDIT_FINDINGS.md), [`results/RESULTS_exp_h.md`](results/RESULTS_exp_h.md), [`results/RESULTS_exp_e.md`](results/RESULTS_exp_e.md).

## Citation

If you use this work, please cite it — see [`CITATION.cff`](CITATION.cff).

## License

Code: MIT. Research write-up, figures, and data: CC BY 4.0. See [`LICENSE`](LICENSE).
