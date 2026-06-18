# RESULTS AUDIT — 2026-06-12 (6-point integrity audit before scaling)

**Method:** integrity checks (counts/dups/completeness) + my live recomputation + a 5-agent adversarial
workflow that re-read the code and INDEPENDENTLY recomputed every headline number from raw `main.jsonl`.

## VERDICT: core result is REAL and confirmed; paper had stale numbers + 4 methodological refinements. None invalidating.

### ✅ Confirmed solid (independent recompute matches to 3 decimals)
- Inversion holds: judge AUROC O0=0.80 → base64=0.26 (CIs non-overlapping, below chance), rawFPR→1.00,
  behavioral flat ~0.59, **75% blind (45/60)**, Falco 0.083/0.00. Every qualitative headline survives.
- TOY-CHECK PASSES: corpus real (RedCode 20 cats; 234 provenance benign from 14 repos), monitors real,
  NO fabrication, NO decoy-tuning (/etc/passwd correctly excluded), verify-the-artifact machinery sound,
  `-i` bug fixed everywhere, resume/dedup integrity good, data stored correctly (1400 rows, 0 dup, 0 missing).

### ❌ Issues found
| # | sev | issue | status |
|---|-----|-------|--------|
| 1 | major | Paper numbers STALE (written for 40/50/630; data is 60/80/1400). O6 "below chance 0.49"→0.55 (CI straddles 0.5, doesn't survive); recall@5%FPR 0.74→0.71; many cells off | FIX = regenerate all from final data |
| 2 | major | `recall_at_fpr` under-reported (quantile heuristic too high; O5 0.45 vs 0.52) | ✅ FIXED (proper threshold sweep) |
| 3 | major | "system-harm recall 0.90" CIRCULAR — subset = where monitor fired → recall≈1.0 by construction | FIX = report all-attack recall (0.23-0.25) + invariance-by-construction; honest n=15 + CI |
| 4 | major | Lineage confound — obf wrappers inflate execve_count → C6 lineage gave behavioral +0.005..0.019 unearned AUROC on obf levels | ✅ FIXED (harm-primitive-only score; spread 0.043→0.013, invariance TIGHTER) |
| 5 | major | Timeouts masquerade as non-exec, LEVEL-CORRELATED (curl-block attacks time out on O-levels not X) → X gets credit O denied | FIX = level-matched subset (auditor verified headline survives: behav spread 0.582-0.625, judge 0.795→0.268) + raise timeout |
| 6 | minor | static "identical twin" overstated (only SENSITIVE_BROAD+PERSISTENCE shared); C1/C2 DNS-exclusion a no-op in data; IPv6 egress missed (sin6_port); destructive over-broad (apt-get FPs); privesc/anti_trace fire 0× | FIX = soften wording; add as limitations |

### Fixes applied this session (code)
- `analyze_headtohead.recall_at_fpr`: proper threshold sweep (max recall s.t. FPR≤target).
- `analyze_headtohead.harm_score`: lineage-free behavioral graded score (harm primitives only); used for
  behav AUROC in analyzer + figures. Pushed to VM.

### Pending (after the n=100/120 scale-up completes)
1. Regenerate ALL numbers + bootstrap CIs from final `main.jsonl` with fixed code; persist CIs into summary JSON.
2. Compute the OOD/cross-encoding comparison on the LEVEL-MATCHED executed subset (attacks executing at all levels).
3. Re-score static baseline on the full 60→100 corpus + all 10 levels (currently 38/50, 7 levels).
4. Note Falco baseline is on the 60-attack / 3-level subset (re-run on 100 attacks optional).
5. Rewrite paper §5-6 from regenerated numbers + interpretation fixes (n; circular→all-attack recall; lineage
   caveat; static twin; C1/C2 no-op; FPR floor ≤1/n_benign; IPv6/destructive/dead-feature limitations).
6. Raise trace_runner timeout (15→25s) for future runs so blocking-curl attacks execute on all levels.

**Bottom line: the conclusion is safe and the corpus/monitors are real; the paper just ran ahead of the data
and three methodological claims were sloppier than represented. All fixable; core science intact.**
