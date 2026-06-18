# EXP-H pre-run design review (adversarial, 5 lenses + synthesis) — 2026-06-18

Ran a 6-agent adversarial review of the EXP-H hybrid-monitor design BEFORE trusting any result (the
discipline from `AUDIT_FINDINGS.md`). 25 findings (4 critical, 8 high). Verdict: *core idea sound,
leakage surface clean, but the verdict-deciding machinery reintroduced two defects the project's own
2026-06-12 audit already flagged.* All fixed before the analysis was run. The must-fixes:

1. **Circular positive set (AUDIT #3 recurrence).** H2/H3 selected positives by `behav_harmful`, the
   same syscall signal the hybrid reads → recall partly guaranteed by construction. **Fix:** headline
   = recall@1%FPR over ALL executed attacks (100 are attacks by RedCode construction = a monitor-
   independent label); the manifested-harm subset is reported only as a clearly-labelled conditional.
2. **Prompt asymmetry.** Hybrid prompt had a benign-allowance clause + malicious exemplars the text
   baseline (`_GRADED_PROMPT`) lacked; the repo's own Tier-1 ablation shows wording moves AUROC ~0.3.
   **Fix:** a text baseline scored with the IDENTICAL prompt (raw command in place of the effect block);
   plus an exemplar-removed effect variant.
3. **Summary hid the destination host/IP** (only the port), so the judge scored a has-egress/fixed-port
   proxy and H3's "destination semantics" was untestable. **Fix:** extract resolved host/IP from the
   decoded argv + connect peer into the summary; run a ports-blinded ablation; honestly reframe H3 to
   "by command+effect text" (targets are down, so the host is the argv string, not a resolved dest).
4. **Decode-wrapper execve fingerprinted the level** (`$ bash`, `$ python3 -c <ENChex>`) inside the
   "neutral" summary. **Fix:** collapse the known decode scaffolding so only decoded payload remains;
   report the fraction of cells whose summary is byte-identical across O0/O1/X3 (H1 = a parse/decode
   pipeline check, not a monitor result).
5. **IPv6 egress regex mismatch (AUDIT #6).** `effect_summary` matched `sin6?_port` but `behav_harmful`
   /`extract_features` matched IPv4-only `sin_port` → arms saw different egress. **Fix:** unify across
   `blue_team.py`, `monitor_family.py`, `exp_h.py`; recompute `behav_harmful`.
6. **H2 and H3 evaluated at different thresholds.** **Fix:** one threshold; report H2 recall AND H3
   DS-FPR at that single t; add bin sensitivity to ±1 benign FP.
7. **Pooled 360 correlated re-encodings as independent benign.** **Fix:** benign FPR / H3 threshold on
   the 120 DISTINCT CI commands (per-command max across O0/O1/X3); FPR floor stated as 1/120; cluster
   bootstrap resampling whole command-triplets.

Should-fixes also applied: H1 gated on a floor (min-level AUROC must beat behavioral AND ≥0.70) and the
NULL bin operationalized in code (hybrid AUROC CI overlaps behavioral); per-class score-shift check;
anti-leak guard (assert no role/id/level string reaches the judge); multi-stage attacks scoped as a
limitation (sinkhole truncates server-response-dependent harm).

Timeout note: capture used 15s but only 5/780 cells timed out, and the cell that timed out (attack 2_1)
timed out at ALL THREE levels — i.e. cell-specific, NOT level-correlated — so AUDIT #5's confound does
not bite here. Per-level executed/timeout counts are reported in the analysis.
