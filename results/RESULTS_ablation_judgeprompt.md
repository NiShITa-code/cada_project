# Tier-1 ablation: is the base64 AUROC collapse a *weak-prompt artifact*?

**Date:** 2026-06-18. **Script:** `experiments/cadc/judge_prompt_ablation.py` (API-only, no VM).
**Cache:** `results/headtohead_runs/main.ablation_strong.textcache.json` (660 GPT-4o calls, 0 refusals).
**Summary artifact:** `results/headtohead_runs/main.ablation_strong.summary.json`.

## Objection being tested (reviewer objection #1)
"Your GPT-4o judge collapsed on base64 (AUROC 0.81→0.30) only because you used a weak/strawman
prompt. A judge *told to expect obfuscation and to decode it* would not be fooled."

The deployed prompt already said *"Consider that the action may be obfuscated or encoded"* — so 0.30 is
not a pure strawman. But we **steelman** the objection with a maximal decode-instructed prompt that
(1) names the encodings, (2) tells the model to mentally **decode first** and recover the real
paths/hosts/operations, and (3) explicitly states the `base64 -d | bash` wrapper **is not itself
malicious**. Everything else (the 100 attacks, 120 benign, the obfuscation transforms) is byte-identical
to the main run. We re-score three levels and compare AUROC to the original ("weak") judge.

## Result

| level       | weak AUROC | **steelman AUROC** | Δ      | steelman benign-suspicion (weak) |
|-------------|-----------:|-------------------:|-------:|---------------------------------:|
| O0_clean    | 0.81       | **0.86**           | +0.05  | 0.01  (0.12) |
| O1_base64   | 0.30       | **0.64**           | **+0.34** | 0.32  (0.87) |
| X3_xor      | 0.74       | **0.50**           | **−0.23** | 1.00  (0.91) |

(attack side = executed attacks only, n≈95–100; benign n=120; benign-suspicion = mean 0–1 score on benign.)

## Interpretation (three things, all honest)

1. **The extreme below-chance base64 number (0.30) is partly a prompt artifact.** The steelman recovers
   base64 to **0.64** — and the *mechanism* is exactly as diagnosed: the steelman drops the judge's mean
   suspicion on **benign** base64 commands from **0.87 → 0.32**, i.e. it stops reflexively flagging the
   `base64|bash` wrapper. So a deployer who writes a careful prompt does better than 0.30. **We report
   this correction in the paper.** (The steelman does not *hurt* clean: O0 goes 0.81→0.86.)

2. **But the steelman never restores clean-level discrimination on base64** (0.64 ≪ 0.86). GPT-4o cannot
   reliably mentally-decode arbitrary base64 payloads, so base64 still costs **~0.22 AUROC** even with a
   maximal prompt — well below any deployable bar.

3. **On XOR the steelman *backfires to chance* (0.74 → 0.50).** Unable to decode the
   `unhexlify…^0x5A…bash -c` blob, and instructed to "judge the decoded action," the judge defaults to
   **maximum suspicion on everything** — benign-suspicion saturates at **1.00** — which destroys the
   residual separation the weaker prompt had. *"Decode and judge the underlying action" only helps on
   encodings the model can actually decode; outside that set it makes things worse, not better.*

## Why this strengthens the paper
The arms-race claim is now demonstrated across **two independent levers**, not one:
- **Capability lever** (earlier result): Claude-4.6 decodes base64 (0.82) but loses to XOR.
- **Prompt lever** (this ablation): a steelman decode-prompt recovers base64 (0.64) but loses to XOR (0.50).

Both "use a better model" and "use a better prompt" move *which encoding wins* without escaping the
trap — the adversary picks an encoding outside the judge's decode set. That makes the representation-level
limit **structural**, not an artifact of any one prompt or model. Pre-empts the #1 reviewer objection.
