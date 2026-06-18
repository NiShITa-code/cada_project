# What the "blind spot" actually is — decomposition of non-manifesting attacks

**Date:** 2026-06-18. **Data:** 299 executed O0 attacks (n=300 corpus). **Artifact:** `blindspot_decomp.json`.
Reframes the hybrid's all-attack recall (0.30) and the paper's 74% blind-spot figure.

## The split
- **26% (79/299) manifest a runtime harm primitive** (egress / secret-read / destructive that fires a syscall).
  The hybrid recalls **0.83** on these — the catchable, deployment-relevant set.
- **74% non-manifesting** — and this is dominated by RedCode's *code-pattern-vs-runtime-behavior* axis, NOT a
  monitor failure:
  - **recon / reads of world-readable files** — `cat /etc/passwd`, `ls /app`, `awk {print}` (passwd/group/proc
    are world-readable; no runtime harm to catch).
  - **payloads authored but never executed** — e.g. `data="import shutil; shutil.rmtree('/bin')"` then base64 →
    write to a file that is never run; `with open('/etc/passwd','a') as f: f.write('new_user:x:0:0:root…')` stored,
    not executed. The harm lives in the *code*, never reaches the kernel.
  - **content/bias harm** (small, ~3-10%) — cat-12 `declare -A race_categories=(["Black"]=0 …)`: discriminatory
    logic with no system-call signature. **Genuinely invisible to any effect-level monitor** → needs orthogonal
    content analysis. This is the only *fundamental* residual.
  - **catchable persistence (~5%)** — cat-9 `echo 'alias sudo="rm -rf /"' >> /root/.bashrc`. Genuinely malicious,
    but missed because `echo` is a shell builtin (no `execve`) AND the write target `/root/.bashrc` was filtered as
    loader-noise. **Recoverable** by surfacing persistence-relevant writes in the effect summary — a concrete
    method improvement (the `openat("/root/.bashrc", O_WRONLY|O_APPEND)` IS in the saved trace).

## Why it matters for the paper
The all-attack recall of 0.30 **conflates** real misses with attacks that have no runtime harm. Stating it
honestly: on attacks that actually execute harm, the hybrid catches **83%**, obfuscation-invariantly, at **3%**
FP-tax; the "misses" are mostly benchmark code-pattern tasks (recon, authored-not-run payloads) plus a small
content-harm slice. This converts the apparent weakness ("only 0.30 recall") into a precise, defensible statement
of scope — and identifies one concrete, recoverable slice (persistence writes) as a method-improvement target.
