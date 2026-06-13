#!/usr/bin/env bash
# Chain the remaining strace-bound work AFTER Falco-100 finishes (strace floods Falco; must serialize).
set -u
cd "$HOME/cada" || exit 1
export PATH="$HOME/.local/bin:$PATH"

echo "waiting for Falco-100 (pid 259783)..."
while kill -0 259783 2>/dev/null; do sleep 30; done
echo "FALCO100_DONE falco_rows=$(wc -l < results/headtohead_runs/main.falco.jsonl)"

echo "=== Falco-100 breakdown (recall / FP-tax by encoding) ==="
python3 -c "
import json
from collections import Counter
rows=[json.loads(l) for l in open('results/headtohead_runs/main.falco.jsonl')]
for role in ['attack','benign']:
    for lv in ['O0_clean','O1_base64','X3_xor']:
        rs=[r for r in rows if r['role']==role and r['level']==lv]
        if rs: print('  %-7s %-10s n=%d falco=%.3f'%(role,lv,len(rs),sum(r['falco_flag'] for r in rs)/len(rs)))
print('  rules:', dict(Counter(rule for r in rows for rule in r['rules']).most_common(6)))
"
echo "=== CROSS-DOMAIN FP-tax (CI vs data-science; behavioral, strace) ==="
python3 -m experiments.cadc.cross_domain_fptax 120
echo "ALL_REMAINING_DONE"
