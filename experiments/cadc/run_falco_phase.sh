#!/usr/bin/env bash
# Run the Falco baseline on a CLEAN (strace-free) system: wait for the scale run to finish, restart
# Falco fresh, validate attribution on a known /etc/shadow read, then a small pilot. (Falco and strace
# both trace syscalls; running them together floods Falco — so this must run after the strace grid.)
set -u
cd "$HOME/cada" || exit 1
export PATH="$HOME/.local/bin:$PATH"

echo "waiting for strace scale run to finish..."
while pgrep -f "headtohead_main.*--tag main" >/dev/null 2>&1; do sleep 15; done
echo "SCALE_DONE rows=$(wc -l < results/headtohead_runs/main.jsonl)"

echo "restarting Falco clean..."
docker rm -f falco >/dev/null 2>&1
docker run -d --name falco --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock:ro -v /proc:/host/proc:ro \
  -v /etc:/host/etc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro \
  falcosecurity/falco:latest falco -o engine.kind=modern_ebpf -o json_output=true -o stdout_output.enabled=true >/dev/null 2>&1
sleep 18
docker logs falco 2>&1 | grep -iE "modern BPF|Falco initialized" | tail -2

echo "=== ATTRIBUTION TEST (calm system; must fire 'Read sensitive file') ==="
python3 -c "import time; from experiments.cadc.falco_baseline import run_cell, falco_alerts_for; run_cell('cadcfal_shadowtest','cat /etc/shadow >/dev/null 2>&1; head -c5 /etc/shadow >/dev/null 2>&1; echo hi'); time.sleep(3); print('SHADOW_ALERTS=', falco_alerts_for('cadcfal_shadowtest'))"

echo "=== FALCO PILOT (5/role x O0,base64,xor) ==="
python3 -m experiments.cadc.falco_baseline --tag main --pilot 5 2>&1 | tail -4
python3 -c "
import json
rows=[json.loads(l) for l in open('results/headtohead_runs/main.falco.jsonl')]
for role in ['attack','benign']:
    for lv in ['O0_clean','O1_base64','X3_xor']:
        rs=[r for r in rows if r['role']==role and r['level']==lv]
        if rs: print(role, lv, 'exec=%.0f%%'%(100*sum(r['executed'] for r in rs)/len(rs)), 'falco_flag=%.2f'%(sum(r['falco_flag'] for r in rs)/len(rs)))
"
echo "FALCO_PHASE_PILOT_DONE"
