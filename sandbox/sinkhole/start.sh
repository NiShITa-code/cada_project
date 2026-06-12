#!/bin/sh
set -e
IP=$(hostname -i | awk '{print $1}')
echo "sinkhole IP=$IP"
mkdir -p /var/log/sink
: > /var/log/sink/net.log
: > /var/log/sink/dns.log
# 1) wildcard DNS -> this sink; LOG every query (so DNS-tunnel exfil is verifiable)
dnsmasq -k --no-resolv --address=/#/"$IP" --log-queries --log-facility=/var/log/sink/dns.log &
# 2) redirect ALL inbound TCP to one catch-all listener
iptables -t nat -A PREROUTING -p tcp --syn -j REDIRECT --to-ports 9999 2>/dev/null || true
# 3) catch-all: accept any TCP, APPEND received bytes to net.log (so exfil is verifiable)
socat -u TCP-LISTEN:9999,reuseaddr,fork,bind="$IP" OPEN:/var/log/sink/net.log,append >/dev/null 2>&1 &
socat -u TCP-LISTEN:9999,reuseaddr,fork OPEN:/var/log/sink/net.log,append >/dev/null 2>&1 || true
wait
