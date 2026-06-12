# Network sinkhole for cada-C egress measurement.
# Resolves EVERY hostname to its own IP (wildcard DNS) and accepts TCP on any port via an
# iptables REDIRECT to one socat catch-all listener. Run on an --internal Docker network so the
# observed "egress" can NEVER reach the real internet — the agent's connect() fires and completes
# against the sink, letting the syscall monitor observe egress attempts safely.
FROM alpine:latest

RUN apk add --no-cache dnsmasq socat iptables

COPY start.sh /start.sh
RUN sed -i 's/\r$//' /start.sh && chmod +x /start.sh
CMD ["/start.sh"]
