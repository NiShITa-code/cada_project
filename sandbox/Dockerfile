# Isolated sandbox for behavioural monitoring (Gate 0-real).
# Executes risky agent actions under syscall tracing, with no real credentials/network.
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip strace auditd curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY canary_files/ /opt/canary/

# eBPF note: Tetragon/Falco run on the HOST (privileged) and observe this container's
# cgroup/PID namespace. `strace` works in-container as the validated fallback backend.
# Run with isolation, e.g.:
#   docker run --rm --network none --read-only --cap-drop ALL cada-sandbox \
#       python3 -c "<agent action>"
CMD ["/bin/bash"]
