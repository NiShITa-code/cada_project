#!/usr/bin/env bash
# cada-C cloud setup — run on a fresh Ubuntu 22.04 Azure VM (azureuser).
#   chmod +x cloud_setup.sh && ./cloud_setup.sh
# After this, copy our code up (see HANDOFF / the scp list) and run the frontier.
set -euo pipefail

echo "=== 1. system deps ==="
sudo apt-get update -y
sudo apt-get install -y git curl strace ca-certificates

echo "=== 2. Docker (engine, native Linux) ==="
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"   # so docker works without sudo (re-login after)

echo "=== 3. Docker address pool (the fix that needed a UI on Windows — here it's just a file) ==="
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json >/dev/null <<'JSON'
{
  "default-address-pools": [
    { "base": "10.201.0.0/16", "size": 24 }
  ]
}
JSON
sudo systemctl restart docker

echo "=== 4. uv (Python tool/runtime manager) ==="
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

echo "=== 5. ControlArena ==="
mkdir -p ~/cada/tools
cd ~/cada/tools
[ -d control-arena ] || git clone --depth 1 https://github.com/UKGovernmentBEIS/control-arena.git
cd control-arena
uv sync --python 3.11

echo ""
echo "=== DONE. Next ==="
echo " - Log out & back in (so 'docker' works without sudo)."
echo " - Copy our code up:  experiments/cadc/, sandbox/, .env, data/benign_real_corpus.json,"
echo "   and the run scripts (cadc_traced.py, run_frontier.py, frontier_analysis.py) into ~/cada/."
echo " - Build the sandbox + benchmark-base images, then run the frontier (PYTHONUTF8 not needed on Linux)."
