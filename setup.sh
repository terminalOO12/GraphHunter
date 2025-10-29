#!/usr/bin/env bash
# setup.sh — Kali-friendly non-interactive setup for GraphHunter + Ollama (no model download)
# Usage: sudo ./setup.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

REQ_FILE="requirements.txt"
OLLAMA_INSTALLER_URL="https://ollama.com/install.sh"

echo "== GraphHunter Setup for Kali Linux =="
echo "This script will:"
echo "  • Install required system packages"
echo "  • Install Flask & Requests via apt (or pip if allowed)"
echo "  • Install Ollama (without pulling any model)"
echo

# ---- System Setup ----
echo "[sys] Updating apt and installing base dependencies..."
apt-get update -y
apt-get install -y curl jq wget ca-certificates gnupg2 unzip build-essential python3 python3-pip

# ---- Python Dependencies ----
install_python_deps_via_apt() {
  echo "[python][apt] Installing Debian-packaged Python dependencies..."
  apt-get install -y python3-flask python3-requests || true
}

install_python_deps_via_pip_break() {
  echo "[python][pip] Installing via pip with --break-system-packages (PEP 668 override)."
  python3 -m pip install --upgrade pip setuptools wheel
  python3 -m pip install --break-system-packages -r "${REQ_FILE}"
}

if [ -f "${REQ_FILE}" ]; then
  echo "[python] Found ${REQ_FILE}."
  set +e
  python3 -m pip install -r "${REQ_FILE}" 2>&1 | tee /tmp/pip_install_log.txt
  rc=${PIPESTATUS[0]}
  set -e
  if [ $rc -ne 0 ]; then
    if grep -qi "externally-managed-environment" /tmp/pip_install_log.txt || grep -qi "PEP 668" /tmp/pip_install_log.txt; then
      echo "[python] Detected PEP 668 restriction. Installing Flask and Requests via apt instead."
      install_python_deps_via_apt
    else
      echo "[python] pip install failed (code $rc). Falling back to apt packages."
      install_python_deps_via_apt
    fi
  fi
  rm -f /tmp/pip_install_log.txt
else
  echo "[python] ${REQ_FILE} not found — installing minimal Flask + Requests via apt."
  install_python_deps_via_apt
fi

# Optional override (force pip --break-system-packages)
if [ "${PIP_BREAK:-0}" = "1" ]; then
  install_python_deps_via_pip_break
fi

# ---- Ollama Installation ----
if command -v ollama >/dev/null 2>&1; then
  echo "[ollama] Already installed at: $(command -v ollama)"
else
  echo "[ollama] Installing Ollama (non-interactive)..."
  TMP_SH="$(mktemp /tmp/ollama-installer-XXXX.sh)"
  if ! curl -fsSL "${OLLAMA_INSTALLER_URL}" -o "$TMP_SH"; then
    echo "[error] Could not download Ollama installer. Visit https://ollama.com to install manually."
    exit 1
  fi
  chmod +x "$TMP_SH"
  if ! bash "$TMP_SH" </dev/null; then
    echo "[error] Ollama installation failed. Install manually from https://ollama.com"
    rm -f "$TMP_SH"
    exit 1
  fi
  rm -f "$TMP_SH"
fi

# Ensure ollama is accessible
if ! command -v ollama >/dev/null 2>&1; then
  for p in /usr/local/bin/ollama /opt/ollama/bin/ollama /usr/bin/ollama /snap/bin/ollama; do
    if [ -x "$p" ]; then
      ln -sf "$p" /usr/local/bin/ollama || true
      echo "[ollama] Linked $p -> /usr/local/bin/ollama"
      break
    fi
  done
fi

if ! command -v ollama >/dev/null 2>&1; then
  echo "[error] ollama not found on PATH even after installation."
  echo "Add manually: export PATH=\$PATH:/usr/local/bin:/opt/ollama/bin"
  exit 1
fi

echo
echo "== ✅ Setup Complete =="
echo "• Flask & Requests installed."
echo "• Ollama installed: $(command -v ollama)"
echo
echo "⚙️  Next Steps:"
echo "  1. Pull the Llama model manually (optional now, ~5GB download):"
echo "       ollama pull llama3.1:8b"
echo "  2. Verify with:"
echo "       ollama list"
echo "  3. Run GraphHunter:"
echo "       python3 graphhunter_final.py --serve --port 1777 --token \"<GRAPH_TOKEN>\""
echo
echo "If pip fails next time, you can run with:"
echo "   sudo PIP_BREAK=1 ./setup.sh"
echo
echo "== Finished successfully. =="
