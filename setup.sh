#!/usr/bin/env bash
# Secure Tunnel — client setup (Linux / macOS)
# Usage: bash setup_client_linux.sh
set -euo pipefail

echo "=== Secure Tunnel Client Setup ==="

# ── Python packages ───────────────────────────────────────────────────────────
echo "[1/2] Installing Python packages..."
python3 -m pip --version &>/dev/null || python3 -m ensurepip --upgrade
python3 -m pip install --upgrade pip --quiet
python3 -m pip install cryptography pillow textual --quiet
echo "      Done."

# ── Tor ───────────────────────────────────────────────────────────────────────
echo "[2/2] Installing Tor..."
if command -v tor &>/dev/null; then
    echo "      Already installed: $(tor --version 2>&1 | head -1)"
else
    if   command -v apt-get &>/dev/null; then sudo apt-get update -qq && sudo apt-get install -y tor
    elif command -v dnf     &>/dev/null; then sudo dnf install -y tor
    elif command -v pacman  &>/dev/null; then sudo pacman -Sy --noconfirm tor
    elif command -v brew    &>/dev/null; then brew install tor
    else echo "      Could not auto-install Tor. Install manually if needed for --tor flag."
    fi
    command -v tor &>/dev/null && echo "      Tor installed." || echo "      Tor not installed (optional)."
fi

echo ""
echo "Setup complete. Start with:"
echo "  python3 tui.py"
echo "  python3 client.py --relay <ip> --secret <key> --name <you> --knock-ports 1000,2000,3000"
