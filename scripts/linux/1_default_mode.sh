#!/bin/bash
# GoodbyeDPI Enhanced - Default mode (mode -9)
# Requires: iptables rules configured (run setup-iptables.sh start first)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GOODBYEDPI="$SCRIPT_DIR/goodbyedpi"

if [ ! -f "$GOODBYEDPI" ]; then
    echo "Error: goodbyedpi binary not found in $SCRIPT_DIR"
    echo "Place the goodbyedpi binary in the same directory as this script."
    exit 1
fi
chmod +x "$GOODBYEDPI"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root privileges. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

echo "Starting GoodbyeDPI in default mode (-9)..."
echo "Press Ctrl+C to stop."
echo ""

"$GOODBYEDPI" -9
