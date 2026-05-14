#!/bin/bash
# GoodbyeDPI Enhanced - Auto TTL mode
# Automatically detects and sets optimal TTL for fake packets

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

echo "Starting GoodbyeDPI with auto TTL (-5)..."
echo "Press Ctrl+C to stop."
echo ""

"$GOODBYEDPI" -5 --dns-addr 9.9.9.9 --dns-port 9953
