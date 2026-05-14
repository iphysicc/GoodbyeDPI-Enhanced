#!/bin/bash
# GoodbyeDPI Enhanced - Compatible mode with set TTL
# Good for ISPs that inspect TTL values

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

echo "Starting GoodbyeDPI in compatible mode (-3 --set-ttl 3)..."
echo "Press Ctrl+C to stop."
echo ""

"$GOODBYEDPI" -3 --set-ttl 3 --dns-addr 9.9.9.9 --dns-port 9953
