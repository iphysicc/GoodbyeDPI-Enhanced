#!/bin/bash
# GoodbyeDPI Enhanced - Full setup and run (one-click)
# Sets up pf rules, runs GoodbyeDPI, cleans up on exit

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

# Cleanup function
cleanup() {
    echo ""
    echo "Stopping GoodbyeDPI and removing pf rules..."
    "$SCRIPT_DIR/setup-pf.sh" stop
    exit 0
}

trap cleanup SIGINT SIGTERM

# Setup pf rules
echo "Setting up pf divert rules..."
"$SCRIPT_DIR/setup-pf.sh" start

echo ""
echo "Starting GoodbyeDPI in default mode (-9)..."
echo "Press Ctrl+C to stop and clean up."
echo ""

"$GOODBYEDPI" -9

# If goodbyedpi exits on its own, still cleanup
cleanup
