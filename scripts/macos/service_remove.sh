#!/bin/bash
# GoodbyeDPI Enhanced - Remove launchd daemon (macOS)

PLIST="/Library/LaunchDaemons/com.goodbyedpi.plist"
INSTALL_DIR="/usr/local/share/goodbyedpi"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root privileges. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

echo "Removing GoodbyeDPI daemon..."

# Unload daemon
launchctl unload "$PLIST" 2>/dev/null

# Remove pf rules
if [ -f "$INSTALL_DIR/setup-pf.sh" ]; then
    "$INSTALL_DIR/setup-pf.sh" stop
fi

# Remove files
rm -f "$PLIST"
rm -f /usr/local/bin/goodbyedpi
rm -rf "$INSTALL_DIR"
rm -f /var/log/goodbyedpi.log
rm -f /var/log/goodbyedpi.error.log

echo ""
echo "Done! GoodbyeDPI daemon removed."
