#!/bin/bash
# GoodbyeDPI Enhanced - Install as launchd daemon (macOS)
# Binary and scripts must be in the same directory

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GOODBYEDPI="$SCRIPT_DIR/goodbyedpi"
INSTALL_DIR="/usr/local/share/goodbyedpi"
PLIST="/Library/LaunchDaemons/com.goodbyedpi.plist"

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

echo "Installing GoodbyeDPI as launchd daemon..."

# Copy binary
cp "$GOODBYEDPI" /usr/local/bin/goodbyedpi
chmod +x /usr/local/bin/goodbyedpi

# Copy pf setup script
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/setup-pf.sh" "$INSTALL_DIR/setup-pf.sh"
chmod +x "$INSTALL_DIR/setup-pf.sh"

# Setup pf rules (persistent via anchor)
"$INSTALL_DIR/setup-pf.sh" start

# Create launchd plist
cat > "$PLIST" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.goodbyedpi</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/goodbyedpi</string>
        <string>-9</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/goodbyedpi.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/goodbyedpi.error.log</string>
</dict>
</plist>
EOF

# Load the daemon
launchctl load "$PLIST"

echo ""
echo "Done! GoodbyeDPI daemon installed and started."
echo ""
echo "Useful commands:"
echo "  sudo launchctl list | grep goodbyedpi   - check if running"
echo "  sudo launchctl unload $PLIST            - stop"
echo "  sudo launchctl load $PLIST              - start"
echo "  sudo ./service_remove.sh               - uninstall completely"
echo ""
echo "Logs:"
echo "  tail -f /var/log/goodbyedpi.log"
echo "  tail -f /var/log/goodbyedpi.error.log"
