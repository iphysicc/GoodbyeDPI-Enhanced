#!/bin/bash
# GoodbyeDPI Enhanced - Install as systemd service
# Binary and scripts must be in the same directory

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GOODBYEDPI="$SCRIPT_DIR/goodbyedpi"
INSTALL_DIR="/usr/local/share/goodbyedpi"

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

echo "Installing GoodbyeDPI as systemd service..."

# Copy binary
cp "$GOODBYEDPI" /usr/local/bin/goodbyedpi
chmod +x /usr/local/bin/goodbyedpi

# Copy iptables setup script
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/setup-iptables.sh" "$INSTALL_DIR/setup-iptables.sh"
chmod +x "$INSTALL_DIR/setup-iptables.sh"

# Create systemd service file
cat > /etc/systemd/system/goodbyedpi.service << 'EOF'
[Unit]
Description=GoodbyeDPI Enhanced - DPI circumvention utility
After=network.target

[Service]
Type=simple
ExecStartPre=/usr/local/share/goodbyedpi/setup-iptables.sh start
ExecStart=/usr/local/bin/goodbyedpi -9
ExecStopPost=/usr/local/share/goodbyedpi/setup-iptables.sh stop
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable goodbyedpi
systemctl start goodbyedpi

echo ""
echo "Done! GoodbyeDPI service installed and started."
echo ""
echo "Useful commands:"
echo "  sudo systemctl status goodbyedpi    - check status"
echo "  sudo systemctl stop goodbyedpi      - stop"
echo "  sudo systemctl restart goodbyedpi   - restart"
echo "  sudo systemctl disable goodbyedpi   - disable auto-start"
echo "  sudo ./service_remove.sh            - uninstall completely"
