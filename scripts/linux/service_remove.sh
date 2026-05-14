#!/bin/bash
# GoodbyeDPI Enhanced - Remove systemd service

if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root privileges. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

echo "Removing GoodbyeDPI service..."

systemctl stop goodbyedpi 2>/dev/null
systemctl disable goodbyedpi 2>/dev/null
rm -f /etc/systemd/system/goodbyedpi.service
systemctl daemon-reload

rm -f /usr/local/bin/goodbyedpi
rm -rf /usr/local/share/goodbyedpi

echo ""
echo "Done! GoodbyeDPI service removed."
