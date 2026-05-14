#!/bin/bash
#
# GoodbyeDPI pf (Packet Filter) setup script for macOS
#
# This script configures pf divert rules for packet interception.
# Requires root privileges.
#
# Usage: ./setup-pf.sh [start|stop]
#

DIVERT_PORT=1234
PF_ANCHOR="com.goodbyedpi"
PF_RULES_FILE="/tmp/goodbyedpi-pf.rules"

start() {
    echo "Setting up pf rules for GoodbyeDPI (divert port $DIVERT_PORT)..."

    # Create pf rules file
    cat > "$PF_RULES_FILE" << EOF
# GoodbyeDPI pf rules
pass out on en0 proto tcp from any to any port {80, 443} divert-to 127.0.0.1 port $DIVERT_PORT
pass in on en0 proto tcp from any port {80, 443} to any divert-to 127.0.0.1 port $DIVERT_PORT
# Uncomment for DNS redirection:
# pass out on en0 proto udp from any to any port 53 divert-to 127.0.0.1 port $DIVERT_PORT
# pass in on en0 proto udp from any port 53 to any divert-to 127.0.0.1 port $DIVERT_PORT
EOF

    # Load the anchor
    pfctl -a "$PF_ANCHOR" -f "$PF_RULES_FILE"
    pfctl -e 2>/dev/null  # Enable pf if not already enabled

    echo "pf rules configured. Note: You may need to adjust 'en0' to your network interface."
    echo "Use 'ifconfig' or 'networksetup -listallhardwareports' to find your interface."
}

stop() {
    echo "Removing GoodbyeDPI pf rules..."

    pfctl -a "$PF_ANCHOR" -F all 2>/dev/null
    rm -f "$PF_RULES_FILE"

    echo "pf rules removed."
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac
