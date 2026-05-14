#!/bin/bash
#
# GoodbyeDPI iptables/nftables setup script for Linux
# This script configures NFQUEUE rules for packet interception.
#
# Usage: ./setup-iptables.sh [start|stop]
#

QUEUE_NUM=0

start() {
    echo "Setting up iptables rules for GoodbyeDPI (queue $QUEUE_NUM)..."

    # Outbound HTTP/HTTPS
    iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num $QUEUE_NUM
    iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num $QUEUE_NUM

    # Inbound HTTP/HTTPS (for passive DPI detection)
    iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num $QUEUE_NUM
    iptables -A INPUT -p tcp --sport 443 -j NFQUEUE --queue-num $QUEUE_NUM

    # DNS (if DNS redirection is needed)
    # iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num $QUEUE_NUM
    # iptables -A INPUT -p udp --sport 53 -j NFQUEUE --queue-num $QUEUE_NUM

    # IPv6 rules
    ip6tables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num $QUEUE_NUM
    ip6tables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num $QUEUE_NUM
    ip6tables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num $QUEUE_NUM
    ip6tables -A INPUT -p tcp --sport 443 -j NFQUEUE --queue-num $QUEUE_NUM

    # Block QUIC (optional, uncomment if needed)
    # iptables -A OUTPUT -p udp --dport 443 -j DROP

    echo "iptables rules configured."
}

stop() {
    echo "Removing GoodbyeDPI iptables rules..."

    iptables -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null
    iptables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null
    iptables -D INPUT -p tcp --sport 80 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null
    iptables -D INPUT -p tcp --sport 443 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null

    # iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null
    # iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null

    ip6tables -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null
    ip6tables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null
    ip6tables -D INPUT -p tcp --sport 80 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null
    ip6tables -D INPUT -p tcp --sport 443 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null

    # iptables -D OUTPUT -p udp --dport 443 -j DROP 2>/dev/null

    echo "iptables rules removed."
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
