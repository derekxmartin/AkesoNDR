#!/bin/bash
# =============================================================================
# AkesoNDR — Test Traffic Generator
#
# Generates synthetic network traffic on the shared Docker network so the
# AkesoNDR sensor has packets to capture. Uses basic Linux networking tools
# (no tcpreplay dependency required for the minimal test case).
#
# If a PCAP file exists at /pcaps/test.pcap AND tcpreplay is installed,
# it will replay that PCAP as well.
# =============================================================================

set -euo pipefail

echo "[traffic-gen] Installing networking tools..."
apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    curl dnsutils netcat-openbsd tcpreplay iputils-ping > /dev/null 2>&1
echo "[traffic-gen] Tools installed."

# Give the sensor a moment to start capturing
sleep 3

LOOP_COUNT=${LOOP_COUNT:-0}
LOOP_DELAY=${LOOP_DELAY:-10}
iteration=0

generate_traffic() {
    echo "[traffic-gen] --- Iteration $((iteration + 1)) ---"

    # DNS queries
    echo "[traffic-gen] Generating DNS traffic..."
    dig @8.8.8.8 example.com A +short 2>/dev/null || true
    dig @8.8.8.8 google.com AAAA +short 2>/dev/null || true
    dig @8.8.8.8 github.com MX +short 2>/dev/null || true
    dig @8.8.8.8 cloudflare.com TXT +short 2>/dev/null || true

    # HTTP traffic
    echo "[traffic-gen] Generating HTTP traffic..."
    curl -s -o /dev/null -w "%{http_code}" http://example.com/ 2>/dev/null || true
    curl -s -o /dev/null -w "%{http_code}" http://httpbin.org/get 2>/dev/null || true
    curl -s -o /dev/null -X POST http://httpbin.org/post -d "test=data" 2>/dev/null || true

    # TLS / HTTPS traffic (generates TLS handshake metadata)
    echo "[traffic-gen] Generating TLS traffic..."
    curl -s -o /dev/null https://example.com/ 2>/dev/null || true
    curl -s -o /dev/null https://github.com/ 2>/dev/null || true

    # ICMP ping
    echo "[traffic-gen] Generating ICMP traffic..."
    ping -c 3 -W 2 sensor 2>/dev/null || true

    # TCP connection to sensor (simulates service probing)
    echo "[traffic-gen] Generating TCP connection attempts..."
    echo "HELLO" | nc -w 2 sensor 80 2>/dev/null || true
    echo "HELLO" | nc -w 2 sensor 443 2>/dev/null || true

    # Replay PCAP if available and tcpreplay is installed
    if [ -f /pcaps/test.pcap ] && command -v tcpreplay &>/dev/null; then
        echo "[traffic-gen] Replaying test.pcap..."
        tcpreplay --intf1=eth0 --topspeed /pcaps/test.pcap 2>/dev/null || true
    fi

    echo "[traffic-gen] Traffic generation complete for iteration $((iteration + 1))."
}

# Run at least once
generate_traffic

# If LOOP_COUNT > 0, keep looping (0 = run once and exit)
if [ "$LOOP_COUNT" -gt 0 ]; then
    iteration=1
    while [ "$iteration" -lt "$LOOP_COUNT" ]; do
        sleep "$LOOP_DELAY"
        generate_traffic
        iteration=$((iteration + 1))
    done
elif [ "$LOOP_COUNT" -eq -1 ]; then
    # Infinite loop mode
    while true; do
        sleep "$LOOP_DELAY"
        iteration=$((iteration + 1))
        generate_traffic
    done
fi

echo "[traffic-gen] Done. Exiting."
