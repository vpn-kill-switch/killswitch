#!/bin/bash
# Interactive macOS packet-path test. Build first, then run with sudo.

set -u

KILLSWITCH="./target/release/killswitch"

cleanup() {
    "$KILLSWITCH" -d >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if [[ ${EUID} -ne 0 ]]; then
    echo "Run with sudo: sudo ./test_killswitch.sh"
    exit 1
fi

if [[ ! -x "$KILLSWITCH" ]]; then
    echo "Missing $KILLSWITCH. Run: cargo build --release --locked"
    exit 1
fi

probe() {
    local family=$1
    local url=$2
    curl "$family" --silent --show-error --max-time 10 "$url" 2>/dev/null
}

expect_blocked() {
    local family=$1
    local url=$2
    if value=$(probe "$family" "$url"); then
        echo "FAIL: $family leaked ($value)"
        return 1
    fi
    echo "PASS: $family blocked"
}

echo "Detected path:"
"$KILLSWITCH" -vv

echo
echo "Generated anchor:"
"$KILLSWITCH" --print -vv

echo
echo "Baseline with VPN connected:"
ipv4_before=$(probe -4 https://api.ipify.org) || {
    echo "IPv4 baseline failed; connect the VPN first."
    exit 1
}
echo "IPv4: $ipv4_before"
ipv6_available=0
if ipv6_before=$(probe -6 https://api64.ipify.org); then
    ipv6_available=1
    echo "IPv6: $ipv6_before"
else
    echo "IPv6: unavailable through VPN (acceptable if the VPN has no IPv6)"
fi

echo
"$KILLSWITCH" -e -v || exit 1
sleep 2

ipv4_enabled=$(probe -4 https://api.ipify.org) || {
    echo "FAIL: IPv4 did not work through VPN after enabling."
    exit 1
}
if [[ "$ipv4_enabled" != "$ipv4_before" ]]; then
    echo "WARNING: public IPv4 changed: $ipv4_before -> $ipv4_enabled"
fi
echo "PASS: VPN IPv4 works ($ipv4_enabled)"

if [[ $ipv6_available -eq 1 ]]; then
    ipv6_enabled=$(probe -6 https://api64.ipify.org) || {
        echo "FAIL: VPN provided IPv6 before enable, but IPv6 is blocked after enable."
        exit 1
    }
    echo "PASS: VPN IPv6 works ($ipv6_enabled)"
else
    expect_blocked -6 https://api64.ipify.org || exit 1
fi

echo
echo "PF counters after VPN-on traffic:"
pfctl -a killswitch -vvsr
pfctl -ss

echo
read -r -p "Disconnect AdGuard VPN, then press Enter... "
sleep 3

failed=0
expect_blocked -4 https://api.ipify.org || failed=1
expect_blocked -6 https://api64.ipify.org || failed=1

echo
echo "PF counters after VPN-off probes:"
pfctl -a killswitch -vvsr
pfctl -ss

echo
read -r -p "Reconnect AdGuard VPN (utun may change), then press Enter... "

connected=0
for _ in {1..15}; do
    if "$KILLSWITCH" -vv 2>&1 | grep -q "VPN interface: *utun"; then
        connected=1
        break
    fi
    sleep 2
done

if [[ $connected -eq 0 ]]; then
    echo "FAIL: no active routed utun detected after reconnect."
    failed=1
elif ipv4_reconnected=$(probe -4 https://api.ipify.org); then
    echo "PASS: reconnect works without --ipv4 ($ipv4_reconnected)"
else
    echo "FAIL: IPv4 did not recover after reconnect."
    failed=1
fi

if [[ $connected -eq 1 && $ipv6_available -eq 1 ]]; then
    if ipv6_reconnected=$(probe -6 https://api64.ipify.org); then
        echo "PASS: reconnect IPv6 works ($ipv6_reconnected)"
    else
        echo "FAIL: IPv6 did not recover after reconnect."
        failed=1
    fi
fi

echo
"$KILLSWITCH" -vv
pfctl -a killswitch -vvsr

if [[ $failed -ne 0 ]]; then
    echo "Packet-path test failed. Capture en0 and the detected utun with tcpdump."
    exit 1
fi

echo "All automated checks passed."
