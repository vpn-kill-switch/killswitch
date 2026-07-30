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

show_pf_diagnostics() {
    pfctl -a killswitch -vvsr
    if [[ ${KILLSWITCH_DEBUG_STATES:-0} -eq 1 ]]; then
        pfctl -ss
    fi
}

endpoint_rules() {
    pfctl -a killswitch -sr 2>/dev/null \
        | grep 'label "killswitch-endpoint"' \
        | sort
}

bootstrap_rule_count() {
    pfctl -a killswitch -sr 2>/dev/null \
        | grep -c 'label "killswitch-bootstrap"' || true
}

echo "Detected path:"
"$KILLSWITCH" -vv

echo
echo "Generated anchor:"
"$KILLSWITCH" --print --reconnect -vv

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
"$KILLSWITCH" -e --reconnect -v || exit 1
sleep 2

monitor_count=$(ps ax -o command= | grep -Ec '[k]illswitch[^ ]* --monitor')
if [[ $monitor_count -ne 1 ]]; then
    echo "FAIL: expected exactly one VPN monitor, found $monitor_count."
    exit 1
fi
echo "PASS: exactly one VPN monitor is running"

endpoint_rules_enabled=$(endpoint_rules)
if [[ -z "$endpoint_rules_enabled" ]]; then
    echo "FAIL: no trusted VPN endpoint rule was installed."
    exit 1
fi

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
show_pf_diagnostics

echo
read -r -p "Disconnect AdGuard VPN, then press Enter... "
sleep 3

failed=0
endpoint_rules_disconnected=$(endpoint_rules)
if [[ "$endpoint_rules_disconnected" != "$endpoint_rules_enabled" ]]; then
    echo "FAIL: endpoint allowlist changed while the VPN was disconnected."
    echo "Expected:"
    echo "$endpoint_rules_enabled"
    echo "Actual:"
    echo "$endpoint_rules_disconnected"
    failed=1
else
    echo "PASS: endpoint allowlist remained pinned"
fi

bootstrap_count=$(bootstrap_rule_count)
if [[ $bootstrap_count -gt 8 ]]; then
    echo "FAIL: reconnect bootstrap allowlist exceeded its limit ($bootstrap_count > 8)."
    failed=1
else
    echo "PASS: reconnect bootstrap allowlist is bounded ($bootstrap_count/8)"
fi

expect_blocked -4 https://api.ipify.org || failed=1
expect_blocked -6 https://api64.ipify.org || failed=1

echo
echo "PF counters after VPN-off probes:"
show_pf_diagnostics

echo
read -r -p "Reconnect AdGuard VPN (utun may change), then press Enter... "

reconnected=0
for _ in {1..20}; do
    if ipv4_reconnected=$(probe -4 https://api.ipify.org); then
        reconnected=1
        break
    fi
    sleep 2
done

if [[ $reconnected -eq 0 ]]; then
    echo "FAIL: IPv4 did not recover within 40 seconds after reconnect."
    failed=1
else
    echo "PASS: reconnect works without --ipv4 ($ipv4_reconnected)"
fi

if [[ $reconnected -eq 1 && $ipv6_available -eq 1 ]]; then
    ipv6_reconnected=""
    for _ in {1..10}; do
        if ipv6_reconnected=$(probe -6 https://api64.ipify.org); then
            break
        fi
        sleep 2
    done
    if [[ -z "$ipv6_reconnected" ]]; then
        echo "FAIL: IPv6 did not recover after reconnect."
        failed=1
    else
        echo "PASS: reconnect IPv6 works ($ipv6_reconnected)"
    fi
fi

echo
"$KILLSWITCH" -vv
show_pf_diagnostics

if [[ $failed -ne 0 ]]; then
    echo "Packet-path test failed. Capture en0 and the detected utun with tcpdump."
    exit 1
fi

echo "All automated checks passed."
