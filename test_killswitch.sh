#!/bin/bash
# Killswitch Interactive Test Script
# Run with: sudo ./test_killswitch.sh

set -e

KILLSWITCH="./target/release/killswitch"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

cleanup() {
    echo ""
    echo -e "${YELLOW}Cleanup: Disabling killswitch...${NC}"
    "$KILLSWITCH" -d 2>/dev/null || true
    echo -e "${GREEN}✓ Killswitch disabled - internet restored${NC}"
}

# Trap to ensure cleanup on exit/error/ctrl+c
trap cleanup EXIT

test_ping() {
    local target=$1
    echo -n "    Ping ($target): " >&2
    if ping -c 1 -W 3 "$target" >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}" >&2
        return 0
    else
        echo -e "${RED}BLOCKED${NC}" >&2
        return 1
    fi
}

test_dns() {
    echo -n "    DNS (nslookup google.com): " >&2
    if nslookup google.com 8.8.8.8 >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}" >&2
        return 0
    else
        echo -e "${RED}BLOCKED${NC}" >&2
        return 1
    fi
}

test_http() {
    echo -n "    HTTP (curl): " >&2
    # Try multiple services
    IP=""
    for url in "https://ifconfig.me/ip" "https://trackip.net/ip"; do
        IP=$(curl -s -m 5 "$url" 2>/dev/null) && [ "$IP" != "" ] && break
    done
    if [ "$IP" != "" ]; then
        echo -e "${GREEN}OK${NC} ${DIM}(IP: $IP)${NC}" >&2
        return 0
    else
        echo -e "${RED}BLOCKED${NC}" >&2
        return 1
    fi
}

run_all_tests() {
    local label=$1
    echo -e "  ${CYAN}$label${NC}" >&2

    local ping_ok=0 dns_ok=0 http_ok=0
    test_ping "8.8.8.8" && ping_ok=1 || true
    test_dns && dns_ok=1 || true
    test_http && http_ok=1 || true

    echo "$ping_ok $dns_ok $http_ok"
}

echo "=============================================="
echo -e "${BOLD}     KILLSWITCH INTERACTIVE TEST${NC}"
echo "=============================================="
echo ""
echo -e "${DIM}Tests: Ping (ICMP), DNS, HTTP${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Please run with sudo${NC}"
    trap - EXIT
    exit 1
fi

# Build if needed
if [ ! -f "$KILLSWITCH" ]; then
    echo "Building release binary..."
    cargo build --release
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo -e "${CYAN}━━━ STEP 1: Pre-flight ━━━${NC}"
echo ""
echo "Checking VPN and peer detection..."
"$KILLSWITCH" -vv 2>&1 | head -20
echo ""

read -p "Is VPN connected and PEER IP shown above? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Please connect VPN and re-run."
    trap - EXIT
    exit 1
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo -e "${CYAN}━━━ STEP 2: Baseline (VPN ON, no killswitch) ━━━${NC}"
echo ""
BASELINE=$(run_all_tests "All traffic should work:")
BASELINE_PING=$(echo "$BASELINE" | cut -d' ' -f1)
BASELINE_DNS=$(echo "$BASELINE" | cut -d' ' -f2)
BASELINE_HTTP=$(echo "$BASELINE" | cut -d' ' -f3)

if [ "$BASELINE_HTTP" -eq 0 ]; then
    echo ""
    echo -e "${RED}ERROR: No HTTP connectivity. Check your VPN.${NC}"
    trap - EXIT
    exit 1
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo -e "${CYAN}━━━ STEP 3: Enable killswitch ━━━${NC}"
"$KILLSWITCH" -e -v
echo -e "${GREEN}✓ Killswitch ENABLED${NC}"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo -e "${CYAN}━━━ STEP 4: Test with VPN ON + killswitch ━━━${NC}"
echo ""
sleep 2
VPN_RESULTS=$(run_all_tests "Traffic through VPN should work:")
VPN_PING=$(echo "$VPN_RESULTS" | cut -d' ' -f1)
VPN_DNS=$(echo "$VPN_RESULTS" | cut -d' ' -f2)
VPN_HTTP=$(echo "$VPN_RESULTS" | cut -d' ' -f3)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo -e "${CYAN}━━━ STEP 5: THE CRITICAL TEST ━━━${NC}"
echo ""
echo -e "${BOLD}${YELLOW}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${YELLOW}║  👉 DISCONNECT YOUR VPN NOW 👈               ║${NC}"
echo -e "${BOLD}${YELLOW}║                                              ║${NC}"
echo -e "${BOLD}${YELLOW}║  Then press ENTER to test if traffic leaks   ║${NC}"
echo -e "${BOLD}${YELLOW}╚══════════════════════════════════════════════╝${NC}"
echo ""
read -p "Press ENTER after disconnecting VPN..."

echo ""
NOVPN_RESULTS=$(run_all_tests "All traffic should be BLOCKED:")
NOVPN_PING=$(echo "$NOVPN_RESULTS" | cut -d' ' -f1)
NOVPN_DNS=$(echo "$NOVPN_RESULTS" | cut -d' ' -f2)
NOVPN_HTTP=$(echo "$NOVPN_RESULTS" | cut -d' ' -f3)

# Check if traffic was blocked
NOVPN_TOTAL=$((NOVPN_PING + NOVPN_DNS + NOVPN_HTTP))
if [ "$NOVPN_TOTAL" -eq 0 ]; then
    echo ""
    echo -e "${GREEN}${BOLD}✓ EXCELLENT! All traffic is BLOCKED without VPN${NC}"
    echo -e "${GREEN}  Killswitch is protecting you!${NC}"
    BLOCK_SUCCESS=1
else
    echo ""
    echo -e "${RED}${BOLD}✗ WARNING: Some traffic LEAKED without VPN!${NC}"
    echo -e "${RED}  Killswitch did NOT fully protect you!${NC}"
    BLOCK_SUCCESS=0
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo -e "${CYAN}━━━ STEP 6: Disable killswitch FIRST ━━━${NC}"
echo ""
echo -e "${DIM}(Must disable before VPN reconnect - new server may have different IP)${NC}"
# Remove trap and disable manually
trap - EXIT
"$KILLSWITCH" -d -v
echo -e "${GREEN}✓ Killswitch DISABLED${NC}"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo -e "${CYAN}━━━ STEP 7: Reconnect VPN ━━━${NC}"
echo ""
echo -e "${YELLOW}👉 RECONNECT YOUR VPN NOW${NC}"
read -p "Press ENTER after reconnecting VPN..."

echo ""
RECONNECT_RESULTS=$(run_all_tests "Traffic should work again:")
RECONNECT_PING=$(echo "$RECONNECT_RESULTS" | cut -d' ' -f1)
RECONNECT_DNS=$(echo "$RECONNECT_RESULTS" | cut -d' ' -f2)
RECONNECT_HTTP=$(echo "$RECONNECT_RESULTS" | cut -d' ' -f3)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo "=============================================="
echo -e "${BOLD}               TEST SUMMARY${NC}"
echo "=============================================="
echo ""
echo -e "  ${BOLD}VPN ON + Killswitch:${NC}"
[ "$VPN_PING" -eq 1 ] && echo -e "    ${GREEN}✓${NC} Ping" || echo -e "    ${RED}✗${NC} Ping"
[ "$VPN_DNS" -eq 1 ] && echo -e "    ${GREEN}✓${NC} DNS" || echo -e "    ${RED}✗${NC} DNS"
[ "$VPN_HTTP" -eq 1 ] && echo -e "    ${GREEN}✓${NC} HTTP" || echo -e "    ${RED}✗${NC} HTTP"
echo ""
echo -e "  ${BOLD}VPN OFF + Killswitch (should be blocked):${NC}"
[ "$NOVPN_PING" -eq 0 ] && echo -e "    ${GREEN}✓${NC} Ping BLOCKED" || echo -e "    ${RED}✗${NC} Ping LEAKED!"
[ "$NOVPN_DNS" -eq 0 ] && echo -e "    ${GREEN}✓${NC} DNS BLOCKED" || echo -e "    ${RED}✗${NC} DNS LEAKED!"
[ "$NOVPN_HTTP" -eq 0 ] && echo -e "    ${GREEN}✓${NC} HTTP BLOCKED" || echo -e "    ${RED}✗${NC} HTTP LEAKED!"
echo ""
echo -e "  ${BOLD}After disable + VPN reconnect:${NC}"
[ "$RECONNECT_HTTP" -eq 1 ] && echo -e "    ${GREEN}✓${NC} Internet restored" || echo -e "    ${YELLOW}⚠${NC} Check manually"
echo ""

# Final verdict
VPN_OK=$((VPN_PING + VPN_DNS + VPN_HTTP))
if [ "$VPN_OK" -ge 2 ] && [ "$BLOCK_SUCCESS" -eq 1 ]; then
    echo -e "${GREEN}══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}   KILLSWITCH IS WORKING CORRECTLY! 🎉${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════${NC}"
else
    echo -e "${RED}══════════════════════════════════════════════${NC}"
    echo -e "${RED}   TEST FAILED - Review results above${NC}"
    echo -e "${RED}══════════════════════════════════════════════${NC}"
fi
echo ""
