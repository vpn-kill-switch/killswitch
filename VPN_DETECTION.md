# VPN Detection Logic

## Critical Implementation Detail

The killswitch needs to detect the **VPN gateway's public IP address** (the remote VPN server), not the local VPN interface peer address. This is crucial for the firewall rules to work correctly.

## Why This Matters

### Wrong Approach ❌
```
Finding local VPN peer from ifconfig:
utun0: inet 10.8.0.2 --> 10.8.0.1

Using 10.8.0.1 in firewall rules
```

**Problem:** `10.8.0.1` is a local address, not the actual VPN server endpoint. Firewall rules allowing traffic to this address won't keep the VPN tunnel alive.

### Correct Approach ✅
```
Finding VPN gateway from routing table:
52.1.2.3  10.8.0.1  UGSH  1  0  utun0

Using 52.1.2.3 in firewall rules
```

**Solution:** `52.1.2.3` is the public IP of the VPN server. Allowing traffic to this address maintains the VPN connection.

## Implementation

### Method 1: Routing Table (Primary)

Examines `netstat -rn` output for routes with special flags:

**UGSH Flags:**
- `U` = Up
- `G` = Gateway  
- `S` = Static
- `H` = Host

**UGSc Flags:**
- `U` = Up
- `G` = Gateway
- `S` = Static  
- `c` = Cloning/Prcloning

These flags indicate static host routes typically created for VPN connections.

```rust
pub fn detect_vpn_peer(verbose: Verbosity) -> Result<String> {
    // Run: netstat -rn -f inet
    let output = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()?;

    // Look for UGSH or UGSc routes
    for line in stdout.lines() {
        if (line.contains("UGSH") || line.contains("UGSc"))
            && let Some(gateway) = extract_gateway(line)
        {
            // Validate it's a public IP (not private/special)
            if is_vpn_gateway(&gateway) {
                return Ok(gateway);
            }
        }
    }
    
    // Fallback to ifconfig method
    detect_vpn_peer_from_ifconfig(verbose)
}
```

### Method 2: Interface Inspection (Fallback)

If routing table doesn't reveal the gateway, fall back to inspecting VPN interfaces:

```rust
fn detect_vpn_peer_from_ifconfig(verbose: Verbosity) -> Result<String> {
    // Look for utun, tun, ppp interfaces
    // Extract peer address from "inet X --> Y" or "inet X peer Y"
}
```

This is less reliable because it finds the local peer, not the remote gateway.

## Validation Logic

### Public IP Detection

The gateway must be a **public IPv4 address**. We reject:

1. **Private ranges (RFC 1918):**
   - `10.0.0.0/8`
   - `172.16.0.0/12`
   - `192.168.0.0/16`

2. **Special addresses:**
   - `0.0.0.0` (default route)
   - `127.0.0.0/8` (localhost)
   - `169.254.0.0/16` (link-local)
   - `128.0.0.0` (special)

3. **IPv6 addresses** (for now)

```rust
fn is_vpn_gateway(ip: &str) -> bool {
    let Ok(IpAddr::V4(ipv4)) = ip.parse() else {
        return false;
    };

    let octets = ipv4.octets();
    
    // Check against private/special ranges
    // Return true only for public IPs
}
```

## Example netstat Output

```
Routing tables

Internet:
Destination      Gateway            Flags  Refs  Use   Netif Expire
default          192.168.1.1        UGSc   0     0     en0
10.8.0.1/32      10.8.0.1           UH     0     0     utun0
52.1.2.3/32      192.168.1.1        UGSH   1     0     en0      <-- VPN gateway!
127.0.0.1        127.0.0.1          UH     0     0     lo0
192.168.1.0/24   link#4             UCS    0     0     en0
```

The **UGSH route to 52.1.2.3** is what we're looking for!

## Comparison with Go Implementation

Our Rust implementation follows the same logic as the original Go version:

### Go (ugsx.go)
```go
const (
    UGSH = syscall.RTF_UP | syscall.RTF_GATEWAY | syscall.RTF_STATIC | syscall.RTF_HOST
    UGSc = syscall.RTF_UP | syscall.RTF_GATEWAY | syscall.RTF_STATIC | syscall.RTF_PRCLONING
)

func UGSX() (net.IP, error) {
    // Fetch routing table via syscall
    // Parse routes looking for UGSH/UGSc flags
    // Filter out private IPs
    // Return first public IP found
}
```

### Rust (network.rs)
```rust
pub fn detect_vpn_peer(verbose: Verbosity) -> Result<String> {
    // Run netstat command
    // Parse text output for "UGSH" or "UGSc" flags
    // Extract gateway IP
    // Validate it's public via is_vpn_gateway()
    // Return gateway or fall back to ifconfig
}
```

**Key Difference:** 
- Go uses syscalls to directly read routing table
- Rust parses `netstat` command output

Both achieve the same result: finding the public VPN gateway IP.

## Testing

### Unit Tests

```rust
#[test]
fn test_is_vpn_gateway_public() {
    assert!(is_vpn_gateway("8.8.8.8"));      // Google DNS
    assert!(is_vpn_gateway("52.1.2.3"));     // AWS IP
}

#[test]
fn test_is_vpn_gateway_private() {
    assert!(!is_vpn_gateway("10.0.0.1"));    // Private
    assert!(!is_vpn_gateway("192.168.1.1")); // Private
}

#[test]
fn test_extract_gateway() {
    let line = "52.1.2.3   10.8.0.1   UGSH   1   0   utun0";
    assert_eq!(extract_gateway(line), Some("10.8.0.1".to_string()));
}
```

### Manual Testing

```bash
# With actual VPN connected:
sudo killswitch --enable -vv

# Expected output:
#   Scanning routing table for VPN gateway...
#   Detected VPN gateway: 52.1.2.3
#   Generating firewall rules...
#   ✓ VPN kill switch enabled

# Verify rules:
sudo pfctl -s rules -a killswitch
# Should show: pass out quick to 52.1.2.3
```

## Debugging

If auto-detection fails:

```bash
# Check routing table manually:
netstat -rn -f inet | grep -E "UGSH|UGSc"

# Look for routes to public IPs
# Common VPN providers use AWS, Google Cloud, etc.

# Override with manual IP:
sudo killswitch --enable --ipv4 52.1.2.3
```

## Edge Cases

### Multiple VPNs
If multiple VPN connections exist, we return the **first public gateway** found. This may not always be correct.

**Solution:** Use `--ipv4` to specify which VPN.

### Split Tunneling
Some VPNs don't create UGSH routes. In this case:
- Routing table method fails
- Falls back to ifconfig (may get wrong address)
- User must specify with `--ipv4`

### IPv6 VPNs
Currently only IPv4 is supported. IPv6 VPNs will:
- Be skipped by `is_vpn_gateway()`
- Fall back to ifconfig
- May fail

**Future:** Add IPv6 support in `is_vpn_gateway()`.

## Future Improvements

1. **Direct Syscalls:** Use libc to read routing table directly (like Go)
2. **IPv6 Support:** Detect IPv6 VPN gateways
3. **Multiple Gateways:** Handle multiple simultaneous VPNs
4. **Provider Detection:** Identify common VPN providers
5. **Caching:** Cache detected gateway between operations

## References

- Go implementation: `ugsx.go` in original killswitch
- macOS routing flags: `man netstat`, `man route`
- RFC 1918: Private Address Space
- OpenVPN routing: Creates UGSH routes for server IP
- WireGuard: May use different routing strategy
