use crate::cli::verbosity::Verbosity;
use anyhow::{Context, Result, anyhow, bail};
use std::net::IpAddr;
use std::process::Command;

#[cfg(target_os = "macos")]
use std::{net::Ipv4Addr, ptr};

#[cfg(target_os = "macos")]
mod bsd_routing {
    // BSD routing constants
    pub const RTF_UP: i32 = 0x1;
    pub const RTF_GATEWAY: i32 = 0x2;
    pub const RTF_HOST: i32 = 0x4;
    pub const RTF_STATIC: i32 = 0x800;
    pub const RTF_PRCLONING: i32 = 0x10000;

    pub const CTL_NET: i32 = 4;
    pub const NET_RT_FLAGS: i32 = 2;
    pub const PF_ROUTE: i32 = 17;

    // UGSH = Up + Gateway + Static + Host
    pub const UGSH: i32 = RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_HOST;
    // UGSc = Up + Gateway + Static + Cloning
    pub const UGSC: i32 = RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_PRCLONING;
}

#[cfg(target_os = "macos")]
use bsd_routing::{CTL_NET, NET_RT_FLAGS, PF_ROUTE, RTF_GATEWAY, RTF_STATIC, RTF_UP, UGSC, UGSH};

/// Detect the VPN server's public IP address (the remote gateway endpoint).
/// This is the IP that firewall rules must allow traffic to in order to keep the tunnel alive.
/// Not to be confused with the local tunnel peer address (e.g. `10.8.0.1`).
pub fn detect_vpn_gateway(verbose: Verbosity) -> Result<String> {
    if verbose.is_debug() {
        eprintln!("  Querying routing table via sysctl...");
    }

    // Try sysctl method first (direct kernel access)
    match detect_vpn_gateway_sysctl(verbose) {
        Ok(gateway) => {
            if verbose.is_verbose() {
                eprintln!("  Detected VPN gateway: {gateway}");
            }
            return Ok(gateway);
        }
        Err(e) => {
            if verbose.is_debug() {
                eprintln!("  Sysctl method failed: {e}");
                eprintln!("  Falling back to netstat...");
            }
        }
    }

    // Fallback to netstat parsing
    detect_vpn_gateway_netstat(verbose).or_else(|_| {
        if verbose.is_debug() {
            eprintln!("  Netstat method failed, trying scutil...");
        }
        // Fallback to macOS Network Extension (scutil) - works for WireGuard/NE-based VPNs
        detect_vpn_gateway_scutil(verbose).or_else(|_| {
            if verbose.is_debug() {
                eprintln!("  Scutil method failed, trying ifconfig...");
            }
            detect_vpn_gateway_from_ifconfig(verbose)
        })
    })
}

/// Query routing table via sysctl (primary method using syscalls)
fn detect_vpn_gateway_sysctl(verbose: Verbosity) -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        // MIB for sysctl: CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_UP|RTF_GATEWAY|RTF_STATIC
        let mut mib: [i32; 6] = [
            CTL_NET,
            PF_ROUTE,
            0,
            libc::AF_INET,
            NET_RT_FLAGS,
            RTF_UP | RTF_GATEWAY | RTF_STATIC,
        ];

        let mib_len: u32 = mib
            .len()
            .try_into()
            .map_err(|_| anyhow!("mib length does not fit into u32"))?;

        // First call: get size
        let mut len: libc::size_t = 0;
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib_len,
                ptr::null_mut(),
                &raw mut len,
                ptr::null_mut(),
                0,
            )
        };

        if ret != 0 {
            bail!("sysctl failed to get routing table size");
        }

        if len == 0 {
            bail!("No routing table entries");
        }

        // Allocate buffer
        let mut buf = vec![0u8; len];

        // Second call: read data
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib_len,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                &raw mut len,
                ptr::null_mut(),
                0,
            )
        };

        if ret != 0 {
            bail!("sysctl failed to read routing table");
        }

        if verbose.is_debug() {
            eprintln!("  Read {len} bytes from routing table");
        }

        // Parse the routing table messages
        let data = buf
            .get(..len)
            .context("sysctl returned a length larger than the buffer")?;
        parse_routing_table(data, verbose)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = verbose;
        bail!("sysctl routing table only supported on macOS")
    }
}

/// Parse BSD routing table from sysctl
#[cfg(target_os = "macos")]
#[allow(clippy::cast_ptr_alignment)] // We're carefully handling alignment
fn parse_routing_table(data: &[u8], verbose: Verbosity) -> Result<String> {
    let mut offset = 0;

    while offset + 4 <= data.len() {
        // Read message length (first 2 bytes)
        let Some(msglen_bytes) = data.get(offset..offset + 2) else {
            break;
        };
        let Ok(msglen_bytes) = <[u8; 2]>::try_from(msglen_bytes) else {
            break;
        };
        let msglen = u16::from_ne_bytes(msglen_bytes) as usize;

        if msglen == 0 || offset + msglen > data.len() {
            break;
        }

        // Read flags (at offset 12-15 in rt_msghdr)
        let Some(flags_bytes) = data.get(offset + 12..offset + 16) else {
            offset += msglen;
            continue;
        };
        let Ok(flags_bytes) = <[u8; 4]>::try_from(flags_bytes) else {
            offset += msglen;
            continue;
        };
        let flags = i32::from_ne_bytes(flags_bytes);

        // Check if this route matches UGSH or UGSc
        if (flags & UGSH == UGSH) || (flags & UGSC == UGSC) {
            if verbose.is_debug() {
                eprintln!("  Found route with UGSH/UGSc flags: 0x{flags:x}");
            }

            // Parse sockaddrs to extract gateway
            if let Some(msg) = data.get(offset..offset + msglen)
                && let Some(gateway) = extract_gateway_from_msg(msg, verbose)
            {
                if is_vpn_gateway(&gateway) {
                    return Ok(gateway);
                } else if verbose.is_debug() {
                    eprintln!("  Skipping non-public gateway: {gateway}");
                }
            }
        }

        offset += msglen;
    }

    bail!("No VPN gateway found in routing table")
}

/// Extract gateway IP from routing message
#[cfg(target_os = "macos")]
fn extract_gateway_from_msg(msg: &[u8], verbose: Verbosity) -> Option<String> {
    // RTA_* flags
    const RTA_DST: i32 = 0x1;

    // rt_msghdr structure:
    // 0-1: msglen
    // 2: version
    // 3: type
    // 4-5: index
    // 6-7: _pad
    // 8-11: addrs (bitmask of which sockaddrs are present)
    // 12-15: flags
    // ... more fields ...
    // Followed by sockaddrs

    if msg.len() < 20 {
        return None;
    }

    let addrs_bytes = msg.get(8..12)?;
    let addrs = i32::from_ne_bytes(<[u8; 4]>::try_from(addrs_bytes).ok()?);

    if addrs & RTA_DST == 0 {
        return None; // No destination in this message
    }

    // Find where sockaddrs start (after rt_msghdr)
    // rt_msghdr is typically 92 bytes on macOS
    let sa_offset = 92;

    if sa_offset >= msg.len() {
        return None;
    }

    // DST is the first sockaddr when present
    let sa = msg.get(sa_offset..)?;
    extract_ipv4_from_sockaddr(sa, verbose)
}

/// Extract IPv4 address from sockaddr
#[cfg(target_os = "macos")]
fn extract_ipv4_from_sockaddr(sa: &[u8], verbose: Verbosity) -> Option<String> {
    let sa_len = sa.first().copied().map(|len| len as usize)?;
    let sa_family = sa.get(1).copied()?;

    // AF_INET = 2
    let af_inet_u8 = u8::try_from(libc::AF_INET).ok()?;
    if sa_family != af_inet_u8 {
        return None;
    }

    // sockaddr_in structure:
    // 0: len (1 byte)
    // 1: family (1 byte)
    // 2-3: port (2 bytes)
    // 4-7: addr (4 bytes)

    if sa_len < 8 || sa.len() < 8 {
        return None;
    }

    let bytes = <[u8; 4]>::try_from(sa.get(4..8)?).ok()?;
    let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let ip_str = addr.to_string();

    if verbose.is_debug() {
        eprintln!("  Extracted IP from sockaddr: {ip_str}");
    }

    Some(ip_str)
}

/// Parse netstat output (primary working method)
fn detect_vpn_gateway_netstat(verbose: Verbosity) -> Result<String> {
    let output = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .context("Failed to execute netstat")?;

    if !output.status.success() {
        bail!("netstat command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for routes with UGSH or UGSc flags
    for line in stdout.lines() {
        if (line.contains("UGSH") || line.contains("UGSc"))
            && let Some(gateway) = extract_gateway(line)
        {
            if is_vpn_gateway(&gateway) {
                if verbose.is_verbose() {
                    eprintln!("  Detected VPN gateway via netstat: {gateway}");
                }
                return Ok(gateway);
            } else if verbose.is_debug() {
                eprintln!("  Skipping non-VPN route: {gateway}");
            }
        }
    }

    bail!("No VPN gateway found")
}

/// Detect VPN gateway via macOS Network Extension (scutil).
/// Works for `WireGuard` and other NE-based VPNs that don't create UGSH/UGSc routes.
/// Parses `scutil --nc list` for connected VPNs, then reads `RemoteAddress` from each.
fn detect_vpn_gateway_scutil(verbose: Verbosity) -> Result<String> {
    let list_output = Command::new("scutil")
        .args(["--nc", "list"])
        .output()
        .context("Failed to execute scutil --nc list")?;

    if !list_output.status.success() {
        bail!("scutil --nc list failed");
    }

    let stdout = String::from_utf8_lossy(&list_output.stdout);

    for line in stdout.lines() {
        if !line.contains("(Connected)") {
            continue;
        }

        // Extract UUID: "* (Connected)      <UUID> VPN ..."
        let uuid = line
            .split_whitespace()
            .nth(2)
            .context("Failed to parse VPN service UUID")?;

        if verbose.is_debug() {
            eprintln!("  Found connected VPN service: {uuid}");
        }

        let show_output = Command::new("scutil")
            .args(["--nc", "show", uuid])
            .output()
            .context("Failed to execute scutil --nc show")?;

        if !show_output.status.success() {
            continue;
        }

        let detail = String::from_utf8_lossy(&show_output.stdout);

        // Look for "RemoteAddress : <ip>"
        for detail_line in detail.lines() {
            let trimmed = detail_line.trim();
            if let Some(ip) = trimmed.strip_prefix("RemoteAddress : ") {
                let ip = ip.trim();
                if is_vpn_gateway(ip) {
                    if verbose.is_verbose() {
                        eprintln!("  Detected VPN gateway via scutil: {ip}");
                    }
                    return Ok(ip.to_string());
                } else if verbose.is_debug() {
                    eprintln!("  Skipping non-public RemoteAddress: {ip}");
                }
            }
        }
    }

    bail!("No VPN gateway found via scutil")
}

/// Last-resort fallback: extract peer address from VPN interfaces via ifconfig.
/// WARNING: This returns the local tunnel peer (e.g. `10.8.0.1`), NOT the server's
/// public IP. Firewall rules using this address may not keep the VPN tunnel alive.
fn detect_vpn_gateway_from_ifconfig(verbose: Verbosity) -> Result<String> {
    let output = Command::new("ifconfig")
        .output()
        .context("Failed to execute ifconfig")?;

    if !output.status.success() {
        bail!("ifconfig command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for common VPN interface patterns
    for line in stdout.lines() {
        if line.starts_with("utun") || line.starts_with("tun") || line.starts_with("ppp") {
            if verbose.is_debug() {
                eprintln!("  Found VPN interface: {}", line.trim());
            }

            let interface_block = stdout
                .split('\n')
                .skip_while(|l| !l.starts_with(line))
                .take_while(|l| !l.is_empty() && (l.starts_with('\t') || l.starts_with(line)))
                .collect::<Vec<_>>()
                .join("\n");

            for detail_line in interface_block.lines() {
                if let Some(peer_ip) = extract_peer_address(detail_line) {
                    if verbose.is_verbose() {
                        eprintln!("  WARNING: falling back to local tunnel peer: {peer_ip}");
                    }
                    return Ok(peer_ip);
                }
            }
        }
    }

    bail!("Could not detect VPN gateway. Please specify it manually with --ipv4")
}

/// Extract destination IP from netstat routing table line
/// Format: "Destination  Gateway  Flags  Netif Expire"
/// For UGSH routes, the destination IS the VPN server's public IP.
fn extract_gateway(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    // netstat output format:
    // [0]=Destination [1]=Gateway [2]=Flags [3]=Netif [4]=Expire
    let destination = parts.first()?;

    // Validate it's an IP address
    if destination.parse::<IpAddr>().is_ok() {
        Some((*destination).to_string())
    } else {
        None
    }
}

/// Check if IP is a valid VPN gateway (public, non-special IP)
fn is_vpn_gateway(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };

    let IpAddr::V4(ipv4) = addr else {
        return false; // Only IPv4 for now
    };

    let octets = ipv4.octets();

    // Skip special addresses
    if ip == "0.0.0.0" || ip == "128.0.0.0" {
        return false;
    }

    // Skip private IP ranges (RFC 1918)
    // 10.0.0.0/8
    if octets[0] == 10 {
        return false;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return false;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return false;
    }

    // Skip localhost
    if octets[0] == 127 {
        return false;
    }

    // Skip link-local (169.254.0.0/16)
    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }

    // Skip broadcast
    if octets == [255, 255, 255, 255] {
        return false;
    }

    // Skip multicast (224.0.0.0/4)
    if octets[0] >= 224 {
        return false;
    }

    // This is a public IP - likely VPN gateway
    true
}

fn hex_to_cidr(hex: &str) -> Option<u8> {
    let hex = hex.strip_prefix("0x")?;
    let value = u32::from_str_radix(hex, 16).ok()?;
    u8::try_from(value.count_ones()).ok()
}

/// Get the public IP address by querying an external HTTP service
pub fn get_public_ip() -> Result<String> {
    for url in ["https://trackip.net/ip", "https://checkip.amazonaws.com"] {
        if let Ok(output) = Command::new("curl").args(["-s", "-m", "5", url]).output()
            && output.status.success()
        {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if ip.parse::<IpAddr>().is_ok() {
                return Ok(ip);
            }
        }
    }
    bail!("Failed to detect public IP")
}

/// Represents a detected network interface
pub struct InterfaceInfo {
    pub name: String,
    pub mac: String,
    pub ip: String,
    pub is_p2p: bool,
}

/// Discover active network interfaces (up, non-loopback, IPv4).
/// Returns regular interfaces and point-to-point (VPN) interfaces.
pub fn get_interfaces() -> Result<Vec<InterfaceInfo>> {
    let output = Command::new("ifconfig")
        .output()
        .context("Failed to execute ifconfig")?;

    if !output.status.success() {
        bail!("ifconfig command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut interfaces = Vec::new();
    let mut current_name = String::new();
    let mut current_mac = String::new();
    let mut current_is_p2p = false;

    for line in stdout.lines() {
        // New interface block: "en0: flags=8863<UP,...> ..."
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(": flags=") {
            current_name = line.split(':').next().unwrap_or("").to_string();
            current_mac = String::new();
            let flags_part = line;
            let is_up = flags_part.contains("UP");
            let is_loopback = flags_part.contains("LOOPBACK");
            current_is_p2p = flags_part.contains("POINTOPOINT");
            if !is_up || is_loopback {
                current_name.clear();
            }
            continue;
        }

        if current_name.is_empty() {
            continue;
        }

        let trimmed = line.trim();

        // MAC address: "ether aa:bb:cc:dd:ee:ff"
        if let Some(mac) = trimmed.strip_prefix("ether ") {
            current_mac = mac.trim().to_string();
        }

        // IPv4: "inet 192.168.1.100 netmask 0xffffff00 broadcast ..."
        if trimmed.starts_with("inet ") && !trimmed.starts_with("inet6") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(ip) = parts.get(1) {
                // Skip loopback IPs
                if ip.starts_with("127.") {
                    continue;
                }

                let ip_display = if current_is_p2p {
                    (*ip).to_string()
                } else if let Some(mask_pos) = parts.iter().position(|&s| s == "netmask")
                    && let Some(mask_hex) = parts.get(mask_pos + 1)
                    && let Some(cidr) = hex_to_cidr(mask_hex)
                {
                    format!("{ip}/{cidr}")
                } else {
                    (*ip).to_string()
                };

                interfaces.push(InterfaceInfo {
                    name: current_name.clone(),
                    mac: current_mac.clone(),
                    ip: ip_display,
                    is_p2p: current_is_p2p,
                });
            }
        }
    }

    Ok(interfaces)
}

fn extract_peer_address(line: &str) -> Option<String> {
    // Look for "inet" lines with "->" indicating peer address
    // Example: "inet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff"
    if line.contains("inet") && line.contains("-->") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|&s| s == "-->")
            && let Some(peer) = parts.get(pos + 1)
        {
            return Some((*peer).to_string());
        }
    }

    // Alternative format: "inet ... peer ..."
    if line.contains("inet") && line.contains("peer") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|&s| s == "peer")
            && let Some(peer) = parts.get(pos + 1)
        {
            return Some((*peer).to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_gateway() {
        // UGSH route: destination is the VPN server's public IP
        let line = "52.1.2.3           192.168.1.1        UGSH              en0";
        assert_eq!(extract_gateway(line), Some("52.1.2.3".to_string()));

        // UGSc route: destination is a network
        let line2 = "203.0.113.50       10.0.0.1           UGSc              en0";
        assert_eq!(extract_gateway(line2), Some("203.0.113.50".to_string()));

        // Non-IP destination (e.g. "default") should return None
        let line3 = "default            192.168.1.1        UGSc              en0";
        assert_eq!(extract_gateway(line3), None);
    }

    #[test]
    fn test_is_vpn_gateway_public() {
        // Public IPs should return true
        assert!(is_vpn_gateway("8.8.8.8"));
        assert!(is_vpn_gateway("1.1.1.1"));
        assert!(is_vpn_gateway("52.1.2.3"));
    }

    #[test]
    fn test_is_vpn_gateway_private() {
        // Private IPs should return false
        assert!(!is_vpn_gateway("10.0.0.1"));
        assert!(!is_vpn_gateway("172.16.0.1"));
        assert!(!is_vpn_gateway("192.168.1.1"));
        assert!(!is_vpn_gateway("127.0.0.1"));
        assert!(!is_vpn_gateway("169.254.1.1"));
    }

    #[test]
    fn test_is_vpn_gateway_special() {
        // Special addresses should return false
        assert!(!is_vpn_gateway("0.0.0.0"));
        assert!(!is_vpn_gateway("128.0.0.0"));
    }

    #[test]
    fn test_extract_peer_address_arrow() {
        let line = "\tinet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff";
        assert_eq!(extract_peer_address(line), Some("10.8.0.1".to_string()));
    }

    #[test]
    fn test_extract_peer_address_peer() {
        let line = "\tinet 192.168.1.2 peer 192.168.1.1 netmask 0xffffff00";
        assert_eq!(extract_peer_address(line), Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_extract_peer_address_none() {
        let line = "\tinet 192.168.1.2 netmask 0xffffff00";
        assert_eq!(extract_peer_address(line), None);
    }

    #[test]
    fn test_is_vpn_gateway_boundary_private() {
        // 172.16-31.x.x range boundaries
        assert!(!is_vpn_gateway("172.16.0.1"));
        assert!(!is_vpn_gateway("172.31.255.255"));
        assert!(is_vpn_gateway("172.15.255.255"));
        assert!(is_vpn_gateway("172.32.0.1"));
    }

    #[test]
    fn test_is_vpn_gateway_multicast_and_reserved() {
        // Multicast and reserved should not be VPN gateways
        assert!(!is_vpn_gateway("0.0.0.0"));
        assert!(!is_vpn_gateway("128.0.0.0"));
        assert!(!is_vpn_gateway("255.255.255.255"));
    }

    #[test]
    fn test_is_vpn_gateway_ipv6_rejected() {
        assert!(!is_vpn_gateway("::1"));
        assert!(!is_vpn_gateway("2001:db8::1"));
    }

    #[test]
    fn test_is_vpn_gateway_invalid_input() {
        assert!(!is_vpn_gateway("not-an-ip"));
        assert!(!is_vpn_gateway(""));
    }

    #[test]
    fn test_extract_gateway_destination_column() {
        // Verify we read column 0 (destination), not column 1 (gateway)
        let line = "8.8.8.8            192.168.1.1        UGSH              en0";
        assert_eq!(extract_gateway(line), Some("8.8.8.8".to_string()));
    }

    #[test]
    fn test_hex_to_cidr_network() {
        assert_eq!(hex_to_cidr("0xffffff00"), Some(24));
        assert_eq!(hex_to_cidr("0xffff0000"), Some(16));
        assert_eq!(hex_to_cidr("0xff000000"), Some(8));
        assert_eq!(hex_to_cidr("0xffffffff"), Some(32));
        assert_eq!(hex_to_cidr("invalid"), None);
    }
}
