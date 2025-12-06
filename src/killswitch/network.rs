use crate::cli::telemetry::Verbosity;
use anyhow::{bail, Context, Result};
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
use bsd_routing::*;

/// Detect VPN gateway by reading routing table via sysctl
/// This finds the remote VPN server endpoint, not the local peer address
/// Logic based on UGSX flags: `RTF_UP` | `RTF_GATEWAY` | `RTF_STATIC` | `RTF_HOST`/`PRCLONING`
pub fn detect_vpn_peer(verbose: Verbosity) -> Result<String> {
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
            eprintln!("  Netstat method failed, trying ifconfig...");
        }
        detect_vpn_peer_from_ifconfig(verbose)
    })
}

/// Query routing table via sysctl (primary method using syscalls)
fn detect_vpn_gateway_sysctl(verbose: Verbosity) -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        // MIB for sysctl: CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_UP|RTF_GATEWAY|RTF_STATIC
        let mib: [i32; 6] = [
            CTL_NET,
            PF_ROUTE,
            0,
            libc::AF_INET,
            NET_RT_FLAGS,
            RTF_UP | RTF_GATEWAY | RTF_STATIC,
        ];

        // First call: get size
        let mut len: libc::size_t = 0;
        let ret = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as u32,
                ptr::null_mut(),
                &mut len,
                ptr::null(),
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
                mib.as_ptr(),
                mib.len() as u32,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                ptr::null(),
                0,
            )
        };

        if ret != 0 {
            bail!("sysctl failed to read routing table");
        }

        if verbose.is_debug() {
            eprintln!("  Read {} bytes from routing table", len);
        }

        // Parse the routing table messages
        return parse_routing_table(&buf[..len], verbose);
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
        if offset + 2 > data.len() {
            break;
        }
        
        let msglen = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
        
        if msglen == 0 || offset + msglen > data.len() {
            break;
        }

        // Read flags (at offset 12-15 in rt_msghdr)
        if offset + 16 > data.len() {
            offset += msglen;
            continue;
        }

        let flags = i32::from_ne_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);

        // Check if this route matches UGSH or UGSc
        if (flags & UGSH == UGSH) || (flags & UGSC == UGSC) {
            if verbose.is_debug() {
                eprintln!("  Found route with UGSH/UGSc flags: 0x{:x}", flags);
            }

            // Parse sockaddrs to extract gateway
            if let Some(gateway) = extract_gateway_from_msg(&data[offset..offset + msglen], verbose) {
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

    let addrs = i32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]);
    
    // RTA_GATEWAY = 0x2 (second bit)
    const RTA_DST: i32 = 0x1;
    const RTA_GATEWAY: i32 = 0x2;
    
    if addrs & RTA_GATEWAY == 0 {
        return None; // No gateway in this message
    }

    // Find where sockaddrs start (after rt_msghdr)
    // rt_msghdr is typically 92 bytes on macOS
    let mut sa_offset = 92;
    
    if sa_offset >= msg.len() {
        return None;
    }

    // Skip DST sockaddr if present
    if addrs & RTA_DST != 0 {
        if let Some(len) = get_sockaddr_len(&msg[sa_offset..]) {
            sa_offset += align_sockaddr(len);
        } else {
            return None;
        }
    }

    // Now we should be at GATEWAY sockaddr
    if sa_offset >= msg.len() {
        return None;
    }

    extract_ipv4_from_sockaddr(&msg[sa_offset..], verbose)
}

/// Get sockaddr length
#[cfg(target_os = "macos")]
fn get_sockaddr_len(sa: &[u8]) -> Option<usize> {
    if sa.is_empty() {
        return None;
    }
    Some(sa[0] as usize)
}

/// Align sockaddr to 4-byte boundary
#[cfg(target_os = "macos")]
fn align_sockaddr(len: usize) -> usize {
    (len + 3) & !3
}

/// Extract IPv4 address from sockaddr
#[cfg(target_os = "macos")]
fn extract_ipv4_from_sockaddr(sa: &[u8], verbose: Verbosity) -> Option<String> {
    if sa.len() < 2 {
        return None;
    }

    let _sa_len = sa[0] as usize;
    let sa_family = sa[1];

    // AF_INET = 2
    if sa_family != libc::AF_INET as u8 {
        return None;
    }

    // sockaddr_in structure:
    // 0: len (1 byte)
    // 1: family (1 byte)
    // 2-3: port (2 bytes)
    // 4-7: addr (4 bytes)
    
    if sa.len() < 8 {
        return None;
    }

    let addr = Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]);
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

/// Fallback method: detect peer from ifconfig (less reliable)
fn detect_vpn_peer_from_ifconfig(verbose: Verbosity) -> Result<String> {
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
                        eprintln!("  Detected VPN peer from interface: {peer_ip}");
                    }
                    return Ok(peer_ip);
                }
            }
        }
    }

    bail!("Could not detect VPN gateway. Please specify it manually with --ipv4")
}

/// Extract gateway IP from netstat routing table line
/// Format: "Destination  Gateway  Flags  Refs  Use  Netif Expire"
fn extract_gateway(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    
    // netstat output format:
    // [0]=Destination [1]=Gateway [2]=Flags [3]=Refs [4]=Use [5]=Netif [6]=Expire
    let gateway = parts.get(1)?;
    
    // Validate it's an IP address
    if gateway.parse::<IpAddr>().is_ok() {
        Some((*gateway).to_string())
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

    // This is a public IP - likely VPN gateway
    true
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
        // Typical netstat line
        let line = "52.1.2.3   10.8.0.1   UGSH   1   0   utun0";
        assert_eq!(extract_gateway(line), Some("10.8.0.1".to_string()));
        
        let line2 = "default   192.168.1.1   UGSc   2   0   en0";
        assert_eq!(extract_gateway(line2), Some("192.168.1.1".to_string()));
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
        assert_eq!(
            extract_peer_address(line),
            Some("10.8.0.1".to_string())
        );
    }

    #[test]
    fn test_extract_peer_address_peer() {
        let line = "\tinet 192.168.1.2 peer 192.168.1.1 netmask 0xffffff00";
        assert_eq!(
            extract_peer_address(line),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_peer_address_none() {
        let line = "\tinet 192.168.1.2 netmask 0xffffff00";
        assert_eq!(extract_peer_address(line), None);
    }
}
