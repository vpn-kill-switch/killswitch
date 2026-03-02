//! Network detection utilities for VPN kill switch.
//!
//! This module provides functions to detect:
//! - VPN peer IP (the remote server's public IP address)
//! - Active network interfaces
//! - Public IP address

use crate::cli::verbosity::Verbosity;
use crate::killswitch::is_private_ip;
use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::process::Command;

// ============================================================================
// VPN Peer IP Detection
// ============================================================================

/// Detect the VPN server's public IP address (the remote peer endpoint).
///
/// This is the IP that firewall rules must allow traffic to in order to keep
/// the VPN tunnel alive. Not to be confused with:
/// - Local tunnel IP (e.g., `10.8.0.2`) - your address inside the tunnel
/// - Tunnel gateway (e.g., `10.8.0.1`) - the server's address inside the tunnel
///
/// Detection methods tried in order:
/// 1. netstat - Parse routing table for UGSH/UGSc routes (most reliable)
/// 2. `WireGuard` - Query `wg show` for endpoint IPs
/// 3. Tailscale - Query `tailscale status` for exit node
/// 4. scutil - Query macOS Network Extension VPN services
///
/// # Errors
/// Returns an error if no VPN peer IP can be detected.
pub fn detect_vpn_peer(verbose: Verbosity) -> Result<String> {
    // Method 1: netstat routing table (most reliable for traditional VPNs)
    if verbose.is_debug() {
        eprintln!("  Trying netstat routing table...");
    }
    if let Ok(peer) = detect_peer_from_netstat(verbose) {
        return Ok(peer);
    }

    // Method 2: WireGuard
    if verbose.is_debug() {
        eprintln!("  Trying WireGuard (wg show)...");
    }
    if let Ok(peer) = detect_peer_from_wireguard(verbose) {
        return Ok(peer);
    }

    // Method 3: Tailscale
    if verbose.is_debug() {
        eprintln!("  Trying Tailscale...");
    }
    if let Ok(peer) = detect_peer_from_tailscale(verbose) {
        return Ok(peer);
    }

    // Method 4: macOS scutil (Network Extension VPNs)
    if verbose.is_debug() {
        eprintln!("  Trying scutil (macOS Network Extension)...");
    }
    if let Ok(peer) = detect_peer_from_scutil(verbose) {
        return Ok(peer);
    }

    bail!("Could not detect VPN peer IP. Please specify it manually with --ipv4")
}

/// Detect VPN peer IP from netstat routing table.
///
/// Looks for routes with UGSH (Up, Gateway, Static, Host) or `UGSc` flags.
/// These routes point directly to the VPN server's public IP.
fn detect_peer_from_netstat(verbose: Verbosity) -> Result<String> {
    let output = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .context("Failed to execute netstat")?;

    if !output.status.success() {
        bail!("netstat command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for routes with UGSH or UGSc flags
    // Format: "Destination  Gateway  Flags  Netif Expire"
    // For UGSH routes, Destination is the VPN server's public IP
    for line in stdout.lines() {
        if !line.contains("UGSH") && !line.contains("UGSc") {
            continue;
        }

        if let Some(peer_ip) = extract_route_destination(line) {
            if is_valid_vpn_peer(&peer_ip) {
                if verbose.is_verbose() {
                    eprintln!("  Detected VPN peer via netstat: {peer_ip}");
                }
                return Ok(peer_ip);
            } else if verbose.is_debug() {
                eprintln!("  Skipping non-public route destination: {peer_ip}");
            }
        }
    }

    bail!("No VPN peer found in routing table")
}

/// Detect VPN peer IP from `WireGuard`.
///
/// Parses `wg show` output for endpoint addresses.
fn detect_peer_from_wireguard(verbose: Verbosity) -> Result<String> {
    let output = Command::new("wg")
        .args(["show"])
        .output()
        .context("Failed to execute wg show")?;

    if !output.status.success() {
        bail!("wg show command failed (WireGuard not installed or no tunnels active)");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for "endpoint: <ip>:<port>" lines
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(endpoint) = trimmed.strip_prefix("endpoint:") {
            let endpoint = endpoint.trim();
            // Extract IP from "IP:port" format
            if let Some(ip) = endpoint.split(':').next()
                && is_valid_vpn_peer(ip)
            {
                if verbose.is_verbose() {
                    eprintln!("  Detected VPN peer via WireGuard: {ip}");
                }
                return Ok(ip.to_string());
            }
        }
    }

    bail!("No WireGuard endpoint found")
}

/// Detect VPN peer IP from Tailscale.
///
/// Queries `tailscale status` for exit node information.
fn detect_peer_from_tailscale(verbose: Verbosity) -> Result<String> {
    // First check if using an exit node
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .context("Failed to execute tailscale status")?;

    if !output.status.success() {
        bail!("tailscale status command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Simple JSON parsing for ExitNodeStatus.Online and TailscaleIPs
    // Looking for exit node's public IP in the DERP relay or direct connection
    if !stdout.contains("\"ExitNodeStatus\"") {
        bail!("No Tailscale exit node active");
    }

    // Try to find the exit node's IP from peer list
    // This is a simplified approach - full JSON parsing would be more robust
    for line in stdout.lines() {
        let trimmed = line.trim();
        // Look for public IPs in the output that could be exit node endpoints
        if trimmed.contains("\"CurAddr\"")
            && let Some(start) = trimmed.find(':')
            && let Some(addr_part) = trimmed.get(start + 1..)
        {
            let addr = addr_part.trim().trim_matches('"').trim_matches(',');
            // Extract IP from "IP:port" format
            if let Some(ip) = addr.split(':').next()
                && is_valid_vpn_peer(ip)
            {
                if verbose.is_verbose() {
                    eprintln!("  Detected VPN peer via Tailscale: {ip}");
                }
                return Ok(ip.to_string());
            }
        }
    }

    bail!("No Tailscale exit node peer found")
}

/// Detect VPN peer IP via macOS Network Extension (scutil).
///
/// Works for VPN apps that use macOS Network Extension framework
/// (e.g., `NordVPN`, `ProtonVPN`, Fortinet).
fn detect_peer_from_scutil(verbose: Verbosity) -> Result<String> {
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
        let Some(uuid) = line.split_whitespace().nth(2) else {
            continue;
        };

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
                if is_valid_vpn_peer(ip) {
                    if verbose.is_verbose() {
                        eprintln!("  Detected VPN peer via scutil: {ip}");
                    }
                    return Ok(ip.to_string());
                } else if verbose.is_debug() {
                    eprintln!("  Skipping non-public RemoteAddress: {ip}");
                }
            }
        }
    }

    bail!("No VPN peer found via scutil")
}

/// Extract destination IP from netstat routing table line.
///
/// Format: "Destination  Gateway  Flags  Netif Expire"
/// For UGSH/UGSc routes, the Destination column contains the VPN server's public IP.
fn extract_route_destination(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let destination = parts.first()?;

    // Validate it's an IP address (not "default" or a network name)
    if destination.parse::<IpAddr>().is_ok() {
        Some((*destination).to_string())
    } else {
        None
    }
}

/// Check if an IP is a valid VPN peer (public, routable IPv4 address).
fn is_valid_vpn_peer(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };

    let IpAddr::V4(ipv4) = addr else {
        return false; // Only IPv4 supported for now
    };

    let octets = ipv4.octets();

    // Reject special addresses used by VPN routing tricks
    if ip == "0.0.0.0" || ip == "128.0.0.0" {
        return false;
    }

    // Reject private/reserved ranges
    if is_private_ip(&ipv4) {
        return false;
    }

    // Reject broadcast
    if octets == [255, 255, 255, 255] {
        return false;
    }

    // Reject multicast (224.0.0.0/4) and reserved (240.0.0.0/4)
    if octets[0] >= 224 {
        return false;
    }

    true
}

// ============================================================================
// Network Interface Detection
// ============================================================================

/// Represents a detected network interface.
pub struct InterfaceInfo {
    name: String,
    mac: String,
    ip: String,
    is_p2p: bool,
}

impl InterfaceInfo {
    /// Get the interface name (e.g., "en0", "utun0").
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the MAC address (empty for virtual interfaces).
    #[must_use]
    pub fn mac(&self) -> &str {
        &self.mac
    }

    /// Get the IP address (may include CIDR notation for non-P2P interfaces).
    #[must_use]
    pub fn ip(&self) -> &str {
        &self.ip
    }

    /// Check if this is a point-to-point (VPN) interface.
    #[must_use]
    pub fn is_p2p(&self) -> bool {
        self.is_p2p
    }
}

/// Discover active network interfaces (up, non-loopback, IPv4).
///
/// Returns both regular interfaces and point-to-point (VPN) interfaces.
///
/// # Errors
/// Returns an error if ifconfig fails to execute.
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

            let is_up = line.contains("UP");
            let is_loopback = line.contains("LOOPBACK");
            current_is_p2p = line.contains("POINTOPOINT");

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

// ============================================================================
// Public IP Detection
// ============================================================================

/// Get the public IP address by querying external HTTP services.
///
/// Tries multiple services with a 5-second timeout each.
///
/// # Errors
/// Returns an error if all services fail or return invalid responses.
pub fn get_public_ip() -> Result<String> {
    const SERVICES: &[&str] = &[
        "https://ifconfig.me/ip",
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
    ];

    for url in SERVICES {
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

// ============================================================================
// Utilities
// ============================================================================

/// Convert a hex netmask (e.g., "0xffffff00") to CIDR notation (e.g., 24).
#[must_use]
pub fn hex_to_cidr(hex: &str) -> Option<u8> {
    let hex = hex.strip_prefix("0x")?;
    let value = u32::from_str_radix(hex, 16).ok()?;
    u8::try_from(value.count_ones()).ok()
}

// ============================================================================
// Legacy Compatibility
// ============================================================================

/// Alias for `detect_vpn_peer` to maintain backward compatibility.
///
/// # Errors
/// Returns an error if no VPN peer IP can be detected.
pub fn detect_vpn_gateway(verbose: Verbosity) -> Result<String> {
    detect_vpn_peer(verbose)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Route destination extraction tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_route_destination_ugsh() {
        let line = "52.1.2.3           192.168.1.1        UGSH              en0";
        assert_eq!(
            extract_route_destination(line),
            Some("52.1.2.3".to_string())
        );
    }

    #[test]
    fn test_extract_route_destination_ugsc() {
        let line = "203.0.113.50       10.0.0.1           UGSc              en0";
        assert_eq!(
            extract_route_destination(line),
            Some("203.0.113.50".to_string())
        );
    }

    #[test]
    fn test_extract_route_destination_default_returns_none() {
        let line = "default            192.168.1.1        UGSc              en0";
        assert_eq!(extract_route_destination(line), None);
    }

    #[test]
    fn test_extract_route_destination_reads_first_column() {
        // Verify we read column 0 (destination), not column 1 (gateway)
        let line = "8.8.8.8            192.168.1.1        UGSH              en0";
        assert_eq!(extract_route_destination(line), Some("8.8.8.8".to_string()));
    }

    // -------------------------------------------------------------------------
    // VPN peer validation tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_valid_vpn_peer_public_ips() {
        assert!(is_valid_vpn_peer("8.8.8.8"));
        assert!(is_valid_vpn_peer("1.1.1.1"));
        assert!(is_valid_vpn_peer("52.1.2.3"));
        assert!(is_valid_vpn_peer("203.0.113.50"));
    }

    #[test]
    fn test_is_valid_vpn_peer_rejects_private() {
        assert!(!is_valid_vpn_peer("10.0.0.1"));
        assert!(!is_valid_vpn_peer("10.8.0.1")); // Common OpenVPN tunnel
        assert!(!is_valid_vpn_peer("172.16.0.1"));
        assert!(!is_valid_vpn_peer("192.168.1.1"));
        assert!(!is_valid_vpn_peer("127.0.0.1"));
        assert!(!is_valid_vpn_peer("169.254.1.1"));
    }

    #[test]
    fn test_is_valid_vpn_peer_rejects_special() {
        assert!(!is_valid_vpn_peer("0.0.0.0"));
        assert!(!is_valid_vpn_peer("128.0.0.0")); // VPN routing trick
        assert!(!is_valid_vpn_peer("255.255.255.255"));
    }

    #[test]
    fn test_is_valid_vpn_peer_rejects_multicast() {
        assert!(!is_valid_vpn_peer("224.0.0.1"));
        assert!(!is_valid_vpn_peer("239.255.255.255"));
    }

    #[test]
    fn test_is_valid_vpn_peer_boundary_private_ranges() {
        // 172.16-31.x.x range boundaries
        assert!(!is_valid_vpn_peer("172.16.0.1"));
        assert!(!is_valid_vpn_peer("172.31.255.255"));
        assert!(is_valid_vpn_peer("172.15.255.255"));
        assert!(is_valid_vpn_peer("172.32.0.1"));
    }

    #[test]
    fn test_is_valid_vpn_peer_rejects_ipv6() {
        assert!(!is_valid_vpn_peer("::1"));
        assert!(!is_valid_vpn_peer("2001:db8::1"));
    }

    #[test]
    fn test_is_valid_vpn_peer_rejects_invalid() {
        assert!(!is_valid_vpn_peer("not-an-ip"));
        assert!(!is_valid_vpn_peer(""));
        assert!(!is_valid_vpn_peer("256.1.1.1"));
    }

    // -------------------------------------------------------------------------
    // Hex to CIDR conversion tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_hex_to_cidr() {
        assert_eq!(hex_to_cidr("0xffffffff"), Some(32));
        assert_eq!(hex_to_cidr("0xffffff00"), Some(24));
        assert_eq!(hex_to_cidr("0xffff0000"), Some(16));
        assert_eq!(hex_to_cidr("0xff000000"), Some(8));
        assert_eq!(hex_to_cidr("0x00000000"), Some(0));
    }

    #[test]
    fn test_hex_to_cidr_invalid() {
        assert_eq!(hex_to_cidr("invalid"), None);
        assert_eq!(hex_to_cidr("ffffff00"), None); // Missing 0x prefix
        assert_eq!(hex_to_cidr(""), None);
    }
}
