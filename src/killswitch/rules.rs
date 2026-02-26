use crate::cli::verbosity::Verbosity;
use crate::killswitch::network;
use anyhow::{Context, Result};
use chrono::Local;
use std::fmt::Write as _;
use std::net::IpAddr;

pub fn generate(vpn_peer: &str, leak: bool, local: bool, verbose: Verbosity) -> Result<String> {
    let vpn_peer_ip: IpAddr = vpn_peer.parse().context("Invalid VPN peer IP address")?;
    let interfaces = network::get_interfaces()?;

    if verbose.is_debug() {
        eprintln!("  VPN gateway: {vpn_peer_ip}");
        eprintln!("  Leak mode: {leak}");
        eprintln!("  Local network: {local}");
    }

    let sep = "-".repeat(62);
    let mut rules = String::new();

    // Header
    writeln!(rules, "# {sep}")?;
    writeln!(
        rules,
        "# {}",
        Local::now().format("%a, %d %b %Y %H:%M:%S %z")
    )?;
    rules.push_str("# sudo pfctl -Fa -f /tmp/killswitch.pf.conf -e\n");
    writeln!(rules, "# {sep}")?;

    // Interface macros
    for iface in &interfaces {
        if iface.is_p2p {
            writeln!(rules, "vpn_{} = \"{}\"", iface.name, iface.name)?;
        } else {
            writeln!(rules, "int_{} = \"{}\"", iface.name, iface.name)?;
        }
    }
    writeln!(rules, "vpn_ip = \"{vpn_peer_ip}\"")?;
    rules.push('\n');

    // Global settings
    rules.push_str("set block-policy drop\n");
    rules.push_str("set ruleset-optimization basic\n");
    rules.push_str("set skip on lo0\n");
    rules.push('\n');

    // Block all
    rules.push_str("block all\n");
    rules.push_str("block out inet6\n");
    rules.push('\n');

    // DNS
    if leak {
        rules.push_str("# dns\n");
        rules.push_str("pass quick proto {tcp, udp} from any to any port 53 keep state\n");
        rules.push('\n');
    }

    // Broadcast
    rules.push_str("# Allow broadcasts on internal interface\n");
    rules.push_str("pass from any to 255.255.255.255 keep state\n");
    rules.push_str("pass from 255.255.255.255 to any keep state\n");
    rules.push('\n');

    // Multicast
    rules.push_str("# Allow multicast\n");
    rules.push_str("pass proto udp from any to 224.0.0.0/4 keep state\n");
    rules.push_str("pass proto udp from 224.0.0.0/4 to any keep state\n");
    rules.push('\n');

    // Per physical interface rules
    for iface in interfaces.iter().filter(|i| !i.is_p2p) {
        if leak {
            writeln!(
                rules,
                "# Allow ping\npass on $int_{} inet proto icmp all icmp-type 8 code 0 keep state",
                iface.name
            )?;
            rules.push('\n');
        }
        writeln!(
            rules,
            "# Allow dhcp\npass on $int_{} proto {{tcp,udp}} from any port 67:68 to any port 67:68 keep state",
            iface.name
        )?;
        rules.push('\n');
        if local {
            writeln!(
                rules,
                "pass from $int_{0}:network to $int_{0}:network",
                iface.name
            )?;
        }
        writeln!(
            rules,
            "# use only the vpn\npass on $int_{} proto {{tcp, udp}} from any to $vpn_ip",
            iface.name
        )?;
    }

    // VPN interface pass-all
    for iface in interfaces.iter().filter(|i| i.is_p2p) {
        writeln!(rules, "pass on $vpn_{} all", iface.name)?;
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_network(line: &str) -> Option<String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let inet_pos = parts.iter().position(|&s| s == "inet")?;
        let ip = parts.get(inet_pos + 1)?;
        let netmask_pos = parts.iter().position(|&s| s == "netmask")?;
        let netmask_hex = parts.get(netmask_pos + 1)?;
        let cidr = hex_to_cidr(netmask_hex)?;
        Some(format!("{ip}/{cidr}"))
    }

    fn hex_to_cidr(hex: &str) -> Option<u8> {
        let hex = hex.strip_prefix("0x")?;
        let value = u32::from_str_radix(hex, 16).ok()?;
        u8::try_from(value.count_ones()).ok()
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_generate_basic() {
        use crate::cli::verbosity::Verbosity;
        let rules = generate("203.0.113.1", false, false, Verbosity::Normal).unwrap();
        assert!(rules.contains("vpn_ip = \"203.0.113.1\""));
        assert!(rules.contains("set block-policy drop"));
        assert!(rules.contains("set skip on lo0"));
        assert!(rules.contains("block all"));
        assert!(rules.contains("block out inet6"));
        assert!(rules.contains("pass from any to 255.255.255.255 keep state"));
        assert!(rules.contains("from any port 67:68 to any port 67:68 keep state"));
        assert!(!rules.contains("icmp-type 8 code 0"));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_generate_with_leak() {
        use crate::cli::verbosity::Verbosity;
        let rules = generate("203.0.113.1", true, false, Verbosity::Normal).unwrap();
        assert!(rules.contains("pass quick proto {tcp, udp} from any to any port 53 keep state"));
        assert!(rules.contains("icmp-type 8 code 0 keep state"));
    }

    #[test]
    fn test_hex_to_cidr() {
        assert_eq!(hex_to_cidr("0xffffff00"), Some(24));
        assert_eq!(hex_to_cidr("0xffff0000"), Some(16));
        assert_eq!(hex_to_cidr("0xffffffff"), Some(32));
    }

    #[test]
    fn test_extract_network() {
        let line = "\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255";
        assert_eq!(extract_network(line), Some("192.168.1.100/24".to_string()));
    }
}
