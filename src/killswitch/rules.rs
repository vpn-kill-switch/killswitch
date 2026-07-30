use crate::killswitch::network::{VpnEndpoint, VpnInfo};
use anyhow::Result;
use std::fmt::Write as _;
use std::net::IpAddr;

const ALLOWED_TAG: &str = "KILLSWITCH_ALLOWED";

/// Generate rules for the dedicated `killswitch` anchor.
///
/// Every allow rule is explicit and `quick`; the final rule blocks all other
/// outbound traffic.  IPv6 is therefore allowed through the selected tunnel
/// and blocked on physical interfaces without disabling IPv6 system-wide.
pub fn generate(info: &VpnInfo, leak: bool, local: bool, reconnect: bool) -> Result<String> {
    let mut rules = String::new();
    rules.push_str("# Managed by killswitch; load only into the killswitch anchor.\n");
    rules.push_str("# Do not load this file as the main PF ruleset.\n\n");

    writeln!(
        rules,
        "pass on lo0 all tag {ALLOWED_TAG} keep state label \"killswitch-loopback\""
    )?;

    if let Some(interface) = &info.interface {
        writeln!(
            rules,
            "pass on {interface} all tag {ALLOWED_TAG} keep state (if-bound) label \"killswitch-vpn\""
        )?;
    }

    if let Some(physical) = &info.physical_interface {
        add_dhcp_rules(&mut rules, physical)?;
        if local {
            writeln!(
                rules,
                "pass on {physical} from {physical}:network to {physical}:network tag {ALLOWED_TAG} keep state (if-bound) label \"killswitch-local\""
            )?;
        }
        if leak {
            writeln!(
                rules,
                "pass out on {physical} proto {{ tcp, udp }} to any port 53 tag {ALLOWED_TAG} keep state (if-bound) label \"killswitch-dns-leak\""
            )?;
            writeln!(
                rules,
                "pass out on {physical} inet proto icmp all tag {ALLOWED_TAG} keep state (if-bound) label \"killswitch-icmp-leak\""
            )?;
            writeln!(
                rules,
                "pass out on {physical} inet6 proto icmp6 all tag {ALLOWED_TAG} keep state (if-bound) label \"killswitch-icmp6-leak\""
            )?;
        }
        for endpoint in &info.endpoints {
            add_endpoint_rule(&mut rules, physical, endpoint, "killswitch-endpoint")?;
        }
        if reconnect {
            for endpoint in &info.bootstrap_endpoints {
                add_endpoint_rule(&mut rules, physical, endpoint, "killswitch-bootstrap")?;
            }
        }
    }

    writeln!(
        rules,
        "block drop out quick all ! tagged {ALLOWED_TAG} label \"killswitch-direct-block\""
    )?;
    Ok(rules)
}

fn add_dhcp_rules(rules: &mut String, interface: &str) -> Result<()> {
    writeln!(
        rules,
        "pass out on {interface} inet proto udp from any port 68 to any port 67 tag {ALLOWED_TAG} keep state (if-bound) label \"killswitch-dhcp-out\""
    )?;
    writeln!(
        rules,
        "pass in on {interface} inet proto udp from any port 67 to any port 68 tag {ALLOWED_TAG} keep state (if-bound) label \"killswitch-dhcp-in\""
    )?;
    writeln!(
        rules,
        "pass out on {interface} inet6 proto udp from any port 546 to ff02::1:2 port 547 tag {ALLOWED_TAG} keep state (if-bound) label \"killswitch-dhcp6-out\""
    )?;
    writeln!(
        rules,
        "pass in on {interface} inet6 proto udp from any port 547 to any port 546 tag {ALLOWED_TAG} keep state (if-bound) label \"killswitch-dhcp6-in\""
    )?;
    Ok(())
}

fn add_endpoint_rule(
    rules: &mut String,
    interface: &str,
    endpoint: &VpnEndpoint,
    label: &str,
) -> Result<()> {
    let family = match endpoint.address {
        IpAddr::V4(_) => "inet",
        IpAddr::V6(_) => "inet6",
    };
    match endpoint.transport {
        crate::killswitch::network::Transport::Tcp => {
            add_endpoint_transport(
                rules,
                interface,
                family,
                "tcp",
                " flags any",
                endpoint,
                label,
            )?;
        }
        crate::killswitch::network::Transport::Udp => {
            add_endpoint_transport(rules, interface, family, "udp", "", endpoint, label)?;
        }
        crate::killswitch::network::Transport::Any => {
            add_endpoint_transport(
                rules,
                interface,
                family,
                "tcp",
                " flags any",
                endpoint,
                label,
            )?;
            add_endpoint_transport(rules, interface, family, "udp", "", endpoint, label)?;
        }
    }
    Ok(())
}

fn add_endpoint_transport(
    rules: &mut String,
    interface: &str,
    family: &str,
    protocol: &str,
    tcp_flags: &str,
    endpoint: &VpnEndpoint,
    label: &str,
) -> Result<()> {
    let port = endpoint
        .port
        .map_or_else(String::new, |value| format!(" port {value}"));
    writeln!(
        rules,
        "pass out on {interface} {family} proto {protocol} from any to {}{port}{tcp_flags} tag {ALLOWED_TAG} keep state (if-bound) label \"{label}\"",
        endpoint.address
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::killswitch::network::{Transport, VpnEndpoint, VpnType};
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Public fixture addresses are from IANA documentation-only ranges.
    fn info(connected: bool, endpoint: bool) -> VpnInfo {
        VpnInfo {
            vpn_type: VpnType::MacOsNetworkExtension,
            interface: connected.then(|| "utun4".to_string()),
            tunnel_ipv4: connected.then(|| Ipv4Addr::new(172, 16, 209, 2)),
            tunnel_ipv6: connected
                .then(|| "fd00::2".parse::<Ipv6Addr>().ok())
                .flatten()
                .into_iter()
                .collect(),
            endpoints: endpoint
                .then(|| VpnEndpoint {
                    address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 107)),
                    port: Some(443),
                    transport: Transport::Udp,
                })
                .into_iter()
                .collect(),
            bootstrap_endpoints: Vec::new(),
            physical_interface: Some("en0".to_string()),
            physical_ipv4: vec![Ipv4Addr::new(192, 0, 2, 10)],
            physical_ipv6: vec!["2001:db8:1:2::66".parse().unwrap_or(Ipv6Addr::LOCALHOST)],
            routes: Vec::new(),
            service: Some("AdGuard VPN".to_string()),
        }
    }

    #[test]
    fn test_anchor_generation_vpn_on() {
        let rules = generate(&info(true, true), false, false, false).unwrap_or_default();
        assert!(rules.contains("pass on utun4 all tag KILLSWITCH_ALLOWED"));
        assert!(
            rules.contains("pass out on en0 inet proto udp from any to 198.51.100.107 port 443")
        );
        assert!(rules.contains("block drop out quick all ! tagged KILLSWITCH_ALLOWED"));
        assert!(!rules.contains("block out inet6"));
    }

    #[test]
    fn test_anchor_generation_vpn_off_is_fail_closed() {
        let rules = generate(&info(false, false), false, false, false).unwrap_or_default();
        assert!(!rules.contains("pass on utun"));
        assert!(!rules.contains("killswitch-endpoint"));
        assert!(rules.contains("block drop out quick all ! tagged KILLSWITCH_ALLOWED"));
    }

    #[test]
    fn test_endpoint_unknown_does_not_open_physical_interface() {
        let rules = generate(&info(true, false), false, false, false).unwrap_or_default();
        assert!(!rules.contains("killswitch-endpoint"));
        assert!(rules.contains("block drop out quick all ! tagged KILLSWITCH_ALLOWED"));
    }

    #[test]
    fn test_ipv6_endpoint_and_tunnel_are_supported() {
        let mut value = info(true, false);
        value.endpoints.push(VpnEndpoint {
            address: "2001:db8::8"
                .parse()
                .unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            port: Some(443),
            transport: Transport::Tcp,
        });
        let rules = generate(&value, false, false, false).unwrap_or_default();
        assert!(rules.contains("inet6 proto tcp"));
        assert!(rules.contains("to 2001:db8::8 port 443"));
        assert!(rules.contains("port 443 flags any tag KILLSWITCH_ALLOWED"));
    }

    #[test]
    fn test_dhcp_loopback_and_optional_local_rules() {
        let rules = generate(&info(true, true), false, true, false).unwrap_or_default();
        assert!(rules.contains("pass on lo0"));
        assert!(rules.contains("port 68 to any port 67"));
        assert!(rules.contains("port 546 to ff02::1:2 port 547"));
        assert!(rules.contains("from en0:network to en0:network"));
    }

    #[test]
    fn test_leak_mode_remains_opt_in() {
        let secure = generate(&info(true, true), false, false, false).unwrap_or_default();
        let leak = generate(&info(true, true), true, false, false).unwrap_or_default();
        assert!(!secure.contains("killswitch-dns-leak"));
        assert!(leak.contains("killswitch-dns-leak"));
        assert!(leak.contains("killswitch-icmp6-leak"));
    }

    #[test]
    fn test_manual_endpoint_allows_tcp_and_udp_without_fixed_port() {
        let mut value = info(true, false);
        value.endpoints.push(VpnEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
            port: None,
            transport: Transport::Any,
        });
        let rules = generate(&value, false, false, false).unwrap_or_default();
        assert!(rules.contains("proto tcp from any to 203.0.113.8 flags any"));
        assert!(rules.contains("proto udp from any to 203.0.113.8 tag"));
        assert!(!rules.contains("203.0.113.8 port"));
    }

    #[test]
    fn test_reconnect_bootstrap_rules_are_opt_in_and_labeled() {
        let mut value = info(false, true);
        value.bootstrap_endpoints.push(VpnEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            port: Some(443),
            transport: Transport::Tcp,
        });

        let strict = generate(&value, false, false, false).unwrap_or_default();
        let reconnect = generate(&value, false, false, true).unwrap_or_default();

        assert!(!strict.contains("killswitch-bootstrap"));
        assert!(reconnect.contains("to 203.0.113.9 port 443"));
        assert!(reconnect.contains("label \"killswitch-bootstrap\""));
    }
}
