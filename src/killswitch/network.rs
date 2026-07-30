//! Detection of the active VPN path on macOS.
//!
//! A Network Extension packet tunnel does not necessarily install a host route
//! for its remote server.  Its provider normally opens a socket bound to the
//! physical path instead.  Consequently the tunnel interface and the outer
//! endpoint are detected independently: routes identify the active `utun`, and
//! VPN-owned sockets identify the endpoint that must remain reachable.

use crate::cli::verbosity::Verbosity;
use crate::killswitch::is_private_ip;
use anyhow::{Context, Result, bail};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs as _};
use std::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VpnType {
    WireGuard,
    Tailscale,
    MacOsNetworkExtension,
    Unknown,
}

impl fmt::Display for VpnType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WireGuard => "WireGuard",
            Self::Tailscale => "Tailscale",
            Self::MacOsNetworkExtension => "macOS Network Extension",
            Self::Unknown => "unknown",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Transport {
    Tcp,
    Udp,
    Any,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VpnEndpoint {
    pub address: IpAddr,
    pub port: Option<u16>,
    pub transport: Transport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteInfo {
    pub destination: String,
    pub gateway: String,
    pub flags: String,
    pub interface: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpnInfo {
    pub vpn_type: VpnType,
    pub interface: Option<String>,
    pub tunnel_ipv4: Option<Ipv4Addr>,
    pub tunnel_ipv6: Vec<Ipv6Addr>,
    pub endpoints: Vec<VpnEndpoint>,
    pub physical_interface: Option<String>,
    pub physical_ipv4: Vec<Ipv4Addr>,
    pub physical_ipv6: Vec<Ipv6Addr>,
    pub routes: Vec<RouteInfo>,
    pub service: Option<String>,
}

impl VpnInfo {
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.interface.is_some()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct InterfaceData {
    name: String,
    mac: String,
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
    point_to_point: bool,
}

/// Detect the physical path, active VPN interface and outer endpoint sockets.
///
/// Partial command failures produce a conservative result.  In particular,
/// an uncertain tunnel is reported as disconnected so rule generation fails
/// closed rather than allowing every `utun` interface.
pub fn detect_vpn(verbose: Verbosity) -> VpnInfo {
    let ifconfig = command_text("ifconfig", &[]).unwrap_or_default();
    let routes4 = command_text("netstat", &["-rn", "-f", "inet"]).unwrap_or_default();
    let routes6 = command_text("netstat", &["-rn", "-f", "inet6"]).unwrap_or_default();
    let default_route = command_text("route", &["-n", "get", "default"]).unwrap_or_default();
    let lsof = command_text("/usr/sbin/lsof", &["-nP", "-iTCP", "-iUDP", "-F", "pcPnT"])
        .unwrap_or_default();
    let wireguard = command_text("wg", &["show", "all", "endpoints"]).unwrap_or_default();
    let tailscale = command_text("tailscale", &["status", "--json"]).unwrap_or_default();
    let scutil_list = command_text("scutil", &["--nc", "list"]).unwrap_or_default();
    let scutil = scutil_details(&scutil_list);

    let info = detect_from_outputs(DetectionOutputs {
        ifconfig: &ifconfig,
        routes4: &routes4,
        routes6: &routes6,
        default_route: &default_route,
        lsof: &lsof,
        wireguard: &wireguard,
        tailscale: &tailscale,
        scutil: &scutil,
    });

    if verbose.is_verbose() {
        if info.is_connected()
            && let Some(interface) = &info.interface
        {
            eprintln!("  VPN interface: {interface} ({})", info.vpn_type);
        } else {
            eprintln!("  No active VPN interface; using fail-closed policy");
        }
        if let Some(interface) = &info.physical_interface {
            eprintln!("  Physical interface: {interface}");
        }
        if info.endpoints.is_empty() {
            eprintln!("  VPN endpoint: unknown (direct traffic remains blocked)");
        } else {
            for endpoint in &info.endpoints {
                eprintln!(
                    "  VPN endpoint: {}{} ({:?})",
                    endpoint.address,
                    endpoint
                        .port
                        .map_or_else(String::new, |port| format!(":{port}")),
                    endpoint.transport
                );
            }
        }
    }

    info
}

fn scutil_details(list: &str) -> String {
    let mut details = String::new();
    for line in list.lines().filter(|line| line.contains("(Connected)")) {
        let Some(identifier) = line.split_whitespace().nth(2) else {
            continue;
        };
        if let Ok(output) = command_text("scutil", &["--nc", "show", identifier]) {
            details.push_str(&output);
            details.push('\n');
        }
    }
    details
}

fn command_text(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute {program}"))?;
    if !output.status.success() {
        bail!("{program} exited unsuccessfully");
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[derive(Clone, Copy)]
struct DetectionOutputs<'a> {
    ifconfig: &'a str,
    routes4: &'a str,
    routes6: &'a str,
    default_route: &'a str,
    lsof: &'a str,
    wireguard: &'a str,
    tailscale: &'a str,
    scutil: &'a str,
}

fn detect_from_outputs(outputs: DetectionOutputs<'_>) -> VpnInfo {
    let interfaces = parse_ifconfig(outputs.ifconfig);
    let mut routes = parse_routes(outputs.routes4);
    routes.extend(parse_routes(outputs.routes6));

    let physical_interface = parse_default_interface(outputs.default_route)
        .or_else(|| default_interface_from_routes(&routes));
    let physical = physical_interface
        .as_deref()
        .and_then(|name| interfaces.iter().find(|interface| interface.name == name));
    let physical_ipv4 = physical.map_or_else(Vec::new, |value| value.ipv4.clone());
    let physical_ipv6 = physical.map_or_else(Vec::new, |value| {
        value
            .ipv6
            .iter()
            .copied()
            .filter(|address| !is_link_local_v6(*address))
            .collect()
    });

    let active_name = select_active_tunnel(&interfaces, &routes);
    let active = active_name
        .as_deref()
        .and_then(|name| interfaces.iter().find(|interface| interface.name == name));

    let mut endpoints = parse_lsof_endpoints(outputs.lsof, &physical_ipv4, &physical_ipv6);
    endpoints.extend(parse_wireguard_endpoints(outputs.wireguard));
    endpoints.extend(parse_scutil_remote_addresses(outputs.scutil));
    endpoints.sort();
    endpoints.dedup();

    let service = parse_lsof_service(outputs.lsof);
    let vpn_type = if !outputs.wireguard.trim().is_empty() {
        VpnType::WireGuard
    } else if outputs.tailscale.contains("\"ExitNodeStatus\"")
        || service
            .as_deref()
            .is_some_and(|name| contains_folded(name, "tailscale"))
    {
        VpnType::Tailscale
    } else if active_name
        .as_deref()
        .is_some_and(|name| name.starts_with("utun"))
    {
        VpnType::MacOsNetworkExtension
    } else {
        VpnType::Unknown
    };

    VpnInfo {
        vpn_type,
        interface: active_name,
        tunnel_ipv4: active.and_then(|value| value.ipv4.first().copied()),
        tunnel_ipv6: active.map_or_else(Vec::new, |value| value.ipv6.clone()),
        endpoints,
        physical_interface,
        physical_ipv4,
        physical_ipv6,
        routes,
        service,
    }
}

fn parse_ifconfig(input: &str) -> Vec<InterfaceData> {
    let mut interfaces = Vec::new();
    let mut current: Option<InterfaceData> = None;

    for line in input.lines() {
        if !line.starts_with([' ', '\t']) && line.contains(": flags=") {
            if let Some(interface) = current.take() {
                interfaces.push(interface);
            }
            let name = line.split(':').next().unwrap_or_default().to_string();
            if !line.contains("UP") || line.contains("LOOPBACK") {
                current = None;
            } else {
                current = Some(InterfaceData {
                    name,
                    point_to_point: line.contains("POINTOPOINT"),
                    ..InterfaceData::default()
                });
            }
            continue;
        }

        let Some(interface) = current.as_mut() else {
            continue;
        };
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("ether ") {
            interface.mac = value.trim().to_string();
        } else if let Some(value) = trimmed.strip_prefix("inet ") {
            if let Some(raw) = value.split_whitespace().next()
                && let Ok(address) = raw.parse::<Ipv4Addr>()
            {
                interface.ipv4.push(address);
            }
        } else if let Some(value) = trimmed.strip_prefix("inet6 ")
            && let Some(raw) = value.split_whitespace().next()
            && let Some(address) = raw.split('%').next()
            && let Ok(address) = address.parse::<Ipv6Addr>()
        {
            interface.ipv6.push(address);
        }
    }

    if let Some(interface) = current {
        interfaces.push(interface);
    }
    interfaces
}

fn parse_routes(input: &str) -> Vec<RouteInfo> {
    input
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || fields.first().is_some_and(|value| *value == "Destination") {
                return None;
            }
            let interface = fields.get(3)?;
            if !is_interface_name(interface) {
                return None;
            }
            Some(RouteInfo {
                destination: fields.first()?.to_string(),
                gateway: fields.get(1)?.to_string(),
                flags: fields.get(2)?.to_string(),
                interface: (*interface).to_string(),
            })
        })
        .collect()
}

fn is_interface_name(value: &str) -> bool {
    value.starts_with("en")
        || value.starts_with("utun")
        || value.starts_with("lo")
        || value.starts_with("bridge")
        || value.starts_with("awdl")
        || value.starts_with("llw")
}

fn parse_default_interface(input: &str) -> Option<String> {
    input.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("interface:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn default_interface_from_routes(routes: &[RouteInfo]) -> Option<String> {
    routes
        .iter()
        .find(|route| route.destination == "default" && !route.interface.starts_with("utun"))
        .map(|route| route.interface.clone())
}

fn select_active_tunnel(interfaces: &[InterfaceData], routes: &[RouteInfo]) -> Option<String> {
    interfaces
        .iter()
        .filter(|interface| interface.point_to_point && interface.name.starts_with("utun"))
        .filter_map(|interface| {
            let route_score: usize = routes
                .iter()
                .filter(|route| {
                    route.interface == interface.name
                        && route.gateway == interface.name
                        && is_tunnel_route(&route.destination, &route.flags)
                })
                .map(|route| {
                    if route.destination == "default" {
                        100
                    } else {
                        10
                    }
                })
                .sum();
            let address_score = usize::from(!interface.ipv4.is_empty()) * 50;
            let score = route_score + address_score;
            (score >= 30).then_some((score, interface.name.clone()))
        })
        .max_by(std::cmp::Ord::cmp)
        .map(|(_, name)| name)
}

fn is_tunnel_route(destination: &str, flags: &str) -> bool {
    if destination.starts_with("fe80") || destination.starts_with("ff") {
        return false;
    }
    destination != "default" || !flags.contains('I')
}

fn parse_lsof_endpoints(
    input: &str,
    physical_ipv4: &[Ipv4Addr],
    physical_ipv6: &[Ipv6Addr],
) -> Vec<VpnEndpoint> {
    let physical: Vec<IpAddr> = physical_ipv4
        .iter()
        .copied()
        .map(IpAddr::V4)
        .chain(physical_ipv6.iter().copied().map(IpAddr::V6))
        .collect();
    let mut command = String::new();
    let mut transport = Transport::Any;
    let mut endpoints = Vec::new();

    for line in input.lines() {
        let Some((tag, value)) = line.split_at_checked(1) else {
            continue;
        };
        match tag {
            "p" => {
                command.clear();
                transport = Transport::Any;
            }
            "c" => command = value.to_string(),
            "P" => {
                transport = match value {
                    "TCP" => Transport::Tcp,
                    "UDP" => Transport::Udp,
                    _ => Transport::Any,
                };
            }
            "n" if is_vpn_process(&command) => {
                let Some((local, remote)) = value.split_once("->") else {
                    continue;
                };
                let Some((local_address, _)) = parse_socket_address(local) else {
                    continue;
                };
                let Some((remote_address, port)) = parse_socket_address(remote) else {
                    continue;
                };
                if physical.contains(&local_address) && is_public_endpoint(remote_address) {
                    endpoints.push(VpnEndpoint {
                        address: remote_address,
                        port,
                        transport,
                    });
                }
            }
            _ => {}
        }
    }
    endpoints
}

fn parse_lsof_service(input: &str) -> Option<String> {
    input.lines().find_map(|line| {
        line.strip_prefix('c')
            .filter(|name| is_vpn_process(name))
            .map(str::to_string)
    })
}

fn is_vpn_process(name: &str) -> bool {
    let folded = name.to_ascii_lowercase();
    [
        "adguard vpn",
        "com.adguard",
        "wireguard",
        "tailscale",
        "openvpn",
        "protonvpn",
        "nordvpn",
    ]
    .iter()
    .any(|needle| folded.contains(needle))
}

fn contains_folded(value: &str, needle: &str) -> bool {
    value.to_ascii_lowercase().contains(needle)
}

fn parse_socket_address(value: &str) -> Option<(IpAddr, Option<u16>)> {
    if let Some(bracketed) = value.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']')?;
        let address = host.split('%').next()?.parse::<IpAddr>().ok()?;
        let port = suffix.strip_prefix(':').and_then(|raw| raw.parse().ok());
        return Some((address, port));
    }
    let (host, port) = value.rsplit_once(':')?;
    Some((host.parse::<IpAddr>().ok()?, port.parse::<u16>().ok()))
}

fn parse_wireguard_endpoints(input: &str) -> Vec<VpnEndpoint> {
    input
        .lines()
        .filter_map(|line| {
            let raw = line.split_whitespace().last()?;
            if raw == "(none)" {
                return None;
            }
            let (address, port) = parse_socket_address(raw)?;
            is_public_endpoint(address).then_some(VpnEndpoint {
                address,
                port,
                transport: Transport::Udp,
            })
        })
        .collect()
}

fn parse_scutil_remote_addresses(input: &str) -> Vec<VpnEndpoint> {
    input
        .lines()
        .filter_map(|line| {
            let raw = line.trim().strip_prefix("RemoteAddress : ")?;
            let (host, port) = split_host_and_port(raw);
            let address = host.parse::<IpAddr>().ok().or_else(|| resolve_host(host))?;
            is_public_endpoint(address).then_some(VpnEndpoint {
                address,
                port,
                transport: Transport::Any,
            })
        })
        .collect()
}

fn split_host_and_port(value: &str) -> (&str, Option<u16>) {
    if let Some(bracketed) = value.strip_prefix('[')
        && let Some((host, suffix)) = bracketed.split_once(']')
    {
        return (
            host,
            suffix.strip_prefix(':').and_then(|raw| raw.parse().ok()),
        );
    }
    if value.matches(':').count() == 1
        && let Some((host, raw_port)) = value.rsplit_once(':')
        && let Ok(port) = raw_port.parse::<u16>()
    {
        return (host, Some(port));
    }
    (value, None)
}

fn resolve_host(host: &str) -> Option<IpAddr> {
    (host, 0)
        .to_socket_addrs()
        .ok()?
        .map(|socket| socket.ip())
        .find(|address| matches!(address, IpAddr::V4(_)))
}

fn is_public_endpoint(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => {
            !is_private_ip(&value)
                && value != Ipv4Addr::UNSPECIFIED
                && value != Ipv4Addr::BROADCAST
                && value.octets()[0] < 224
        }
        IpAddr::V6(value) => {
            !value.is_unspecified()
                && !value.is_loopback()
                && !value.is_multicast()
                && !is_link_local_v6(value)
                && value.segments()[0] & 0xfe00 != 0xfc00
        }
    }
}

fn is_link_local_v6(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

/// Display information for the default CLI action.
pub fn describe(info: &VpnInfo) -> String {
    use std::fmt::Write as _;
    let mut output = String::new();
    let _ = writeln!(output, "VPN type:              {}", info.vpn_type);
    let _ = writeln!(
        output,
        "VPN interface:         {}",
        info.interface.as_deref().unwrap_or("not detected")
    );
    let _ = writeln!(
        output,
        "Tunnel IPv4:           {}",
        info.tunnel_ipv4
            .map_or_else(|| "none".to_string(), |ip| ip.to_string())
    );
    let _ = writeln!(
        output,
        "Physical interface:    {}",
        info.physical_interface.as_deref().unwrap_or("not detected")
    );
    if info.endpoints.is_empty() {
        let _ = writeln!(output, "VPN endpoint:          unknown");
    } else {
        for endpoint in &info.endpoints {
            let _ = writeln!(
                output,
                "VPN endpoint:          {}{} {:?}",
                endpoint.address,
                endpoint
                    .port
                    .map_or_else(String::new, |port| format!(":{port}")),
                endpoint.transport
            );
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const EN0: &str = r"en0: flags=8863<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
    ether aa:bb:cc:dd:ee:ff
    inet 192.168.1.66 netmask 0xffffff00 broadcast 192.168.1.255
    inet6 2a00:1370:817c:4a82::66 prefixlen 64
";
    const UTUN4: &str = r"utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
    inet 172.16.209.2 --> 127.1.1.1 netmask 0xffffffff
    inet6 fd00::2 prefixlen 64
";
    const ROUTES4: &str = r"Destination Gateway Flags Netif Expire
default 192.168.1.254 UGScg en0
1 utun4 USc utun4
2/7 utun4 USc utun4
64/2 utun4 USc utun4
";

    fn outputs<'a>(ifconfig: &'a str, routes4: &'a str, lsof: &'a str) -> DetectionOutputs<'a> {
        DetectionOutputs {
            ifconfig,
            routes4,
            routes6: "",
            default_route: "interface: en0",
            lsof,
            wireguard: "",
            tailscale: "",
            scutil: "",
        }
    }

    #[test]
    fn test_vpn_not_found() {
        let info = detect_from_outputs(outputs(EN0, "malformed", ""));
        assert!(!info.is_connected());
        assert!(info.endpoints.is_empty());
    }

    #[test]
    fn test_utun4_found_with_ipv4_and_ipv6() {
        let input = format!("{EN0}{UTUN4}");
        let info = detect_from_outputs(outputs(&input, ROUTES4, ""));
        assert_eq!(info.interface.as_deref(), Some("utun4"));
        assert_eq!(info.tunnel_ipv4, Some(Ipv4Addr::new(172, 16, 209, 2)));
        assert!(
            info.tunnel_ipv6
                .contains(&"fd00::2".parse().unwrap_or(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(info.vpn_type, VpnType::MacOsNetworkExtension);
    }

    #[test]
    fn test_reconnect_selects_utun5() {
        let utun5 = UTUN4.replace("utun4", "utun5");
        let routes = ROUTES4.replace("utun4", "utun5");
        let input = format!("{EN0}{utun5}");
        let info = detect_from_outputs(outputs(&input, &routes, ""));
        assert_eq!(info.interface.as_deref(), Some("utun5"));
    }

    #[test]
    fn test_endpoint_known_from_adguard_socket() {
        let input = format!("{EN0}{UTUN4}");
        let lsof = concat!(
            "p811\ncAdGuard VPN\nPUDP\n",
            "n192.168.1.66:54794->216.211.192.107:443\n",
            "n192.168.1.66:54795->216.211.192.107:443\n",
        );
        let info = detect_from_outputs(outputs(&input, ROUTES4, lsof));
        // Ephemeral source ports must not become part of the PF exception:
        // the provider retries from a new port after a blocked first SYN.
        assert_eq!(info.endpoints.len(), 1);
        assert_eq!(
            info.endpoints.first(),
            Some(&VpnEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(216, 211, 192, 107)),
                port: Some(443),
                transport: Transport::Udp,
            })
        );
    }

    #[test]
    fn test_endpoint_unknown_is_preserved_as_empty() {
        let input = format!("{EN0}{UTUN4}");
        let info = detect_from_outputs(outputs(&input, ROUTES4, ""));
        assert!(info.endpoints.is_empty());
    }

    #[test]
    fn test_physical_interface_en0_and_global_addresses() {
        let info = detect_from_outputs(outputs(EN0, ROUTES4, ""));
        assert_eq!(info.physical_interface.as_deref(), Some("en0"));
        assert_eq!(info.physical_ipv4, [Ipv4Addr::new(192, 168, 1, 66)]);
        assert_eq!(info.physical_ipv6.len(), 1);
    }

    #[test]
    fn test_malformed_routing_table_does_not_select_unrelated_utun() {
        let unrelated = "utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n    inet6 fe80::1%utun0 prefixlen 64\n";
        let input = format!("{EN0}{unrelated}");
        let info = detect_from_outputs(outputs(&input, "bad route data", ""));
        assert!(info.interface.is_none());
    }

    #[test]
    fn test_multiple_utun_selects_routed_tunnel() {
        let unrelated = "utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n    inet6 fe80::1%utun0 prefixlen 64\n";
        let input = format!("{EN0}{unrelated}{UTUN4}");
        let info = detect_from_outputs(outputs(&input, ROUTES4, ""));
        assert_eq!(info.interface.as_deref(), Some("utun4"));
    }

    #[test]
    fn test_non_vpn_process_socket_is_not_endpoint() {
        let lsof = "p99\ncBrowser\nPTCP\nn192.168.1.66:50000->203.0.113.1:443\n";
        let info = detect_from_outputs(outputs(EN0, ROUTES4, lsof));
        assert!(info.endpoints.is_empty());
    }

    #[test]
    fn test_wireguard_ipv4_and_ipv6_endpoints() {
        let endpoints =
            parse_wireguard_endpoints("wg0 key 203.0.113.8:51820\nwg1 key [2001:db8::8]:51820\n");
        assert_eq!(endpoints.len(), 2);
        assert!(
            endpoints
                .iter()
                .all(|endpoint| endpoint.transport == Transport::Udp)
        );
    }
}
