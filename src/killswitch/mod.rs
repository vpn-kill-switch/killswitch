use anyhow::Result;
use pnet::datalink::{self, NetworkInterface};
use std::net::IpAddr;

struct ActiveInterface {
    network_interface: NetworkInterface,
    ips: Vec<IpAddr>,
}

pub fn default() -> Result<String> {
    let all_interfaces = datalink::interfaces();

    let mut interface_with_ip: Vec<ActiveInterface> = Vec::new();

    for interface in all_interfaces {
        if interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty() {
            // Filter out loopback IPs and create IpNetwork instances
            let ips: Vec<IpAddr> = interface
                .ips
                .iter()
                .filter_map(|ip| match ip.ip() {
                    IpAddr::V4(ipv4) if !ipv4.is_loopback() => Some(IpAddr::V4(ipv4)),
                    IpAddr::V6(ipv6) if !ipv6.is_loopback() && ipv6.segments()[0] != 0xfe80 => {
                        Some(IpAddr::V6(ipv6))
                    }
                    _ => None,
                })
                .collect();

            if ips.is_empty() {
                continue;
            }

            let active_interface = ActiveInterface {
                network_interface: interface,
                ips,
            };

            interface_with_ip.push(active_interface);
        }
    }

    for x in interface_with_ip {
        println!("{} - ips:{:#?} ", x.network_interface.name, x.ips);
    }

    Ok("".to_string())
}
