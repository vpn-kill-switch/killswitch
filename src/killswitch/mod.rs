pub mod whoami;

use anyhow::Result;
use colored::*;
use pnet::datalink::{self, NetworkInterface};
use std::net::IpAddr;

pub fn default() -> Result<String> {
    if let Ok(interface) = default_net::get_default_interface() {
        println!("Default network interface");
        println!("  Name: {}", interface.name);

        let ipv4 = interface.ipv4.iter().map(|ip| ip).collect::<Vec<_>>();

        let ipv6 = interface.ipv6.iter().map(|ip| ip).collect::<Vec<_>>();

        if ipv4.len() > 0 {
            println!("  IPv4: {}", ipv4[0]);
            for ip in &ipv4[1..] {
                println!("    {}", ip);
            }
        }

        if ipv6.len() > 0 {
            println!("  IPv6: {}", ipv6[0]);
            for ip in &ipv6[1..] {
                println!("        {}", ip);
            }
        }

        println!(
            "  MAC Address: {}",
            interface
                .mac_addr
                .map_or("N/A".to_string(), |m| format!("{}", m)),
        );

        println!(
            "  Gateway: {}",
            interface
                .gateway
                .map_or("N/A".to_string(), |m| format!("{:#?}", m.ip_addr)),
        );

        println!("  Type: {:?}", interface.if_type);
    }

    println!("");

    let public_ip = whoami::whoami()?;

    println!("Public IP Address: {}", public_ip.red());

    Ok("".to_string())
}
