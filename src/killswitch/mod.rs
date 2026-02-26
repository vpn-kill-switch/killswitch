mod network;
mod pf;
mod rules;

use crate::cli::verbosity::Verbosity;
use anyhow::{Context, Result, bail};

fn check_root() -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!("This operation requires root privileges. Try: sudo killswitch");
    }
    Ok(())
}

fn validate_ipv4(ip: &str) -> Result<()> {
    use std::net::IpAddr;
    let addr: IpAddr = ip.parse().context("Invalid IP address")?;
    let IpAddr::V4(v4) = addr else {
        bail!("IPv6 addresses are not supported: {ip}");
    };
    let o = v4.octets();
    if o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
    {
        bail!("{ip} is a private/reserved IP address. VPN peer must be a public IP");
    }
    Ok(())
}

/// Resolve the VPN peer IP from user input or auto-detection
fn resolve_vpn_ip(ipv4: Option<&str>, verbose: Verbosity) -> Result<String> {
    if let Some(ip) = ipv4 {
        validate_ipv4(ip)?;
        if verbose.is_debug() {
            eprintln!("  Using provided VPN gateway: {ip}");
        }
        Ok(ip.to_string())
    } else {
        if verbose.is_verbose() {
            eprintln!("  Auto-detecting VPN gateway address...");
        }
        network::detect_vpn_gateway(verbose)
    }
}

/// Enable the VPN kill switch
///
/// # Errors
/// Returns an error if:
/// - Not running with root privileges
/// - VPN gateway address cannot be detected (when not provided)
/// - Firewall rules cannot be generated or applied
pub fn enable(leak: bool, local: bool, ipv4: Option<&str>, verbose: Verbosity) -> Result<()> {
    check_root()?;

    let vpn_ip = resolve_vpn_ip(ipv4, verbose)?;

    if verbose.is_debug() {
        eprintln!("  VPN gateway: {vpn_ip}");
        eprintln!("  Generating firewall rules...");
    }

    let rules_content = rules::generate(&vpn_ip, leak, local, verbose)?;

    if verbose.is_debug() {
        eprintln!("  Applying rules to pf...");
    }

    pf::apply_rules(&rules_content, verbose)?;

    Ok(())
}

/// Disable the VPN kill switch
///
/// # Errors
/// Returns an error if:
/// - Not running with root privileges
/// - Firewall rules cannot be removed
pub fn disable(verbose: Verbosity) -> Result<()> {
    check_root()?;
    pf::disable(verbose)?;
    Ok(())
}

/// Get the current status of the VPN kill switch
///
/// # Errors
/// Returns an error if the firewall status cannot be queried
pub fn status() -> Result<String> {
    pf::status()
}

/// Generate firewall rules without applying them
///
/// # Errors
/// Returns an error if:
/// - VPN gateway address cannot be detected (when not provided)
/// - Rules cannot be generated
pub fn generate_rules(
    leak: bool,
    local: bool,
    ipv4: Option<&str>,
    verbose: Verbosity,
) -> Result<String> {
    let vpn_ip = resolve_vpn_ip(ipv4, verbose)?;

    rules::generate(&vpn_ip, leak, local, verbose)
}

/// Show active network interfaces, VPN peer IP, and usage hints.
/// Mirrors the Go (master) default behavior.
///
/// # Errors
/// Returns an error if interface detection fails
pub fn show_interfaces(verbose: Verbosity) -> Result<String> {
    use std::fmt::Write;

    let interfaces = network::get_interfaces()?;

    if interfaces.is_empty() {
        bail!("No active interfaces found, verify you are connected to the network");
    }

    let mut out = String::new();
    let _ = writeln!(out, "Interface  MAC address         IP");

    let has_vpn = interfaces.iter().any(|i| i.is_p2p);

    for iface in &interfaces {
        let _ = writeln!(out, "{:<10} {:<19} {}", iface.name, iface.mac, iface.ip);
    }

    // Show public IP
    if let Ok(public_ip) = network::get_public_ip() {
        let _ = writeln!(out, "\nPublic IP address: \x1b[0;31m{public_ip}\x1b[0m");
    }

    // Try to detect VPN peer IP
    match network::detect_vpn_gateway(verbose) {
        Ok(peer) => {
            let _ = writeln!(out, "PEER IP address:   \x1b[0;33m{peer}\x1b[0m");
        }
        Err(_) if !has_vpn => {
            let _ = writeln!(out, "\nNo VPN interface found, verify VPN is connected");
        }
        Err(_) => {}
    }

    let _ = writeln!(out, "\nTo enable the kill switch run: sudo killswitch -e");
    let _ = writeln!(out, "To disable:                    sudo killswitch -d");

    Ok(out)
}
