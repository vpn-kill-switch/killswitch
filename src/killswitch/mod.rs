mod network;
mod pf;
mod rules;

use crate::cli::telemetry::Verbosity;
use anyhow::{bail, Result};

fn check_root() -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!("This operation requires root privileges. Try: sudo killswitch");
    }
    Ok(())
}

/// Enable the VPN kill switch
///
/// # Errors
/// Returns an error if:
/// - Not running with root privileges
/// - VPN peer address cannot be detected (when not provided)
/// - Firewall rules cannot be generated or applied
pub fn enable(leak: bool, local: bool, ipv4: Option<&str>, verbose: Verbosity) -> Result<()> {
    check_root()?;

    let vpn_ip = if let Some(ip) = ipv4 {
        if verbose.is_debug() {
            eprintln!("  Using provided VPN peer: {ip}");
        }
        ip.to_string()
    } else {
        if verbose.is_verbose() {
            eprintln!("  Auto-detecting VPN peer address...");
        }
        network::detect_vpn_peer(verbose)?
    };

    if verbose.is_debug() {
        eprintln!("  VPN peer: {vpn_ip}");
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
/// - VPN peer address cannot be detected (when not provided)
/// - Rules cannot be generated
pub fn generate_rules(
    leak: bool,
    local: bool,
    ipv4: Option<&str>,
    verbose: Verbosity,
) -> Result<String> {
    let vpn_ip = if let Some(ip) = ipv4 {
        ip.to_string()
    } else {
        network::detect_vpn_peer(verbose)?
    };

    rules::generate(&vpn_ip, leak, local, verbose)
}
