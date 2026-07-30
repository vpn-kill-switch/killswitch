mod network;
mod pf;
mod rules;

use crate::cli::verbosity::Verbosity;
use anyhow::{Context, Result, bail};
use network::{Transport, VpnEndpoint, VpnInfo};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const MONITOR_CONFIG_PATH: &str = "/var/run/killswitch.monitor.conf";
const MONITOR_PID_PATH: &str = "/var/run/killswitch.monitor.pid";
const MONITOR_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, PartialEq, Eq)]
struct MonitorConfig {
    leak: bool,
    local: bool,
    manual_endpoint: Option<Ipv4Addr>,
}

/// Check whether an IPv4 address is private or locally scoped.
#[must_use]
pub fn is_private_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || octets[0] == 127
        || (octets[0] == 169 && octets[1] == 254)
}

fn check_root() -> Result<()> {
    let effective_user = unsafe { libc::geteuid() };
    if effective_user != 0 {
        bail!("This operation requires root privileges. Try: sudo killswitch");
    }
    Ok(())
}

fn validate_manual_endpoint(value: &str) -> Result<Ipv4Addr> {
    let address: IpAddr = value.parse().context("Invalid IP address")?;
    let IpAddr::V4(address) = address else {
        bail!("--ipv4 accepts an IPv4 endpoint only: {value}");
    };
    if is_private_ip(&address) {
        bail!("{value} is a private/reserved IP address. VPN endpoint must be public");
    }
    Ok(address)
}

fn detect_with_override(ipv4: Option<&str>, verbose: Verbosity) -> Result<VpnInfo> {
    let mut info = network::detect_vpn(verbose);
    if let Some(value) = ipv4 {
        let address = validate_manual_endpoint(value)?;
        info.endpoints = vec![VpnEndpoint {
            address: IpAddr::V4(address),
            port: None,
            transport: Transport::Any,
        }];
        if verbose.is_debug() {
            eprintln!("  Using the manual compatibility endpoint: {address}");
        }
    }
    Ok(info)
}

fn physical_addresses(info: &VpnInfo) -> Vec<IpAddr> {
    info.physical_ipv4
        .iter()
        .copied()
        .map(IpAddr::V4)
        .chain(info.physical_ipv6.iter().copied().map(IpAddr::V6))
        .collect()
}

/// Enable the kill switch and start the interface/endpoint monitor.
///
/// # Errors
/// Returns an error if privileges, detection, PF validation, or monitor startup fails.
pub fn enable(leak: bool, local: bool, ipv4: Option<&str>, verbose: Verbosity) -> Result<()> {
    check_root()?;
    let info = detect_with_override(ipv4, verbose)?;
    let generated = rules::generate(&info, leak, local)?;
    pf::apply_rules(&generated, &physical_addresses(&info), true, verbose)?;

    let config = MonitorConfig {
        leak,
        local,
        manual_endpoint: ipv4.map(validate_manual_endpoint).transpose()?,
    };
    write_monitor_config(&config)?;
    restart_monitor(verbose)?;
    Ok(())
}

/// Disable only the dedicated anchor and stop its monitor.
///
/// # Errors
/// Returns an error if privileges or the scoped PF cleanup fails.
pub fn disable(verbose: Verbosity) -> Result<()> {
    check_root()?;
    stop_monitor(verbose)?;
    pf::disable(verbose)
}

/// Return PF rules and counters for the dedicated anchor.
///
/// # Errors
/// Returns an error if PF status cannot be queried.
#[must_use = "status returns user-facing text"]
pub fn status() -> Result<String> {
    pf::status()
}

/// Generate the exact anchor rules without applying them.
///
/// # Errors
/// Returns an error if a manual endpoint is invalid or rules cannot be formatted.
pub fn generate_rules(
    leak: bool,
    local: bool,
    ipv4: Option<&str>,
    verbose: Verbosity,
) -> Result<String> {
    let info = detect_with_override(ipv4, verbose)?;
    rules::generate(&info, leak, local)
}

/// Show the detection result used by rule generation.
///
/// # Errors
/// Returns an error if the user-facing report cannot be produced.
pub fn show_interfaces(verbose: Verbosity) -> Result<String> {
    let info = network::detect_vpn(verbose);
    let mut output = network::describe(&info);
    output.push_str("\nTraffic policy when enabled:\n");
    output.push_str("  selected VPN interface: allowed\n");
    output.push_str("  direct IPv4/IPv6:       blocked\n");
    output.push_str("\nTo enable:  sudo killswitch -e\n");
    output.push_str("To disable: sudo killswitch -d\n");
    Ok(output)
}

fn write_monitor_config(config: &MonitorConfig) -> Result<()> {
    let manual = config
        .manual_endpoint
        .map_or_else(String::new, |address| address.to_string());
    let contents = format!(
        "leak={}\nlocal={}\nmanual_endpoint={manual}\n",
        u8::from(config.leak),
        u8::from(config.local)
    );
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let mut file = options
        .open(MONITOR_CONFIG_PATH)
        .context("Failed to write monitor configuration")?;
    file.write_all(contents.as_bytes())
        .context("Failed to write monitor configuration")?;
    file.sync_all()
        .context("Failed to sync monitor configuration")?;
    Ok(())
}

fn read_monitor_config() -> Result<MonitorConfig> {
    let contents =
        fs::read_to_string(MONITOR_CONFIG_PATH).context("Failed to read monitor configuration")?;
    parse_monitor_config(&contents)
}

fn parse_monitor_config(contents: &str) -> Result<MonitorConfig> {
    let mut leak = false;
    let mut local = false;
    let mut manual_endpoint = None;
    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "leak" => leak = value == "1",
            "local" => local = value == "1",
            "manual_endpoint" if !value.is_empty() => {
                manual_endpoint = Some(validate_manual_endpoint(value)?);
            }
            _ => {}
        }
    }
    Ok(MonitorConfig {
        leak,
        local,
        manual_endpoint,
    })
}

fn restart_monitor(verbose: Verbosity) -> Result<()> {
    stop_monitor(verbose)?;
    let executable =
        std::env::current_exe().context("Failed to locate the killswitch executable")?;
    let mut command = Command::new(executable);
    command
        .arg("--monitor")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command
        .spawn()
        .context("Failed to start the killswitch monitor")?;
    fs::write(MONITOR_PID_PATH, format!("{}\n", child.id()))
        .context("Failed to save monitor PID")?;
    fs::set_permissions(MONITOR_PID_PATH, fs::Permissions::from_mode(0o600))
        .context("Failed to protect monitor PID file")?;
    if verbose.is_verbose() {
        eprintln!("  VPN monitor started (PID {})", child.id());
    }
    Ok(())
}

fn stop_monitor(verbose: Verbosity) -> Result<()> {
    if let Ok(contents) = fs::read_to_string(MONITOR_PID_PATH)
        && let Ok(pid) = contents.trim().parse::<libc::pid_t>()
        && process_is_monitor(pid)
    {
        let result = unsafe { libc::kill(pid, libc::SIGTERM) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error).context("Failed to stop the killswitch monitor");
            }
        } else if verbose.is_debug() {
            eprintln!("  Stopped VPN monitor PID {pid}");
        }
    }
    if Path::new(MONITOR_PID_PATH).exists() {
        fs::remove_file(MONITOR_PID_PATH).context("Failed to remove monitor PID file")?;
    }
    Ok(())
}

fn process_is_monitor(pid: libc::pid_t) -> bool {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output();
    output.is_ok_and(|value| {
        value.status.success()
            && String::from_utf8_lossy(&value.stdout).contains("killswitch --monitor")
    })
}

/// Hidden monitor entry point. It always removes a stale tunnel allow rule
/// when detection becomes uncertain, while retaining only observed VPN server
/// endpoints so the provider can reconnect.
///
/// # Errors
/// Returns an error if privileges or the persisted monitor configuration is invalid.
pub fn monitor() -> Result<()> {
    check_root()?;
    let config = read_monitor_config()?;
    let mut known_endpoints = BTreeSet::new();
    if let Some(address) = config.manual_endpoint {
        known_endpoints.insert(VpnEndpoint {
            address: IpAddr::V4(address),
            port: None,
            transport: Transport::Any,
        });
    }
    let mut previous = fs::read_to_string("/var/run/killswitch.pf.conf").unwrap_or_default();

    loop {
        let mut info = network::detect_vpn(Verbosity::Normal);
        if config.manual_endpoint.is_none() && !info.endpoints.is_empty() {
            known_endpoints = info.endpoints.iter().cloned().collect();
        }
        info.endpoints = known_endpoints.iter().cloned().collect();
        if let Ok(generated) = rules::generate(&info, config.leak, config.local)
            && generated != previous
            && pf::apply_rules(
                &generated,
                &physical_addresses(&info),
                true,
                Verbosity::Normal,
            )
            .is_ok()
        {
            previous = generated;
        }
        thread::sleep(MONITOR_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ipv4_detection() {
        assert!(is_private_ip(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ip(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_private_ip(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_private_ip(&Ipv4Addr::new(203, 0, 113, 1)));
    }

    #[test]
    fn test_monitor_config_round_trip_parser() {
        let config = parse_monitor_config("leak=0\nlocal=1\nmanual_endpoint=216.211.192.107\n")
            .unwrap_or(MonitorConfig {
                leak: true,
                local: false,
                manual_endpoint: None,
            });
        assert!(!config.leak);
        assert!(config.local);
        assert_eq!(
            config.manual_endpoint,
            Some(Ipv4Addr::new(216, 211, 192, 107))
        );
    }

    #[test]
    fn test_monitor_config_rejects_private_manual_endpoint() {
        assert!(parse_monitor_config("manual_endpoint=192.168.1.1\n").is_err());
    }
}
