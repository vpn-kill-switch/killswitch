mod network;
mod pf;
mod rules;

use crate::cli::verbosity::Verbosity;
use anyhow::{Context, Result, bail};
use network::{Transport, VpnEndpoint, VpnInfo};
use std::collections::BTreeSet;
use std::fmt::Write as _;
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
const MAX_RECONNECT_ENDPOINTS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
struct MonitorConfig {
    leak: bool,
    local: bool,
    reconnect: bool,
    manual_endpoint: Option<Ipv4Addr>,
    trusted_endpoints: Vec<VpnEndpoint>,
}

/// Check whether an IPv4 address is private or locally scoped.
#[must_use]
pub fn is_private_ip(ip: &Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
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
pub fn enable(
    leak: bool,
    local: bool,
    reconnect: bool,
    ipv4: Option<&str>,
    verbose: Verbosity,
) -> Result<()> {
    check_root()?;
    let info = detect_with_override(ipv4, verbose)?;
    let generated = rules::generate(&info, leak, local, reconnect)?;
    pf::apply_rules(&generated, &physical_addresses(&info), true, verbose)?;

    let config = MonitorConfig {
        leak,
        local,
        reconnect,
        manual_endpoint: ipv4.map(validate_manual_endpoint).transpose()?,
        trusted_endpoints: info.endpoints,
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
    reconnect: bool,
    ipv4: Option<&str>,
    verbose: Verbosity,
) -> Result<String> {
    let info = detect_with_override(ipv4, verbose)?;
    rules::generate(&info, leak, local, reconnect)
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
    let mut contents = format!(
        "leak={}\nlocal={}\nreconnect={}\nmanual_endpoint={manual}\n",
        u8::from(config.leak),
        u8::from(config.local),
        u8::from(config.reconnect)
    );
    for endpoint in &config.trusted_endpoints {
        let transport = match endpoint.transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            Transport::Any => "any",
        };
        let port = endpoint
            .port
            .map_or_else(String::new, |port| port.to_string());
        writeln!(
            contents,
            "trusted_endpoint={transport}|{}|{port}",
            endpoint.address
        )?;
    }
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
    let mut reconnect = false;
    let mut manual_endpoint = None;
    let mut trusted_endpoints = Vec::new();
    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "leak" => leak = value == "1",
            "local" => local = value == "1",
            "reconnect" => reconnect = value == "1",
            "manual_endpoint" if !value.is_empty() => {
                manual_endpoint = Some(validate_manual_endpoint(value)?);
            }
            "trusted_endpoint" => trusted_endpoints.push(parse_trusted_endpoint(value)?),
            _ => {}
        }
    }
    trusted_endpoints.sort();
    trusted_endpoints.dedup();
    Ok(MonitorConfig {
        leak,
        local,
        reconnect,
        manual_endpoint,
        trusted_endpoints,
    })
}

fn parse_trusted_endpoint(value: &str) -> Result<VpnEndpoint> {
    let mut fields = value.split('|');
    let transport = match fields.next() {
        Some("tcp") => Transport::Tcp,
        Some("udp") => Transport::Udp,
        Some("any") => Transport::Any,
        _ => bail!("Invalid trusted endpoint transport"),
    };
    let address = fields
        .next()
        .context("Missing trusted endpoint address")?
        .parse()
        .context("Invalid trusted endpoint address")?;
    let port = match fields.next() {
        Some("") => None,
        Some(port) => Some(port.parse().context("Invalid trusted endpoint port")?),
        None => bail!("Missing trusted endpoint port"),
    };
    if fields.next().is_some() {
        bail!("Invalid trusted endpoint fields");
    }
    Ok(VpnEndpoint {
        address,
        port,
        transport,
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
    let mut monitor_pids = BTreeSet::new();
    if let Ok(contents) = fs::read_to_string(MONITOR_PID_PATH)
        && let Ok(pid) = contents.trim().parse::<libc::pid_t>()
    {
        monitor_pids.insert(pid);
    }
    if let Ok(output) = Command::new("ps")
        .args(["ax", "-o", "pid=,command="])
        .output()
        && output.status.success()
    {
        monitor_pids.extend(parse_monitor_processes(&String::from_utf8_lossy(
            &output.stdout,
        )));
    }

    for pid in monitor_pids
        .into_iter()
        .filter(|pid| process_is_monitor(*pid))
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
        value.status.success() && command_is_monitor(&String::from_utf8_lossy(&value.stdout))
    })
}

fn parse_monitor_processes(input: &str) -> Vec<libc::pid_t> {
    input
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (raw_pid, command) = line.split_once(char::is_whitespace)?;
            command_is_monitor(command)
                .then(|| raw_pid.parse().ok())
                .flatten()
        })
        .collect()
}

fn command_is_monitor(command: &str) -> bool {
    let mut arguments = command.split_whitespace();
    let Some(executable) = arguments.next() else {
        return false;
    };
    let Some(name) = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
    else {
        return false;
    };
    (name == "killswitch" || name.starts_with("killswitch-"))
        && arguments.any(|argument| argument == "--monitor")
}

fn monitor_pid_is_current(pid: u32) -> bool {
    fs::read_to_string(MONITOR_PID_PATH).is_ok_and(|contents| contents.trim() == pid.to_string())
}

fn reconnect_endpoints(
    known_endpoints: &BTreeSet<VpnEndpoint>,
    detected_endpoints: &[VpnEndpoint],
    bootstrap_endpoints: &[VpnEndpoint],
) -> Vec<VpnEndpoint> {
    let mut selected = Vec::new();
    for endpoint in detected_endpoints.iter().chain(bootstrap_endpoints) {
        if selected.len() == MAX_RECONNECT_ENDPOINTS {
            break;
        }
        if endpoint.port == Some(443)
            && matches!(endpoint.transport, Transport::Tcp | Transport::Udp)
            && !known_endpoints.contains(endpoint)
            && !selected.contains(endpoint)
        {
            selected.push(endpoint.clone());
        }
    }
    selected
}

/// Hidden monitor entry point. It always removes a stale tunnel allow rule
/// when detection becomes uncertain. Endpoint exceptions are pinned when the
/// kill switch is enabled; the monitor never learns from later direct sockets.
///
/// # Errors
/// Returns an error if privileges or the persisted monitor configuration is invalid.
pub fn monitor() -> Result<()> {
    check_root()?;
    let config = read_monitor_config()?;
    let known_endpoints: BTreeSet<_> = config.trusted_endpoints.iter().cloned().collect();
    let mut previous = fs::read_to_string("/var/run/killswitch.pf.conf").unwrap_or_default();

    loop {
        let mut info = network::detect_vpn(Verbosity::Normal);
        info.bootstrap_endpoints = if config.reconnect {
            reconnect_endpoints(&known_endpoints, &info.endpoints, &info.bootstrap_endpoints)
        } else {
            Vec::new()
        };
        info.endpoints = known_endpoints.iter().cloned().collect();
        if let Ok(generated) = rules::generate(&info, config.leak, config.local, config.reconnect)
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
        if !monitor_pid_is_current(std::process::id()) {
            return Ok(());
        }
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
        let config = parse_monitor_config(concat!(
            "leak=0\n",
            "local=1\n",
            "reconnect=1\n",
            "manual_endpoint=198.51.100.107\n",
            "trusted_endpoint=any|198.51.100.107|\n",
            "trusted_endpoint=tcp|2001:db8::8|443\n",
        ))
        .unwrap_or(MonitorConfig {
            leak: true,
            local: false,
            reconnect: false,
            manual_endpoint: None,
            trusted_endpoints: Vec::new(),
        });
        assert!(!config.leak);
        assert!(config.local);
        assert!(config.reconnect);
        assert_eq!(
            config.manual_endpoint,
            Some(Ipv4Addr::new(198, 51, 100, 107))
        );
        assert_eq!(config.trusted_endpoints.len(), 2);
        assert_eq!(
            config.trusted_endpoints.get(1),
            Some(&VpnEndpoint {
                address: "2001:db8::8"
                    .parse()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port: Some(443),
                transport: Transport::Tcp,
            })
        );
    }

    #[test]
    fn test_monitor_config_rejects_private_manual_endpoint() {
        assert!(parse_monitor_config("manual_endpoint=192.168.1.1\n").is_err());
    }

    #[test]
    fn test_monitor_process_detection_accepts_renamed_binary() {
        assert!(command_is_monitor(
            "/opt/homebrew/bin/killswitch-ne --monitor"
        ));
        assert!(command_is_monitor("/usr/local/bin/killswitch --monitor"));
        assert!(!command_is_monitor("/usr/local/bin/killswitch --status"));
        assert!(!command_is_monitor("/usr/bin/not-killswitch --monitor"));
    }

    #[test]
    fn test_parse_monitor_processes_finds_all_instances() {
        let processes = concat!(
            " 34249 /opt/homebrew/bin/killswitch-ne --monitor\n",
            " 51068 /opt/homebrew/bin/killswitch-ne --monitor\n",
            " 52000 /usr/local/bin/killswitch --status\n",
        );

        assert_eq!(parse_monitor_processes(processes), [34249, 51068]);
    }

    #[test]
    fn test_monitor_config_rejects_malformed_trusted_endpoint() {
        assert!(parse_monitor_config("trusted_endpoint=tcp|not-an-ip|443\n").is_err());
        assert!(parse_monitor_config("trusted_endpoint=sctp|203.0.113.1|443\n").is_err());
    }

    #[test]
    fn test_reconnect_endpoints_are_bounded_and_exclude_pinned_transport() {
        let pinned = VpnEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 107)),
            port: Some(443),
            transport: Transport::Tcp,
        };
        let detected: Vec<_> = (1..=12)
            .map(|last| VpnEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)),
                port: Some(443),
                transport: Transport::Tcp,
            })
            .collect();
        let ignored = VpnEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100)),
            port: Some(80),
            transport: Transport::Tcp,
        };
        let known = BTreeSet::from([pinned.clone()]);

        let selected = reconnect_endpoints(&known, &[pinned, ignored], &detected);

        assert_eq!(selected.len(), MAX_RECONNECT_ENDPOINTS);
        assert!(selected.iter().all(|endpoint| endpoint.port == Some(443)));
    }
}
