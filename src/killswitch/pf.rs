use crate::cli::verbosity::Verbosity;
use anyhow::{Context, Result, bail};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

const ANCHOR: &str = "killswitch";
const PF_RULES_PATH: &str = "/var/run/killswitch.pf.conf";
const PF_SYSTEM_CONF: &str = "/etc/pf.conf";
const PF_SYSTEM_BACKUP: &str = "/etc/pf.conf.killswitch.backup";
const PF_TOKEN_PATH: &str = "/var/run/killswitch.pf.token";
const ANCHOR_MARKER: &str = "# killswitch anchor (managed by killswitch)";

pub fn apply_rules(
    rules: &str,
    physical_addresses: &[IpAddr],
    terminate_direct_states: bool,
    verbose: Verbosity,
) -> Result<()> {
    ensure_anchor_reference(verbose)?;
    write_rules(rules)?;
    validate_rules(PF_RULES_PATH)?;
    ensure_pf_enabled(verbose)?;

    run_pfctl(
        &["-a", ANCHOR, "-f", PF_RULES_PATH],
        "load killswitch anchor",
    )?;

    if terminate_direct_states {
        kill_states_from(physical_addresses, verbose)?;
    }
    if verbose.is_verbose() {
        eprintln!("  Loaded PF anchor: {ANCHOR}");
    }
    Ok(())
}

fn write_rules(rules: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let mut file = options
        .open(PF_RULES_PATH)
        .context("Failed to create the killswitch anchor file")?;
    file.write_all(rules.as_bytes())
        .context("Failed to write the killswitch anchor file")?;
    file.sync_all()
        .context("Failed to sync the killswitch anchor file")?;
    Ok(())
}

fn validate_rules(path: &str) -> Result<()> {
    run_pfctl(
        &["-n", "-a", ANCHOR, "-f", path],
        "validate killswitch anchor",
    )?;
    Ok(())
}

fn ensure_pf_enabled(verbose: Verbosity) -> Result<()> {
    if Path::new(PF_TOKEN_PATH).exists() {
        return Ok(());
    }
    let output = Command::new("pfctl")
        .arg("-E")
        .output()
        .context("Failed to execute pfctl -E")?;
    if !output.status.success() {
        bail!(
            "Failed to acquire a PF enable reference: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let token = parse_pf_token(&combined)
        .context("pfctl -E succeeded but did not return an enable-reference token")?;
    fs::write(PF_TOKEN_PATH, format!("{token}\n"))
        .context("Failed to save the PF enable-reference token")?;
    fs::set_permissions(PF_TOKEN_PATH, fs::Permissions::from_mode(0o600))
        .context("Failed to protect the PF token file")?;
    if verbose.is_debug() {
        eprintln!("  Acquired PF enable reference");
    }
    Ok(())
}

fn parse_pf_token(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (_, value) = line.split_once("Token")?;
        let token = value.trim_start_matches([' ', ':']).trim();
        (!token.is_empty()).then(|| token.to_string())
    })
}

fn kill_states_from(addresses: &[IpAddr], verbose: Verbosity) -> Result<()> {
    for address in addresses {
        if verbose.is_debug() {
            eprintln!("  Terminating pre-existing direct states from {address}");
        }
        run_pfctl(
            &["-k", &address.to_string()],
            "terminate pre-existing direct PF states",
        )?;
    }
    Ok(())
}

fn ensure_anchor_reference(verbose: Verbosity) -> Result<()> {
    let config = fs::read_to_string(PF_SYSTEM_CONF).context("Failed to read /etc/pf.conf")?;
    let updated = normalize_anchor_reference(&config);
    if updated == config {
        return activate_anchor_reference_if_needed(verbose);
    }

    if verbose.is_verbose() {
        eprintln!("  Placing the killswitch attachment point before other PF filter anchors");
    }
    if !Path::new(PF_SYSTEM_BACKUP).exists() {
        fs::copy(PF_SYSTEM_CONF, PF_SYSTEM_BACKUP)
            .context("Failed to create the one-time /etc/pf.conf backup")?;
    }

    let temporary = temporary_pf_conf_path();
    let result = install_pf_conf(&temporary, &updated);
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result?;

    // Reloading the main configuration is required only once to create the
    // anchor attachment point.  Unlike the old implementation this does not
    // use -F or flush all anchors/states.
    run_pfctl(
        &["-f", PF_SYSTEM_CONF],
        "activate killswitch anchor reference",
    )?;
    verify_live_anchor_reference()
}

fn activate_anchor_reference_if_needed(verbose: Verbosity) -> Result<()> {
    let live = run_pfctl(&["-sr"], "inspect the main PF ruleset")?;
    if has_anchor_reference(&live) {
        return Ok(());
    }
    if verbose.is_verbose() {
        eprintln!("  Activating the configured killswitch anchor attachment point");
    }
    run_pfctl(
        &["-f", PF_SYSTEM_CONF],
        "activate configured killswitch anchor reference",
    )?;
    verify_live_anchor_reference()
}

fn verify_live_anchor_reference() -> Result<()> {
    let live = run_pfctl(&["-sr"], "verify the killswitch anchor attachment point")?;
    if !has_anchor_reference(&live) {
        bail!("The killswitch anchor is configured but is not attached to the live PF ruleset");
    }
    Ok(())
}

fn install_pf_conf(temporary: &Path, contents: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o644);
    let mut file = options
        .open(temporary)
        .context("Failed to create a temporary PF configuration")?;
    file.write_all(contents.as_bytes())
        .context("Failed to write a temporary PF configuration")?;
    file.sync_all()
        .context("Failed to sync a temporary PF configuration")?;
    let path = temporary
        .to_str()
        .context("Temporary PF configuration path is not valid UTF-8")?;
    run_pfctl(&["-n", "-f", path], "validate updated /etc/pf.conf")?;
    fs::rename(temporary, PF_SYSTEM_CONF).context("Failed to install updated /etc/pf.conf")?;
    Ok(())
}

fn temporary_pf_conf_path() -> PathBuf {
    PathBuf::from(format!("/etc/.pf.conf.killswitch.{}", std::process::id()))
}

fn has_anchor_reference(contents: &str) -> bool {
    contents.lines().any(is_killswitch_anchor_line)
}

fn is_killswitch_anchor_line(line: &str) -> bool {
    let code = line.split('#').next().unwrap_or_default().trim();
    code.starts_with("anchor") && code.contains(&format!("\"{ANCHOR}\""))
}

fn is_filter_anchor_line(line: &str) -> bool {
    let code = line.split('#').next().unwrap_or_default().trim();
    code.starts_with("anchor ") && !is_killswitch_anchor_line(line)
}

fn normalize_anchor_reference(contents: &str) -> String {
    let mut lines = Vec::new();
    let mut inserted = false;
    for line in contents.lines() {
        if is_killswitch_anchor_line(line) || line.trim() == ANCHOR_MARKER {
            continue;
        }
        if !inserted && is_filter_anchor_line(line) {
            lines.push(ANCHOR_MARKER);
            lines.push("anchor \"killswitch\"");
            inserted = true;
        }
        lines.push(line);
    }
    if !inserted {
        if lines.last().is_some_and(|line| !line.is_empty()) {
            lines.push("");
        }
        lines.push(ANCHOR_MARKER);
        lines.push("anchor \"killswitch\"");
    }
    let mut normalized = lines.join("\n");
    normalized.push('\n');
    normalized
}

fn run_pfctl(args: &[&str], action: &str) -> Result<String> {
    let output = Command::new("pfctl")
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute pfctl while trying to {action}"))?;
    if !output.status.success() {
        bail!(
            "Failed to {action}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn disable(verbose: Verbosity) -> Result<()> {
    run_pfctl(
        &["-a", ANCHOR, "-F", "rules"],
        "flush killswitch anchor rules",
    )?;

    if let Ok(token) = fs::read_to_string(PF_TOKEN_PATH) {
        let token = token.trim();
        if !token.is_empty() {
            run_pfctl(&["-X", token], "release the killswitch PF enable reference")?;
        }
        fs::remove_file(PF_TOKEN_PATH).context("Failed to remove the PF token file")?;
    }
    if Path::new(PF_RULES_PATH).exists() {
        fs::remove_file(PF_RULES_PATH).context("Failed to remove the runtime anchor file")?;
    }
    if verbose.is_verbose() {
        eprintln!("  Flushed only the killswitch anchor; other PF anchors were preserved");
    }
    Ok(())
}

pub fn status() -> Result<String> {
    let main = run_pfctl(&["-sr"], "read the main PF ruleset")?;
    if !has_anchor_reference(&main) {
        return Ok("VPN kill switch: DISABLED (anchor is not attached)".to_string());
    }
    let rules = run_pfctl(&["-a", ANCHOR, "-sr"], "read killswitch anchor rules")?;
    if rules.trim().is_empty() {
        return Ok("VPN kill switch: DISABLED".to_string());
    }
    let counters = run_pfctl(&["-a", ANCHOR, "-vvsr"], "read killswitch counters")?;
    Ok(format!("VPN kill switch: ENABLED\n\n{counters}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_reference_detection() {
        assert!(has_anchor_reference("anchor \"killswitch\"\n"));
        assert!(!has_anchor_reference("# anchor \"killswitch\"\n"));
        assert!(!has_anchor_reference("anchor \"com.apple/*\"\n"));
    }

    #[test]
    fn test_anchor_reference_is_added_before_system_filter_anchors() {
        let original = "scrub-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\n";
        let updated = normalize_anchor_reference(original);
        assert!(updated.contains(ANCHOR_MARKER));
        let killswitch = updated
            .lines()
            .position(|line| line == "anchor \"killswitch\"");
        let apple = updated
            .lines()
            .position(|line| line == "anchor \"com.apple/*\"");
        assert!(
            killswitch
                .zip(apple)
                .is_some_and(|(left, right)| left < right)
        );
    }

    #[test]
    fn test_anchor_reference_is_reordered_idempotently() {
        let original = "anchor \"com.apple/*\"\nanchor \"killswitch\"\n";
        let updated = normalize_anchor_reference(original);
        assert_eq!(normalize_anchor_reference(&updated), updated);
        assert_eq!(updated.matches("anchor \"killswitch\"").count(), 1);
    }

    #[test]
    fn test_pf_enable_token_parsing() {
        assert_eq!(
            parse_pf_token("pf enabled\nToken : 123456789\n"),
            Some("123456789".to_string())
        );
        assert_eq!(parse_pf_token("pf enabled"), None);
    }

    #[test]
    fn test_anchor_reload_and_disable_are_scoped() {
        let reload = ["-a", ANCHOR, "-f", PF_RULES_PATH];
        let disable = ["-a", ANCHOR, "-F", "rules"];
        assert_eq!(reload[0..2], ["-a", "killswitch"]);
        assert_eq!(disable, ["-a", "killswitch", "-F", "rules"]);
        assert!(!reload.contains(&"-Fa"));
        assert!(!disable.contains(&"all"));
    }

    #[test]
    fn test_rules_path_is_not_world_writable_tmp() {
        assert!(PF_RULES_PATH.starts_with("/var/run/"));
        assert!(!PF_RULES_PATH.starts_with("/tmp/"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires root and intentionally validates only; run manually on macOS"]
    fn test_real_pf_parser_integration() {
        let rules = concat!(
            "pass on lo0 all tag KILLSWITCH_ALLOWED keep state\n",
            "pass out on en0 inet proto tcp from any to 203.0.113.1 port 443 ",
            "flags any tag KILLSWITCH_ALLOWED keep state (if-bound)\n",
            "pass out on en0 inet proto udp from any to 203.0.113.1 port 443 ",
            "tag KILLSWITCH_ALLOWED keep state (if-bound)\n",
            "block drop out quick all ! tagged KILLSWITCH_ALLOWED\n",
        );
        let path = format!("/tmp/killswitch-test-{}.pf", std::process::id());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        if let Ok(mut file) = options.open(&path)
            && file.write_all(rules.as_bytes()).is_ok()
        {
            let result = validate_rules(&path);
            let _ = fs::remove_file(&path);
            assert!(result.is_ok());
        }
    }
}
