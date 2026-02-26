use crate::cli::verbosity::Verbosity;
use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

const PF_RULES_PATH: &str = "/tmp/killswitch.pf.conf";
const PF_SYSTEM_CONF: &str = "/etc/pf.conf";

pub fn apply_rules(rules: &str, verbose: Verbosity) -> Result<()> {
    if verbose.is_debug() {
        eprintln!("  Writing rules to {PF_RULES_PATH}");
    }

    let mut file =
        fs::File::create(PF_RULES_PATH).context("Failed to create killswitch rules file")?;
    file.write_all(rules.as_bytes())
        .context("Failed to write rules")?;

    if verbose.is_debug() {
        eprintln!("  Rules written");
    }

    enable_pf(verbose)?;

    // Flush all rules and load killswitch rules
    let output = Command::new("pfctl")
        .args(["-Fa", "-f", PF_RULES_PATH])
        .output()
        .context("Failed to execute pfctl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to load rules: {stderr}");
    }

    if verbose.is_verbose() {
        eprintln!("  Firewall rules applied");
    }

    Ok(())
}

fn enable_pf(verbose: Verbosity) -> Result<()> {
    if verbose.is_debug() {
        eprintln!("  Enabling pf");
    }

    let output = Command::new("pfctl")
        .args(["-e"])
        .output()
        .context("Failed to execute pfctl -e")?;

    // pfctl -e returns exit code 1 if pf is already enabled, which is fine
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("already enabled") {
            bail!("Failed to enable pf: {stderr}");
        }
    }

    if verbose.is_debug() {
        eprintln!("  pf enabled");
    }

    Ok(())
}

pub fn disable(verbose: Verbosity) -> Result<()> {
    if verbose.is_debug() {
        eprintln!("  Restoring system pf rules");
    }

    // Clean up any leftover anchor references in pf.conf from older versions
    cleanup_legacy_anchor(verbose)?;

    enable_pf(verbose)?;

    // Flush all and reload system default rules
    let output = Command::new("pfctl")
        .args(["-Fa", "-f", PF_SYSTEM_CONF])
        .output()
        .context("Failed to execute pfctl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to restore system rules: {stderr}");
    }

    // Clean up rules file
    if Path::new(PF_RULES_PATH).exists() {
        fs::remove_file(PF_RULES_PATH).context("Failed to remove rules file")?;
    }

    if verbose.is_verbose() {
        eprintln!("  Firewall rules removed");
    }

    Ok(())
}

fn cleanup_legacy_anchor(verbose: Verbosity) -> Result<()> {
    let conf = fs::read_to_string(PF_SYSTEM_CONF).context("Failed to read pf.conf")?;
    if !conf.contains("killswitch") {
        return Ok(());
    }

    if verbose.is_verbose() {
        eprintln!("  Removing legacy killswitch anchor from pf.conf");
    }

    let cleaned: String = conf
        .lines()
        .filter(|line| !line.contains("killswitch"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    fs::write(PF_SYSTEM_CONF, cleaned).context("Failed to clean pf.conf")?;
    Ok(())
}

pub fn status() -> Result<String> {
    let output = Command::new("pfctl")
        .args(["-sr"])
        .output()
        .context("Failed to execute pfctl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to get status: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // If killswitch rules file exists and pf has rules beyond defaults, it's enabled
    let has_killswitch = Path::new(PF_RULES_PATH).exists()
        && stdout
            .lines()
            .any(|line| !line.is_empty() && !line.contains("ALTQ"));

    if has_killswitch {
        Ok(format!("VPN kill switch: ENABLED\n\n{stdout}"))
    } else {
        Ok("VPN kill switch: DISABLED".to_string())
    }
}
