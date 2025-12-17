use crate::cli::telemetry::Verbosity;
use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

const PF_ANCHOR: &str = "killswitch";
const PF_RULES_PATH: &str = "/etc/pf.anchors/killswitch";
const PF_CONF: &str = "/etc/pf.conf";

pub fn apply_rules(rules: &str, verbose: Verbosity) -> Result<()> {
    if verbose.is_debug() {
        eprintln!("  Writing rules to {PF_RULES_PATH}");
    }

    // Ensure /etc/pf.anchors directory exists
    let anchors_dir = Path::new("/etc/pf.anchors");
    if !anchors_dir.exists() {
        fs::create_dir_all(anchors_dir).context("Failed to create pf.anchors directory")?;
    }

    // Write rules to file
    let mut file =
        fs::File::create(PF_RULES_PATH).context("Failed to create killswitch rules file")?;
    file.write_all(rules.as_bytes())
        .context("Failed to write rules")?;

    if verbose.is_debug() {
        eprintln!("  Rules written");
    }

    // Check if anchor is already in pf.conf
    ensure_anchor_in_conf(verbose)?;

    // Load the anchor
    load_anchor(verbose)?;

    // Enable pf if not already enabled
    enable_pf(verbose)?;

    if verbose.is_verbose() {
        eprintln!("  Firewall rules applied");
    }

    Ok(())
}

fn ensure_anchor_in_conf(verbose: Verbosity) -> Result<()> {
    let conf_content = fs::read_to_string(PF_CONF).context("Failed to read pf.conf")?;

    let anchor_line = format!("anchor \"{PF_ANCHOR}\"");
    let load_anchor_line = format!("load anchor \"{PF_ANCHOR}\" from \"{PF_RULES_PATH}\"");

    if conf_content.contains(&anchor_line) && conf_content.contains(&load_anchor_line) {
        if verbose.is_debug() {
            eprintln!("  Anchor already in pf.conf");
        }
        return Ok(());
    }

    if verbose.is_verbose() {
        eprintln!("  Adding anchor to pf.conf");
    }

    // Backup original conf
    let backup_path = format!("{PF_CONF}.backup");
    fs::copy(PF_CONF, &backup_path).context("Failed to backup pf.conf")?;

    // Add anchor lines if not present
    let mut new_content = conf_content.clone();

    if !conf_content.contains(&anchor_line) {
        // Add anchor line after the last existing anchor or at the beginning
        if let Some(pos) = conf_content.rfind("anchor") {
            let line_end = conf_content[pos..]
                .find('\n')
                .map_or(conf_content.len(), |i| pos + i + 1);
            new_content.insert_str(line_end, &format!("{anchor_line}\n"));
        } else {
            new_content.insert_str(0, &format!("{anchor_line}\n"));
        }
    }

    if !conf_content.contains(&load_anchor_line) {
        // Add load anchor line after the last existing load anchor or at the end
        if let Some(pos) = conf_content.rfind("load anchor") {
            let line_end = conf_content[pos..]
                .find('\n')
                .map_or(conf_content.len(), |i| pos + i + 1);
            new_content.insert_str(line_end, &format!("{load_anchor_line}\n"));
        } else {
            new_content.push('\n');
            new_content.push_str(&load_anchor_line);
            new_content.push('\n');
        }
    }

    fs::write(PF_CONF, new_content).context("Failed to write updated pf.conf")?;

    if verbose.is_debug() {
        eprintln!("  pf.conf updated");
    }

    Ok(())
}

fn load_anchor(verbose: Verbosity) -> Result<()> {
    if verbose.is_debug() {
        eprintln!("  Loading anchor");
    }

    let output = Command::new("pfctl")
        .args(["-a", PF_ANCHOR, "-f", PF_RULES_PATH])
        .output()
        .context("Failed to execute pfctl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to load anchor: {stderr}");
    }

    if verbose.is_debug() {
        eprintln!("  Anchor loaded");
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
        eprintln!("  Flushing anchor rules");
    }

    let output = Command::new("pfctl")
        .args(["-a", PF_ANCHOR, "-F", "all"])
        .output()
        .context("Failed to execute pfctl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to flush anchor: {stderr}");
    }

    // Remove rules file
    if Path::new(PF_RULES_PATH).exists() {
        if verbose.is_debug() {
            eprintln!("  Removing rules file");
        }
        fs::remove_file(PF_RULES_PATH).context("Failed to remove rules file")?;
    }

    if verbose.is_verbose() {
        eprintln!("  Firewall rules removed");
    }

    Ok(())
}

pub fn status() -> Result<String> {
    let output = Command::new("pfctl")
        .args(["-s", "all", "-a", PF_ANCHOR])
        .output()
        .context("Failed to execute pfctl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to get status: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.trim().is_empty() {
        Ok("VPN kill switch: DISABLED".to_string())
    } else {
        Ok(format!("VPN kill switch: ENABLED\n\n{stdout}"))
    }
}
