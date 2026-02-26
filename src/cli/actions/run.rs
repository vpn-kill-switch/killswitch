use super::Action;
use crate::killswitch;
use anyhow::Result;

/// Execute the given action
///
/// # Errors
/// Returns an error if the killswitch operation fails
pub fn execute(action: &Action) -> Result<()> {
    match action {
        Action::Enable {
            ipv4,
            leak,
            local,
            verbose,
        } => {
            if verbose.is_verbose() {
                eprintln!("Enabling VPN kill switch...");
                if let Some(ip) = ipv4 {
                    eprintln!("  VPN gateway: {ip}");
                }
                if *leak {
                    eprintln!("  Allowing ICMP and DNS");
                }
                if *local {
                    eprintln!("  Allowing local network");
                }
            }
            killswitch::enable(*leak, *local, ipv4.as_deref(), *verbose)?;
            println!("✓ VPN kill switch enabled");
        }

        Action::Disable { verbose } => {
            if verbose.is_verbose() {
                eprintln!("Disabling VPN kill switch...");
            }
            killswitch::disable(*verbose)?;
            println!("✓ VPN kill switch disabled");
        }

        Action::Status { verbose } => {
            if verbose.is_verbose() {
                eprintln!("Checking kill switch status...");
            }
            let status = killswitch::status()?;
            println!("{status}");
        }

        Action::Print {
            ipv4,
            leak,
            local,
            verbose,
        } => {
            if verbose.is_verbose() {
                eprintln!("Generating pf rules...");
            }
            let rules = killswitch::generate_rules(*leak, *local, ipv4.as_deref(), *verbose)?;
            println!("{rules}");
        }

        Action::ShowInterfaces { verbose } => {
            let output = killswitch::show_interfaces(*verbose)?;
            print!("{output}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::verbosity::Verbosity;

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_action_print_execution() {
        // Print action should not require root privileges
        let action = Action::Print {
            ipv4: Some("203.0.113.1".to_string()),
            leak: false,
            local: false,
            verbose: Verbosity::Normal,
        };

        // Should succeed without root
        let result = execute(&action);
        assert!(result.is_ok());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_action_print_with_options() {
        let action = Action::Print {
            ipv4: Some("198.51.100.1".to_string()),
            leak: true,
            local: true,
            verbose: Verbosity::Normal,
        };

        let result = execute(&action);
        assert!(result.is_ok());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_action_print_rejects_private_ip() {
        let action = Action::Print {
            ipv4: Some("10.8.0.1".to_string()),
            leak: false,
            local: false,
            verbose: Verbosity::Normal,
        };

        let result = execute(&action);
        assert!(result.is_err());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_action_enable_requires_root() {
        let action = Action::Enable {
            ipv4: Some("10.8.0.1".to_string()),
            leak: false,
            local: false,
            verbose: Verbosity::Normal,
        };

        // Should fail without root (unless running as root)
        let result = execute(&action);
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("root privileges"));
        }
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_action_disable_requires_root() {
        let action = Action::Disable {
            verbose: Verbosity::Normal,
        };

        let result = execute(&action);
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("root privileges"));
        }
    }
}
