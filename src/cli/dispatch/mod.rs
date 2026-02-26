use crate::cli::{actions::Action, verbosity::Verbosity};
use anyhow::Result;
use clap::ArgMatches;

/// Convert CLI arguments to an Action
///
/// # Errors
/// Returns an error if no action is specified or if arguments are invalid
pub fn handler(matches: &ArgMatches, verbose: Verbosity) -> Result<Action> {
    let enable = matches.get_flag("enable");
    let disable = matches.get_flag("disable");
    let status = matches.get_flag("status");
    let print = matches.get_flag("print");

    if enable {
        let ipv4 = matches.get_one::<String>("ipv4").map(String::from);
        let leak = matches.get_flag("leak");
        let local = matches.get_flag("local");

        if print {
            Ok(Action::Print {
                ipv4,
                leak,
                local,
                verbose,
            })
        } else {
            Ok(Action::Enable {
                ipv4,
                leak,
                local,
                verbose,
            })
        }
    } else if disable {
        Ok(Action::Disable { verbose })
    } else if status {
        Ok(Action::Status { verbose })
    } else if print {
        let ipv4 = matches.get_one::<String>("ipv4").map(String::from);
        let leak = matches.get_flag("leak");
        let local = matches.get_flag("local");
        Ok(Action::Print {
            ipv4,
            leak,
            local,
            verbose,
        })
    } else {
        Ok(Action::ShowInterfaces { verbose })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::commands;

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_handler_enable() {
        use crate::cli::verbosity::Verbosity;
        let matches = commands::new().get_matches_from(vec!["killswitch", "--enable"]);
        let action = handler(&matches, Verbosity::Normal).unwrap();
        assert!(matches!(action, Action::Enable { .. }));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_handler_disable() {
        use crate::cli::verbosity::Verbosity;
        let matches = commands::new().get_matches_from(vec!["killswitch", "-d"]);
        let action = handler(&matches, Verbosity::Normal).unwrap();
        assert!(matches!(action, Action::Disable { .. }));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_handler_status() {
        use crate::cli::verbosity::Verbosity;
        let matches = commands::new().get_matches_from(vec!["killswitch", "--status"]);
        let action = handler(&matches, Verbosity::Normal).unwrap();
        assert!(matches!(action, Action::Status { .. }));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_handler_print() {
        use crate::cli::verbosity::Verbosity;
        let matches = commands::new().get_matches_from(vec!["killswitch", "--print"]);
        let action = handler(&matches, Verbosity::Normal).unwrap();
        assert!(matches!(action, Action::Print { .. }));
    }

    #[allow(clippy::unwrap_used, clippy::panic)]
    #[test]
    fn test_handler_enable_with_options() {
        use crate::cli::verbosity::Verbosity;
        let matches = commands::new().get_matches_from(vec![
            "killswitch",
            "-e",
            "--local",
            "--leak",
            "--ipv4",
            "10.0.0.1",
        ]);
        let action = handler(&matches, Verbosity::Normal).unwrap();
        if let Action::Enable {
            ipv4,
            leak,
            local,
            verbose: _,
        } = action
        {
            assert_eq!(ipv4, Some("10.0.0.1".to_string()));
            assert!(leak);
            assert!(local);
        } else {
            panic!("Expected Action::Enable");
        }
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_handler_no_action() {
        use crate::cli::verbosity::Verbosity;
        let matches = commands::new().get_matches_from(vec!["killswitch"]);
        let result = handler(&matches, Verbosity::Normal);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Action::ShowInterfaces { .. }));
    }
}
