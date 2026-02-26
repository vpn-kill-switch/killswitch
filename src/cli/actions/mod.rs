pub mod run;

use crate::cli::verbosity::Verbosity;
use anyhow::Result;

#[derive(Debug)]
pub enum Action {
    Enable {
        ipv4: Option<String>,
        leak: bool,
        local: bool,
        verbose: Verbosity,
    },
    Disable {
        verbose: Verbosity,
    },
    Status {
        verbose: Verbosity,
    },
    Print {
        ipv4: Option<String>,
        leak: bool,
        local: bool,
        verbose: Verbosity,
    },
    ShowInterfaces {
        verbose: Verbosity,
    },
}

impl Action {
    /// Execute this action
    ///
    /// # Errors
    /// Returns an error if the action execution fails
    pub fn execute(&self) -> Result<()> {
        run::execute(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::verbosity::Verbosity;

    #[test]
    fn test_action_debug_format() {
        let action = Action::Enable {
            ipv4: Some("10.8.0.1".to_string()),
            leak: false,
            local: false,
            verbose: Verbosity::Normal,
        };
        let debug_str = format!("{action:?}");
        assert!(debug_str.contains("Enable"));
        assert!(debug_str.contains("10.8.0.1"));
    }

    #[test]
    fn test_action_variants() {
        let enable = Action::Enable {
            ipv4: None,
            leak: true,
            local: true,
            verbose: Verbosity::Verbose,
        };
        assert!(matches!(enable, Action::Enable { .. }));

        let disable = Action::Disable {
            verbose: Verbosity::Normal,
        };
        assert!(matches!(disable, Action::Disable { .. }));

        let status = Action::Status {
            verbose: Verbosity::Debug,
        };
        assert!(matches!(status, Action::Status { .. }));

        let print = Action::Print {
            ipv4: Some("192.168.1.1".to_string()),
            leak: false,
            local: false,
            verbose: Verbosity::Normal,
        };
        assert!(matches!(print, Action::Print { .. }));
    }
}
