use clap::{
    Arg, ArgAction, ColorChoice, Command,
    builder::styling::{AnsiColor, Effects, Styles},
};

pub mod built_info {
    #![allow(clippy::doc_markdown)]
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[must_use]
pub fn new() -> Command {
    let styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default());

    let git_hash = built_info::GIT_COMMIT_HASH.unwrap_or("unknown");
    let long_version: &'static str =
        Box::leak(format!("{} - {}", env!("CARGO_PKG_VERSION"), git_hash).into_boxed_str());

    Command::new(env!("CARGO_PKG_NAME"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .color(ColorChoice::Auto)
        .long_version(long_version)
        .styles(styles)
        .arg(
            Arg::new("enable")
                .short('e')
                .long("enable")
                .help("Enable the VPN kill switch")
                .action(ArgAction::SetTrue)
                .conflicts_with("disable"),
        )
        .arg(
            Arg::new("disable")
                .short('d')
                .long("disable")
                .help("Disable the VPN kill switch")
                .action(ArgAction::SetTrue)
                .conflicts_with("enable"),
        )
        .arg(
            Arg::new("status")
                .short('s')
                .long("status")
                .help("Show kill switch status")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["enable", "disable"]),
        )
        .arg(
            Arg::new("ipv4")
                .long("ipv4")
                .help("VPN peer IPv4 address (auto-detected if not specified)")
                .value_name("IP")
                .conflicts_with_all(["disable", "status"]),
        )
        .arg(
            Arg::new("leak")
                .long("leak")
                .help("Allow ICMP (ping) and DNS requests outside the VPN")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["disable", "status"]),
        )
        .arg(
            Arg::new("local")
                .long("local")
                .help("Allow local network traffic")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["disable", "status"]),
        )
        .arg(
            Arg::new("print")
                .short('p')
                .long("print")
                .help("Print the pf firewall rules without applying them")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["disable", "status"]),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Increase output verbosity (-v: verbose, -vv: debug)")
                .action(ArgAction::Count),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_command() {
        new().debug_assert();
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_command_metadata() {
        let cmd = new();
        assert_eq!(cmd.get_name(), env!("CARGO_PKG_NAME"));
        assert_eq!(cmd.get_version().unwrap(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_enable_flag() {
        let matches = new().get_matches_from(vec!["killswitch", "--enable"]);
        assert!(matches.get_flag("enable"));
    }

    #[test]
    fn test_disable_flag() {
        let matches = new().get_matches_from(vec!["killswitch", "-d"]);
        assert!(matches.get_flag("disable"));
    }

    #[test]
    fn test_verbose_count() {
        let matches = new().get_matches_from(vec!["killswitch", "-vvv"]);
        assert_eq!(matches.get_count("verbose"), 3);
    }
}
