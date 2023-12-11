use clap::{
    builder::styling::{AnsiColor, Effects, Styles},
    Arg, ColorChoice, Command,
};
use std::env;

pub fn new() -> Command {
    let styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default());

    Command::new("killswitch")
        .about("VPN killswitch")
        .version(env!("CARGO_PKG_VERSION"))
        .color(ColorChoice::Auto)
        .styles(styles)
        .arg(
            Arg::new("enable")
                .short('e')
                .long("enable")
                .help("Enable the killswitch")
                .num_args(0)
                .conflicts_with("disable"),
        )
        .arg(
            Arg::new("disable")
                .short('d')
                .long("disable")
                .help("Disable the killswitch")
                .num_args(0)
                .conflicts_with("enable"),
        )
        .arg(
            Arg::new("ipv4")
                .long("ipv4")
                .help("VPN peer IPv4 address, (killswitch tries to find it automatically)")
                .conflicts_with("disable"),
        )
        .arg(
            Arg::new("leak")
                .long("leak")
                .help("Allow ICMP traffic (ping) and DNS requests outside the VPN")
                .num_args(0)
                .conflicts_with("disable"),
        )
        .arg(
            Arg::new("local")
                .long("local")
                .help("Allow local network traffic")
                .num_args(0)
                .conflicts_with("disable"),
        )
        .arg(
            Arg::new("print")
                .long("print")
                .short('p')
                .num_args(0)
                .help("Print the pf rules"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let command = new();

        assert_eq!(command.get_name(), "killswitch");

        assert_eq!(
            command.get_version().unwrap().to_string(),
            env!("CARGO_PKG_VERSION")
        );
    }
}
