use crate::cli::actions::Action;
use anyhow::Result;

pub fn handler(matches: &clap::ArgMatches) -> Result<Action> {
    matches.subcommand_name();
    {
        let action = Action::Default {
            enable: matches.get_one("enable").copied().unwrap_or(false),
            disable: matches.get_one("disable").copied().unwrap_or(false),
            ipv4: matches
                .get_one::<String>("ipv4")
                .map(|s: &String| s.to_string()),
            leak: matches.get_one("leak").copied().unwrap_or(false),
            local: matches.get_one("local").copied().unwrap_or(false),
            print: matches.get_one("print").copied().unwrap_or(false),
        };

        Ok(action)
    }
}
