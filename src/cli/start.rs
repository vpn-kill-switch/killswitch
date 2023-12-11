use crate::cli::{actions::Action, commands, dispatch::handler};
use anyhow::Result;

/// Start the CLI
pub fn start() -> Result<Action> {
    let matches = commands::new().get_matches();

    let action = handler(&matches)?;

    Ok(action)
}
