use anyhow::Result;
use killswitch::cli::{actions, actions::Action, start};

// Main function
fn main() -> Result<()> {
    // Start the program
    let action = start()?;

    // Handle the action
    match action {
        _ => actions::default::handle(action)?,
    }

    Ok(())
}
