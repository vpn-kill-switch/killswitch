use crate::cli::actions::Action;
use crate::killswitch;
use anyhow::Result;

/// Handle the create action
pub fn handle(action: Action) -> Result<()> {
    match action {
        Action::Default {
            enable,
            disable,
            ipv4,
            leak,
            local,
            print,
        } => {
            let info = killswitch::default()?;
            println!("{}", info);
        }
    }

    Ok(())
}
