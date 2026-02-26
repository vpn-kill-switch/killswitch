use crate::cli::{commands, dispatch, verbosity};
use anyhow::Result;

/// Start the CLI application
///
/// # Errors
/// Returns an error if:
/// - Argument dispatching fails
/// - Action execution fails
pub fn start() -> Result<()> {
    let matches = commands::new().get_matches();

    let verbosity_count = matches.get_count("verbose");
    let verbosity = verbosity::Verbosity::from(verbosity_count);

    let action = dispatch::handler(&matches, verbosity)?;
    action.execute()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_start_compiles() {
        // The start function is tested via integration
        // This just verifies the module compiles
    }
}
