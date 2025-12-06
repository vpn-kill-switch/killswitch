/// Verbosity level for output
#[derive(Debug, Clone, Copy)]
pub enum Verbosity {
    Normal,
    Verbose,
    Debug,
}

impl From<u8> for Verbosity {
    fn from(count: u8) -> Self {
        match count {
            0 => Self::Normal,
            1 => Self::Verbose,
            _ => Self::Debug,
        }
    }
}

impl Verbosity {
    /// Check if verbose output should be shown
    #[must_use]
    pub const fn is_verbose(self) -> bool {
        matches!(self, Self::Verbose | Self::Debug)
    }

    /// Check if debug output should be shown
    #[must_use]
    pub const fn is_debug(self) -> bool {
        matches!(self, Self::Debug)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verbosity_from_count() {
        assert!(matches!(Verbosity::from(0), Verbosity::Normal));
        assert!(matches!(Verbosity::from(1), Verbosity::Verbose));
        assert!(matches!(Verbosity::from(2), Verbosity::Debug));
        assert!(matches!(Verbosity::from(3), Verbosity::Debug));
        assert!(matches!(Verbosity::from(10), Verbosity::Debug));
    }

    #[test]
    fn test_verbosity_is_verbose() {
        assert!(!Verbosity::Normal.is_verbose());
        assert!(Verbosity::Verbose.is_verbose());
        assert!(Verbosity::Debug.is_verbose());
    }

    #[test]
    fn test_verbosity_is_debug() {
        assert!(!Verbosity::Normal.is_debug());
        assert!(!Verbosity::Verbose.is_debug());
        assert!(Verbosity::Debug.is_debug());
    }
}
