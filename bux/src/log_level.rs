//! libkrun log-verbosity enum, decoupled from the Unix-only [`crate::vm`]
//! module so that it can travel through cross-platform config types
//! (`VmConfig`, serialisation, CLI) on any target.

use serde::{Deserialize, Serialize};

/// Log verbosity level for libkrun.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(u32)]
pub enum LogLevel {
    /// Logging disabled.
    Off = 0,
    /// Errors only.
    Error = 1,
    /// Errors and warnings.
    Warn = 2,
    /// Errors, warnings, and informational messages.
    #[default]
    Info = 3,
    /// Verbose debug output.
    Debug = 4,
    /// Maximum verbosity.
    Trace = 5,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        })
    }
}

/// Error returned when parsing an invalid [`LogLevel`] string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLogLevelError(pub String);

impl std::fmt::Display for ParseLogLevelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown log level: {}", self.0)
    }
}

impl std::error::Error for ParseLogLevelError {}

impl std::str::FromStr for LogLevel {
    type Err = ParseLogLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(ParseLogLevelError(s.to_owned())),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    reason = "tests may unwrap and omit docs"
)]
mod tests {
    use super::*;

    #[test]
    fn log_level_display_roundtrip() {
        let levels = [
            LogLevel::Off,
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ];
        for level in levels {
            let s = level.to_string();
            let parsed: LogLevel = s.parse().expect("parse failed");
            assert_eq!(parsed, level);
        }
    }

    #[test]
    fn log_level_parse_case_insensitive() {
        assert_eq!("INFO".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("Debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert!("invalid".parse::<LogLevel>().is_err());
    }

    #[test]
    fn log_level_default_is_info() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }
}
