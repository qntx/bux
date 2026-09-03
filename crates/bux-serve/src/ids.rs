//! Tenant and agent identifiers.
//!
//! `-` is the separator in formatted names and is not in the id alphabet.
//! That keeps [`sandbox_name`] and [`workspace_volume_name`] injective.

const TENANT_LEN: std::ops::RangeInclusive<usize> = 1..=32;
const AGENT_LEN: std::ops::RangeInclusive<usize> = 1..=64;

/// Invalid tenant or agent identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// `tenant_id` failed the alphabet or length check.
    #[error("invalid tenant_id {0:?}: ids are [A-Za-z0-9._], tenant 1..=32, agent 1..=64")]
    Tenant(String),
    /// `agent_id` failed the alphabet or length check.
    #[error("invalid agent_id {0:?}: ids are [A-Za-z0-9._], tenant 1..=32, agent 1..=64")]
    Agent(String),
}

const fn is_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '_'
}

fn id_ok(id: &str, len: std::ops::RangeInclusive<usize>) -> bool {
    len.contains(&id.len()) && id.chars().all(is_id_char)
}

/// Check a tenant id (`[A-Za-z0-9._]`, 1..=32).
///
/// # Errors
///
/// Returns [`IdError::Tenant`] when the id is empty, too long, or contains a
/// character outside the alphabet (including `-`).
pub fn validate_tenant_id(id: &str) -> Result<(), IdError> {
    if id_ok(id, TENANT_LEN) {
        Ok(())
    } else {
        Err(IdError::Tenant(id.to_owned()))
    }
}

/// Check an agent id (`[A-Za-z0-9._]`, 1..=64).
///
/// # Errors
///
/// Returns [`IdError::Agent`] when the id is empty, too long, or contains a
/// character outside the alphabet (including `-`).
pub fn validate_agent_id(id: &str) -> Result<(), IdError> {
    if id_ok(id, AGENT_LEN) {
        Ok(())
    } else {
        Err(IdError::Agent(id.to_owned()))
    }
}

/// VM name `a-{tenant_id}-{agent_id}`.
///
/// # Errors
///
/// Returns [`IdError`] if either id fails validation. Validation runs before
/// formatting so a hyphen in an id cannot collide with the separator.
pub fn sandbox_name(tenant_id: &str, agent_id: &str) -> Result<String, IdError> {
    validate_tenant_id(tenant_id)?;
    validate_agent_id(agent_id)?;
    Ok(format!("a-{tenant_id}-{agent_id}"))
}

/// Volume name `ws-{tenant_id}-{agent_id}`.
///
/// # Errors
///
/// Returns [`IdError`] if either id fails validation. Validation runs before
/// formatting so a hyphen in an id cannot collide with the separator.
pub fn workspace_volume_name(tenant_id: &str, agent_id: &str) -> Result<String, IdError> {
    validate_tenant_id(tenant_id)?;
    validate_agent_id(agent_id)?;
    Ok(format!("ws-{tenant_id}-{agent_id}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn sandbox_name_is_injective_across_hyphen_boundary() {
        assert_ne!(
            sandbox_name("x", "yz").unwrap(),
            sandbox_name("xy", "z").unwrap(),
            "a-x-yz vs a-xy-z"
        );
        assert_ne!(
            workspace_volume_name("x", "yz").unwrap(),
            workspace_volume_name("xy", "z").unwrap(),
            "ws-x-yz vs ws-xy-z"
        );
        assert!(sandbox_name("x-y", "z").is_err(), "hyphen in tenant");
        assert!(sandbox_name("x", "y-z").is_err(), "hyphen in agent");
        assert!(sandbox_name("x", "y:z").is_err(), "colon in agent");
    }

    #[test]
    fn formatted_names() {
        assert_eq!(sandbox_name("t", "a").unwrap(), "a-t-a", "sandbox");
        assert_eq!(workspace_volume_name("t", "a").unwrap(), "ws-t-a", "volume");
    }

    #[test]
    fn tenant_length_bounds() {
        let ok32 = "a".repeat(32);
        let bad33 = "a".repeat(33);
        assert!(validate_tenant_id(&ok32).is_ok(), "32");
        assert!(validate_tenant_id(&bad33).is_err(), "33");
        assert!(validate_tenant_id("").is_err(), "empty");
    }

    #[test]
    fn agent_length_bounds() {
        let ok64 = "a".repeat(64);
        let bad65 = "a".repeat(65);
        assert!(validate_agent_id(&ok64).is_ok(), "64");
        assert!(validate_agent_id(&bad65).is_err(), "65");
    }

    #[test]
    fn dot_and_underscore_allowed() {
        assert!(
            sandbox_name("t.id_1", "ag.nt_2").is_ok(),
            "dot and underscore"
        );
    }
}
