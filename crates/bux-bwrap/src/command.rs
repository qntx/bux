//! Fluent builder for a bubblewrap-wrapped [`std::process::Command`].
//!
//! [`BwrapCommand`] wraps `bwrap(1)` arguments with a type-safe API.
//! The builder stores raw strings; resolution of the `bwrap` binary
//! happens once at construction (via [`BwrapCommand::new`]) and any
//! subsequent chaining is infallible.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::Command;

use crate::discover::path;
use crate::error::{Error, Result};

/// Linux namespace types that bwrap can unshare.
///
/// Values map directly to bwrap command-line flags:
/// - [`Namespace::Pid`] → `--unshare-pid`
/// - [`Namespace::Ipc`] → `--unshare-ipc`
/// - [`Namespace::Uts`] → `--unshare-uts`
/// - [`Namespace::User`] → `--unshare-user`
/// - [`Namespace::Cgroup`] → `--unshare-cgroup`
/// - [`Namespace::Net`] → `--unshare-net`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Namespace {
    /// PID namespace (`--unshare-pid`).
    Pid,
    /// System V IPC namespace (`--unshare-ipc`).
    Ipc,
    /// UTS namespace, hostname isolation (`--unshare-uts`).
    Uts,
    /// User namespace (`--unshare-user`).
    User,
    /// Cgroup namespace (`--unshare-cgroup`).
    Cgroup,
    /// Network namespace (`--unshare-net`).
    Net,
}

impl Namespace {
    /// Return the bwrap CLI flag (including the leading `--`).
    #[must_use]
    pub const fn flag(self) -> &'static str {
        match self {
            Self::Pid => "--unshare-pid",
            Self::Ipc => "--unshare-ipc",
            Self::Uts => "--unshare-uts",
            Self::User => "--unshare-user",
            Self::Cgroup => "--unshare-cgroup",
            Self::Net => "--unshare-net",
        }
    }
}

/// Fluent builder for a bubblewrap-wrapped child command.
///
/// # Example
///
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # fn main() -> Result<(), bux_bwrap::Error> {
/// use bux_bwrap::{BwrapCommand, Namespace};
///
/// let cmd = BwrapCommand::new()?
///     .unshare([Namespace::Pid, Namespace::Ipc, Namespace::Uts])
///     .die_with_parent()
///     .ro_bind("/", "/")
///     .tmpfs("/tmp")
///     .tmpfs("/dev/shm")
///     .program("/usr/bin/id")
///     .into_command();
/// // `cmd` is now a `std::process::Command` ready to spawn.
/// drop(cmd);
/// # Ok(()) }
/// # #[cfg(not(target_os = "linux"))]
/// # fn main() {}
/// ```
#[derive(Debug, Clone)]
#[must_use = "BwrapCommand does nothing until you call `.into_command()`"]
pub struct BwrapCommand {
    /// Resolved path to the `bwrap` binary.
    bwrap: PathBuf,
    /// Accumulated arguments passed to `bwrap` itself (before `--`).
    bwrap_args: Vec<OsString>,
    /// The program to run inside the sandbox (everything after `--`).
    program: Option<OsString>,
    /// Arguments passed to the sandboxed program.
    program_args: Vec<OsString>,
}

impl BwrapCommand {
    /// Create a new builder, resolving the `bwrap` binary path eagerly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `bwrap` cannot be located via any
    /// of the strategies in [`crate::path`].
    pub fn new() -> Result<Self> {
        let bwrap = path().ok_or(Error::NotFound)?.to_path_buf();
        Ok(Self {
            bwrap,
            bwrap_args: Vec::new(),
            program: None,
            program_args: Vec::new(),
        })
    }

    /// Request that bwrap unshare each given namespace.
    pub fn unshare<I>(mut self, namespaces: I) -> Self
    where
        I: IntoIterator<Item = Namespace>,
    {
        for ns in namespaces {
            self.bwrap_args.push(OsString::from(ns.flag()));
        }
        self
    }

    /// Ask bwrap to exit (taking the sandboxed process with it) when
    /// the parent process dies (`--die-with-parent`).
    pub fn die_with_parent(mut self) -> Self {
        self.bwrap_args.push(OsString::from("--die-with-parent"));
        self
    }

    /// Bind-mount `host` onto `guest` as **read-only**
    /// (`--ro-bind host guest`).
    pub fn ro_bind<H, G>(mut self, host: H, guest: G) -> Self
    where
        H: AsRef<OsStr>,
        G: AsRef<OsStr>,
    {
        self.bwrap_args.push(OsString::from("--ro-bind"));
        self.bwrap_args.push(host.as_ref().to_os_string());
        self.bwrap_args.push(guest.as_ref().to_os_string());
        self
    }

    /// Bind-mount `host` onto `guest` as read-write
    /// (`--bind host guest`).
    pub fn bind<H, G>(mut self, host: H, guest: G) -> Self
    where
        H: AsRef<OsStr>,
        G: AsRef<OsStr>,
    {
        self.bwrap_args.push(OsString::from("--bind"));
        self.bwrap_args.push(host.as_ref().to_os_string());
        self.bwrap_args.push(guest.as_ref().to_os_string());
        self
    }

    /// Bind-mount a device node (`--dev-bind host guest`).
    pub fn dev_bind<H, G>(mut self, host: H, guest: G) -> Self
    where
        H: AsRef<OsStr>,
        G: AsRef<OsStr>,
    {
        self.bwrap_args.push(OsString::from("--dev-bind"));
        self.bwrap_args.push(host.as_ref().to_os_string());
        self.bwrap_args.push(guest.as_ref().to_os_string());
        self
    }

    /// Mount a fresh tmpfs at `mount_point` (`--tmpfs mount_point`).
    pub fn tmpfs<P: AsRef<OsStr>>(mut self, mount_point: P) -> Self {
        self.bwrap_args.push(OsString::from("--tmpfs"));
        self.bwrap_args.push(mount_point.as_ref().to_os_string());
        self
    }

    /// Append a raw bwrap argument. Use for flags not covered by the
    /// typed helpers above.
    pub fn raw_arg<A: AsRef<OsStr>>(mut self, arg: A) -> Self {
        self.bwrap_args.push(arg.as_ref().to_os_string());
        self
    }

    /// Set the program to execute inside the sandbox.
    ///
    /// Calling this more than once overwrites the previous value.
    pub fn program<P: AsRef<OsStr>>(mut self, program: P) -> Self {
        self.program = Some(program.as_ref().to_os_string());
        self
    }

    /// Append one argument to the sandboxed program.
    pub fn arg<A: AsRef<OsStr>>(mut self, arg: A) -> Self {
        self.program_args.push(arg.as_ref().to_os_string());
        self
    }

    /// Append multiple arguments to the sandboxed program.
    pub fn args<I, A>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
    {
        for a in args {
            self.program_args.push(a.as_ref().to_os_string());
        }
        self
    }

    /// Consume the builder and produce a ready-to-spawn [`Command`].
    ///
    /// The returned command invokes `bwrap` with all accumulated
    /// bwrap flags, followed by `--`, then the sandboxed program
    /// and its arguments (if [`BwrapCommand::program`] was called).
    #[must_use]
    pub fn into_command(self) -> Command {
        let mut cmd = Command::new(&self.bwrap);
        cmd.args(&self.bwrap_args);
        if let Some(ref program) = self.program {
            cmd.arg("--").arg(program).args(&self.program_args);
        }
        cmd
    }

    /// Return the resolved `bwrap` binary path.
    #[must_use]
    pub fn bwrap_path(&self) -> &std::path::Path {
        &self.bwrap
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    reason = "tests are allowed to use unwrap and omit docs"
)]
mod tests {
    use super::*;

    #[test]
    fn namespace_flags_match_bwrap_cli() {
        assert_eq!(Namespace::Pid.flag(), "--unshare-pid");
        assert_eq!(Namespace::Ipc.flag(), "--unshare-ipc");
        assert_eq!(Namespace::Uts.flag(), "--unshare-uts");
        assert_eq!(Namespace::User.flag(), "--unshare-user");
        assert_eq!(Namespace::Cgroup.flag(), "--unshare-cgroup");
        assert_eq!(Namespace::Net.flag(), "--unshare-net");
    }
}
