//! Bundled [bubblewrap] binary and a safe command-builder for bux.
//!
//! This crate does two things:
//!
//! 1. **Discovery** — downloads a pre-built `bwrap` binary at build time
//!    and exposes [`path()`] for runtime lookup.
//! 2. **Command building** — [`BwrapCommand`] is a fluent builder that
//!    produces a ready-to-spawn [`std::process::Command`] wrapping a
//!    target program with bubblewrap namespace isolation.
//!
//! Bubblewrap provides unprivileged Linux namespace isolation and is
//! the basis of the `bux-shim` sandbox.
//!
//! # Platform
//!
//! Linux only. On other platforms:
//! - [`path()`] returns `None`.
//! - [`BwrapCommand::new`] always returns [`Error::NotFound`].
//! - The types remain constructible so downstream `cfg` gating can be
//!   minimised.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn main() -> Result<(), bux_bwrap::Error> {
//! use bux_bwrap::{BwrapCommand, Namespace};
//!
//! let cmd = BwrapCommand::new()?
//!     .unshare([Namespace::Pid, Namespace::Ipc, Namespace::Uts])
//!     .die_with_parent()
//!     .ro_bind("/", "/")
//!     .tmpfs("/tmp")
//!     .program("/usr/bin/id")
//!     .into_command();
//! // Ready to `.spawn()`.
//! drop(cmd);
//! # Ok(()) }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```
//!
//! [bubblewrap]: https://github.com/containers/bubblewrap

#![cfg_attr(docsrs, feature(doc_cfg))]

mod command;
mod discover;
mod error;

pub use command::{BwrapCommand, Namespace};
pub use discover::path;
pub use error::{Error, Result};
