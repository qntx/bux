//! Repeatable `--listen` specs: TCP `HOST:PORT` and `unix://` sockets.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// A single bind target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ListenAddr {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => fmt::Display::fmt(addr, f),
            #[cfg(unix)]
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}

/// CLI `--listen` values, else comma-separated `BUX_LISTEN`, else empty (defaults).
#[must_use]
pub fn listen_specs(cli: &[String], env: Option<&str>) -> Vec<String> {
    if !cli.is_empty() {
        return cli.to_vec();
    }
    env.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|spec| !spec.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(crate) fn resolve_listen<I, S>(specs: I, public: bool) -> Result<Vec<ListenAddr>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let addrs = parse_listen_list(specs)?;
    check_public(&addrs, public)?;
    Ok(addrs)
}

fn parse_listen_list<I, S>(specs: I) -> Result<Vec<ListenAddr>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut addrs = Vec::new();
    for spec in specs {
        let spec = spec.as_ref().trim();
        if spec.is_empty() {
            continue;
        }
        addrs.push(parse_listen(spec)?);
    }
    if addrs.is_empty() {
        return Ok(default_listen());
    }
    Ok(addrs)
}

fn parse_listen(spec: &str) -> Result<ListenAddr> {
    if let Some(path) = spec.strip_prefix("unix://") {
        return parse_unix_path(path, spec);
    }
    if spec.starts_with('/') {
        return parse_unix_path(spec, spec);
    }
    spec.parse::<SocketAddr>()
        .map(ListenAddr::Tcp)
        .map_err(|_| Error::InvalidListen(spec.to_owned()))
}

fn parse_unix_path(path: &str, original: &str) -> Result<ListenAddr> {
    #[cfg(not(unix))]
    {
        let _ = path;
        return Err(Error::InvalidListen(original.to_owned()));
    }
    #[cfg(unix)]
    {
        // Relative sockets follow cwd; the contract is an absolute path.
        let path = PathBuf::from(path);
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(Error::InvalidListen(original.to_owned()));
        }
        Ok(ListenAddr::Unix(path))
    }
}

fn check_public(addrs: &[ListenAddr], public: bool) -> Result<()> {
    let mut any_tcp = false;
    for addr in addrs {
        if let ListenAddr::Tcp(tcp) = addr {
            any_tcp = true;
            if !tcp.ip().is_loopback() && !public {
                return Err(Error::NonLoopback(*tcp));
            }
        }
    }
    if public && !any_tcp {
        return Err(Error::PublicRequiresTcp);
    }
    Ok(())
}

fn default_listen() -> Vec<ListenAddr> {
    let tcp = ListenAddr::Tcp(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 8080)));
    #[cfg(unix)]
    {
        vec![tcp, ListenAddr::Unix(default_unix_path())]
    }
    #[cfg(not(unix))]
    {
        vec![tcp]
    }
}

#[cfg(unix)]
fn default_unix_path() -> PathBuf {
    default_unix_path_from(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        current_uid(),
    )
}

#[cfg(unix)]
fn default_unix_path_from(xdg_runtime_dir: Option<&std::ffi::OsStr>, uid: u32) -> PathBuf {
    match xdg_runtime_dir {
        Some(dir) if !dir.is_empty() => Path::new(dir).join("bux.sock"),
        _ => PathBuf::from(format!("/tmp/bux-{uid}.sock")),
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid is POSIX, always succeeds, and has no preconditions.
    #[allow(unsafe_code, reason = "getuid has no preconditions")]
    unsafe {
        libc::getuid()
    }
}

enum Bound {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix {
        listener: tokio::net::UnixListener,
        _guard: UnixSocketGuard,
    },
}

#[cfg(unix)]
#[derive(Debug)]
struct UnixSocketGuard {
    path: PathBuf,
    dev: u64,
    ino: u64,
    #[allow(dead_code, reason = "cloned fd keeps the bind inode alive")]
    _pin: OwnedFd,
}

#[cfg(unix)]
impl UnixSocketGuard {
    fn from_bound(path: PathBuf, fd: impl AsFd) -> Result<Self> {
        // Darwin fstat on the listener fd is not the bind-path inode
        // (`st_dev` is -1). Pin only stops Linux from reusing the inode.
        let (dev, ino) = path_dev_ino(&path)?;
        Ok(Self {
            path,
            dev,
            ino,
            _pin: fd.as_fd().try_clone_to_owned()?,
        })
    }
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        // Only unlink if this path still names the inode we bound. A later
        // worker may have stolen the name; unlinking it would drop their socket.
        let Ok((dev, ino)) = path_dev_ino(&self.path) else {
            return;
        };
        if dev != self.dev || ino != self.ino {
            return;
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %err,
                    "failed to unlink unix socket"
                );
            }
        }
    }
}

#[cfg(unix)]
fn prepare_unix_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(unix)]
fn path_dev_ino(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(unix)]
fn bind_unix(path: &Path) -> Result<Bound> {
    prepare_unix_path(path)?;
    let listener = tokio::net::UnixListener::bind(path)?;
    match UnixSocketGuard::from_bound(path.to_path_buf(), &listener) {
        Ok(guard) => Ok(Bound::Unix {
            listener,
            _guard: guard,
        }),
        Err(err) => {
            // Bound, but we cannot identify the inode; drop our name so a
            // failed start does not leave a socket without a guard.
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(unlink_err) if unlink_err.kind() == io::ErrorKind::NotFound => {}
                Err(unlink_err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %unlink_err,
                        "failed to unlink unix socket after fstat error"
                    );
                }
            }
            Err(err)
        }
    }
}

pub(crate) async fn serve_listeners(
    addrs: &[ListenAddr],
    app: axum::Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let bound = bind_all(addrs).await?;
    run_bound(bound, app, shutdown).await
}

async fn bind_all(addrs: &[ListenAddr]) -> Result<Vec<Bound>> {
    let mut bound = Vec::with_capacity(addrs.len());
    for addr in addrs {
        bound.push(bind_one(addr).await?);
    }
    Ok(bound)
}

async fn bind_one(addr: &ListenAddr) -> Result<Bound> {
    match addr {
        ListenAddr::Tcp(tcp) => {
            let listener = tokio::net::TcpListener::bind(tcp).await?;
            tracing::info!(listen = %tcp, "listening");
            Ok(Bound::Tcp(listener))
        }
        #[cfg(unix)]
        ListenAddr::Unix(path) => {
            let bound = bind_unix(path)?;
            tracing::info!(listen = %addr, "listening");
            Ok(bound)
        }
    }
}

async fn run_bound(
    bound: Vec<Bound>,
    app: axum::Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();
    for item in bound {
        let app = app.clone();
        let stop_rx = stop_rx.clone();
        tasks.spawn(async move { serve_one(item, app, stop_rx).await });
    }
    let signal_tx = stop_tx.clone();
    tokio::spawn(async move {
        shutdown.await;
        notify_stop(&signal_tx);
    });
    join_servers(&mut tasks, &stop_tx).await
}

async fn serve_one(
    item: Bound,
    app: axum::Router,
    stop_rx: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    match item {
        Bound::Tcp(listener) => {
            axum::serve(listener, app)
                .with_graceful_shutdown(wait_stop(stop_rx))
                .await
        }
        #[cfg(unix)]
        Bound::Unix { listener, _guard } => {
            axum::serve(listener, app)
                .with_graceful_shutdown(wait_stop(stop_rx))
                .await
        }
    }
}

async fn wait_stop(mut rx: tokio::sync::watch::Receiver<bool>) {
    drop(rx.wait_for(|stop| *stop).await);
}

fn notify_stop(tx: &tokio::sync::watch::Sender<bool>) {
    tx.send_replace(true);
}

async fn join_servers(
    tasks: &mut tokio::task::JoinSet<io::Result<()>>,
    stop_tx: &tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    let mut first_err = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                notify_stop(stop_tx);
                first_err.get_or_insert(err);
            }
            Err(join_err) => {
                notify_stop(stop_tx);
                first_err.get_or_insert_with(|| io::Error::other(join_err));
            }
        }
    }
    first_err.map_or(Ok(()), |err| Err(err.into()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp() {
        assert_eq!(
            parse_listen("127.0.0.1:8080").unwrap(),
            ListenAddr::Tcp("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!(
            parse_listen("[::1]:8080").unwrap(),
            ListenAddr::Tcp("[::1]:8080".parse().unwrap())
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_unix_scheme_and_absolute() {
        let expected = ListenAddr::Unix(PathBuf::from("/tmp/bux.sock"));
        assert_eq!(parse_listen("unix:///tmp/bux.sock").unwrap(), expected);
        assert_eq!(parse_listen("/tmp/bux.sock").unwrap(), expected);
    }

    #[test]
    fn parse_rejects_relative_and_garbage() {
        assert!(matches!(
            parse_listen("unix://bux.sock"),
            Err(Error::InvalidListen(_))
        ));
        assert!(matches!(
            parse_listen("unix://"),
            Err(Error::InvalidListen(_))
        ));
        assert!(matches!(
            parse_listen("localhost:8080"),
            Err(Error::InvalidListen(_))
        ));
        assert!(matches!(parse_listen("nope"), Err(Error::InvalidListen(_))));
    }

    #[test]
    fn empty_specs_are_tcp_and_unix_defaults() {
        let addrs = parse_listen_list(Vec::<&str>::new()).unwrap();
        assert!(
            matches!(addrs.first(), Some(ListenAddr::Tcp(a)) if a.to_string() == "127.0.0.1:8080"),
            "{addrs:?}"
        );
        #[cfg(unix)]
        assert!(
            matches!(addrs.get(1), Some(ListenAddr::Unix(_))),
            "{addrs:?}"
        );
        assert_eq!(addrs.len(), default_listen().len(), "default count");
    }

    #[cfg(unix)]
    #[test]
    fn unix_only_is_valid() {
        let addrs = parse_listen_list(["unix:///tmp/only.sock"]).unwrap();
        assert_eq!(addrs.len(), 1, "one");
        assert!(
            matches!(addrs.first(), Some(ListenAddr::Unix(_))),
            "{addrs:?}"
        );
    }

    #[test]
    fn public_requires_tcp() {
        #[cfg(unix)]
        {
            let err = resolve_listen(["unix:///tmp/x.sock"], true).unwrap_err();
            assert!(matches!(err, Error::PublicRequiresTcp), "{err}");
        }
        let err = resolve_listen(["0.0.0.0:8080"], false).unwrap_err();
        assert!(matches!(err, Error::NonLoopback(_)), "{err}");
        resolve_listen(["0.0.0.0:8080"], true).unwrap();
        resolve_listen(["127.0.0.1:8080"], false).unwrap();
    }

    #[test]
    fn listen_specs_cli_wins_over_env() {
        let cli = vec!["127.0.0.1:1".into()];
        assert_eq!(
            listen_specs(&cli, Some("unix:///tmp/x")),
            vec!["127.0.0.1:1"]
        );
    }

    #[test]
    fn listen_specs_env_is_comma_separated() {
        assert_eq!(
            listen_specs(&[], Some("127.0.0.1:8080, unix:///tmp/bux.sock")),
            vec!["127.0.0.1:8080", "unix:///tmp/bux.sock"]
        );
        assert!(listen_specs(&[], None).is_empty(), "empty");
        assert!(listen_specs(&[], Some("")).is_empty(), "blank env");
    }

    #[cfg(unix)]
    #[test]
    fn default_unix_path_xdg_then_tmp_uid() {
        use std::ffi::OsStr;
        assert_eq!(
            default_unix_path_from(Some(OsStr::new("/run/user/1000")), 1000),
            PathBuf::from("/run/user/1000/bux.sock")
        );
        assert_eq!(
            default_unix_path_from(None, 501),
            PathBuf::from("/tmp/bux-501.sock")
        );
        assert_eq!(
            default_unix_path_from(Some(OsStr::new("")), 7),
            PathBuf::from("/tmp/bux-7.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_guard_drop_unlinks_own_inode() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let guard = UnixSocketGuard::from_bound(path.clone(), &listener).unwrap();
        drop(guard);
        assert!(!path.exists(), "own name unlinked");
        drop(listener);
    }

    #[cfg(unix)]
    #[test]
    fn unix_guard_drop_skips_replaced_inode() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        let first = UnixListener::bind(&path).unwrap();
        let guard = UnixSocketGuard::from_bound(path.clone(), &first).unwrap();
        drop(first);
        std::fs::remove_file(&path).unwrap();
        let second = UnixListener::bind(&path).unwrap();
        drop(guard);
        assert!(path.exists(), "replacement kept");
        drop(second);
    }
}
