# bux

Embedded micro-VM sandbox for running AI agents

Part of [bux](https://github.com/qntx/bux).

## Linux jailer

On Linux, bux runs each VM's `bux-shim` inside [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`), with its own PID, IPC, UTS and mount namespaces. An unprivileged `bwrap` needs a user namespace for that.

### Which bwrap runs

bux tries each `bwrap` on `$PATH`, then the one it bundles, and uses the first that works. It runs each candidate once to find out, with the namespaces and mounts of a real VM and a command that does nothing. `bux system info` shows the one in use:

```text
namespaces:     yes (/usr/bin/bwrap)
```

The system's `bwrap` comes first because a distribution's security policy can only cover that one. AppArmor profiles attach by path, and the bundled `bwrap` lives in a user-writable directory whose name changes with each bux version, so no profile can safely cover it. The bundled one is for hosts without bubblewrap.

When no `bwrap` works, `bux create` fails before it starts the VM. It says why and what to do, and `bux system info` shows the same under `warnings`. The jailer does not degrade: `--allow-degraded` only covers Landlock, and dropping the namespaces takes an explicit `--no-jailer`.

### Ubuntu

Ubuntu sets `kernel.apparmor_restrict_unprivileged_userns=1`: a process can create a user namespace only under an AppArmor profile that allows it.

| Release | Profile for `/usr/bin/bwrap` | What to do |
| --- | --- | --- |
| 25.04 and later | Shipped by the `apparmor` package | Nothing on a desktop install, which has bubblewrap. Elsewhere: `sudo apt install bubblewrap` |
| 24.04 and its derivatives | None | Install the profile below, and `sudo apt install bubblewrap` if needed |

#### Installing the profile on 24.04

This is upstream AppArmor's own profile, byte-identical to the file Ubuntu 25.04 and 25.10 enable. bux prints these commands but never runs them: system security policy is the administrator's decision, and it needs `sudo`.

```sh
curl -fsSLO https://gitlab.com/apparmor/apparmor/-/raw/v4.1.0/profiles/apparmor/profiles/extras/bwrap-userns-restrict &&
echo "634d3d3427c483f123cb5ed53b71ea13040187e07d9f67ca74421d42a6170f0e  bwrap-userns-restrict" | sha256sum -c &&
sudo install -m 0644 bwrap-userns-restrict /etc/apparmor.d/ &&
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
```

What it does:

- `/usr/bin/bwrap` may create user namespaces. A copy of it at another path may not.
- What `bwrap` runs gets no capabilities (it runs as `bwrap//&unpriv_bwrap`), so `bwrap` cannot be used to get around the restriction: `unshare -Ur` fails inside the sandbox.
- It applies to everything that runs `/usr/bin/bwrap`, such as Flatpak and GNOME's thumbnailers. Ubuntu 25.04 and later run them this way, but Ubuntu does not ship this profile for 24.04. If a program misbehaves after you install it, remove the profile.

#### Another profile for /usr/bin/bwrap

Keep the file at this path and with these profile names. When two profiles attach to `/usr/bin/bwrap`, AppArmor applies neither, and `bwrap` fails again with `setting up uid map: Permission denied`. See what is loaded with `sudo aa-status | grep bwrap`.

#### Upgrading and removing

Upgrading to Ubuntu 25.04 or later puts the package's copy at the same path, so there is still one profile. If `dpkg` asks about the file, take the package's version.

Uninstalling bux does not remove the profile, because other programs may rely on it. To remove it:

```sh
sudo apparmor_parser -R /etc/apparmor.d/bwrap-userns-restrict
sudo rm /etc/apparmor.d/bwrap-userns-restrict
```

### Other hosts

`bwrap` also fails when user namespaces are off (`kernel.unprivileged_userns_clone=0`, `user.max_user_namespaces=0`), or inside a container that denies them. The error names those sysctls when they are the cause.
