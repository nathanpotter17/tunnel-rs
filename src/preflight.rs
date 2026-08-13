//! Environment preflight

use anyhow::{anyhow, bail, Result};
use std::path::PathBuf;
use tracing::{info, warn};

/// How this host's resolver is managed — decided once, here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsBackend {
    /// systemd-resolved is live: per-link DNS + `~.` routing domain.
    SystemdResolved,
    /// No resolved: `/etc/resolv.conf` is the resolver, rewritten under a guard.
    ResolvConf,
}

/// Everything preflight resolved for the session.
#[derive(Debug, Clone)]
pub struct Preflight {
    pub dns: DnsBackend,
}

/// Run every precondition check. `capture` is true when the engine will hijack
/// the default route (i.e. NOT `--no-route`); the kill-switch and resolver
/// checks only apply then.
pub fn run(capture: bool) -> Result<Preflight> {
    platform::run(capture)
}

/// Feed a ruleset to `nft -f -`. The only place this process invokes nftables,
/// so preflight's probes, the kill switch and the tripwire's lockdown cannot
/// disagree about WHICH `nft` — which is not "whatever PATH says": on Ubuntu it
/// is in `/usr/sbin`, absent from a desktop `sudo` PATH. Two of the three
/// callers used the bare name, so preflight passed and the kill switch did not.
#[cfg(target_os = "linux")]
pub(crate) use platform::nft_apply;

// ============================================================================
// Linux
// ============================================================================
#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;

    /// Directories searched in addition to `PATH`: `nft` and `ip` live in
    /// `/usr/sbin` on Ubuntu, which is absent from a desktop session's PATH even
    /// under `sudo` unless `secure_path` covers it.
    const SBIN_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/local/sbin"];

    /// Tables this process owns. A leftover means a prior run died hard (or, for
    /// the panic table, that the tripwire fired and the host has not rebooted).
    const KILLSWITCH_TABLE: &str = "tunnel_killswitch";
    const PANIC_TABLE: &str = "tunnel_panic";

    pub fn run(capture: bool) -> Result<Preflight> {
        require_root()?;
        require_tun_device()?;
        let ip = require_tool("ip", "iproute2")?;
        info!("preflight: iproute2 at {}", ip.display());

        if capture {
            info!("preflight: nftables at {}", require_nft()?.display());
            require_nft_inet_family()?;
            reject_panic_lockdown()?;
            clear_stale_killswitch()?;
        }

        let dns = if capture { detect_dns_backend()? } else { DnsBackend::ResolvConf };
        if capture {
            warn_on_ipv6_default(&ip);
            warn_on_sudo_home();
        }
        #[cfg(feature = "gui")]
        warn_on_desktop_session();

        info!("preflight: OK (resolver backend: {:?})", dns);
        Ok(Preflight { dns })
    }

    fn require_root() -> Result<()> {
        let uid = unsafe { libc::geteuid() };
        if uid != 0 {
            bail!(
                "must run as root (effective uid {uid}).\n\
                 The engine creates a TUN, rewrites the default route, arms an \
                 nftables kill switch, and rebinds the resolver — all of which \
                 need CAP_NET_ADMIN, and the `ip`/`nft` helpers it execs do not \
                 inherit file capabilities.\n\
                 Run:  sudo -E ./tunnel <settings>.toml"
            );
        }
        Ok(())
    }

    fn require_tun_device() -> Result<()> {
        let path = std::path::Path::new("/dev/net/tun");
        if !path.exists() {
            bail!(
                "/dev/net/tun is missing.\n\
                 Fix:  sudo modprobe tun\n\
                 In a container, add:  --device /dev/net/tun --cap-add NET_ADMIN"
            );
        }
        // Existence is not access: a container can expose the node without the
        // capability to open it, and that failure must not surface later as an
        // opaque \"failed to create TUN device\".
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| {
                anyhow!(
                    "/dev/net/tun exists but cannot be opened: {e}.\n\
                     The process needs CAP_NET_ADMIN (container: --cap-add NET_ADMIN)."
                )
            })?;
        Ok(())
    }

    /// Locate an executable on `PATH` plus the sbin directories.
    fn find_tool(name: &str) -> Option<PathBuf> {
        let path_var = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path_var)
            .chain(SBIN_DIRS.iter().map(PathBuf::from))
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    }

    fn require_tool(name: &str, package: &str) -> Result<PathBuf> {
        find_tool(name).ok_or_else(|| {
            anyhow!(
                "`{name}` not found on PATH or in {dirs:?}.\n\
                 Fix:  sudo apt-get install -y {package}",
                dirs = SBIN_DIRS
            )
        })
    }

    /// The `nft` binary, located once. Cached because the tripwire's lockdown
    /// reaches for it on the way down, where a PATH walk is the last thing
    /// worth doing.
    fn nft_binary() -> Option<&'static Path> {
        static NFT: OnceLock<Option<PathBuf>> = OnceLock::new();
        NFT.get_or_init(|| find_tool("nft")).as_deref()
    }

    fn require_nft() -> Result<&'static Path> {
        nft_binary().ok_or_else(|| {
            anyhow!(
                "`nft` not found on PATH or in {dirs:?}.\n\
                 Fix:  sudo apt-get install -y nftables",
                dirs = SBIN_DIRS
            )
        })
    }

    /// Prove the kernel exposes nf_tables' `inet` family AND that we may write to
    /// it. `nft` being installed proves neither: a container without
    /// CAP_NET_ADMIN, or a kernel without `nf_tables_inet`, fails only at rule
    /// load — which, without this check, happens after the route is hijacked.
    fn require_nft_inet_family() -> Result<()> {
        const PROBE: &str = "tunnel_preflight";
        let script = format!(
            "add table inet {PROBE}\n\
             add chain inet {PROBE} out {{ type filter hook output priority 0 ; policy accept ; }}\n\
             delete table inet {PROBE}\n"
        );
        nft_apply(&script).map_err(|e| {
            anyhow!(
                "nftables cannot load an `inet` filter chain: {e}\n\
                 The kill switch (TunnelVision mitigation) cannot be armed, and \
                 the engine refuses to capture traffic without it.\n\
                 Check:  sudo modprobe nf_tables nft_chain_filter\n\
                 In a container, add:  --cap-add NET_ADMIN"
            )
        })
    }

    /// A surviving panic table means the tripwire fired and the host has not
    /// rebooted. That lockdown is deliberately reboot-clearable; silently
    /// stepping over it would resume a session that was declared compromised.
    fn reject_panic_lockdown() -> Result<()> {
        if table_exists(PANIC_TABLE) {
            bail!(
                "the `inet {PANIC_TABLE}` lockdown is still installed — a previous \
                 session tripped the snooper detector and this host has NOT been \
                 rebooted.\n\
                 Reboot and rotate keys. To clear it deliberately without a reboot:\n\
                 \x20 sudo nft delete table inet {PANIC_TABLE}"
            );
        }
        Ok(())
    }

    /// A surviving kill-switch table means the previous run was hard-killed
    /// (SIGKILL / panic past the guard). Its rules reference an interface name
    /// that may no longer be the uplink, so it is stale policy, not protection:
    /// clear it here rather than layering a second table on top of it.
    fn clear_stale_killswitch() -> Result<()> {
        if table_exists(KILLSWITCH_TABLE) {
            warn!(
                "clearing a leftover `inet {KILLSWITCH_TABLE}` table from a \
                 hard-killed previous run"
            );
            nft_apply(&format!("delete table inet {KILLSWITCH_TABLE}\n"))?;
        }
        Ok(())
    }

    fn table_exists(table: &str) -> bool {
        let Some(nft) = nft_binary() else {
            return false;
        };
        Command::new(nft)
            .args(["list", "table", "inet", table])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// See [`crate::preflight::nft_apply`].
    pub fn nft_apply(script: &str) -> Result<()> {
        let nft = require_nft()?;
        let mut child = Command::new(nft)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", nft.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("nft stdin unavailable"))?
            .write_all(script.as_bytes())
            .map_err(|e| anyhow!("writing nft ruleset: {e}"))?;
        let out = child.wait_with_output().map_err(|e| anyhow!("waiting on nft: {e}"))?;
        if !out.status.success() {
            return Err(anyhow!("{}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(())
    }

    /// Decide the resolver strategy. This is the single most common Ubuntu
    /// failure: with the kill switch armed, queries to a LAN resolver leave the
    /// uplink unmarked and are dropped, so the resolver MUST be moved onto the
    /// TUN. Which mechanism does that differs between a desktop (resolved) and a
    /// server/container (`/etc/resolv.conf`), and guessing wrong is silent.
    fn detect_dns_backend() -> Result<DnsBackend> {
        let resolved_live = find_tool("resolvectl")
            .map(|p| {
                Command::new(p)
                    .arg("status")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if resolved_live {
            return Ok(DnsBackend::SystemdResolved);
        }

        // No resolved: /etc/resolv.conf is the resolver and we rewrite it under a
        // guard. If it is a symlink into resolved's runtime directory while
        // resolved is dead, the host's DNS is already broken and rewriting it
        // would hide that, so fail loudly instead.
        let path = std::path::Path::new("/etc/resolv.conf");
        let meta = std::fs::symlink_metadata(path).map_err(|e| {
            anyhow!(
                "systemd-resolved is not running and /etc/resolv.conf is unreadable ({e}).\n\
                 With the kill switch armed, DNS to a LAN resolver is dropped, so \
                 the engine needs one of the two to work.\n\
                 Fix:  sudo systemctl enable --now systemd-resolved\n\
                 \x20 or create a writable /etc/resolv.conf"
            )
        })?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(path).unwrap_or_default();
            if target.to_string_lossy().contains("systemd") {
                bail!(
                    "/etc/resolv.conf is a symlink to {} but systemd-resolved is not \
                     running — this host has no working resolver path.\n\
                     Fix:  sudo systemctl enable --now systemd-resolved",
                    target.display()
                );
            }
        }
        Ok(DnsBackend::ResolvConf)
    }

    /// The engine captures IPv4 only, and the kill switch therefore DROPS IPv6
    /// out the uplink rather than let it bypass the tunnel. That is correct, and
    /// it is also invisible: a host with working IPv6 loses it the moment we arm.
    /// Say so up front instead of leaving the user to diagnose it.
    fn warn_on_ipv6_default(ip: &std::path::Path) {
        let has_v6_default = Command::new(ip)
            .args(["-6", "route", "show", "default"])
            .output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false);
        if has_v6_default {
            warn!(
                "this host has an IPv6 default route. The engine captures IPv4 \
                 only, so the kill switch DROPS IPv6 out the uplink to stop it \
                 bypassing the tunnel — IPv6 connectivity will be unavailable \
                 while the tunnel is up. This is intentional, not a fault."
            );
        }
    }

    /// Under `sudo`, `$HOME` is root's, so the session flow CSV lands somewhere
    /// the invoking user does not own. Name the real path.
    fn warn_on_sudo_home() {
        if let Ok(user) = std::env::var("SUDO_USER") {
            warn!(
                "running under sudo as {user}: the session flow CSV is written as \
                 root (HOME={}). Chown it afterwards, or run with `sudo -E` and a \
                 settings file under your own home.",
                std::env::var("HOME").unwrap_or_else(|_| "/root".into())
            );
        }
    }

    /// The dashboard needs a display. With file sharing removed there are no
    /// portal-backed file dialogs left, so a session bus is no longer required —
    /// only a display server the invoking user's session already owns.
    #[cfg(feature = "gui")]
    fn warn_on_desktop_session() {
        let has_display =
            std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
        if !has_display {
            warn!(
                "no DISPLAY/WAYLAND_DISPLAY — the dashboard cannot open a window. \
                 Use `sudo -E ./tunnel ...` from a desktop session, or build \
                 headless with `--no-default-features`."
            );
        }
    }
}

// ============================================================================
// Windows
// ============================================================================
//
// Elevation is proven by the operations themselves: wintun adapter creation and
// the `route`/`netsh` calls fail without it, and `tunio` already reports that
// precisely. What is NOT self-reporting is a missing arch-matched `wintun.dll`
// or a missing helper on PATH, so those are checked here.
#[cfg(windows)]
mod platform {
    use super::*;

    pub fn run(capture: bool) -> Result<Preflight> {
        // The loader's own search, not a copy of it.
        crate::tunio::locate_wintun_dll().ok_or_else(|| {
            anyhow!(
                "wintun.dll not found. Place the architecture-matching DLL next to \
                 tunnel.exe, or in bin\\<arch>\\ (amd64 | arm64 | x86). \
                 Download: https://www.wintun.net/"
            )
        })?;
        if capture {
            for tool in ["route.exe", "netsh.exe", "powershell.exe"] {
                if which(tool).is_none() {
                    bail!("`{tool}` not found on PATH — routing cannot be installed");
                }
            }
        }
        // Windows has no socket marks; the kill switch keys on app id via WFP and
        // resolves DNS per-interface with netsh. There is no resolver strategy to
        // choose, so the field records the only mechanism in use.
        Ok(Preflight { dns: DnsBackend::ResolvConf })
    }

    fn which(name: &str) -> Option<PathBuf> {
        let path_var = std::env::var_os("PATH")?;
        std::env::split_paths(&path_var).map(|d| d.join(name)).find(|p| p.is_file())
    }
}
