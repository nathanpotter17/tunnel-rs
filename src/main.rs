//! Software-defined tunnel: smoltcp egress engine + live observability,
//! plus a standalone encrypted file-sharing channel.

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

mod conn;
mod config;
mod crypto;
mod device;
mod engine;
mod file_session;
mod file_transfer;
mod inspect;
mod outbound;
mod pin;
mod protocol;
mod route;
mod settings;
mod state;
mod tunio;
mod wg;

#[cfg(feature = "gui")]
mod gui;

use crypto::Keypair;
use settings::Settings;
use state::Shared;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!(
        "tunnel {VERSION} - software-defined egress engine + file sharing

USAGE:
    tunnel [OPTIONS] [COMMAND] [SETTINGS.toml]

COMMANDS:
    gui                  Run the engine + dashboard (default). File sharing is
                         on only if the settings file has an [identity] section.
    connect <peer_ip>    Also dial <peer_ip> to share files (needs [identity],
                         and --key once per new peer)
    keygen               Generate a file-sharing identity: prints a paste-ready
                         [identity] section for your settings file
    init                 Write a starter settings file (includes a fresh identity)
    pubkey               Print this host's public key (needs [identity])

ARGS:
    <SETTINGS.toml>      The one settings file (engine + optional [wireguard]
                         + optional [identity]). Any positional ending in .toml.
                         Default: tunnel.toml in the working directory.

OPTIONS:
    -s, --settings <P>   Settings file (same as the positional form)
    -k, --key <BASE64>   File peer's public key (pinned per endpoint)
        --no-route       Do not redirect the default route into the TUN
    -v, --verbose        Verbose logging
    -h, --help / -V, --version

Unknown commands, arguments, or settings fields are errors — nothing is
silently ignored."
    );
}

/// Install a logger that prints to stdout (headless) and mirrors into the
/// dashboard log ring (`Shared`).
fn setup_logging(verbose: bool, shared: Arc<Shared>) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = if verbose {
        EnvFilter::new("tunnel=debug,snow=info")
    } else {
        EnvFilter::new("tunnel=info")
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(SharedLogLayer { shared })
        .init();
}

/// Tracing layer that mirrors events into `Shared.logs`.
struct SharedLogLayer {
    shared: Arc<Shared>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SharedLogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = match *event.metadata().level() {
            tracing::Level::ERROR => "error",
            tracing::Level::WARN => "warn",
            tracing::Level::INFO => "info",
            tracing::Level::DEBUG | tracing::Level::TRACE => "debug",
        };
        let mut v = MsgVisitor::default();
        event.record(&mut v);
        let msg = if !v.message.is_empty() {
            v.message
        } else if !v.fields.is_empty() {
            v.fields.join(" ")
        } else {
            return;
        };
        self.shared.push_log(level, msg);
    }
}

#[derive(Default)]
struct MsgVisitor {
    message: String,
    fields: Vec<String>,
}

impl tracing::field::Visit for MsgVisitor {
    fn record_debug(&mut self, f: &tracing::field::Field, val: &dyn std::fmt::Debug) {
        if f.name() == "message" {
            self.message = format!("{val:?}").trim_matches('"').to_string();
        } else {
            self.fields.push(format!("{}={val:?}", f.name()));
        }
    }
    fn record_str(&mut self, f: &tracing::field::Field, val: &str) {
        if f.name() == "message" {
            self.message = val.to_string();
        } else {
            self.fields.push(format!("{}={val}", f.name()));
        }
    }
}

/// Resolve the file-peer endpoint + pinned public key. The trust store lives
/// next to the settings file.
fn resolve_file_peer(
    settings_path: &std::path::Path,
    target: &str,
    key: Option<&str>,
) -> Result<(SocketAddr, [u8; 32])> {
    let endpoint = if target.contains(':') {
        target.to_string()
    } else {
        format!("{target}:51821") // file channel port (engine UDP is separate)
    };
    let addr: SocketAddr = endpoint.parse().context("invalid peer endpoint")?;

    let pubkey_b64 = match key {
        Some(k) => {
            config::save_known_server(settings_path, &endpoint, k)
                .unwrap_or_else(|e| tracing::warn!("could not pin key for {endpoint}: {e}"));
            k.to_string()
        }
        None => config::load_known_server(settings_path, &endpoint).ok_or_else(|| {
            anyhow::anyhow!("no pinned key for {endpoint}; pass --key <peer_pubkey> once")
        })?,
    };
    Ok((addr, Keypair::decode_public_key(&pubkey_b64)?))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut settings_path: Option<PathBuf> = None;
    let mut key: Option<String> = None;
    let mut verbose = false;
    let mut install_route = true;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => { print_usage(); return Ok(()); }
            "-V" | "--version" => { println!("tunnel {VERSION}"); return Ok(()); }
            "-v" | "--verbose" => verbose = true,
            "--no-route" => install_route = false,
            "-s" | "--settings" => { i += 1; settings_path = Some(PathBuf::from(args.get(i).context("--settings needs a path")?)); }
            "-k" | "--key" => { i += 1; key = Some(args.get(i).context("--key needs a value")?.clone()); }
            a if a.starts_with('-') => bail!("unknown option: {a}"),
            a => positional.push(a.to_string()),
        }
        i += 1;
    }

    // Positional arguments: exactly one optional command, plus an optional
    // settings file (any positional ending in .toml). Anything else is a hard
    // error — silently ignored arguments once left the engine running on
    // built-in defaults while the user's real config sat unread.
    let mut command: Option<&str> = None;
    let mut connect_target: Option<String> = None;
    for a in &positional {
        match a.as_str() {
            "keygen" | "init" | "pubkey" | "gui" | "connect" => {
                if command.is_some() {
                    bail!("multiple commands given: {} and {}", command.unwrap(), a);
                }
                command = Some(match a.as_str() {
                    "keygen" => "keygen",
                    "init" => "init",
                    "pubkey" => "pubkey",
                    "gui" => "gui",
                    _ => "connect",
                });
            }
            t if command == Some("connect") && connect_target.is_none() => {
                connect_target = Some(t.to_string());
            }
            t if t.ends_with(".toml") => {
                if settings_path.is_some() {
                    bail!("settings file given twice ({t} and --settings)");
                }
                settings_path = Some(PathBuf::from(t));
            }
            other => bail!("unknown argument: {other} (run with --help for usage)"),
        }
    }

    // Settings path is resolved BEFORE subcommands — init/pubkey operate on
    // the same one file the engine reads. An explicitly named file that
    // doesn't exist is a fatal error for the engine; only the implicit root
    // default may fall back to built-in defaults (loudly).
    let settings_explicit = settings_path.is_some();
    let settings_path = settings_path.unwrap_or_else(|| PathBuf::from("tunnel.toml"));

    // Config subcommands run before the engine.
    match command {
        Some("keygen") => return crypto::generate_keypair(),
        Some("init") => return settings::init_config(&settings_path),
        Some("pubkey") => {
            let settings = Settings::load_or_default(&settings_path)?;
            match &settings.identity {
                Some(id) => {
                    println!("Public key: {}", id.public_key()?);
                    return Ok(());
                }
                None => bail!(
                    "no [identity] section in {}.\n\
                     Run: tunnel.exe keygen   and paste the printed [identity] \
                     section into {}",
                    settings_path.display(),
                    settings_path.display()
                ),
            }
        }
        _ => {}
    }

    // Logging first, so settings load messages reach stdout AND the dashboard
    // log ring.
    let shared = Shared::new();
    setup_logging(verbose, shared.clone());

    if settings_explicit && !settings_path.exists() {
        bail!("settings file not found: {}", settings_path.display());
    }
    let settings = Settings::load_or_default(&settings_path)?;

    // File sharing runs ONLY with an [identity] in the settings file. Without
    // one the engine runs normally and the reason + fix are stated up front.
    let file_channel: Option<(file_session::FileHandle, tokio::task::JoinHandle<()>)> =
        match &settings.identity {
            Some(id) => {
                let local_private = id.private_key_bytes().with_context(|| {
                    format!("[identity] in {} is invalid", settings_path.display())
                })?;
                let file_cfg = file_session::FileConfig {
                    local_private,
                    download_dir: file_transfer::FileTransferManager::default_download_dir(),
                    auto_accept: false,
                    approval_timeout: Some(Duration::from_secs(60)),
                };
                let role = match (command, connect_target.as_deref()) {
                    (Some("connect"), Some(target)) => {
                        let (peer, remote_public) =
                            resolve_file_peer(&settings_path, target, key.as_deref())?;
                        file_session::Role::Connect {
                            bind: "0.0.0.0:0".parse().unwrap(),
                            peer,
                            remote_public,
                        }
                    }
                    (Some("connect"), None) => {
                        bail!("connect needs a peer ip (tunnel connect <peer_ip>)")
                    }
                    _ => file_session::Role::Listen { bind: "0.0.0.0:51821".parse().unwrap() },
                };
                Some(file_session::spawn(role, file_cfg, shared.clone()))
            }
            None => {
                if command == Some("connect") {
                    bail!(
                        "'connect' needs a file-sharing identity, and {} has no \
                         [identity] section.\n\
                         Run: tunnel.exe keygen   and paste the printed [identity] \
                         section into {}",
                        settings_path.display(),
                        settings_path.display()
                    );
                }
                tracing::info!(
                    "File sharing DISABLED — no [identity] in {}. To enable: run \
                     'tunnel.exe keygen' and paste the printed section into {}.",
                    settings_path.display(),
                    settings_path.display()
                );
                None
            }
        };

    // The GUI holds the cloneable handle; `main` keeps the join handle so it can
    // await a clean teardown (Disconnect sent, socket dropped) on shutdown.
    let (files, file_task): (
        Option<file_session::FileHandle>,
        Option<tokio::task::JoinHandle<()>>,
    ) = match file_channel {
        Some((handle, task)) => (Some(handle), Some(task)),
        None => (None, None),
    };

    #[cfg(feature = "gui")]
    {
        let engine_shared = shared.clone();
        let engine = tokio::spawn(async move {
            if let Err(e) = engine::run(settings, install_route, engine_shared.clone()).await {
                engine_shared.push_log("error", format!("engine: {e:#}"));
            }
        });
        let gui_result = gui::TunnelApp::run(shared.clone(), files)
            .map_err(|e| anyhow::anyhow!("dashboard: {e}"));

        // The GUI has returned — it set `shutdown` on window close (or the user
        // hit Ctrl-C). Wait for the engine task to observe that, run its
        // shutdown sequence (flush the flow CSV, drop the route guard to restore
        // routing), and exit. Without this await the task is dropped mid-write:
        // the CSV is lost AND routing teardown races the process exit. Belt-and-
        // suspenders: ensure the flag is set even on the Ctrl-C path.
        shared.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Err(e) = engine.await {
            shared.push_log("error", format!("engine task join: {e}"));
        }
        // Now the file channel: it observes the same flag, sends its Disconnect,
        // and drops its socket. Awaiting it makes teardown deterministic instead
        // of racing the runtime shutdown.
        if let Some(task) = file_task {
            if let Err(e) = task.await {
                shared.push_log("error", format!("file task join: {e}"));
            }
        }
        gui_result
    }

    #[cfg(not(feature = "gui"))]
    {
        let _ = files; // handle is GUI-only; headless has no dashboard
        let res = engine::run(settings, install_route, shared.clone()).await;
        shared.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(task) = file_task {
            let _ = task.await;
        }
        res
    }
}