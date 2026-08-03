//! Software-defined tunnel: smoltcp egress engine + live observability.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod conn;
mod device;
mod engine;
mod inspect;
mod killswitch;
mod outbound;
mod pin;
mod preflight;
mod route;
mod settings;
mod state;
mod tripwire;
mod tunio;
mod wg;

#[cfg(feature = "gui")]
mod gui;

use settings::Settings;
use state::Shared;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!(
        "tunnel {VERSION} - software-defined egress engine

USAGE:
    tunnel [OPTIONS] [COMMAND] [SETTINGS.toml]

COMMANDS:
    gui                  Run the engine + dashboard (default)
    init                 Write a starter settings file

ARGS:
    <SETTINGS.toml>      The one settings file (engine + optional [wireguard]).
                         Any positional ending in .toml.
                         Default: tunnel.toml in the working directory.

OPTIONS:
    -s, --settings <P>   Settings file (same as the positional form)
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

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut settings_path: Option<PathBuf> = None;
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
    for a in &positional {
        match a.as_str() {
            "init" | "gui" => {
                if command.is_some() {
                    bail!("multiple commands given: {} and {}", command.unwrap(), a);
                }
                command = Some(if a == "init" { "init" } else { "gui" });
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

    // Settings path is resolved BEFORE subcommands — `init` writes the same one
    // file the engine reads. An explicitly named file that doesn't exist is a
    // fatal error for the engine; only the implicit default may fall back to
    // built-in defaults (loudly).
    let settings_explicit = settings_path.is_some();
    let settings_path = settings_path.unwrap_or_else(|| PathBuf::from("tunnel.toml"));

    // Config subcommands run before the engine.
    if command == Some("init") {
        return settings::init_config(&settings_path);
    }

    // Logging first, so settings load messages reach stdout AND the dashboard
    // log ring.
    let shared = Shared::new();
    setup_logging(verbose, shared.clone());

    if settings_explicit && !settings_path.exists() {
        bail!("settings file not found: {}", settings_path.display());
    }
    let settings = Settings::load_or_default(&settings_path)?;

    // Environment gate. Every precondition the engine needs is checked BEFORE
    // the TUN exists, the route is hijacked, or the kill switch is armed — so a
    // host that cannot support the engine costs one message instead of a
    // half-installed network. It also resolves the resolver strategy once, so
    // detection (there) and use (route::DnsGuard) cannot disagree, exactly as
    // the egress pin below is resolved once and shared.
    let dns_backend = preflight::run(install_route)?.dns;

    // Discover the uplink and verify the egress pin ONCE, before anything can
    // hijack the route, then hand it to the engine so the pin and the host-route
    // cannot disagree on which uplink is real.
    let (egress, orig_gateway) = pin::discover_egress();

    #[cfg(feature = "gui")]
    {
        let engine_shared = shared.clone();
        let engine = tokio::spawn(async move {
            if let Err(e) = engine::run(
                settings,
                install_route,
                egress,
                orig_gateway,
                dns_backend,
                engine_shared.clone(),
            )
            .await
            {
                engine_shared.push_log("error", format!("engine: {e:#}"));
            }
        });
        let gui_result =
            gui::TunnelApp::run(shared.clone()).map_err(|e| anyhow::anyhow!("dashboard: {e}"));

        // The GUI has returned — it set `shutdown` on window close (or the user
        // hit Ctrl-C). Wait for the engine task to observe that, run its shutdown
        // sequence (flush the flow CSV, drop the guards that restore routing and
        // the resolver), and exit. Without this await the task is dropped
        // mid-write: the CSV is lost AND teardown races the process exit.
        // Belt-and-suspenders: ensure the flag is set even on the Ctrl-C path.
        shared.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Err(e) = engine.await {
            shared.push_log("error", format!("engine task join: {e}"));
        }
        gui_result
    }

    #[cfg(not(feature = "gui"))]
    {
        let res = engine::run(
            settings,
            install_route,
            egress,
            orig_gateway,
            dns_backend,
            shared.clone(),
        )
        .await;
        shared.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        res
    }
}
