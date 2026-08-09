//! Software-defined tunnel

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;

mod conn;
mod device;
mod engine;
mod inspect;
mod killswitch;
mod pin;
mod preflight;
/// The inbound port lease is engine machinery, not dashboard machinery: the
/// exit driver installs what it negotiates, headless or not.
mod portmap;
/// Active probes are driven from the dashboard only, so the module follows the
/// GUI feature rather than sitting dead in a headless build.
#[cfg(feature = "gui")]
mod probe;
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
        --log            Also write the full log transcript to
                         tunnel-<timestamp>.txt, next to the session flow CSV
    -v, --verbose        Verbose logging
    -h, --help / -V, --version

Unknown commands, arguments, or settings fields are errors — nothing is
silently ignored."
    );
}

/// Install the process logger.
///
/// Console output is always on. `--log` adds a second sink writing the same
/// stream, unstyled, to `tunnel-<stamp>.txt` beside the session flow CSV — the
/// transcript is a file, not a UI surface. A panic hook writes to both, because
/// the one message worth capturing above all others is the one that arrives on
/// the way down.
fn setup_logging(verbose: bool, log_file: Option<&Path>) -> Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = if verbose {
        EnvFilter::new("tunnel=debug,snow=info")
    } else {
        EnvFilter::new("tunnel=info")
    };

    let sink = match log_file {
        Some(path) => {
            let file = std::fs::File::create(path)
                .with_context(|| format!("could not create log file {}", path.display()))?;
            Some(FileSink(Arc::new(Mutex::new(file))))
        }
        None => None,
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(sink.clone().map(|s| {
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(s)
        }))
        .init();

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(s) = &sink {
            let mut w = s.clone();
            let _ = writeln!(w, "PANIC: {info}");
            let _ = w.flush();
        }
        default_hook(info);
    }));

    if let Some(path) = log_file {
        tracing::info!("log transcript: {}", path.display());
    }
    Ok(())
}

/// A shared, line-buffered handle to the transcript file.
///
/// `tracing-subscriber` needs a `MakeWriter` that can hand out an independent
/// writer per event; the mutex serialises the interleaved records from the
/// engine's tasks so lines never tear.
#[derive(Clone)]
struct FileSink(Arc<Mutex<std::fs::File>>);

impl std::io::Write for FileSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Poisoning cannot silence the transcript: the lock guards a plain File
        // handle and nothing under it can panic, so recover the guard and keep
        // writing — the panic hook itself writes through this sink, on whatever
        // thread is going down.
        self.0.lock().unwrap_or_else(|e| e.into_inner()).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).flush()
    }
}

impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for FileSink {
    type Writer = FileSink;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut settings_path: Option<PathBuf> = None;
    let mut verbose = false;
    let mut install_route = true;
    let mut log_to_file = false;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => { print_usage(); return Ok(()); }
            "-V" | "--version" => { println!("tunnel {VERSION}"); return Ok(()); }
            "-v" | "--verbose" => verbose = true,
            "--no-route" => install_route = false,
            "--log" => log_to_file = true,
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
                if let Some(prev) = command {
                    bail!("multiple commands given: {prev} and {a}");
                }
                command = Some(a.as_str());
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

    // Logging first, so settings-load messages reach the console and, when
    // requested, the transcript. `Shared` is constructed before it because it
    // owns the session paths the transcript is named from.
    let shared = Shared::new();
    let log_path = log_to_file.then(|| shared.session.log_txt());
    setup_logging(verbose, log_path.as_deref())?;

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

    // One engine future, built once and consumed by whichever tail this build
    // has. The wrapper is the single place every engine exit passes through, so
    // it is where the outcome lands in the shared status: `running` goes false
    // and, on an error, `last_error` carries the reason. The dashboard renders
    // exactly that — a dead engine can never keep wearing CONNECTED, and the
    // failure text appears where the user is actually looking.
    let engine_shared = shared.clone();
    let engine_fut = async move {
        let result = engine::run(
            settings,
            install_route,
            egress,
            orig_gateway,
            dns_backend,
            engine_shared.clone(),
        )
        .await;
        if let Ok(mut st) = engine_shared.status.lock() {
            st.running = false;
            if let Err(e) = &result {
                st.last_error = Some(format!("{e:#}"));
            }
        }
        result
    };

    #[cfg(feature = "gui")]
    {
        let engine = tokio::spawn(async move {
            if let Err(e) = engine_fut.await {
                tracing::error!("engine: {e:#}");
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
            tracing::error!("engine task join: {e}");
        }
        gui_result
    }

    #[cfg(not(feature = "gui"))]
    {
        let res = engine_fut.await;
        shared.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        res
    }
}
