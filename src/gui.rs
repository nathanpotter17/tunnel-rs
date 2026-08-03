//! Live dashboard for the egress engine: status, traffic observability, log.

use eframe::egui::{self, Color32, Rounding, Stroke, Vec2};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::inspect::TrafficSnapshot;
use crate::state::Shared;

/// Map the engine's log-level string into the GUI enum.
fn map_level(level: &str) -> LogLevel {
    match level {
        "error" => LogLevel::Error,
        "warn" => LogLevel::Warn,
        "debug" => LogLevel::Debug,
        _ => LogLevel::Info,
    }
}

struct Theme {
    background: Color32,
    surface: Color32,
    surface_hover: Color32,
    border: Color32,
    text_primary: Color32,
    text_secondary: Color32,
    text_muted: Color32,
    accent: Color32,
    accent_hover: Color32,
    success: Color32,
    warning: Color32,
    error: Color32,
}

const MONO_THEME: Theme = Theme {
    background: Color32::from_rgb(10, 10, 10),
    surface: Color32::from_rgb(18, 18, 18),
    surface_hover: Color32::from_rgb(26, 26, 26),
    border: Color32::from_rgb(51, 51, 51),
    text_primary: Color32::from_rgb(255, 255, 255),
    text_secondary: Color32::from_rgb(153, 153, 153),
    text_muted: Color32::from_rgb(102, 102, 102),
    accent: Color32::from_rgb(255, 255, 255),
    accent_hover: Color32::from_rgb(204, 204, 204),
    success: Color32::from_rgb(153, 153, 153),
    warning: Color32::from_rgb(179, 179, 179),
    error: Color32::from_rgb(135, 135, 135),
};

// EMBER Theme
#[allow(dead_code)]
const EMBER: Theme = Theme {
    background:       Color32::from_rgb(28, 20, 15),
    surface:          Color32::from_rgb(38, 26, 15),
    surface_hover:    Color32::from_rgb(61, 43, 26),
    border:           Color32::from_rgb(61, 43, 26),
    text_primary:     Color32::from_rgb(255, 214, 171),
    text_secondary:   Color32::from_rgb(201, 168, 138),
    text_muted:       Color32::from_rgb(125, 84, 59),
    accent:           Color32::from_rgb(250, 115, 23),
    accent_hover:     Color32::from_rgb(252, 186, 117),
    success:          Color32::from_rgb(33, 196, 94),
    warning:          Color32::from_rgb(235, 89, 13),
    error:            Color32::from_rgb(153, 46, 18),
};

impl Default for Theme {
    fn default() -> Self {
        Self {
            background: MONO_THEME.background,
            surface: MONO_THEME.surface,
            surface_hover:  MONO_THEME.surface_hover,
            border:  MONO_THEME.border,
            text_primary:  MONO_THEME.text_primary,
            text_secondary:  MONO_THEME.text_secondary,
            text_muted:  MONO_THEME.text_muted,
            accent:  MONO_THEME.accent,
            accent_hover:  MONO_THEME.accent_hover,
            success:  MONO_THEME.success,
            warning:  MONO_THEME.warning,
            error:  MONO_THEME.error,
        }
    }
}

fn apply_theme(ctx: &egui::Context, theme: &Theme) {
    let mut style = (*ctx.style()).clone();

    // Visuals
    style.visuals.dark_mode = true;
    style.visuals.override_text_color = Some(theme.text_primary);
    style.visuals.panel_fill = theme.background;
    style.visuals.window_fill = theme.surface;
    style.visuals.extreme_bg_color = theme.background;
    style.visuals.faint_bg_color = theme.surface;

    // Widget visuals
    style.visuals.widgets.noninteractive.bg_fill = theme.surface;
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, theme.text_secondary);
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, theme.border);
    style.visuals.widgets.noninteractive.rounding = Rounding::same(2.0);

    style.visuals.widgets.inactive.bg_fill = theme.surface;
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, theme.text_secondary);
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, theme.border);
    style.visuals.widgets.inactive.rounding = Rounding::same(2.0);

    style.visuals.widgets.hovered.bg_fill = theme.surface_hover;
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, theme.text_primary);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, theme.accent_hover);
    style.visuals.widgets.hovered.rounding = Rounding::same(2.0);

    style.visuals.widgets.active.bg_fill = theme.surface_hover;
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, theme.accent);
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.0, theme.accent);
    style.visuals.widgets.active.rounding = Rounding::same(2.0);

    style.visuals.widgets.open.bg_fill = theme.surface;
    style.visuals.widgets.open.fg_stroke = Stroke::new(1.0, theme.text_primary);
    style.visuals.widgets.open.bg_stroke = Stroke::new(1.0, theme.border);
    style.visuals.widgets.open.rounding = Rounding::same(2.0);

    // Selection
    style.visuals.selection.bg_fill = theme.surface_hover;
    style.visuals.selection.stroke = Stroke::new(1.0, theme.accent);

    // Window
    style.visuals.window_rounding = Rounding::same(0.0);
    style.visuals.window_stroke = Stroke::new(1.0, theme.border);

    // Spacing
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(8.0, 4.0);
    style.spacing.window_margin = egui::Margin::same(12.0);

    ctx.set_style(style);
}

/// Shared state between engine and GUI (view model).
#[derive(Default)]
pub struct AppState {
    pub logs: VecDeque<LogEntry>,
    pub status: Status,
    /// Live traffic observability snapshot (throughput, flows, protocols).
    /// Shared by reference with the monitor: the engine publishes one per tick,
    /// the dashboard borrows it for as many frames as it lasts.
    pub traffic: Arc<TrafficSnapshot>,
}

#[derive(Clone, Default)]
pub struct Status {
    pub running: bool,
    /// e.g. "WireGuard → 1.2.3.4:51820" or "Direct (uplink)".
    pub exit: String,
    pub started_at: Option<Instant>,
}

#[derive(Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Clone, Copy, PartialEq)]
pub enum LogLevel {
    Info,
    Debug,
    Warn,
    Error,
}

impl AppState {
    #[allow(dead_code)]
    pub fn push_log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.logs.push_back(LogEntry {
            timestamp: String::new(),
            level,
            message: message.into(),
        });
        while self.logs.len() > 500 {
            self.logs.pop_front();
        }
    }

    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }
}

pub struct TunnelApp {
    state: Arc<Mutex<AppState>>,
    shared: Arc<Shared>,
    theme: Theme,
    show_debug_logs: bool,
    auto_scroll: bool,
    log_filter: String,
    theme_applied: bool,
    /// Last log sequence copied into the view model. The engine bumps its
    /// counter per line; frames that see no change skip rebuilding the ring.
    log_seq: u64,
}

impl TunnelApp {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self {
            state: Arc::new(Mutex::new(AppState::default())),
            shared,
            theme: Theme::default(),
            show_debug_logs: false,
            auto_scroll: true,
            log_filter: String::new(),
            theme_applied: false,
            log_seq: u64::MAX,
        }
    }

    pub fn run(shared: Arc<Shared>) -> eframe::Result<()> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1000.0, 700.0])
                .with_min_inner_size([800.0, 600.0]),
            ..Default::default()
        };

        eframe::run_native(
            "Quorum IO - VPN v1.0",
            options,
            Box::new(move |_cc| Ok(Box::new(TunnelApp::new(shared)))),
        )
    }

    /// Copy engine state into the view model. Called once per frame.
    ///
    /// Traffic is an `Arc` clone, so the packet path is never blocked by a
    /// repaint. The log is rebuilt only when the engine's sequence counter has
    /// moved: regenerating five hundred `String`s ten times a second for a ring
    /// that usually has not changed is pure waste, and it takes the same lock the
    /// logger writes under.
    fn sync_from_engine(&mut self) {
        let traffic = self.shared.monitor.snapshot();
        let (running, exit, started_at) = if let Ok(st) = self.shared.status.lock() {
            (st.running, st.exit.clone(), st.started_at)
        } else {
            (false, String::new(), None)
        };

        let seq = self.shared.log_seq.load(std::sync::atomic::Ordering::Relaxed);
        let logs: Option<Vec<(LogLevel, String)>> = if seq == self.log_seq {
            None
        } else {
            self.log_seq = seq;
            self.shared
                .logs
                .lock()
                .ok()
                .map(|l| l.iter().map(|line| (map_level(line.level), line.msg.clone())).collect())
        };

        if let Ok(mut s) = self.state.lock() {
            s.status.running = running;
            s.status.exit = exit;
            s.status.started_at = started_at;
            s.traffic = traffic;

            // Rebuild the console ring from the unified engine log — the engine
            // is the single source of truth, so the view is regenerated rather
            // than appended to.
            if let Some(logs) = logs {
                s.logs.clear();
                for (level, message) in logs {
                    s.logs.push_back(LogEntry { timestamp: String::new(), level, message });
                }
            }
        }
    }
}

impl eframe::App for TunnelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply theme once
        if !self.theme_applied {
            apply_theme(ctx, &self.theme);
            self.theme_applied = true;
        }

        ctx.request_repaint_after(Duration::from_millis(100));

        // Pull engine + file-channel state into the view model each frame.
        self.sync_from_engine();

        // On window close, ask the engine to restore routing before exit.
        if ctx.input(|i| i.viewport().close_requested()) {
            self.shared.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        let mut show_debug_logs = self.show_debug_logs;
        let mut auto_scroll = self.auto_scroll;
        let mut log_filter = std::mem::take(&mut self.log_filter);
        let state_arc = self.state.clone();
        let theme = &self.theme;

        // Header panel
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::none()
                .fill(theme.background)
                .inner_margin(egui::Margin::symmetric(16.0, 12.0)))
            .show(ctx, |ui| {
                let state = state_arc.lock().unwrap();
                render_header(ui, &state, theme);
            });

        // Main content
        egui::CentralPanel::default()
            .frame(egui::Frame::none()
                .fill(theme.background)
                .inner_margin(egui::Margin::same(12.0)))
            .show(ctx, |ui| {
                let mut state = state_arc.lock().unwrap();

                // Two stacked regions: the traffic dashboard and the console.
                // The console takes whatever remains AT RENDER TIME so it meets
                // the window bottom exactly — a precomputed residual drifts from
                // egui's actual layout (implicit item spacing between widgets)
                // and leaves a gap.
                let available = ui.available_size();
                let spacing = 8.0;
                let total_width = available.x;
                let traffic_height = (available.y * 0.62).max(280.0);

                render_panel(ui, "TRAFFIC", total_width, traffic_height, theme, |ui| {
                    render_traffic(ui, &state.traffic, theme);
                });

                ui.add_space(spacing);

                let console_height = ui.available_height().max(110.0);
                render_panel(ui, "LOG", total_width, console_height, theme, |ui| {
                    render_console(ui, &mut state, &mut show_debug_logs, &mut auto_scroll, &mut log_filter, theme);
                });
            });

        self.show_debug_logs = show_debug_logs;
        self.auto_scroll = auto_scroll;
        self.log_filter = log_filter;
    }
}

// ============================================================================
// Render Functions
// ============================================================================

fn render_panel(
    ui: &mut egui::Ui,
    title: &str,
    width: f32,
    height: f32,
    theme: &Theme,
    content: impl FnOnce(&mut egui::Ui),
) {
    egui::Frame::none()
        .fill(theme.surface)
        .stroke(Stroke::new(1.0, theme.border))
        .rounding(Rounding::same(2.0))
        .show(ui, |ui| {
            ui.set_width(width);
            ui.set_height(height);

            ui.vertical(|ui| {
                // Panel header
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new(title)
                        .color(theme.text_muted)
                        .size(10.0)
                        .strong());
                });

                ui.add_space(4.0);

                // Separator line
                let rect = ui.available_rect_before_wrap();
                ui.painter().hline(
                    rect.x_range(),
                    rect.top(),
                    Stroke::new(1.0, theme.border),
                );

                ui.add_space(4.0);

                // Content area with padding
                egui::Frame::none()
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                    .show(ui, |ui| {
                        content(ui);
                    });
            });
        });
}

fn render_header(ui: &mut egui::Ui, state: &AppState, theme: &Theme) {
    ui.horizontal(|ui| {
        // Title
        ui.label(egui::RichText::new("QUORUM IO - VPN v1.0")
            .color(theme.text_primary)
            .size(14.0)
            .strong()
            .monospace());

        ui.add_space(16.0);

        // Status indicator
        let (status_text, status_color, connstat) = if state.status.running {
            ("CONNECTED", theme.text_primary, "[ON]")
        } else {
            ("OFFLINE", theme.text_muted, "[OFF]")
        };

        ui.label(egui::RichText::new(connstat)
            .color(status_color)
            .size(10.0)
            .monospace());
        ui.label(egui::RichText::new(status_text)
            .color(status_color)
            .size(10.0)
            .monospace());

        if state.status.running && !state.status.exit.is_empty() {
            ui.add_space(8.0);
            ui.label(egui::RichText::new(&state.status.exit)
                .color(theme.text_muted)
                .size(10.0)
                .monospace());
        }

        // Right side: uptime and session totals, read from the traffic monitor —
        // the only remaining source of truth now the peer-session table is gone.
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(started) = state.status.started_at {
                ui.label(egui::RichText::new(format_duration(started.elapsed()))
                    .color(theme.text_muted)
                    .size(10.0)
                    .monospace());
            }

            let total = state.traffic.total_up + state.traffic.total_down;
            if total > 0 {
                ui.add_space(16.0);
                ui.label(egui::RichText::new(format_bytes(total))
                    .color(theme.text_secondary)
                    .size(10.0)
                    .monospace());
            }
        });
    });
}

fn render_console(
    ui: &mut egui::Ui,
    state: &mut AppState,
    show_debug_logs: &mut bool,
    auto_scroll: &mut bool,
    log_filter: &mut String,
    theme: &Theme,
) {
    // Toolbar
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(log_filter)
            .desired_width(120.0)
            .hint_text("filter...")
            .font(egui::TextStyle::Monospace));

        ui.add_space(8.0);

        ui.checkbox(show_debug_logs, "");
        ui.label(egui::RichText::new("debug")
            .color(theme.text_muted)
            .size(10.0)
            .monospace());

        ui.checkbox(auto_scroll, "");
        ui.label(egui::RichText::new("follow")
            .color(theme.text_muted)
            .size(10.0)
            .monospace());

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if mono_button(ui, "CLEAR", theme).clicked() {
                state.clear_logs();
            }

            ui.label(egui::RichText::new(format!("{}", state.logs.len()))
                .color(theme.text_muted)
                .size(9.0)
                .monospace());
        });
    });

    ui.add_space(4.0);

    // Log area
    egui::ScrollArea::vertical()
        .id_salt("console_scroll")
        .auto_shrink([false, false])
        .stick_to_bottom(*auto_scroll)
        .show(ui, |ui| {
            ui.style_mut().override_text_style = Some(egui::TextStyle::Monospace);

            for entry in &state.logs {
                if entry.level == LogLevel::Debug && !*show_debug_logs {
                    continue;
                }
                if !log_filter.is_empty() &&
                   !entry.message.to_lowercase().contains(&log_filter.to_lowercase()) {
                    continue;
                }

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&entry.timestamp)
                        .color(theme.text_muted)
                        .size(9.0));

                    let level_color = match entry.level {
                        LogLevel::Info => theme.text_secondary,
                        LogLevel::Debug => theme.text_muted,
                        LogLevel::Warn => theme.warning,
                        LogLevel::Error => theme.error,
                    };

                    let level_char = match entry.level {
                        LogLevel::Info => "[INFO]",
                        LogLevel::Debug => "[DEBUG]",
                        LogLevel::Warn => "[WARN]",
                        LogLevel::Error => "[ERR]",
                    };

                    ui.label(egui::RichText::new(level_char)
                        .color(level_color)
                        .size(9.0));

                    ui.label(egui::RichText::new(&entry.message)
                        .color(theme.text_secondary)
                        .size(10.0));
                });
            }
        });
}

// ============================================================================
// Traffic observability dashboard
// ============================================================================

fn render_traffic(ui: &mut egui::Ui, traffic: &TrafficSnapshot, theme: &Theme) {
    // Top block: throughput graph (left) + stat tiles (right). Sized to the
    // panel, not a fixed cap — a 150px ceiling once left the graph at half
    // height on any normally-sized window.
    let graph_h = (ui.available_height() * 0.45).clamp(96.0, 360.0);
    ui.horizontal(|ui| {
        let graph_w = (ui.available_width() * 0.60).max(140.0);
        ui.vertical(|ui| {
            ui.set_width(graph_w);
            draw_throughput(ui, traffic, graph_w, graph_h, theme);
        });

        ui.add_space(12.0);

        ui.vertical(|ui| {
            stat_row(ui, "DOWN", &format_rate(traffic.rate_down), theme.accent, theme);
            stat_row(ui, "UP", &format_rate(traffic.rate_up), theme.text_primary, theme);
            stat_row(ui, "RX", &format_bytes(traffic.total_down), theme.text_secondary, theme);
            stat_row(ui, "TX", &format_bytes(traffic.total_up), theme.text_secondary, theme);
            stat_row(ui, "FLOWS", &traffic.active_flows.to_string(), theme.text_secondary, theme);
            stat_row(
                ui,
                "PKTS",
                &format!("{}", traffic.pkts_up + traffic.pkts_down),
                theme.text_muted,
                theme,
            );
        });
    });

    ui.add_space(8.0);
    render_proto_bar(ui, traffic, theme);
    ui.add_space(8.0);

    // Flow table header.
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        mono_cell(ui, format!("{:<25}", "REMOTE"), theme.text_muted);
        mono_cell(ui, format!("{:<12}", "APP"), theme.text_muted);
        mono_cell(ui, format!("{:<5}", "L4"), theme.text_muted);
        mono_cell(ui, format!("{:>10}", "RX"), theme.text_muted);
        mono_cell(ui, format!("{:>10}", "TX"), theme.text_muted);
        mono_cell(ui, format!("{:>11}", "RATE"), theme.text_muted);
    });

    let rect = ui.available_rect_before_wrap();
    ui.painter().hline(rect.x_range(), rect.top(), Stroke::new(1.0, theme.border));
    ui.add_space(4.0);

    if traffic.flows.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(16.0);
            ui.label(
                egui::RichText::new("no traffic captured yet — connect and generate some")
                    .color(theme.text_muted)
                    .size(11.0)
                    .monospace(),
            );
        });
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt("traffic_flows_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for f in &traffic.flows {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let remote = truncate(&f.remote, 24);
                    // Shed / reaped rows are deliberate admission-control actions,
                    // not live conversations — render the whole row muted and swap
                    // the rate cell for a status badge so they don't read as
                    // anomalous up-only or half-open flows.
                    let tagged = !f.status.is_empty();
                    // Fade rows that have gone quiet, and tagged rows always.
                    let base = if tagged || f.idle_ms > 5000 {
                        theme.text_muted
                    } else {
                        theme.text_secondary
                    };
                    let app_color = if tagged { theme.text_muted } else { proto_color(f.app, theme) };
                    mono_cell(ui, format!("{:<25}", remote), base);
                    mono_cell(ui, format!("{:<12}", f.app), app_color);
                    mono_cell(ui, format!("{:<5}", f.proto), theme.text_muted);
                    mono_cell(ui, format!("{:>10}", format_bytes_short(f.down)), base);
                    mono_cell(ui, format!("{:>10}", format_bytes_short(f.up)), base);
                    if tagged {
                        mono_cell(ui, format!("{:>11}", f.status), theme.text_muted);
                    } else {
                        let rate_color = if f.rate > 0.0 { theme.text_primary } else { theme.text_muted };
                        mono_cell(ui, format!("{:>11}", format_rate(f.rate)), rate_color);
                    }
                });
            }
        });
}

/// Draw the up/down throughput history as a small area/line chart.
fn draw_throughput(ui: &mut egui::Ui, traffic: &TrafficSnapshot, w: f32, h: f32, theme: &Theme) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, h), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, Rounding::same(2.0), theme.background);

    let max = traffic
        .down_series
        .iter()
        .chain(traffic.up_series.iter())
        .cloned()
        .fold(1.0_f64, f64::max);

    let plot = |series: &[f64], color: Color32, fill: bool| {
        if series.len() < 2 {
            return;
        }
        let n = series.len();
        let dx = rect.width() / (n - 1) as f32;
        let mut pts: Vec<egui::Pos2> = Vec::with_capacity(n);
        for (i, v) in series.iter().enumerate() {
            let x = rect.left() + dx * i as f32;
            let y = rect.bottom() - (v / max) as f32 * (rect.height() - 4.0) - 2.0;
            pts.push(egui::pos2(x, y));
        }
        if fill {
            // Faint filled area bars under the download line.
            for (i, p) in pts.iter().enumerate() {
                let x0 = rect.left() + dx * i as f32;
                let bar = egui::Rect::from_min_max(
                    egui::pos2(x0, p.y),
                    egui::pos2((x0 + dx).min(rect.right()), rect.bottom()),
                );
                painter.rect_filled(bar, Rounding::ZERO, with_alpha(color, 40));
            }
        }
        for w in pts.windows(2) {
            painter.line_segment([w[0], w[1]], Stroke::new(1.5, color));
        }
    };

    plot(&traffic.down_series, theme.accent, true);
    plot(&traffic.up_series, theme.text_primary, false);

    // Legend.
    painter.text(
        rect.left_top() + Vec2::new(6.0, 4.0),
        egui::Align2::LEFT_TOP,
        format!("▼ {}   ▲ {}", format_rate(traffic.rate_down), format_rate(traffic.rate_up)),
        egui::FontId::monospace(10.0),
        theme.text_secondary,
    );
}

/// A labeled statistic aligned in a fixed-width tile.
fn stat_row(ui: &mut egui::Ui, label: &str, value: &str, value_color: Color32, theme: &Theme) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(format!("{:<6}", label))
                .color(theme.text_muted)
                .size(10.0)
                .monospace(),
        );
        ui.label(
            egui::RichText::new(value)
                .color(value_color)
                .size(12.0)
                .monospace()
                .strong(),
        );
    });
}

/// Stacked bar + legend showing byte share per application protocol.
fn render_proto_bar(ui: &mut egui::Ui, traffic: &TrafficSnapshot, theme: &Theme) {
    let total: u64 = traffic.protos.iter().map(|(_, b)| *b).sum();
    if total == 0 {
        return;
    }

    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 12.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, Rounding::same(2.0), theme.surface_hover);

    let mut x = rect.left();
    for (label, bytes) in &traffic.protos {
        let frac = *bytes as f32 / total as f32;
        let seg_w = frac * rect.width();
        let seg = egui::Rect::from_min_size(egui::pos2(x, rect.top()), Vec2::new(seg_w, rect.height()));
        painter.rect_filled(seg, Rounding::ZERO, proto_color(label, theme));
        x += seg_w;
    }

    ui.add_space(4.0);

    // Legend: top protocols.
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        for (label, bytes) in traffic.protos.iter().take(8) {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                let (sq, _) = ui.allocate_exact_size(Vec2::new(8.0, 8.0), egui::Sense::hover());
                ui.painter().rect_filled(sq, Rounding::ZERO, proto_color(label, theme));
                ui.label(
                    egui::RichText::new(format!("{} {}", label, format_bytes_short(*bytes)))
                        .color(theme.text_secondary)
                        .size(9.0)
                        .monospace(),
                );
            });
        }
    });
}

/// Stable color per application protocol, tuned to read on the dark surfaces.
fn proto_color(app: &str, theme: &Theme) -> Color32 {
    match app {
        "WireGuard" => Color32::from_rgb(88, 166, 255),
        "OpenVPN" => Color32::from_rgb(255, 149, 0),
        "Shadowsocks" | "Obfuscated" => Color32::from_rgb(230, 90, 90),
        "TLS" => Color32::from_rgb(120, 200, 130),
        "QUIC" => Color32::from_rgb(180, 140, 240),
        "DNS" => Color32::from_rgb(230, 200, 100),
        "HTTP" => Color32::from_rgb(150, 190, 220),
        "SSH" => Color32::from_rgb(200, 120, 200),
        "NTP" | "DHCP" => Color32::from_rgb(120, 160, 160),
        "ICMP" => Color32::from_rgb(150, 150, 150),
        _ => theme.text_muted,
    }
}

fn with_alpha(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

fn mono_cell(ui: &mut egui::Ui, text: String, color: Color32) {
    ui.label(egui::RichText::new(text).color(color).size(10.0).monospace());
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn format_rate(bps: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    if bps >= GB {
        format!("{:.2} GB/s", bps / GB)
    } else if bps >= MB {
        format!("{:.2} MB/s", bps / MB)
    } else if bps >= KB {
        format!("{:.1} KB/s", bps / KB)
    } else {
        format!("{:.0} B/s", bps)
    }
}

fn mono_button(ui: &mut egui::Ui, text: &str, theme: &Theme) -> egui::Response {
    let button = egui::Button::new(
        egui::RichText::new(text)
            .color(theme.text_secondary)
            .size(9.0)
            .monospace()
    )
    .fill(theme.background)
    .stroke(Stroke::new(1.0, theme.border))
    .rounding(Rounding::same(2.0));

    ui.add(button)
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_bytes_short(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.0}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.0}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.0}K", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;

    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, mins, secs)
    } else {
        format!("{:02}:{:02}", mins, secs)
    }
}