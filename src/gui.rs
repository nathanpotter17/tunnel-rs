//! Provides a cross-platform GUI for managing tunnel connections,
//! file sharing, and viewing session logs.

use eframe::egui::{self, Color32, Rounding, Stroke, Vec2};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::file_transfer::FileTransferManager;
use crate::inspect::TrafficSnapshot;
use crate::state::Shared;
use crate::file_session::{FileAction, FileHandle};

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
    pub sessions: Vec<SessionInfo>,
    pub logs: VecDeque<LogEntry>,
    pub shared_files: Vec<SharedFile>,
    pub remote_files: Vec<RemoteFile>,
    pub status: Status,
    pub transfer: Option<TransferProgress>,
    pub pending_actions: Vec<GuiAction>,
    /// Pending file transfer requests awaiting user approval
    pub pending_transfers: Vec<PendingTransferInfo>,
    /// Live traffic observability snapshot (throughput, flows, protocols).
    pub traffic: TrafficSnapshot,
}

/// Info about a pending transfer shown in the GUI
#[derive(Clone)]
pub struct PendingTransferInfo {
    pub request_id: u32,
    pub direction: String,
    pub file_name: String,
    pub file_size: u64,
    pub file_type: String,
}

#[derive(Clone, Default)]
pub struct Status {
    pub running: bool,
    pub listen_addr: String,
    pub started_at: Option<Instant>,
}

#[derive(Clone)]
pub struct SessionInfo {
    pub peer_addr: String,
    pub tun_ip: String,
    pub bytes_transferred: u64,
    pub connected_at: Instant,
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

#[derive(Clone)]
pub struct SharedFile {
    pub name: String,
    #[allow(dead_code)]
    pub path: PathBuf,
    pub size: u64,
    pub file_type: FileType,
}

#[derive(Clone)]
pub struct RemoteFile {
    pub name: String,
    pub size: u64,
    pub file_type: String,
}

#[derive(Clone)]
pub struct TransferProgress {
    pub file_name: String,
    pub progress: f32,
    pub is_upload: bool,
    #[allow(dead_code)]
    pub started_at: Instant,
}

#[derive(Clone, Debug)]
pub enum GuiAction {
    ShareFile(PathBuf),
    UnshareFile(String),
    RequestFileList,
    DownloadFile(String),
    ApproveTransfer(u32),
    DenyTransfer(u32),
}

#[derive(Clone, Copy, PartialEq)]
pub enum FileType {
    Image,
    Video,
    Text,
    Pdf,
    Other,
}

impl FileType {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "png" | "jpg" | "jpeg" | "gif" | "webp" => FileType::Image,
            "mp4" | "webm" | "mov" | "avi" | "mkv" => FileType::Video,
            "txt" | "md" | "rs" | "toml" | "json" | "yaml" => FileType::Text,
            "pdf" => FileType::Pdf,
            _ => FileType::Other,
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            FileType::Image => "IMG",
            FileType::Video => "VID",
            FileType::Text => "TXT",
            FileType::Pdf => "PDF",
            FileType::Other => "---",
        }
    }
}

impl AppState {
    pub fn push_log(&mut self, level: LogLevel, message: impl Into<String>) {
        let now = chrono::Local::now();
        self.logs.push_back(LogEntry {
            timestamp: now.format("%H:%M:%S").to_string(),
            level,
            message: message.into(),
        });
        while self.logs.len() > 500 {
            self.logs.pop_front();
        }
    }

    pub fn add_shared_file(&mut self, path: PathBuf) -> std::io::Result<()> {
        let metadata = std::fs::metadata(&path)?;
        let name = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let ext = path.extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();

        if self.shared_files.iter().any(|f| f.name == name) {
            return Ok(());
        }

        self.shared_files.push(SharedFile {
            name: name.clone(),
            path: path.clone(),
            size: metadata.len(),
            file_type: FileType::from_extension(&ext),
        });

        self.pending_actions.push(GuiAction::ShareFile(path));
        self.push_log(LogLevel::Info, format!("+ {}", name));
        Ok(())
    }

    pub fn remove_shared_file(&mut self, name: &str) {
        self.shared_files.retain(|f| f.name != name);
        self.pending_actions.push(GuiAction::UnshareFile(name.to_string()));
        self.push_log(LogLevel::Info, format!("- {}", name));
    }

    pub fn request_file_list(&mut self) {
        self.pending_actions.push(GuiAction::RequestFileList);
        self.push_log(LogLevel::Debug, "requesting file list");
    }

    pub fn download_file(&mut self, name: &str) {
        self.pending_actions.push(GuiAction::DownloadFile(name.to_string()));
        self.push_log(LogLevel::Info, format!("download: {}", name));
    }

    pub fn approve_transfer(&mut self, request_id: u32) {
        self.pending_actions.push(GuiAction::ApproveTransfer(request_id));
        self.pending_transfers.retain(|t| t.request_id != request_id);
        self.push_log(LogLevel::Info, format!("approved transfer #{}", request_id));
    }

    pub fn deny_transfer(&mut self, request_id: u32) {
        self.pending_actions.push(GuiAction::DenyTransfer(request_id));
        self.pending_transfers.retain(|t| t.request_id != request_id);
        self.push_log(LogLevel::Info, format!("denied transfer #{}", request_id));
    }

    pub fn take_pending_actions(&mut self) -> Vec<GuiAction> {
        std::mem::take(&mut self.pending_actions)
    }

    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }
}

// ============================================================================
// Application
// ============================================================================

pub struct TunnelApp {
    state: Arc<Mutex<AppState>>,
    shared: Arc<Shared>,
    files: Option<FileHandle>,
    theme: Theme,
    show_debug_logs: bool,
    auto_scroll: bool,
    log_filter: String,
    theme_applied: bool,
}

impl TunnelApp {
    pub fn new(shared: Arc<Shared>, files: Option<FileHandle>) -> Self {
        Self {
            state: Arc::new(Mutex::new(AppState::default())),
            shared,
            files,
            theme: Theme::default(),
            show_debug_logs: false,
            auto_scroll: true,
            log_filter: String::new(),
            theme_applied: false,
        }
    }

    pub fn run(shared: Arc<Shared>, files: Option<FileHandle>) -> eframe::Result<()> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1000.0, 700.0])
                .with_min_inner_size([800.0, 600.0])
                .with_drag_and_drop(true),
            ..Default::default()
        };

        eframe::run_native(
            "Quorum IO - VPN v1.0",
            options,
            Box::new(move |_cc| Ok(Box::new(TunnelApp::new(shared, files)))),
        )
    }

    /// Copy engine + file-channel state into the view model, and forward any
    /// queued UI actions to the file channel. Called once per frame.
    fn sync_from_engine(&mut self) {
        // Forward last frame's queued actions to the channel.
        let actions = if let Ok(mut s) = self.state.lock() {
            s.take_pending_actions()
        } else {
            Vec::new()
        };
        for a in actions {
            let fa = match a {
                GuiAction::ShareFile(p) => FileAction::Share(p),
                GuiAction::UnshareFile(n) => FileAction::Unshare(n),
                GuiAction::RequestFileList => FileAction::RequestList,
                GuiAction::DownloadFile(n) => FileAction::Download(n),
                GuiAction::ApproveTransfer(id) => FileAction::Approve(id),
                GuiAction::DenyTransfer(id) => FileAction::Deny(id),
            };
            if let Some(files) = &self.files {
                let _ = files.actions.try_send(fa);
            }
        }

        // Snapshot engine truth.
        let traffic = self.shared.monitor.snapshot();
        let (running, exit, started_at) = if let Ok(st) = self.shared.status.lock() {
            (st.running, st.exit.clone(), st.started_at)
        } else {
            (false, String::new(), None)
        };
        let logs: Vec<(LogLevel, String)> = if let Ok(l) = self.shared.logs.lock() {
            l.iter().map(|line| (map_level(line.level), line.msg.clone())).collect()
        } else {
            Vec::new()
        };
        let view = self
            .files
            .as_ref()
            .and_then(|f| f.view.lock().ok().map(|v| v.clone()));

        if let Ok(mut s) = self.state.lock() {
            s.status.running = running;
            s.status.listen_addr = exit.clone();
            s.status.started_at = started_at;
            s.traffic = traffic;

            // Rebuild the console ring from the unified engine log.
            s.logs.clear();
            for (level, message) in logs {
                s.logs.push_back(LogEntry { timestamp: String::new(), level, message });
            }

            if let Some(v) = view {
                s.sessions = if v.connected {
                    vec![SessionInfo {
                        peer_addr: v.peer.map(|p| p.to_string()).unwrap_or_else(|| "peer".into()),
                        tun_ip: exit,
                        bytes_transferred: 0,
                        connected_at: started_at.unwrap_or_else(Instant::now),
                    }]
                } else {
                    Vec::new()
                };
                s.shared_files = v.shared.iter().map(|f| SharedFile {
                    name: f.name.clone(),
                    path: PathBuf::new(),
                    size: f.size,
                    file_type: FileType::from_extension(&f.file_type),
                }).collect();
                s.remote_files = v.remote.iter().map(|f| RemoteFile {
                    name: f.name.clone(),
                    size: f.size,
                    file_type: f.file_type.clone(),
                }).collect();
                s.pending_transfers = v.pending.iter().map(|p| PendingTransferInfo {
                    request_id: p.id,
                    direction: p.direction.to_string(),
                    file_name: p.file_name.clone(),
                    file_size: p.file_size,
                    file_type: p.file_type.clone(),
                }).collect();
                s.transfer = v.transfer.as_ref().map(|(n, prog, up)| TransferProgress {
                    file_name: n.clone(),
                    progress: *prog,
                    is_upload: *up,
                    started_at: Instant::now(),
                });
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

                // Pending transfer approvals (prominent banner)
                if !state.pending_transfers.is_empty() {
                    render_pending_approvals(ui, &mut state, theme);
                    ui.add_space(8.0);
                }

                // Transfer progress bar (if active)
                if state.transfer.is_some() {
                    render_transfer(ui, &state, theme);
                    ui.add_space(8.0);
                }

                // Main grid layout
                // Top row: Sessions | Local Files | Remote Files
                // Bottom row: Console (full width)

                let available = ui.available_size();
                let spacing = 8.0;

                // Calculate column width so 3 panels + 2 gaps = total width
                let total_width = available.x;
                let col_width = (total_width - spacing * 2.0) / 3.0;

                // Three stacked regions: status row, traffic dashboard, console.
                // Only the first two are precomputed; the console takes whatever
                // remains AT RENDER TIME, so it meets the window bottom exactly —
                // a precomputed residual drifts from egui's actual layout (implicit
                // item spacing between widgets) and leaves a gap.
                let top_height = (available.y * 0.24).max(130.0);
                let traffic_height = (available.y * 0.46).max(240.0);

                // Row 1 - Sessions | Local | Remote
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = spacing;

                    render_panel(ui, "SESSIONS", col_width, top_height, theme, |ui| {
                        render_sessions(ui, &state, theme);
                    });

                    render_panel(ui, "LOCAL", col_width, top_height, theme, |ui| {
                        render_local_files(ui, &mut state, theme);
                    });

                    render_panel(ui, "REMOTE", col_width, top_height, theme, |ui| {
                        render_remote_files(ui, &mut state, theme);
                    });
                });

                ui.add_space(spacing);

                // Row 2 - Traffic observability (full width)
                render_panel(ui, "TRAFFIC", total_width, traffic_height, theme, |ui| {
                    render_traffic(ui, &state.traffic, theme);
                });

                ui.add_space(spacing);

                // Row 3 - Console fills exactly to the window bottom.
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

        if state.status.running && !state.status.listen_addr.is_empty() {
            ui.add_space(8.0);
            ui.label(egui::RichText::new(&state.status.listen_addr)
                .color(theme.text_muted)
                .size(10.0)
                .monospace());
        }

        // Right side: uptime
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(started) = state.status.started_at {
                ui.label(egui::RichText::new(format_duration(started.elapsed()))
                    .color(theme.text_muted)
                    .size(10.0)
                    .monospace());
            }

            // Stats
            let total_bytes: u64 = state.sessions.iter().map(|s| s.bytes_transferred).sum();
            if total_bytes > 0 {
                ui.add_space(16.0);
                ui.label(egui::RichText::new(format_bytes(total_bytes))
                    .color(theme.text_secondary)
                    .size(10.0)
                    .monospace());
            }
        });
    });
}

fn render_pending_approvals(ui: &mut egui::Ui, state: &mut AppState, theme: &Theme) {
    for i in 0..state.pending_transfers.len() {
        let transfer = &state.pending_transfers[i];
        let request_id = transfer.request_id;
        let direction = transfer.direction.clone();
        let file_name = transfer.file_name.clone();
        let file_size = transfer.file_size;

        egui::Frame::none()
            .fill(theme.surface)
            .stroke(Stroke::new(1.0, theme.warning))
            .rounding(Rounding::same(2.0))
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("[?]")
                        .color(theme.warning)
                        .size(11.0)
                        .monospace()
                        .strong());

                    ui.label(egui::RichText::new(format!(
                        "Peer wants to {} \"{}\" ({})",
                        direction, file_name, format_bytes_short(file_size)
                    ))
                        .color(theme.text_primary)
                        .size(11.0)
                        .monospace());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let deny_btn = egui::Button::new(
                            egui::RichText::new("DENY")
                                .color(theme.error)
                                .size(10.0)
                                .monospace()
                        )
                        .fill(theme.background)
                        .stroke(Stroke::new(1.0, theme.error))
                        .rounding(Rounding::same(2.0));

                        if ui.add(deny_btn).clicked() {
                            state.deny_transfer(request_id);
                        }

                        ui.add_space(4.0);

                        let approve_btn = egui::Button::new(
                            egui::RichText::new("ALLOW")
                                .color(theme.success)
                                .size(10.0)
                                .monospace()
                        )
                        .fill(theme.background)
                        .stroke(Stroke::new(1.0, theme.success))
                        .rounding(Rounding::same(2.0));

                        if ui.add(approve_btn).clicked() {
                            state.approve_transfer(request_id);
                        }
                    });
                });
            });
        ui.add_space(4.0);
    }
}

fn render_transfer(ui: &mut egui::Ui, state: &AppState, theme: &Theme) {
    if let Some(ref transfer) = state.transfer {
        egui::Frame::none()
            .fill(theme.surface)
            .stroke(Stroke::new(1.0, theme.border))
            .rounding(Rounding::same(2.0))
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let direction = if transfer.is_upload { "UP" } else { "DN" };
                    ui.label(egui::RichText::new(direction)
                        .color(theme.text_muted)
                        .size(10.0)
                        .monospace());

                    ui.label(egui::RichText::new(&transfer.file_name)
                        .color(theme.text_secondary)
                        .size(11.0)
                        .monospace());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(format!("{:.0}%", transfer.progress))
                            .color(theme.text_primary)
                            .size(11.0)
                            .monospace());

                        // Progress bar
                        let available_width = ui.available_width().min(200.0);
                        let (rect, _) = ui.allocate_exact_size(
                            Vec2::new(available_width, 4.0),
                            egui::Sense::hover(),
                        );

                        // Background
                        ui.painter().rect_filled(rect, 2.0, theme.border);

                        // Fill
                        let fill_width = rect.width() * (transfer.progress / 100.0);
                        let fill_rect = egui::Rect::from_min_size(
                            rect.min,
                            Vec2::new(fill_width, rect.height()),
                        );
                        ui.painter().rect_filled(fill_rect, 2.0, theme.text_secondary);
                    });
                });
            });
    }
}

fn render_sessions(ui: &mut egui::Ui, state: &AppState, theme: &Theme) {
    if state.sessions.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label(egui::RichText::new("no active sessions")
                .color(theme.text_muted)
                .size(11.0)
                .monospace());
        });
    } else {
        egui::ScrollArea::vertical()
            .id_salt("sessions_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for session in &state.sessions {
                    egui::Frame::none()
                        .fill(theme.background)
                        .rounding(Rounding::same(2.0))
                        .inner_margin(egui::Margin::same(8.0))
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(&session.peer_addr)
                                    .color(theme.text_primary)
                                    .size(11.0)
                                    .monospace());

                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(&session.tun_ip)
                                        .color(theme.text_muted)
                                        .size(10.0)
                                        .monospace());

                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.label(egui::RichText::new(format_bytes(session.bytes_transferred))
                                            .color(theme.text_secondary)
                                            .size(10.0)
                                            .monospace());
                                    });
                                });
                            });
                        });
                    ui.add_space(4.0);
                }
            });
    }
}

fn render_local_files(ui: &mut egui::Ui, state: &mut AppState, theme: &Theme) {
    // Toolbar
    ui.horizontal(|ui| {
        if mono_button(ui, "+ ADD", theme).clicked() {
            if let Some(paths) = rfd::FileDialog::new()
                .set_title("Select files")
                .pick_files()
            {
                for path in paths {
                    let _ = state.add_shared_file(path);
                }
            }
        }

        if mono_button(ui, "FOLDER", theme).clicked() {
            if let Some(folder) = rfd::FileDialog::new()
                .set_title("Select folder")
                .pick_folder()
            {
                if let Ok(entries) = std::fs::read_dir(&folder) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            let _ = state.add_shared_file(path);
                        }
                    }
                }
            }
        }
    });

    ui.add_space(8.0);

    // File list
    if state.shared_files.is_empty() {
        ui.label(egui::RichText::new("no files shared")
            .color(theme.text_muted)
            .size(10.0)
            .monospace());
    } else {
        egui::ScrollArea::vertical()
            .id_salt("local_files_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let mut to_remove = None;

                for file in &state.shared_files {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(file.file_type.icon())
                            .color(theme.text_muted)
                            .size(9.0)
                            .monospace());

                        ui.label(egui::RichText::new(&file.name)
                            .color(theme.text_secondary)
                            .size(10.0)
                            .monospace());

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(egui::Label::new(
                                egui::RichText::new("×")
                                    .color(theme.text_muted)
                                    .size(12.0)
                            ).sense(egui::Sense::click())).clicked() {
                                to_remove = Some(file.name.clone());
                            }

                            ui.label(egui::RichText::new(format_bytes_short(file.size))
                                .color(theme.text_muted)
                                .size(9.0)
                                .monospace());
                        });
                    });
                }

                if let Some(name) = to_remove {
                    state.remove_shared_file(&name);
                }
            });
    }
}

fn render_remote_files(ui: &mut egui::Ui, state: &mut AppState, theme: &Theme) {
    // Toolbar
    ui.horizontal(|ui| {
        if mono_button(ui, "REFRESH", theme).clicked() {
            state.request_file_list();
        }

        if mono_button(ui, "OPEN DIR", theme).clicked() {
            let download_dir = FileTransferManager::default_download_dir();
            let _ = std::fs::create_dir_all(&download_dir);
            let _ = open::that(&download_dir);
        }
    });

    ui.add_space(8.0);

    // File list
    if state.remote_files.is_empty() {
        ui.label(egui::RichText::new("no remote files")
            .color(theme.text_muted)
            .size(10.0)
            .monospace());
    } else {
        egui::ScrollArea::vertical()
            .id_salt("remote_files_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let mut download_file = None;

                for file in &state.remote_files {
                    ui.horizontal(|ui| {
                        let icon = match file.file_type.as_str() {
                            "png" | "jpg" | "jpeg" | "gif" | "webp" => "IMG",
                            "mp4" | "mov" | "webm" | "avi" => "VID",
                            "txt" | "md" | "rs" | "toml" => "TXT",
                            "pdf" => "PDF",
                            _ => "---",
                        };

                        ui.label(egui::RichText::new(icon)
                            .color(theme.text_muted)
                            .size(9.0)
                            .monospace());

                        ui.label(egui::RichText::new(&file.name)
                            .color(theme.text_secondary)
                            .size(10.0)
                            .monospace());

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(egui::Label::new(
                                egui::RichText::new("Download")
                                    .color(theme.text_secondary)
                                    .size(11.0)
                            ).sense(egui::Sense::click())).clicked() {
                                download_file = Some(file.name.clone());
                            }

                            ui.label(egui::RichText::new(format_bytes_short(file.size))
                                .color(theme.text_muted)
                                .size(9.0)
                                .monospace());
                        });
                    });
                }

                if let Some(name) = download_file {
                    state.download_file(&name);
                }
            });
    }
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
                    // Fade rows that have gone quiet.
                    let base = if f.idle_ms > 5000 { theme.text_muted } else { theme.text_secondary };
                    mono_cell(ui, format!("{:<25}", remote), base);
                    mono_cell(ui, format!("{:<12}", f.app), proto_color(f.app, theme));
                    mono_cell(ui, format!("{:<5}", f.proto), theme.text_muted);
                    mono_cell(ui, format!("{:>10}", format_bytes_short(f.down)), base);
                    mono_cell(ui, format!("{:>10}", format_bytes_short(f.up)), base);
                    let rate_color = if f.rate > 0.0 { theme.text_primary } else { theme.text_muted };
                    mono_cell(ui, format!("{:>11}", format_rate(f.rate)), rate_color);
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