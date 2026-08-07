//! Live dashboard for the egress engine.
//!
//! The window is a grid: throughput chart and flow table on top, interchangeable
//! inspection cells below. The grid REFLOWS rather than shrinks — three cells
//! become two, then one, and below a width where side-by-side panels stop being
//! readable the whole thing becomes a scrolling single column. Tables reflow the
//! same way: columns are dropped in priority order rather than squeezed until
//! they clip.
//!
//! Every cell reads the same per-tick [`TrafficSnapshot`] published by the
//! monitor, so nothing here computes over live engine state and no frame can
//! block the packet path.
//!
//! There is no log pane. The engine's transcript goes to the console and, with
//! `--log`, to a text file beside the session flow CSV — a scrolling firehose is
//! not an inspection tool, and mirroring it into the UI put a mutex the logger
//! writes under on the render path.

use eframe::egui::{self, Align, Color32, Layout, Rounding, Stroke, Vec2};
use std::sync::Arc;
use std::time::Duration;

use crate::inspect::TrafficSnapshot;
use crate::state::{Shared, Status};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// Below this width a panel cannot hold a legible table, so the grid drops a
/// column instead of narrowing every cell.
const COL_MIN_W: f32 = 340.0;
/// Below this width side-by-side panels stop working at all: stack and scroll.
const STACK_W: f32 = 800.0;
/// Below this height the two-row grid squeezes both rows past usefulness.
const STACK_H: f32 = 470.0;
/// Row heights used by the stacked (narrow) layout.
const STACK_CHART_H: f32 = 190.0;
const STACK_FLOWS_H: f32 = 280.0;
const STACK_CELL_H: f32 = 250.0;
/// Point size every table and label is drawn at. Column budgets are computed
/// from this, so the two cannot drift apart.
const MONO_PT: f32 = 10.0;

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
};

impl Default for Theme {
    fn default() -> Self {
        MONO_THEME
    }
}

fn apply_theme(ctx: &egui::Context, theme: &Theme) {
    let mut style = (*ctx.style()).clone();

    style.visuals.dark_mode = true;
    style.visuals.override_text_color = Some(theme.text_primary);
    style.visuals.panel_fill = theme.background;
    style.visuals.window_fill = theme.surface;
    style.visuals.extreme_bg_color = theme.background;
    style.visuals.faint_bg_color = theme.surface;

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

    style.visuals.selection.bg_fill = theme.surface_hover;
    style.visuals.selection.stroke = Stroke::new(1.0, theme.accent);

    style.visuals.window_rounding = Rounding::same(0.0);
    style.visuals.window_stroke = Stroke::new(1.0, theme.border);

    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(6.0, 3.0);
    style.spacing.window_margin = egui::Margin::same(12.0);
    style.spacing.interact_size.y = 18.0;

    ctx.set_style(style);
}

// ---------------------------------------------------------------------------
// Cell / sort selection
// ---------------------------------------------------------------------------

/// One selectable view for an inspection cell. Each answers a different question
/// about the same session: what protocols, which hosts, which services, and the
/// raw counters. Cells are independent, so the same view can sit in two of them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cell {
    Protocols,
    Hosts,
    Services,
    Composition,
    Counters,
}

impl Cell {
    const ALL: [Cell; 5] = [
        Cell::Protocols,
        Cell::Hosts,
        Cell::Services,
        Cell::Composition,
        Cell::Counters,
    ];

    fn label(self) -> &'static str {
        match self {
            Cell::Protocols => "PROTOCOLS",
            Cell::Hosts => "HOSTS",
            Cell::Services => "SERVICES",
            Cell::Composition => "COMPOSITION",
            Cell::Counters => "COUNTERS",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Bytes,
    Rate,
    Recent,
}

impl Sort {
    const ALL: [Sort; 3] = [Sort::Bytes, Sort::Rate, Sort::Recent];

    fn label(self) -> &'static str {
        match self {
            Sort::Bytes => "bytes",
            Sort::Rate => "rate",
            Sort::Recent => "recent",
        }
    }
}

// ---------------------------------------------------------------------------
// Responsive monospace tables
// ---------------------------------------------------------------------------

/// One column of a monospace table.
///
/// Widths are in characters, not pixels, because the cells are drawn in a
/// monospace font and the header must line up with every row. Exactly one column
/// per table carries `width: 0` — the flexible one, which absorbs whatever slack
/// is left after the fixed columns are placed.
#[derive(Clone, Copy)]
struct Col {
    title: &'static str,
    width: usize,
    right: bool,
    /// Drop priority: higher goes first when the cell is too narrow. `0` is
    /// never dropped, so a table always keeps its identifying column and its
    /// most important measure.
    drop: u8,
}

impl Col {
    const fn new(title: &'static str, width: usize, right: bool, drop: u8) -> Self {
        Col { title, width, right, drop }
    }
}

/// How many monospace characters fit across `ui`'s remaining width.
fn char_budget(ui: &egui::Ui) -> usize {
    let font = egui::FontId::monospace(MONO_PT);
    let cw = ui.ctx().fonts(|f| f.glyph_width(&font, '0')).max(1.0);
    (ui.available_width() / cw).floor().max(8.0) as usize
}

/// Pick the columns that fit in `budget` characters.
///
/// Dropping whole columns beats scaling them: a 4-character `REMOTE` column is
/// worse than no `L4` column, because a truncated address identifies nothing
/// while a missing protocol label is simply one fact fewer.
fn fit(cols: &[Col], budget: usize, flex_min: usize, flex_max: usize) -> Vec<Col> {
    let mut keep: Vec<Col> = cols.to_vec();
    loop {
        let fixed: usize = keep.iter().map(|c| c.width).sum();
        if fixed + flex_min <= budget {
            break;
        }
        // Drop the least important column still present. `max_by_key` returns
        // the LAST maximum, which keeps the drop order stable left-to-right.
        let victim = keep
            .iter()
            .enumerate()
            .filter(|(_, c)| c.drop > 0)
            .max_by_key(|(_, c)| c.drop)
            .map(|(i, _)| i);
        match victim {
            Some(i) => {
                keep.remove(i);
            }
            None => break,
        }
    }
    let fixed: usize = keep.iter().map(|c| c.width).sum();
    let flex = budget.saturating_sub(fixed).clamp(flex_min, flex_max);
    for c in keep.iter_mut() {
        if c.width == 0 {
            c.width = flex;
        }
    }

    // Spread whatever is still unused evenly across the surviving columns, so
    // the row spans the whole cell instead of huddling against the left edge
    // with a third of the panel blank. The flexible column has already taken
    // its share up to `flex_max`; past that, extra width is dead space unless
    // every column gets some of it.
    let used: usize = keep.iter().map(|c| c.width).sum();
    if budget > used && !keep.is_empty() {
        let extra = budget - used;
        let each = extra / keep.len();
        let mut rem = extra % keep.len();
        for c in keep.iter_mut() {
            c.width += each;
            if rem > 0 {
                c.width += 1;
                rem -= 1;
            }
        }
    }
    keep
}

/// Pad (or truncate) to exactly `width` characters, always leaving one space of
/// separation so adjacent columns never run together.
fn pad(s: &str, width: usize, right: bool) -> String {
    let t = truncate(s, width.saturating_sub(1).max(1));
    if right {
        format!("{:>width$}", t, width = width)
    } else {
        format!("{:<width$}", t, width = width)
    }
}

fn table_header(ui: &mut egui::Ui, plan: &[Col], theme: &Theme) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for c in plan {
            mono_cell(ui, pad(c.title, c.width, c.right), theme.text_muted);
        }
    });
    header_rule(ui, theme);
}

/// Render one row. `cell` is asked only for the columns that survived `fit`, so
/// a dropped column costs nothing to format.
fn table_row(ui: &mut egui::Ui, plan: &[Col], cell: impl Fn(&str) -> (String, Color32)) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for c in plan {
            let (text, color) = cell(c.title);
            mono_cell(ui, pad(&text, c.width, c.right), color);
        }
    });
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct TunnelApp {
    shared: Arc<Shared>,
    theme: Theme,
    theme_applied: bool,

    /// Latest published view. An `Arc` clone per frame, not a rebuild.
    traffic: Arc<TrafficSnapshot>,
    status: Status,

    filter: String,
    sort: Sort,
    hide_idle: bool,

    /// Which view each inspection cell shows. Only the first `n` are visible,
    /// where `n` is what the current window width supports.
    cells: [Cell; 3],
}

impl TunnelApp {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            theme: Theme::default(),
            theme_applied: false,
            traffic: Arc::new(TrafficSnapshot::default()),
            status: Status::default(),
            filter: String::new(),
            sort: Sort::Bytes,
            hide_idle: false,
            cells: [Cell::Protocols, Cell::Hosts, Cell::Services],
        }
    }

    pub fn run(shared: Arc<Shared>) -> eframe::Result<()> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1280.0, 800.0])
                .with_min_inner_size([460.0, 380.0]),
            ..Default::default()
        };

        eframe::run_native(
            concat!("Quorum IO — tunnel ", env!("CARGO_PKG_VERSION")),
            options,
            Box::new(move |_cc| Ok(Box::new(TunnelApp::new(shared)))),
        )
    }

    /// Pull engine state into the frame. Both reads are O(1): the traffic view
    /// is an `Arc` clone of the snapshot the monitor published on its last tick,
    /// and the status is a short struct behind an uncontended mutex.
    fn sync_from_engine(&mut self) {
        self.traffic = self.shared.monitor.snapshot();
        if let Ok(st) = self.shared.status.lock() {
            self.status = st.clone();
        }
    }
}

impl eframe::App for TunnelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            apply_theme(ctx, &self.theme);
            self.theme_applied = true;
        }

        ctx.request_repaint_after(Duration::from_millis(100));
        self.sync_from_engine();

        if ctx.input(|i| i.viewport().close_requested()) {
            self.shared.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // The background colour is copied out rather than held as a borrow:
        // the central closure needs `&mut self`, and a live `&self.theme` in the
        // same statement would be a shared and a unique borrow of one value.
        let bg = self.theme.background;
        let traffic = self.traffic.clone();

        egui::TopBottomPanel::top("header")
            .frame(
                egui::Frame::none()
                    .fill(bg)
                    .inner_margin(egui::Margin::symmetric(14.0, 9.0)),
            )
            .show(ctx, |ui| {
                render_header(ui, &self.status, &traffic, &self.theme);
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(bg)
                    .inner_margin(egui::Margin::same(10.0)),
            )
            .show(ctx, |ui| {
                let gap = 8.0;
                let avail = ui.available_size();

                // Reflow, don't shrink: below these bounds side-by-side panels
                // stop being readable at all, so the grid becomes one scrolling
                // column instead of six unusable cells.
                if avail.x < STACK_W || avail.y < STACK_H {
                    self.stacked(ui, &traffic, gap);
                } else {
                    self.grid(ui, &traffic, avail, gap);
                }
            });
    }
}

impl TunnelApp {
    /// Wide layout: chart and flows share the top row, inspection cells fill the
    /// bottom. The cell count follows the width so no cell is ever narrower than
    /// `COL_MIN_W`.
    fn grid(&mut self, ui: &mut egui::Ui, traffic: &Arc<TrafficSnapshot>, avail: Vec2, gap: f32) {
        let theme = &self.theme;
        let n = (((avail.x + gap) / (COL_MIN_W + gap)).floor() as usize).clamp(1, 3);

        // Both rows get a floor, and the top row cannot eat the bottom's floor.
        // The top row is content-hungry (a chart wants height, the flow table
        // wants rows); the bottom cells are short tables. An even split leaves
        // the bottom half mostly blank.
        let top_h = ((avail.y - gap) * 0.6)
            .max(200.0)
            .min((avail.y - gap - 170.0).max(200.0));
        let half_w = (avail.x - gap) * 0.5 - 2.0;

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            render_panel(ui, half_w, top_h, theme, |ui| {
                panel_title(ui, "THROUGHPUT", theme);
            }, |ui| {
                draw_chart(ui, traffic, theme);
            });
            render_panel(ui, half_w, top_h, theme, |ui| {
                panel_title(ui, "FLOWS", theme);
            }, |ui| {
                flows_pane(ui, traffic, &mut self.filter, &mut self.sort, &mut self.hide_idle, theme);
            });
        });

        ui.add_space(gap);

        let bottom_h = ui.available_height().max(170.0);
        let cell_w = (avail.x - gap * (n as f32 - 1.0)) / n as f32 - 2.0;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            for idx in 0..n {
                // `shown` and `next` are separate bindings on purpose: the
                // header closure mutates the selection while the content closure
                // reads this frame's value. One binding would be a `&mut` and a
                // `&` to the same place at one call.
                let shown = self.cells[idx];
                let mut next = shown;
                render_panel(ui, cell_w, bottom_h, theme, |ui| {
                    cell_selector(ui, idx, &mut next, theme);
                }, |ui| {
                    render_cell(ui, shown, traffic, theme);
                });
                self.cells[idx] = next;
            }
        });
    }

    /// Narrow or short window: one full-width column, vertically scrolled. Fixed
    /// row heights, because a 380x400 window divided into six proportional cells
    /// is six unreadable cells rather than three readable ones and a scrollbar.
    fn stacked(&mut self, ui: &mut egui::Ui, traffic: &Arc<TrafficSnapshot>, gap: f32) {
        let theme = &self.theme;
        egui::ScrollArea::vertical()
            .id_salt("stack_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let w = (ui.available_width() - 2.0).max(120.0);

                render_panel(ui, w, STACK_CHART_H, theme, |ui| {
                    panel_title(ui, "THROUGHPUT", theme);
                }, |ui| {
                    draw_chart(ui, traffic, theme);
                });
                ui.add_space(gap);

                render_panel(ui, w, STACK_FLOWS_H, theme, |ui| {
                    panel_title(ui, "FLOWS", theme);
                }, |ui| {
                    flows_pane(ui, traffic, &mut self.filter, &mut self.sort, &mut self.hide_idle, theme);
                });

                for idx in 0..3 {
                    ui.add_space(gap);
                    let shown = self.cells[idx];
                    let mut next = shown;
                    render_panel(ui, w, STACK_CELL_H, theme, |ui| {
                        cell_selector(ui, idx, &mut next, theme);
                    }, |ui| {
                        render_cell(ui, shown, traffic, theme);
                    });
                    self.cells[idx] = next;
                }
            });
    }
}

// ---------------------------------------------------------------------------
// Chrome
// ---------------------------------------------------------------------------

/// A bordered cell with a header strip and a padded content area.
///
/// The body is built with `allocate_ui_with_layout` and an EXPLICIT top-down
/// layout. `allocate_ui` alone inherits the caller's layout, and the callers here
/// are `ui.horizontal` — which lays the title, the rule and every table row out
/// left-to-right on one vertically-centred baseline, then grows the frame past
/// its requested size to fit the overflow.
///
/// The size argument matters for the same reason: `set_width`/`set_height` only
/// raise a *minimum*, so `available_height()` inside would still report the whole
/// window's remaining space and anything sized from it would overflow its cell.
fn render_panel(
    ui: &mut egui::Ui,
    width: f32,
    height: f32,
    theme: &Theme,
    header: impl FnOnce(&mut egui::Ui),
    content: impl FnOnce(&mut egui::Ui),
) {
    egui::Frame::none()
        .fill(theme.surface)
        .stroke(Stroke::new(1.0, theme.border))
        .rounding(Rounding::same(2.0))
        .show(ui, |ui| {
            ui.allocate_ui_with_layout(
                Vec2::new(width, height),
                Layout::top_down(Align::Min),
                |ui| {
                    ui.set_min_size(Vec2::new(width, height));
                    // Dense spacing: the default 6px vertical gap turns a
                    // twenty-row table into a scrollbar.
                    ui.spacing_mut().item_spacing = Vec2::new(6.0, 3.0);

                    ui.horizontal(|ui| {
                        ui.add_space(8.0);
                        header(ui);
                    });

                    ui.add_space(3.0);
                    let rule = ui.available_rect_before_wrap();
                    ui.painter()
                        .hline(rule.x_range(), rule.top(), Stroke::new(1.0, theme.border));
                    ui.add_space(3.0);

                    egui::Frame::none()
                        .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                        .show(ui, |ui| {
                            ui.set_min_size(ui.available_size());
                            content(ui);
                        });
                },
            );
        });
}

fn panel_title(ui: &mut egui::Ui, title: &str, theme: &Theme) {
    ui.label(
        egui::RichText::new(title)
            .color(theme.text_muted)
            .size(MONO_PT)
            .strong()
            .monospace(),
    );
}

fn cell_selector(ui: &mut egui::Ui, idx: usize, kind: &mut Cell, theme: &Theme) {
    egui::ComboBox::from_id_salt(("cell", idx))
        .selected_text(
            egui::RichText::new(kind.label())
                .color(theme.text_muted)
                .size(MONO_PT)
                .strong()
                .monospace(),
        )
        .width(118.0)
        .show_ui(ui, |ui| {
            for option in Cell::ALL {
                ui.selectable_value(
                    kind,
                    option,
                    egui::RichText::new(option.label()).size(MONO_PT).monospace(),
                );
            }
        });
}

fn render_header(ui: &mut egui::Ui, status: &Status, traffic: &TrafficSnapshot, theme: &Theme) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("QUORUM IO")
                .color(theme.text_primary)
                .size(13.0)
                .strong()
                .monospace(),
        );

        ui.add_space(10.0);

        // Three honest states: running, stopped by an error, and not running.
        // The failure reason is rendered right here — an engine that bailed
        // (kill switch, resolver, TUN) must never keep wearing CONNECTED.
        let error_color = Color32::from_rgb(230, 90, 90);
        let (status_text, status_color, connstat) = if status.running {
            ("CONNECTED", theme.text_primary, "[ON]")
        } else if status.last_error.is_some() {
            ("ENGINE STOPPED", error_color, "[ERR]")
        } else {
            ("OFFLINE", theme.text_muted, "[OFF]")
        };

        ui.label(
            egui::RichText::new(connstat)
                .color(status_color)
                .size(MONO_PT)
                .monospace(),
        );
        ui.label(
            egui::RichText::new(status_text)
                .color(status_color)
                .size(MONO_PT)
                .monospace(),
        );

        if let Some(err) = &status.last_error {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(truncate(err, 96))
                    .color(error_color)
                    .size(MONO_PT)
                    .monospace(),
            )
            .on_hover_text(err);
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(started) = status.started_at {
                ui.label(
                    egui::RichText::new(format_duration(started.elapsed()))
                        .color(theme.text_muted)
                        .size(MONO_PT)
                        .monospace(),
                );
            }

            let total = traffic.total_up + traffic.total_down;
            if total > 0 {
                ui.add_space(12.0);
                ui.label(
                    egui::RichText::new(format_bytes(total))
                        .color(theme.text_secondary)
                        .size(MONO_PT)
                        .monospace(),
                );
            }

            // The exit descriptor is long and least critical, so it sits between
            // the two anchored groups and is the first thing squeezed out.
            if status.running && !status.exit.is_empty() {
                ui.add_space(12.0);
                ui.label(
                    egui::RichText::new(truncate(&status.exit, 42))
                        .color(theme.text_muted)
                        .size(MONO_PT)
                        .monospace(),
                );
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Throughput chart
// ---------------------------------------------------------------------------

/// Up/down history filling the whole cell, with the session counters drawn
/// inside it along the left edge. The numbers belong on the chart: they are the
/// same quantities the two lines plot, and giving them their own column cost a
/// third of the cell for six short strings.
fn draw_chart(ui: &mut egui::Ui, traffic: &TrafficSnapshot, theme: &Theme) {
    let size = Vec2::new(
        ui.available_width().max(120.0),
        ui.available_height().max(80.0),
    );
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, Rounding::same(2.0), theme.background);

    let max = traffic
        .down_series
        .iter()
        .chain(traffic.up_series.iter())
        .cloned()
        .fold(1.0_f64, f64::max);

    for frac in [0.25_f32, 0.5, 0.75] {
        let y = rect.bottom() - frac * (rect.height() - 4.0) - 2.0;
        painter.hline(rect.x_range(), y, Stroke::new(1.0, with_alpha(theme.border, 90)));
    }

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

    painter.text(
        rect.right_top() + Vec2::new(-6.0, 4.0),
        egui::Align2::RIGHT_TOP,
        format!("peak {}", format_rate(max)),
        egui::FontId::monospace(9.0),
        theme.text_muted,
    );

    // Counters, left-aligned inside the plot area. Dropped entirely if the cell
    // is too short to hold them without covering the trace.
    let rows: [(&str, String, Color32); 6] = [
        ("DOWN", format_rate(traffic.rate_down), theme.accent),
        ("UP", format_rate(traffic.rate_up), theme.text_primary),
        ("RX", format_bytes(traffic.total_down), theme.text_secondary),
        ("TX", format_bytes(traffic.total_up), theme.text_secondary),
        ("FLOWS", traffic.active_flows.to_string(), theme.text_secondary),
        (
            "PKTS",
            (traffic.pkts_up + traffic.pkts_down).to_string(),
            theme.text_muted,
        ),
    ];

    let line_h = 14.0;
    let shown = (((rect.height() - 10.0) / line_h).floor() as usize).min(rows.len());
    let x = rect.left() + 7.0;
    let mut y = rect.top() + 5.0;
    for (label, value, color) in rows.iter().take(shown) {
        painter.text(
            egui::pos2(x, y),
            egui::Align2::LEFT_TOP,
            *label,
            egui::FontId::monospace(9.0),
            theme.text_muted,
        );
        painter.text(
            egui::pos2(x + 38.0, y),
            egui::Align2::LEFT_TOP,
            value,
            egui::FontId::monospace(10.0),
            *color,
        );
        y += line_h;
    }
}

// ---------------------------------------------------------------------------
// Flow table
// ---------------------------------------------------------------------------

/// Toolbar plus table. Both live in one closure because a `TextEdit` holding
/// `&mut filter` in a panel header and a `&filter` read in the panel body are
/// two live borrows of one place at a single call.
fn flows_pane(
    ui: &mut egui::Ui,
    traffic: &TrafficSnapshot,
    filter: &mut String,
    sort: &mut Sort,
    hide_idle: &mut bool,
    theme: &Theme,
) {
    let wide = ui.available_width() >= 330.0;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 5.0;
        ui.add(
            egui::TextEdit::singleline(filter)
                .desired_width(if wide { 130.0 } else { 90.0 })
                .hint_text("filter")
                .font(egui::TextStyle::Monospace),
        );
        egui::ComboBox::from_id_salt("flow_sort")
            .selected_text(
                egui::RichText::new(sort.label())
                    .color(theme.text_muted)
                    .size(9.0)
                    .monospace(),
            )
            .width(62.0)
            .show_ui(ui, |ui| {
                for option in Sort::ALL {
                    ui.selectable_value(
                        sort,
                        option,
                        egui::RichText::new(option.label()).size(MONO_PT).monospace(),
                    );
                }
            });
        ui.checkbox(hide_idle, "");
        if wide {
            ui.label(
                egui::RichText::new("live only")
                    .color(theme.text_muted)
                    .size(9.0)
                    .monospace(),
            );
        }
    });
    ui.add_space(3.0);

    render_flows(ui, traffic, filter, *sort, *hide_idle, theme);
}

fn render_flows(
    ui: &mut egui::Ui,
    traffic: &TrafficSnapshot,
    filter: &str,
    sort: Sort,
    hide_idle: bool,
    theme: &Theme,
) {
    const COLS: [Col; 6] = [
        Col::new("REMOTE", 0, false, 0),
        Col::new("APP", 11, false, 2),
        Col::new("L4", 5, false, 4),
        Col::new("RX", 8, true, 1),
        Col::new("TX", 8, true, 3),
        Col::new("RATE", 11, true, 0),
    ];
    let plan = fit(&COLS, char_budget(ui), 14, 38);
    table_header(ui, &plan, theme);

    // Filter and sort by reference — the snapshot is shared, so the view is a
    // vector of borrows, never a clone of the rows.
    let needle = filter.to_lowercase();
    let mut rows: Vec<&crate::inspect::FlowRow> = traffic
        .flows
        .iter()
        .filter(|f| !hide_idle || f.idle_ms <= 5000)
        .filter(|f| {
            needle.is_empty()
                || f.remote.to_lowercase().contains(&needle)
                || f.app.to_lowercase().contains(&needle)
                || f.proto.to_lowercase().contains(&needle)
        })
        .collect();

    match sort {
        // `flows` arrives byte-sorted, so this branch is already ordered.
        Sort::Bytes => {}
        Sort::Rate => rows.sort_by(|a, b| b.rate.total_cmp(&a.rate)),
        Sort::Recent => rows.sort_by_key(|f| f.idle_ms),
    }

    if rows.is_empty() {
        empty_note(
            ui,
            if traffic.flows.is_empty() {
                "no traffic yet"
            } else {
                "no flows match the filter"
            },
            theme,
        );
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt("flows_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for f in rows {
                // Shed / reaped rows are deliberate admission-control actions,
                // not live conversations — render the whole row muted and swap
                // the rate cell for a status badge so they don't read as
                // anomalous up-only or half-open flows.
                let tagged = !f.status.is_empty();
                let base = if tagged || f.idle_ms > 5000 {
                    theme.text_muted
                } else {
                    theme.text_secondary
                };
                table_row(ui, &plan, |title| match title {
                    "REMOTE" => (f.remote.clone(), base),
                    "APP" => (
                        f.app.to_string(),
                        if tagged { theme.text_muted } else { proto_color(f.app, theme) },
                    ),
                    "L4" => (f.proto.to_string(), theme.text_muted),
                    "RX" => (format_bytes_short(f.down), base),
                    "TX" => (format_bytes_short(f.up), base),
                    _ if tagged => (f.status.to_string(), theme.text_muted),
                    _ => (
                        format_rate(f.rate),
                        if f.rate > 0.0 { theme.text_primary } else { theme.text_muted },
                    ),
                });
            }
        });
}

// ---------------------------------------------------------------------------
// Inspection cells
// ---------------------------------------------------------------------------

fn render_cell(ui: &mut egui::Ui, kind: Cell, traffic: &TrafficSnapshot, theme: &Theme) {
    match kind {
        Cell::Protocols => render_protocols(ui, traffic, theme),
        Cell::Hosts => render_hosts(ui, traffic, theme),
        Cell::Services => render_services(ui, traffic, theme),
        Cell::Composition => render_composition(ui, traffic, theme),
        Cell::Counters => render_counters(ui, traffic, theme),
    }
}

/// Donut of byte share by application protocol, with a legend beside it when the
/// cell is wide enough and beneath it when it is not.
fn render_protocols(ui: &mut egui::Ui, traffic: &TrafficSnapshot, theme: &Theme) {
    let total: u64 = traffic.apps.iter().map(|a| a.bytes).sum();
    if total == 0 {
        empty_note(ui, "no classified traffic yet", theme);
        return;
    }

    let avail = ui.available_size();
    let side_by_side = avail.x >= 300.0;

    if side_by_side {
        let dia = (avail.y - 4.0).min(avail.x * 0.42).clamp(70.0, 320.0);
        ui.horizontal_top(|ui| {
            draw_donut(ui, traffic, total, dia, theme);
            ui.add_space(10.0);
            // The legend MUST be given its own top-down region. `ScrollArea`
            // builds its viewport with the caller's layout, and the caller here
            // is a horizontal one — inherited, the legend lays its rows out
            // left-to-right and overflows the panel, pushing the sibling cells
            // off screen.
            let rest = Vec2::new(ui.available_width(), ui.available_height());
            ui.allocate_ui_with_layout(rest, Layout::top_down(Align::Min), |ui| {
                ui.set_min_size(rest);
                proto_legend(ui, traffic, total, theme);
            });
        });
    } else {
        let dia = (avail.y * 0.5).min(avail.x - 10.0).clamp(60.0, 190.0);
        ui.vertical_centered(|ui| {
            draw_donut(ui, traffic, total, dia, theme);
        });
        ui.add_space(6.0);
        proto_legend(ui, traffic, total, theme);
    }
}

/// Swatch, then a normal fitted table — so the legend spans the cell and lines
/// up column-wise instead of trailing off at whatever width the text happened
/// to need.
fn proto_legend(ui: &mut egui::Ui, traffic: &TrafficSnapshot, total: u64, theme: &Theme) {
    const COLS: [Col; 3] = [
        Col::new("PROTOCOL", 0, false, 0),
        Col::new("SHARE", 8, true, 0),
        Col::new("BYTES", 9, true, 1),
    ];
    // Three characters are reserved for the colour swatch and its gap.
    const SWATCH: usize = 3;
    let plan = fit(&COLS, char_budget(ui).saturating_sub(SWATCH), 8, 22);

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        mono_cell(ui, " ".repeat(SWATCH), theme.text_muted);
        for c in &plan {
            mono_cell(ui, pad(c.title, c.width, c.right), theme.text_muted);
        }
    });
    header_rule(ui, theme);

    egui::ScrollArea::vertical()
        .id_salt("proto_legend")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for a in traffic.apps.iter().filter(|a| a.bytes > 0) {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let (sq, _) = ui.allocate_exact_size(Vec2::new(9.0, 9.0), egui::Sense::hover());
                    ui.painter()
                        .rect_filled(sq, Rounding::ZERO, proto_color(a.name, theme));
                    mono_cell(ui, " ".to_string(), theme.text_muted);
                    for c in &plan {
                        let (text, color) = match c.title {
                            "PROTOCOL" => (a.name.to_string(), theme.text_secondary),
                            "SHARE" => (
                                format!("{:.1}%", a.bytes as f64 * 100.0 / total as f64),
                                theme.text_primary,
                            ),
                            _ => (format_bytes_short(a.bytes), theme.text_muted),
                        };
                        mono_cell(ui, pad(&text, c.width, c.right), color);
                    }
                });
            }
        });
}

/// Donut: a base disc in the dominant protocol's colour, the remaining sectors
/// painted over it, then the centre punched out.
///
/// Two details matter for how it reads. First, each sector is ONE polygon, not a
/// fan of triangles — every triangle in a fan is antialiased against what is
/// behind it, so a fan draws a hundred visible spokes across a solid slice. A
/// sector stays convex up to half a turn, so `convex_polygon` is valid as long as
/// wide slices are split; splitting at 120 degrees bounds that at two internal
/// seams. Second, the largest slice is drawn as a full circle underneath
/// everything else, which removes its seams entirely — and the largest slice is
/// exactly the one where they would show.
fn draw_donut(ui: &mut egui::Ui, traffic: &TrafficSnapshot, total: u64, dia: f32, theme: &Theme) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(dia, dia), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let c = rect.center();
    let r = dia * 0.5 - 2.0;
    if r <= 6.0 || total == 0 {
        return;
    }

    // `apps` arrives sorted by bytes descending, so the first live entry is the
    // dominant one.
    let live: Vec<&crate::inspect::AppRow> =
        traffic.apps.iter().filter(|a| a.bytes > 0).collect();
    let Some(first) = live.first() else {
        return;
    };

    painter.circle_filled(c, r, proto_color(first.name, theme));

    let sweep_of = |bytes: u64| bytes as f32 / total as f32 * std::f32::consts::TAU;
    let mut angle = -std::f32::consts::FRAC_PI_2 + sweep_of(first.bytes);

    for a in live.iter().skip(1) {
        let sweep = sweep_of(a.bytes);
        let color = proto_color(a.name, theme);
        const MAX_CHUNK: f32 = 2.0944; // 120 degrees: safely convex
        let chunks = ((sweep / MAX_CHUNK).ceil() as usize).max(1);
        let chunk = sweep / chunks as f32;
        for k in 0..chunks {
            let start = angle + chunk * k as f32;
            // One arc point per ~3 degrees, minimum two so a hairline slice is
            // still a wedge rather than a line.
            let steps = ((chunk / 0.052).ceil() as usize).max(2);
            let mut pts: Vec<egui::Pos2> = Vec::with_capacity(steps + 2);
            pts.push(c);
            for i in 0..=steps {
                let t = start + chunk * (i as f32 / steps as f32);
                pts.push(c + Vec2::new(t.cos() * r, t.sin() * r));
            }
            painter.add(egui::Shape::convex_polygon(pts, color, Stroke::NONE));
        }
        angle += sweep;
    }

    painter.circle_filled(c, r * 0.58, theme.surface);
    painter.text(
        c,
        egui::Align2::CENTER_CENTER,
        format_bytes_short(total),
        egui::FontId::monospace(MONO_PT),
        theme.text_primary,
    );
}

/// Unique remote hosts: every conversation with one address on one row.
fn render_hosts(ui: &mut egui::Ui, traffic: &TrafficSnapshot, theme: &Theme) {
    const COLS: [Col; 5] = [
        Col::new("HOST", 0, false, 0),
        Col::new("APP", 10, false, 2),
        Col::new("FL", 4, true, 3),
        Col::new("BYTES", 8, true, 1),
        Col::new("RATE", 10, true, 0),
    ];
    let plan = fit(&COLS, char_budget(ui), 12, 34);
    table_header(ui, &plan, theme);

    if traffic.hosts.is_empty() {
        empty_note(ui, "no remote hosts yet", theme);
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt("hosts_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for h in &traffic.hosts {
                let base = if h.idle_ms > 5000 {
                    theme.text_muted
                } else {
                    theme.text_secondary
                };
                table_row(ui, &plan, |title| match title {
                    "HOST" => (h.ip.clone(), base),
                    "APP" => (h.app.to_string(), proto_color(h.app, theme)),
                    "FL" => (h.flows.to_string(), theme.text_muted),
                    "BYTES" => (format_bytes_short(h.up + h.down), base),
                    _ => (
                        format_rate(h.rate),
                        if h.rate > 0.0 { theme.text_primary } else { theme.text_muted },
                    ),
                });
            }
        });
}

/// Remote service ports: what this host is actually talking to, by destination.
fn render_services(ui: &mut egui::Ui, traffic: &TrafficSnapshot, theme: &Theme) {
    const COLS: [Col; 6] = [
        Col::new("PORT", 7, false, 0),
        Col::new("SERVICE", 0, false, 0),
        Col::new("L4", 5, false, 4),
        Col::new("FL", 4, true, 3),
        Col::new("BYTES", 8, true, 2),
        Col::new("RATE", 10, true, 1),
    ];
    let plan = fit(&COLS, char_budget(ui), 8, 20);
    table_header(ui, &plan, theme);

    if traffic.ports.is_empty() {
        empty_note(ui, "no services yet", theme);
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt("services_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for p in &traffic.ports {
                table_row(ui, &plan, |title| match title {
                    "PORT" => (p.port.to_string(), theme.text_secondary),
                    "SERVICE" => {
                        if p.service.is_empty() {
                            ("—".to_string(), theme.text_muted)
                        } else {
                            (p.service.to_string(), theme.text_secondary)
                        }
                    }
                    "L4" => (p.l4.to_string(), theme.text_muted),
                    "FL" => (p.flows.to_string(), theme.text_muted),
                    "BYTES" => (format_bytes_short(p.up + p.down), theme.text_secondary),
                    _ => (
                        format_rate(p.rate),
                        if p.rate > 0.0 { theme.text_primary } else { theme.text_muted },
                    ),
                });
            }
        });
}

/// Stacked share bar plus per-protocol bars: the compact form of the same data
/// the donut shows, for when the cell is short.
fn render_composition(ui: &mut egui::Ui, traffic: &TrafficSnapshot, theme: &Theme) {
    let total: u64 = traffic.apps.iter().map(|a| a.bytes).sum();
    if total == 0 {
        empty_note(ui, "no classified traffic yet", theme);
        return;
    }

    let (bar, _) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 13.0), egui::Sense::hover());
    let painter = ui.painter_at(bar);
    painter.rect_filled(bar, Rounding::same(2.0), theme.surface_hover);
    let mut x = bar.left();
    for a in traffic.apps.iter().filter(|a| a.bytes > 0) {
        let seg_w = a.bytes as f32 / total as f32 * bar.width();
        let seg =
            egui::Rect::from_min_size(egui::pos2(x, bar.top()), Vec2::new(seg_w, bar.height()));
        painter.rect_filled(seg, Rounding::ZERO, proto_color(a.name, theme));
        x += seg_w;
    }

    ui.add_space(5.0);

    let budget = char_budget(ui);
    let name_w = budget.saturating_sub(12).clamp(5, 12);
    let show_bar = budget >= 34;

    egui::ScrollArea::vertical()
        .id_salt("composition_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for a in traffic.apps.iter().filter(|a| a.bytes > 0) {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    mono_cell(ui, pad(a.name, name_w, false), theme.text_secondary);
                    mono_cell(ui, format!("{:>4}", a.flows), theme.text_muted);
                    mono_cell(ui, format!("{:>8}", format_bytes_short(a.bytes)), theme.text_muted);
                    if show_bar {
                        ui.add_space(4.0);
                        let track_w = ui.available_width().max(1.0);
                        let (track, _) =
                            ui.allocate_exact_size(Vec2::new(track_w, 7.0), egui::Sense::hover());
                        let p = ui.painter_at(track);
                        p.rect_filled(track, Rounding::ZERO, theme.surface_hover);
                        let w = a.bytes as f32 / total as f32 * track.width();
                        p.rect_filled(
                            egui::Rect::from_min_size(track.min, Vec2::new(w, track.height())),
                            Rounding::ZERO,
                            proto_color(a.name, theme),
                        );
                    }
                });
            }
        });
}

/// Raw session counters, including the ones that only matter when something is
/// wrong: the up/down packet split, mean packet size, and how much of the flow
/// table has already been evicted to the archive.
fn render_counters(ui: &mut egui::Ui, traffic: &TrafficSnapshot, theme: &Theme) {
    let pkts = traffic.pkts_up + traffic.pkts_down;
    let bytes = traffic.total_up + traffic.total_down;
    let mean = if pkts > 0 { bytes / pkts } else { 0 };
    let ratio = if traffic.total_up > 0 {
        format!("{:.2}:1", traffic.total_down as f64 / traffic.total_up as f64)
    } else {
        "—".to_string()
    };

    let rows: [(&str, String, Color32); 12] = [
        ("RX", format_bytes(traffic.total_down), theme.text_primary),
        ("TX", format_bytes(traffic.total_up), theme.text_primary),
        ("RATIO", ratio, theme.text_secondary),
        ("PKT RX", traffic.pkts_down.to_string(), theme.text_secondary),
        ("PKT TX", traffic.pkts_up.to_string(), theme.text_secondary),
        ("MEAN", format!("{mean} B"), theme.text_secondary),
        ("TCP", traffic.tcp_flows.to_string(), theme.text_secondary),
        ("UDP", traffic.udp_flows.to_string(), theme.text_secondary),
        ("LIVE", traffic.active_flows.to_string(), theme.text_secondary),
        ("ARCHIV", traffic.archived_flows.to_string(), theme.text_muted),
        ("HOSTS", traffic.hosts.len().to_string(), theme.text_muted),
        ("SVCS", traffic.ports.len().to_string(), theme.text_muted),
    ];

    // As many columns as fit. `allocate_ui_with_layout` advances the cursor by
    // the child's ACTUAL min_rect, not the size requested — so without
    // `set_min_width` each pair collapses onto the previous one and the row
    // reads as "RX 5.64 MBTX 205.1 KB".
    let width = ui.available_width();
    let cols = ((width / 190.0).floor() as usize).clamp(1, 4);
    let cell_w = width / cols as f32;

    egui::ScrollArea::vertical()
        .id_salt("counters_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for chunk in rows.chunks(cols) {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    for (label, value, color) in chunk {
                        ui.allocate_ui_with_layout(
                            Vec2::new(cell_w, 15.0),
                            Layout::top_down(Align::Min),
                            |ui| {
                                ui.set_min_width(cell_w);
                                stat_row(ui, label, value, *color, theme);
                            },
                        );
                    }
                });
            }
        });
}

// ---------------------------------------------------------------------------
// Small shared pieces
// ---------------------------------------------------------------------------

fn header_rule(ui: &mut egui::Ui, theme: &Theme) {
    ui.add_space(1.0);
    let rect = ui.available_rect_before_wrap();
    ui.painter()
        .hline(rect.x_range(), rect.top(), Stroke::new(1.0, theme.border));
    ui.add_space(3.0);
}

fn empty_note(ui: &mut egui::Ui, text: &str, theme: &Theme) {
    ui.vertical_centered(|ui| {
        ui.add_space(10.0);
        ui.label(
            egui::RichText::new(text)
                .color(theme.text_muted)
                .size(MONO_PT)
                .monospace(),
        );
    });
}

fn stat_row(ui: &mut egui::Ui, label: &str, value: &str, value_color: Color32, theme: &Theme) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label(
            egui::RichText::new(format!("{:<8}", label))
                .color(theme.text_muted)
                .size(MONO_PT)
                .monospace(),
        );
        ui.label(
            egui::RichText::new(value)
                .color(value_color)
                .size(MONO_PT)
                .monospace()
                .strong(),
        );
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
        "mDNS" | "LLMNR" => Color32::from_rgb(190, 165, 90),
        "SSDP" | "NetBIOS" => Color32::from_rgb(140, 130, 170),
        "HTTP" => Color32::from_rgb(150, 190, 220),
        "SSH" => Color32::from_rgb(200, 120, 200),
        "NTP" | "DHCP" | "DHCPv6" => Color32::from_rgb(120, 160, 160),
        "IGMP" => Color32::from_rgb(110, 140, 110),
        "ICMP" => Color32::from_rgb(150, 150, 150),
        _ => theme.text_muted,
    }
}

fn with_alpha(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

fn mono_cell(ui: &mut egui::Ui, text: String, color: Color32) {
    ui.label(
        egui::RichText::new(text)
            .color(color)
            .size(MONO_PT)
            .monospace(),
    );
}

/// Truncate to `max` characters. Counts chars, not bytes: an address string is
/// ASCII, but a protocol label need not stay that way, and slicing mid-codepoint
/// panics.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let keep = max.saturating_sub(1);
        let mut out: String = s.chars().take(keep).collect();
        out.push('…');
        out
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
        format!("{:.1}G", bytes as f64 / GB as f64)
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

#[cfg(test)]
mod tests {
    use super::*;

    const FLOW_COLS: [Col; 6] = [
        Col::new("REMOTE", 0, false, 0),
        Col::new("APP", 11, false, 2),
        Col::new("L4", 5, false, 4),
        Col::new("RX", 8, true, 1),
        Col::new("TX", 8, true, 3),
        Col::new("RATE", 11, true, 0),
    ];

    fn at(budget: usize) -> Vec<&'static str> {
        fit(&FLOW_COLS, budget, 14, 30)
            .iter()
            .map(|c| c.title)
            .collect()
    }

    #[test]
    fn wide_budget_keeps_every_column_and_widens_the_flexible_one() {
        assert_eq!(at(80), ["REMOTE", "APP", "L4", "RX", "TX", "RATE"]);
        // 43 fixed characters; REMOTE takes the slack first, up to its cap.
        assert_eq!(fit(&FLOW_COLS, 60, 14, 38)[0].width, 17);
        assert_eq!(fit(&FLOW_COLS, 80, 14, 38)[0].width, 37);
    }

    #[test]
    fn slack_beyond_the_flexible_cap_is_spread_so_rows_fill_the_cell() {
        // A very wide panel: REMOTE saturates at 38 and the remaining 129
        // characters are shared out, so the row spans the full width instead of
        // leaving two thirds of the cell blank.
        let plan = fit(&FLOW_COLS, 210, 14, 38);
        assert_eq!(plan.len(), 6);
        assert_eq!(plan.iter().map(|c| c.width).sum::<usize>(), 210);
        assert!(plan[0].width > 38);
        // Every column shares in the slack; none is left at its base width.
        assert!(plan.iter().all(|c| c.width > 11));
    }

    #[test]
    fn narrowing_drops_columns_in_priority_order() {
        assert_eq!(at(57), ["REMOTE", "APP", "L4", "RX", "TX", "RATE"]);
        assert_eq!(at(52), ["REMOTE", "APP", "RX", "TX", "RATE"]); // L4 out
        assert_eq!(at(44), ["REMOTE", "APP", "RX", "RATE"]); // TX out
        assert_eq!(at(34), ["REMOTE", "RX", "RATE"]); // APP out
        assert_eq!(at(30), ["REMOTE", "RATE"]); // RX out
        // The identifying column and the headline measure are never dropped,
        // however narrow the cell gets.
        assert_eq!(at(4), ["REMOTE", "RATE"]);
    }

    #[test]
    fn flexible_column_never_falls_below_its_floor() {
        let plan = fit(&FLOW_COLS, 4, 14, 30);
        assert_eq!(plan.iter().find(|c| c.title == "REMOTE").unwrap().width, 14);
    }

    #[test]
    fn every_table_keeps_exactly_one_flexible_column() {
        // `fit` gives all slack to the single zero-width column; two would
        // silently split it and the header would stop lining up with the rows.
        for cols in [FLOW_COLS.as_slice()] {
            assert_eq!(cols.iter().filter(|c| c.width == 0).count(), 1);
        }
    }

    #[test]
    fn pad_produces_exactly_the_requested_character_count() {
        assert_eq!(pad("abc", 6, false).chars().count(), 6);
        assert_eq!(pad("abc", 6, true).chars().count(), 6);
        assert_eq!(pad("abcdefghij", 5, false).chars().count(), 5);
        // Always at least one space of separation after truncation.
        assert!(pad("abcdefghij", 5, false).ends_with(' '));
        assert!(pad("abcdefghij", 5, true).starts_with(' '));
    }

    #[test]
    fn truncate_is_codepoint_safe() {
        assert_eq!(truncate("1.2.3.4:443", 20), "1.2.3.4:443");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
        // Multi-byte: a byte slice at 5 would land mid-codepoint and panic.
        assert_eq!(truncate("ααααα", 3), "αα…");
    }

    #[test]
    fn byte_and_rate_scales_step_at_the_right_boundaries() {
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes_short(1024 * 1024), "1M");
        assert_eq!(format_rate(0.0), "0 B/s");
        assert_eq!(format_rate(2048.0), "2.0 KB/s");
    }

    #[test]
    fn every_cell_kind_is_reachable_from_the_selector() {
        for kind in Cell::ALL {
            assert!(!kind.label().is_empty());
        }
        assert_eq!(Cell::ALL.len(), 5);
        assert_eq!(Sort::ALL.len(), 3);
    }
}
