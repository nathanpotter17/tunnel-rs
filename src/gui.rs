//! Live dashboard for the egress engine.
//!
//! The window is a grid of WIDGETS: rows of cells that can each be retyped and
//! resized. The throughput chart and the flow table are widgets like any other,
//! so a session spent chasing DNS can be three probes and a host table, and a
//! session spent chasing throughput can be one big chart.
//!
//! The grid REFLOWS rather than shrinks. A row holds as many widgets as the
//! window can show at a legible width; the rest wrap onto a continuation band of
//! the same height instead of being squeezed or hidden. Tables reflow the same
//! way: columns are dropped in priority order rather than clipped. Row heights
//! stretch to fill a tall window and scroll in a short one, so a resize the
//! operator made is a ratio, not a pixel count that goes wrong at the next
//! window size.
//!
//! Every cell reads the same per-tick [`TrafficSnapshot`] published by the
//! monitor, so nothing here computes over live engine state and no frame can
//! block the packet path. The one exception is the PROBE widget, which
//! originates traffic — and it does that on its own thread (see `probe.rs`),
//! never on the render loop.
//!
//! There is no log pane. The engine's transcript goes to the console and, with
//! `--log`, to a text file beside the session flow CSV — a scrolling firehose is
//! not an inspection tool, and mirroring it into the UI put a mutex the logger
//! writes under on the render path.

use eframe::egui::{self, Align, Color32, Layout, Rounding, Stroke, Vec2};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::inspect::TrafficSnapshot;
use crate::probe;
use crate::state::{Shared, Status};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// Below this width a widget cannot hold a legible table, so a row wraps
/// instead of narrowing every cell in it.
const COL_MIN_W: f32 = 340.0;
/// The grid's one spacing unit.
///
/// The margin around the grid, the seam between two widgets and the seam under
/// a band are all exactly this, so no gap in the window is a special case. The
/// seams double as the resize affordances, which is why they replace the gap
/// rather than adding to it — the space between two widgets IS the handle.
const GAP: f32 = 8.0;
/// Height of a widget's header strip. Fixed, and the selector is centred in it,
/// so every widget's rule sits at the same offset whatever its header holds.
const HEADER_H: f32 = 24.0;
/// Padding between a widget's border and its content, on both axes.
const PAD_X: f32 = 8.0;
const PAD_Y: f32 = 6.0;
/// Vertical space between two rows of a table.
const ROW_GAP: f32 = 3.0;
/// Frame egui puts around a `TextEdit`'s text area, per side.
///
/// `desired_width` sizes the TEXT, not the widget, so a row fitted to an exact
/// width without allowing for this overflows it — and because a panel's size is
/// a minimum, the widget then grows and swallows the seam beside it. Pinned with
/// `TextEdit::margin` in [`text_field`] so the arithmetic cannot drift.
const EDIT_PAD: f32 = 4.0;
/// A row shorter than this holds no table worth reading.
const MIN_ROW_H: f32 = 120.0;
/// Default heights: the first row is content-hungry (a chart wants height, the
/// flow table wants rows), later rows are short tables.
const DEFAULT_TOP_H: f32 = 360.0;
const DEFAULT_ROW_H: f32 = 250.0;
/// Point size every table and label is drawn at. Column budgets are computed
/// from this, so the two cannot drift apart.
const MONO_PT: f32 = 10.0;
/// Fallback resolver for the PROBE widget before the engine has published one.
const FALLBACK_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// `Copy` because half the render tree wants the palette while the same
/// statement holds a `&mut` to the widget being drawn; a borrowed theme would
/// make every one of those a borrow conflict for no benefit — it is nine
/// colours.
#[derive(Clone, Copy)]
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

/// Red, for a stopped engine and a failed probe. Not in [`Theme`]: it is the
/// one colour that must not be re-themed away.
const ERROR_RED: Color32 = Color32::from_rgb(230, 90, 90);
const OK_GREEN: Color32 = Color32::from_rgb(120, 200, 130);

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

    // `bg_fill` is what containers paint with; `weak_bg_fill` is what BUTTONS
    // and combo boxes paint with. Setting only the former left every selector
    // and the probe's button wearing egui's default greys on a palette that has
    // none. `expansion` goes to zero for the same reason the grid has one gap:
    // a control that grows a pixel on hover is noise in a monospace table.
    let paint = |w: &mut egui::style::WidgetVisuals, bg, weak, fg, stroke| {
        w.bg_fill = bg;
        w.weak_bg_fill = weak;
        w.fg_stroke = Stroke::new(1.0, fg);
        w.bg_stroke = Stroke::new(1.0, stroke);
        w.rounding = Rounding::same(2.0);
        w.expansion = 0.0;
    };
    let w = &mut style.visuals.widgets;
    paint(&mut w.noninteractive, theme.surface, theme.surface, theme.text_secondary, theme.border);
    paint(&mut w.inactive, theme.surface, theme.surface, theme.text_secondary, theme.border);
    paint(&mut w.hovered, theme.surface_hover, theme.surface_hover, theme.text_primary, theme.accent_hover);
    paint(&mut w.active, theme.surface_hover, theme.surface_hover, theme.accent, theme.accent);
    paint(&mut w.open, theme.surface, theme.surface, theme.text_primary, theme.border);

    style.visuals.selection.bg_fill = theme.surface_hover;
    style.visuals.selection.stroke = Stroke::new(1.0, theme.accent);

    style.visuals.window_rounding = Rounding::same(0.0);
    style.visuals.window_stroke = Stroke::new(1.0, theme.border);

    style.spacing.item_spacing = Vec2::new(GAP, ROW_GAP);
    style.spacing.button_padding = Vec2::new(6.0, 3.0);
    style.spacing.window_margin = egui::Margin::same(12.0);
    style.spacing.interact_size.y = 18.0;

    ctx.set_style(style);
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/// One selectable view for a widget. Each answers a different question about the
/// same session: throughput over time, the live conversations, what protocols,
/// which hosts, which services, the raw counters — and, alone among them, PROBE,
/// which asks a question instead of reporting one. Widgets are independent, so
/// the same view can sit in two of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum View {
    Throughput,
    Flows,
    Protocols,
    Hosts,
    Services,
    Composition,
    Counters,
    Probe,
}

impl View {
    const ALL: [View; 8] = [
        View::Throughput,
        View::Flows,
        View::Protocols,
        View::Hosts,
        View::Services,
        View::Composition,
        View::Counters,
        View::Probe,
    ];

    fn label(self) -> &'static str {
        match self {
            View::Throughput => "THROUGHPUT",
            View::Flows => "FLOWS",
            View::Protocols => "PROTOCOLS",
            View::Hosts => "HOSTS",
            View::Services => "SERVICES",
            View::Composition => "COMPOSITION",
            View::Counters => "COUNTERS",
            View::Probe => "PROBE",
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
// Widgets and layout model
// ---------------------------------------------------------------------------

/// Per-widget state for the flow table. Held per widget rather than per app so
/// two FLOWS widgets can carry two different filters — which is the point of
/// being able to add a second one.
struct FlowUi {
    filter: String,
    sort: Sort,
    hide_idle: bool,
}

impl Default for FlowUi {
    fn default() -> Self {
        FlowUi { filter: String::new(), sort: Sort::Bytes, hide_idle: false }
    }
}

/// Per-widget state for the probe. `last` outlives `job`: a finished lookup
/// stays on screen until the next one replaces it.
#[derive(Default)]
struct ProbeUi {
    target: String,
    record: ProbeRecord,
    server: String,
    /// Whether the resolver field has been filled from the engine's pinned
    /// resolver. Once seeded, an operator's own entry is never overwritten.
    server_seeded: bool,
    job: Option<probe::Job>,
    last: Option<Result<probe::Outcome, String>>,
}

/// Newtype so [`ProbeUi`] can derive `Default` without `probe::RecordType`
/// having to pick a default that only makes sense to the UI.
struct ProbeRecord(probe::RecordType);

impl Default for ProbeRecord {
    fn default() -> Self {
        ProbeRecord(probe::RecordType::Auto)
    }
}

struct Widget {
    /// Stable for the widget's life. Everything that must not be confused
    /// between two widgets keys on this: egui's scroll and combo ids, and the
    /// resize seams. Index-based ids would tie that state to a position rather
    /// than to a widget, so two widgets showing the same view would share one
    /// scroll offset.
    id: u64,
    view: View,
    /// Share of the row's width. Stored in whatever units the last resize left
    /// behind (pixels, after a drag) because only the ratio within a row is ever
    /// used — see [`resolve_widths`].
    weight: f32,
    flow: FlowUi,
    probe: ProbeUi,
}

impl Widget {
    fn new(id: u64, view: View) -> Self {
        Widget { id, view, weight: 1.0, flow: FlowUi::default(), probe: ProbeUi::default() }
    }
}

struct Row {
    height: f32,
    widgets: Vec<Widget>,
}

/// A row's widgets as actually drawn: a row too wide for the window is drawn as
/// several bands of the same height rather than squeezed or truncated.
struct Band {
    row: usize,
    start: usize,
    len: usize,
}

/// How much to scale every stored row height by so the bands and their trailing
/// seams exactly fill `avail_h`.
///
/// Returns `1.0` once the rows no longer fit, which is the switch from
/// stretch-to-fill to scroll. Kept separate from the render loop because the
/// property that matters — that `sum(h * scale) + bands * GAP` is exactly the
/// height available, so the last row keeps its bottom edge — is arithmetic, and
/// arithmetic can be tested.
fn height_scale(sum_h: f32, bands: usize, avail_h: f32) -> f32 {
    let free = avail_h - bands as f32 * GAP;
    (free / sum_h.max(1.0)).max(1.0)
}

/// Split each row's widgets into bands of at most `per_band`.
fn bands_of(rows: &[Row], per_band: usize) -> Vec<Band> {
    let per_band = per_band.max(1);
    let mut out = Vec::new();
    for (r, row) in rows.iter().enumerate() {
        let mut start = 0;
        while start < row.widgets.len() {
            let len = per_band.min(row.widgets.len() - start);
            out.push(Band { row: r, start, len });
            start += len;
        }
    }
    out
}

/// Turn a band's weights into pixel widths that sum to `avail`, with nothing
/// below `min_w`.
///
/// A widget dragged very wide must not push its neighbours below the width at
/// which their tables stop being readable, so undersized cells are pinned to the
/// floor and the remainder is re-shared among the rest. If the floor cannot be
/// honoured at all (a very narrow window), it drops to an even split — the same
/// "reflow, don't clip" rule the tables follow.
fn resolve_widths(weights: &[f32], avail: f32, min_w: f32) -> Vec<f32> {
    let n = weights.len();
    if n == 0 {
        return Vec::new();
    }
    let min_w = min_w.min(avail / n as f32).max(0.0);
    let w: Vec<f32> = weights.iter().map(|x| if *x > 0.0 { *x } else { 1.0 }).collect();
    let mut out = vec![0.0f32; n];
    let mut pinned = vec![false; n];

    // At most one column is pinned per pass, so this terminates in `n` passes.
    for _ in 0..=n {
        let used: f32 = (0..n).filter(|&i| pinned[i]).map(|i| out[i]).sum();
        let free = (avail - used).max(0.0);
        let sum: f32 = (0..n).filter(|&i| !pinned[i]).map(|i| w[i]).sum();
        if sum <= 0.0 {
            break;
        }
        for i in 0..n {
            if !pinned[i] {
                out[i] = free * w[i] / sum;
            }
        }
        match (0..n).find(|&i| !pinned[i] && out[i] < min_w) {
            Some(i) => {
                out[i] = min_w;
                pinned[i] = true;
            }
            None => break,
        }
    }
    out
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
    let mut flex_idx = None;
    for (i, c) in keep.iter_mut().enumerate() {
        if c.width == 0 {
            c.width = flex;
            flex_idx = Some(i);
        }
    }

    // Spread whatever is still unused evenly across the OTHER columns, so the
    // row spans the whole cell instead of huddling against the left edge with a
    // third of the panel blank.
    //
    // The flexible column is excluded because it has already taken its share up
    // to `flex_max`. Letting it take a second helping is what turned an
    // 18-character address into a 48-character column: one enormous gap before
    // the next field, while the numbers on the right stayed bunched together.
    let used: usize = keep.iter().map(|c| c.width).sum();
    if budget > used && !keep.is_empty() {
        let extra = budget - used;
        let mut targets: Vec<usize> = (0..keep.len()).filter(|i| Some(*i) != flex_idx).collect();
        // A table narrowed down to its flexible column alone must still span the
        // cell, so with nothing else left it does take the slack.
        if targets.is_empty() {
            targets = (0..keep.len()).collect();
        }
        let each = extra / targets.len();
        let mut rem = extra % targets.len();
        for i in targets {
            keep[i].width += each;
            if rem > 0 {
                keep[i].width += 1;
                rem -= 1;
            }
        }
    }
    keep
}

/// Pad (or truncate) to exactly `width` characters, always leaving one space of
/// separation so adjacent columns never run together.
/// Columns of the probe answer table.
///
/// NAME is sized for a reverse-DNS name (`38.173.125.74.in-addr.arpa` is 26
/// characters, and PTR lookups are most of what this widget is pointed at), TYPE
/// for the longest record label, and TTL for a formatted duration. `DATA` is
/// capped below the general flexible maximum so that a wide cell spreads its
/// slack across the other three rather than pouring all of it into the answer.
///
/// Module-level so the layout tests measure the real table instead of a copy
/// that drifts from it — these widths were previously stated twice.
const PROBE_COLS: [Col; 4] = [
    Col::new("NAME", 28, false, 2),
    Col::new("TYPE", 7, false, 1),
    Col::new("TTL", 8, true, 3),
    Col::new("DATA", 0, false, 0),
];
const PROBE_DATA_MIN: usize = 16;
const PROBE_DATA_MAX: usize = 45;

/// Lay a value out in exactly `width` characters, one of which is a gutter.
///
/// The gutter has to sit on the side facing the NEXT column. A right-aligned
/// cell padded on the left reserves its blank before the value, leaving the last
/// character flush against whatever follows — which is how a 1h TTL rendered as
/// `1hfra24s25-in-f6.1e100.net`. Columns carry their own separation because the
/// row is drawn with zero item spacing: the characters are the layout.
fn pad(s: &str, width: usize, right: bool, gutter: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let inner = width.saturating_sub(gutter).max(1);
    let blanks = width.saturating_sub(inner);
    if right {
        format!("{:>inner$}{}", truncate(s, inner), " ".repeat(blanks), inner = inner)
    } else {
        format!("{:<width$}", truncate(s, inner), width = width)
    }
}

/// How much blank a cell reserves on the side facing the next column.
///
/// One character everywhere except a right-aligned column followed by a
/// left-aligned one, which gets two. At every other boundary the neighbour's own
/// padding already opens the gap — a right-aligned cell is mostly leading
/// blanks, a left-aligned one trails off into them. Only at a right→left seam
/// are both values pushed hard against it, and there a single space reads as a
/// collision: `1h` beside an answer looked like `1h fra24s25-in-f6.1e100.net`
/// with no column to speak of.
///
/// `TTL`→`DATA` in the probe table is the only such boundary in the window,
/// which is why this is a rule about neighbours rather than a wider gutter on
/// every right-aligned column — that would cost `RATE` the width it needs to
/// print `715.2 KB/s` without an ellipsis.
fn gutter(col: &Col, next: Option<&Col>) -> usize {
    match next {
        Some(n) if col.right && !n.right => 2,
        _ => 1,
    }
}

fn table_header(ui: &mut egui::Ui, plan: &[Col], theme: &Theme) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (i, c) in plan.iter().enumerate() {
            let g = gutter(c, plan.get(i + 1));
            mono_cell(ui, pad(c.title, c.width, c.right, g), theme.text_muted);
        }
    });
    header_rule(ui, theme);
}

/// Render one row. `cell` is asked only for the columns that survived `fit`, so
/// a dropped column costs nothing to format.
fn table_row(ui: &mut egui::Ui, plan: &[Col], cell: impl Fn(&str) -> (String, Color32)) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (i, c) in plan.iter().enumerate() {
            let (text, color) = cell(c.title);
            let g = gutter(c, plan.get(i + 1));
            mono_cell(ui, pad(&text, c.width, c.right, g), color);
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

    rows: Vec<Row>,
}

/// The layout the dashboard opens with. Which view sits in which cell is the
/// operator's from the first frame on — this is only where the selectors start.
fn default_rows() -> Vec<Row> {
    let mut next_id = 0u64;
    let mut mk = |view| {
        next_id += 1;
        Widget::new(next_id, view)
    };
    vec![
        Row {
            height: DEFAULT_TOP_H,
            widgets: vec![mk(View::Throughput), mk(View::Flows)],
        },
        Row {
            height: DEFAULT_ROW_H,
            widgets: vec![mk(View::Protocols), mk(View::Hosts), mk(View::Probe)],
        },
    ]
}

impl TunnelApp {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            theme: Theme::default(),
            theme_applied: false,
            traffic: Arc::new(TrafficSnapshot::default()),
            status: Status::default(),
            rows: default_rows(),
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

        self.frame(ctx);
    }
}

impl TunnelApp {
    /// Draw the window: header bar on top, widget grid below.
    ///
    /// Split out of `update` so the render tests draw through the real thing,
    /// frames and margins included. They used to build their own panels with
    /// egui's default frames, whose 8px bottom margin is exactly the kind of
    /// discrepancy that makes a layout test agree with itself and disagree with
    /// the window.
    fn frame(&mut self, ctx: &egui::Context) {
        let theme = self.theme;
        let traffic = self.traffic.clone();
        let dns = self.status.dns;

        // The two panels share one left edge: the header's text starts where a
        // widget's header text starts (grid margin + border + content padding),
        // so the title column and the first selector line up.
        let edge = GAP + 1.0 + PAD_X;
        egui::TopBottomPanel::top("header")
            .frame(
                egui::Frame::none()
                    .fill(theme.background)
                    // No bottom margin: the grid's own top margin is the gap
                    // below the header, so it is one GAP and not two stacked.
                    .inner_margin(egui::Margin {
                        left: edge,
                        right: edge,
                        top: GAP,
                        bottom: 0.0,
                    }),
            )
            .show(ctx, |ui| {
                render_header(ui, &self.status, &traffic, &theme);
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(theme.background)
                    // No bottom margin either: every band carries a trailing
                    // seam, and the last one is the window's bottom gap.
                    .inner_margin(egui::Margin {
                        left: GAP,
                        right: GAP,
                        top: GAP,
                        bottom: 0.0,
                    }),
            )
            .show(ctx, |ui| {
                self.dashboard(ui, &traffic, dns);
            });
    }

    /// Draw every band, with a draggable seam between neighbouring widgets and
    /// under each band.
    fn dashboard(&mut self, ui: &mut egui::Ui, traffic: &Arc<TrafficSnapshot>, dns: Option<Ipv4Addr>) {
        let theme = self.theme;
        let avail = ui.available_size();

        // How many widgets a band can hold before one of them would be too
        // narrow to read. This is the reflow rule: widgets wrap, they never
        // shrink past legibility and they are never hidden.
        let per_band = (((avail.x + GAP) / (COL_MIN_W + GAP)).floor() as usize).max(1);
        let bands = bands_of(&self.rows, per_band);
        if bands.is_empty() {
            empty_note(ui, "no widgets", &theme);
            return;
        }

        // Stretch to fill a tall window, scroll in a short one. The scale is
        // applied to the drawn height and divided back out of a drag, so a resize
        // is a ratio the operator keeps across window sizes.
        //
        // Every band is exactly its height plus one trailing seam and nothing
        // else, so `sum(h) + n*GAP == avail.y` when stretching — which is the
        // whole reason the vertical spacing below is zeroed. Left at egui's
        // default, the 6px between each band and its seam accumulated into the
        // scroll area and pushed the last row's bottom edge out of the window.
        let sum_h: f32 = bands.iter().map(|b| self.rows[b.row].height).sum();
        let scale = height_scale(sum_h, bands.len(), avail.y);

        egui::ScrollArea::vertical()
            .id_salt("dashboard")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing = Vec2::ZERO;
                for band in &bands {
                    // The floor is a safety net, not part of the budget: a
                    // stored height is never below it (the drag clamps) and the
                    // scale is never below 1, so it cannot fire while
                    // stretching and break the exact fit.
                    let h = (self.rows[band.row].height * scale).max(MIN_ROW_H);
                    // No slack for the borders: `Frame` advances the cursor by
                    // exactly the size its child claimed and paints the 1px
                    // stroke centred on that boundary. Reserving 2px a widget
                    // for it made every seam 10px wide against an 8px margin.
                    let seams = GAP * (band.len as f32 - 1.0);
                    let content_w = (ui.available_width() - seams).max(60.0);
                    let weights: Vec<f32> = (0..band.len)
                        .map(|k| self.rows[band.row].widgets[band.start + k].weight)
                        .collect();
                    let widths = resolve_widths(&weights, content_w, COL_MIN_W);

                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        for k in 0..band.len {
                            let i = band.start + k;
                            let (wid, view) = {
                                let w = &self.rows[band.row].widgets[i];
                                (w.id, w.view)
                            };
                            let mut next_view = view;
                            {
                                let w = &mut self.rows[band.row].widgets[i];
                                render_panel(
                                    ui,
                                    widths[k],
                                    h,
                                    &theme,
                                    |ui| view_selector(ui, wid, &mut next_view, &theme),
                                    |ui| render_widget(ui, w, traffic, &theme, dns),
                                );
                            }
                            self.rows[band.row].widgets[i].view = next_view;

                            if k + 1 < band.len {
                                let next_id = self.rows[band.row].widgets[i + 1].id;
                                let dx = v_seam(ui, h, ("vseam", wid, next_id), &theme);
                                if dx != 0.0 {
                                    // Move width between the two neighbours only,
                                    // then write the whole band's pixel widths
                                    // back as weights so the units stay uniform.
                                    let mut px = widths.clone();
                                    let total = px[k] + px[k + 1];
                                    let floor = COL_MIN_W.min(total * 0.5);
                                    let left = (px[k] + dx).clamp(floor, total - floor);
                                    px[k] = left;
                                    px[k + 1] = total - left;
                                    for (j, v) in px.iter().enumerate() {
                                        self.rows[band.row].widgets[band.start + j].weight = *v;
                                    }
                                }
                            }
                        }
                    });

                    let dy = h_seam(ui, ("hseam", band.row, band.start), &theme);
                    if dy != 0.0 {
                        let row = &mut self.rows[band.row];
                        row.height = (row.height + dy / scale).max(MIN_ROW_H);
                    }
                }
            });
    }
}

// ---------------------------------------------------------------------------
// Resize seams
// ---------------------------------------------------------------------------

/// The draggable seam between two widgets. Returns the horizontal drag delta.
fn v_seam(ui: &mut egui::Ui, height: f32, id: impl std::hash::Hash, theme: &Theme) -> f32 {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(GAP, height), egui::Sense::hover());
    // An explicit id, not the auto-generated positional one: widgets come and go,
    // and a seam whose identity shifts mid-drag drops the drag.
    let resp = ui.interact(rect, egui::Id::new(id), egui::Sense::drag());
    let live = resp.hovered() || resp.dragged();
    if live {
        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
    }
    let color = if live { theme.accent_hover } else { theme.border };
    ui.painter()
        .vline(rect.center().x, rect.y_range(), Stroke::new(1.0, color));
    resp.drag_delta().x
}

/// The draggable seam under a band. Returns the vertical drag delta.
fn h_seam(ui: &mut egui::Ui, id: impl std::hash::Hash, theme: &Theme) -> f32 {
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, GAP), egui::Sense::hover());
    let resp = ui.interact(rect, egui::Id::new(id), egui::Sense::drag());
    let live = resp.hovered() || resp.dragged();
    if live {
        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
    }
    if live {
        ui.painter()
            .hline(rect.x_range(), rect.center().y, Stroke::new(1.0, theme.accent_hover));
    }
    resp.drag_delta().y
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
///
/// Every band of the panel is measured, never inferred:
///
/// ```text
///   HEADER_H          header strip, selector vertically centred in it
///   (rule)            drawn exactly at HEADER_H, no space of its own
///   PAD_Y
///   height - HEADER_H - 2*PAD_Y     content
///   PAD_Y
/// ```
///
/// The content used to be sized from `available_size()` instead, which reads the
/// space left AFTER the frame's top margin but does not know about its bottom
/// one — so every widget overran its cell by `PAD_Y` and the last row in the
/// window lost its bottom edge.
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
                    // Zero vertical spacing at the panel level so the three
                    // bands above are exactly what they say. Table row spacing
                    // is set inside the content frame, where it belongs.
                    ui.spacing_mut().item_spacing = Vec2::new(6.0, 0.0);

                    // `Align::Center` is what centres the selector in the strip:
                    // laid out top-down it would sit against the upper border
                    // with all the slack beneath it.
                    ui.allocate_ui_with_layout(
                        Vec2::new(width, HEADER_H),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            ui.set_min_size(Vec2::new(width, HEADER_H));
                            ui.spacing_mut().item_spacing = Vec2::new(6.0, ROW_GAP);
                            ui.add_space(PAD_X);
                            header(ui);
                        },
                    );

                    let rule = ui.available_rect_before_wrap();
                    ui.painter()
                        .hline(rule.x_range(), rule.top(), Stroke::new(1.0, theme.border));

                    let content_h = (height - HEADER_H - 2.0 * PAD_Y).max(0.0);
                    egui::Frame::none()
                        .inner_margin(egui::Margin::symmetric(PAD_X, PAD_Y))
                        .show(ui, |ui| {
                            ui.spacing_mut().item_spacing = Vec2::new(6.0, ROW_GAP);
                            ui.set_min_size(Vec2::new(width - 2.0 * PAD_X, content_h));
                            content(ui);
                        });
                },
            );
        });
}

fn view_selector(ui: &mut egui::Ui, wid: u64, kind: &mut View, theme: &Theme) {
    egui::ComboBox::from_id_salt(("view", wid))
        .selected_text(
            egui::RichText::new(kind.label())
                .color(theme.text_muted)
                .size(MONO_PT)
                .strong()
                .monospace(),
        )
        .width(118.0)
        .show_ui(ui, |ui| {
            for option in View::ALL {
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

        ui.add_space(GAP * 2.0);

        // Three honest states: running, stopped by an error, and not running.
        // The failure reason is rendered right here — an engine that bailed
        // (kill switch, resolver, TUN) must never keep wearing CONNECTED.
        let (status_text, status_color, connstat) = if status.running {
            ("CONNECTED", theme.text_primary, "[ON]")
        } else if status.last_error.is_some() {
            ("ENGINE STOPPED", ERROR_RED, "[ERR]")
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
            ui.add_space(GAP);
            ui.label(
                egui::RichText::new(truncate(err, 96))
                    .color(ERROR_RED)
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

            // Three states, because they need three different actions from the
            // operator and only one of them is a fault:
            //
            //   FWD ERR     no lease at all — the reason says what to fix
            //   FWD :P IDLE leased, but nothing has ever arrived on it
            //   FWD :P n    leased and carrying inbound
            //
            // IDLE is muted rather than red: a port nobody has dialled yet looks
            // exactly like one that forwards nothing, and calling that an error
            // would cry wolf on every quiet start.
            match (status.forward_port, &status.forward_error) {
                (_, Some(err)) => {
                    ui.add_space(GAP * 2.0);
                    ui.label(
                        egui::RichText::new("FWD ERR")
                            .color(ERROR_RED)
                            .size(MONO_PT)
                            .monospace(),
                    )
                    .on_hover_text(err.clone());
                }
                (Some(port), None) => {
                    let live = status.forwarded_in > 0;
                    ui.add_space(GAP * 2.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "FWD :{port} {}",
                            if live {
                                format!("{}", status.forwarded_in)
                            } else {
                                "IDLE".into()
                            }
                        ))
                        .color(if live { theme.text_primary } else { theme.text_muted })
                        .size(MONO_PT)
                        .monospace(),
                    )
                    .on_hover_text(if live {
                        "inbound packets accepted on the forwarded port".to_string()
                    } else {
                        "the port is leased but nothing has arrived on it — check the \
                         application listens on this exact port, and that the firewall \
                         permits inbound on the tunnel adapter"
                            .to_string()
                    });
                }
                (None, None) => {}
            }

            let total = traffic.total_up + traffic.total_down;
            if total > 0 {
                ui.add_space(GAP * 2.0);
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
                ui.add_space(GAP * 2.0);
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
// Widget dispatch
// ---------------------------------------------------------------------------

fn render_widget(
    ui: &mut egui::Ui,
    w: &mut Widget,
    traffic: &TrafficSnapshot,
    theme: &Theme,
    dns: Option<Ipv4Addr>,
) {
    let id = w.id;
    match w.view {
        View::Throughput => draw_chart(ui, traffic, theme),
        View::Flows => flows_pane(ui, id, traffic, &mut w.flow, theme),
        View::Protocols => render_protocols(ui, id, traffic, theme),
        View::Hosts => render_hosts(ui, id, traffic, theme),
        View::Services => render_services(ui, id, traffic, theme),
        View::Composition => render_composition(ui, id, traffic, theme),
        View::Counters => render_counters(ui, id, traffic, theme),
        View::Probe => render_probe(ui, id, &mut w.probe, traffic, theme, dns),
    }
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
    wid: u64,
    traffic: &TrafficSnapshot,
    state: &mut FlowUi,
    theme: &Theme,
) {
    let wide = ui.available_width() >= 330.0;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        text_field(ui, &mut state.filter, if wide { 130.0 } else { 90.0 }, "filter");
        egui::ComboBox::from_id_salt(("flow_sort", wid))
            .selected_text(
                egui::RichText::new(state.sort.label())
                    .color(theme.text_muted)
                    .size(9.0)
                    .monospace(),
            )
            .width(62.0)
            .show_ui(ui, |ui| {
                for option in Sort::ALL {
                    ui.selectable_value(
                        &mut state.sort,
                        option,
                        egui::RichText::new(option.label()).size(MONO_PT).monospace(),
                    );
                }
            });
        ui.checkbox(&mut state.hide_idle, "");
        if wide {
            ui.label(
                egui::RichText::new("live only")
                    .color(theme.text_muted)
                    .size(9.0)
                    .monospace(),
            );
        }
    });
    ui.add_space(ROW_GAP);

    render_flows(ui, wid, traffic, &state.filter, state.sort, state.hide_idle, theme);
}

#[allow(clippy::too_many_arguments)]
fn render_flows(
    ui: &mut egui::Ui,
    wid: u64,
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
        .id_salt(("flows_scroll", wid))
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
// Probe
// ---------------------------------------------------------------------------

/// Pick a host, ask it something.
///
/// The target list is the session's own host table, because the question worth
/// asking is almost always about an address that is already on screen and
/// unidentified. Free text is allowed alongside it: a name that has not been
/// contacted yet is a perfectly good thing to look up, and the answer often
/// explains a row that has.
fn render_probe(
    ui: &mut egui::Ui,
    wid: u64,
    p: &mut ProbeUi,
    traffic: &TrafficSnapshot,
    theme: &Theme,
    dns: Option<Ipv4Addr>,
) {
    // Seed the resolver from the engine's pinned one the first time it exists,
    // so the probe asks the same nameserver everything else on this host asks.
    if !p.server_seeded {
        if let Some(ip) = dns {
            p.server = ip.to_string();
            p.server_seeded = true;
        } else if p.server.is_empty() {
            p.server = FALLBACK_DNS.to_string();
        }
    }

    // Collect a finished probe. `last` then holds it until the next run, so the
    // answer does not vanish on the frame the thread exits.
    if let Some(job) = &p.job {
        if let Some(result) = job.take() {
            p.last = Some(result);
            p.job = None;
        }
    }

    let busy = p.job.is_some();
    let wide = ui.available_width() >= 420.0;
    let mut go = false;

    // Both control rows are laid out from the same total, so their left and
    // right edges line up with each other and with the table below: the
    // fixed-width controls anchor the ends and the text field takes the slack.
    //   row 1:  [ target .................. ][ ACTIVE ]
    //   row 2:  [ AUTO ][ resolver .......... ][ LOOKUP ]
    // Sized in absolute terms rather than by letting each widget claim what it
    // wants, which is what left the two rows ragged against one another.
    let full_w = ui.available_width();
    let combo_w = 76.0;
    let button_w = 62.0;
    let target_w = (full_w - combo_w - GAP).max(60.0);
    let server_w = (full_w - combo_w - button_w - 2.0 * GAP).max(60.0);
    // Narrow: the resolver field is dropped, so the type selector and the button
    // are the whole row and the target field spans the width above them.
    let server_w = if wide { server_w } else { 0.0 };

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        let entry = text_field(ui, &mut p.target, target_w, "host or address");
        if entry.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            go = true;
        }

        egui::ComboBox::from_id_salt(("probe_host", wid))
            .selected_text(
                egui::RichText::new("ACTIVE")
                    .color(theme.text_muted)
                    .size(9.0)
                    .monospace(),
            )
            .width(combo_w)
            .show_ui(ui, |ui| {
                if traffic.hosts.is_empty() {
                    ui.label(
                        egui::RichText::new("no active hosts")
                            .color(theme.text_muted)
                            .size(MONO_PT)
                            .monospace(),
                    );
                }
                for h in &traffic.hosts {
                    let line = format!("{:<22}{:>9} {}", truncate(&h.ip, 22), format_bytes_short(h.up + h.down), h.app);
                    if ui
                        .selectable_label(
                            p.target == h.ip,
                            egui::RichText::new(line).size(MONO_PT).monospace(),
                        )
                        .clicked()
                    {
                        p.target = h.ip.clone();
                    }
                }
            });
    });

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        egui::ComboBox::from_id_salt(("probe_type", wid))
            .selected_text(
                egui::RichText::new(p.record.0.label())
                    .color(theme.text_muted)
                    .size(9.0)
                    .monospace(),
            )
            .width(combo_w)
            .show_ui(ui, |ui| {
                for option in probe::RecordType::ALL {
                    ui.selectable_value(
                        &mut p.record.0,
                        option,
                        egui::RichText::new(option.label()).size(MONO_PT).monospace(),
                    );
                }
            });

        if wide {
            let edit = text_field(ui, &mut p.server, server_w, "resolver")
                .on_hover_text("nameserver to ask; defaults to the resolver the tunnel pinned");
            // An entry typed before the engine published its resolver is still
            // the operator's choice: seeding must not come along later and
            // overwrite it.
            if edit.changed() {
                p.server_seeded = true;
            }
        }

        if ui
            .add_enabled(
                !busy,
                egui::Button::new(
                    egui::RichText::new(if busy { "…" } else { "LOOKUP" })
                        .size(MONO_PT)
                        .monospace(),
                )
                .min_size(Vec2::new(button_w, 0.0)),
            )
            .clicked()
        {
            go = true;
        }
    });

    if go && !busy {
        match parse_server(&p.server) {
            Ok(server) => {
                p.last = None;
                p.job = Some(probe::spawn(probe::Request {
                    action: probe::Action::Nslookup,
                    target: p.target.clone(),
                    record: p.record.0,
                    server,
                    timeout: probe::DEFAULT_TIMEOUT,
                }));
            }
            Err(e) => p.last = Some(Err(e)),
        }
    }

    ui.add_space(ROW_GAP);
    probe_status(ui, p, theme);

    if let Some(Ok(outcome)) = &p.last {
        probe_answers(ui, wid, outcome, theme);
    }
}

/// One or two compact lines saying what happened, above the answers.
fn probe_status(ui: &mut egui::Ui, p: &ProbeUi, theme: &Theme) {
    if let Some(job) = &p.job {
        mono_cell(
            ui,
            format!("… {} ({:.1}s)", job.summary, job.elapsed().as_secs_f32()),
            theme.text_secondary,
        );
        return;
    }
    match &p.last {
        None => mono_cell(
            ui,
            "pick a host or type a name, then LOOKUP".to_string(),
            theme.text_muted,
        ),
        Some(Err(e)) => {
            ui.label(
                egui::RichText::new(truncate(e, 220))
                    .color(ERROR_RED)
                    .size(MONO_PT)
                    .monospace(),
            )
            .on_hover_text(e);
        }
        Some(Ok(o)) => {
            let ok = o.rcode == "NOERROR" && !o.answers.is_empty();
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                mono_cell(
                    ui,
                    format!("{:<9}", o.rcode),
                    if ok { OK_GREEN } else { ERROR_RED },
                );
                mono_cell(
                    ui,
                    format!(
                        "{:>3} ans  {:>5} ms  {}{}",
                        o.answers.len(),
                        o.elapsed.as_millis(),
                        o.transport,
                        if o.authoritative { "  auth" } else { "" }
                    ),
                    theme.text_secondary,
                );
            });
            ui.label(
                egui::RichText::new(truncate(
                    &format!("{} {} @ {}", o.record.label(), o.question, o.server),
                    120,
                ))
                .color(theme.text_muted)
                .size(9.0)
                .monospace(),
            );
            if let Some(note) = &o.note {
                ui.label(
                    egui::RichText::new(truncate(note, 120))
                        .color(theme.text_muted)
                        .size(9.0)
                        .monospace(),
                )
                .on_hover_text(note);
            }
        }
    }
}

fn probe_answers(ui: &mut egui::Ui, wid: u64, outcome: &probe::Outcome, theme: &Theme) {
    ui.add_space(ROW_GAP);
    let plan = fit(&PROBE_COLS, char_budget(ui), PROBE_DATA_MIN, PROBE_DATA_MAX);
    table_header(ui, &plan, theme);

    if outcome.answers.is_empty() {
        empty_note(ui, "no records in the answer section", theme);
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt(("probe_scroll", wid))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for a in &outcome.answers {
                table_row(ui, &plan, |title| match title {
                    "NAME" => (a.name.clone(), theme.text_muted),
                    "TYPE" => (a.kind.clone(), theme.text_secondary),
                    "TTL" => (format_ttl(a.ttl), theme.text_muted),
                    _ => (a.data.clone(), theme.text_primary),
                });
            }
        });
}

/// Accept `1.1.1.1`, `1.1.1.1:53`, or a bracketed v6 literal. A bare address is
/// the common case, so it must not need a port.
fn parse_server(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(SocketAddr::from((FALLBACK_DNS, 53)));
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    match s.parse::<IpAddr>() {
        Ok(ip) => Ok(SocketAddr::new(ip, 53)),
        Err(_) => Err(format!("{s} is not an address; give the resolver as an IP")),
    }
}

// ---------------------------------------------------------------------------
// Inspection cells
// ---------------------------------------------------------------------------

/// Donut of byte share by application protocol, with a legend beside it when the
/// cell is wide enough and beneath it when it is not.
fn render_protocols(ui: &mut egui::Ui, wid: u64, traffic: &TrafficSnapshot, theme: &Theme) {
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
            ui.add_space(GAP);
            // The legend MUST be given its own top-down region. `ScrollArea`
            // builds its viewport with the caller's layout, and the caller here
            // is a horizontal one — inherited, the legend lays its rows out
            // left-to-right and overflows the panel, pushing the sibling cells
            // off screen.
            let rest = Vec2::new(ui.available_width(), ui.available_height());
            ui.allocate_ui_with_layout(rest, Layout::top_down(Align::Min), |ui| {
                ui.set_min_size(rest);
                proto_legend(ui, wid, traffic, total, theme);
            });
        });
    } else {
        let dia = (avail.y * 0.5).min(avail.x - 10.0).clamp(60.0, 190.0);
        ui.vertical_centered(|ui| {
            draw_donut(ui, traffic, total, dia, theme);
        });
        ui.add_space(GAP);
        proto_legend(ui, wid, traffic, total, theme);
    }
}

/// Swatch, then a normal fitted table — so the legend spans the cell and lines
/// up column-wise instead of trailing off at whatever width the text happened
/// to need.
fn proto_legend(ui: &mut egui::Ui, wid: u64, traffic: &TrafficSnapshot, total: u64, theme: &Theme) {
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
        for (i, c) in plan.iter().enumerate() {
            mono_cell(ui, pad(c.title, c.width, c.right, gutter(c, plan.get(i + 1))), theme.text_muted);
        }
    });
    header_rule(ui, theme);

    egui::ScrollArea::vertical()
        .id_salt(("proto_legend", wid))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for a in traffic.apps.iter().filter(|a| a.bytes > 0) {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let (sq, _) = ui.allocate_exact_size(Vec2::new(9.0, 9.0), egui::Sense::hover());
                    ui.painter()
                        .rect_filled(sq, Rounding::ZERO, proto_color(a.name, theme));
                    mono_cell(ui, " ".to_string(), theme.text_muted);
                    for (i, c) in plan.iter().enumerate() {
                        let (text, color) = match c.title {
                            "PROTOCOL" => (a.name.to_string(), theme.text_secondary),
                            "SHARE" => (
                                format!("{:.1}%", a.bytes as f64 * 100.0 / total as f64),
                                theme.text_primary,
                            ),
                            _ => (format_bytes_short(a.bytes), theme.text_muted),
                        };
                        mono_cell(ui, pad(&text, c.width, c.right, gutter(c, plan.get(i + 1))), color);
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
fn render_hosts(ui: &mut egui::Ui, wid: u64, traffic: &TrafficSnapshot, theme: &Theme) {
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
        .id_salt(("hosts_scroll", wid))
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
fn render_services(ui: &mut egui::Ui, wid: u64, traffic: &TrafficSnapshot, theme: &Theme) {
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
        .id_salt(("services_scroll", wid))
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
fn render_composition(ui: &mut egui::Ui, wid: u64, traffic: &TrafficSnapshot, theme: &Theme) {
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

    ui.add_space(GAP);

    let budget = char_budget(ui);
    let name_w = budget.saturating_sub(12).clamp(5, 12);
    let show_bar = budget >= 34;

    egui::ScrollArea::vertical()
        .id_salt(("composition_scroll", wid))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for a in traffic.apps.iter().filter(|a| a.bytes > 0) {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    mono_cell(ui, pad(a.name, name_w, false, 1), theme.text_secondary);
                    mono_cell(ui, format!("{:>4}", a.flows), theme.text_muted);
                    mono_cell(ui, format!("{:>8}", format_bytes_short(a.bytes)), theme.text_muted);
                    if show_bar {
                        ui.add_space(GAP);
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
fn render_counters(ui: &mut egui::Ui, wid: u64, traffic: &TrafficSnapshot, theme: &Theme) {
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
        .id_salt(("counters_scroll", wid))
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

/// The line under a table's column titles. Equal space above and below, so the
/// titles read as a header band rather than as a row that drifted upwards.
fn header_rule(ui: &mut egui::Ui, theme: &Theme) {
    ui.add_space(ROW_GAP);
    let rect = ui.available_rect_before_wrap();
    ui.painter()
        .hline(rect.x_range(), rect.top(), Stroke::new(1.0, theme.border));
    ui.add_space(ROW_GAP);
}

fn empty_note(ui: &mut egui::Ui, text: &str, theme: &Theme) {
    ui.vertical_centered(|ui| {
        ui.add_space(GAP);
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
        "Shadowsocks" | "Obfuscated" => ERROR_RED,
        "TLS" => OK_GREEN,
        "QUIC" => Color32::from_rgb(180, 140, 240),
        "DNS" => Color32::from_rgb(230, 200, 100),
        "mDNS" | "LLMNR" => Color32::from_rgb(190, 165, 90),
        "SSDP" | "NetBIOS" => Color32::from_rgb(140, 130, 170),
        // One family, one hue: uTP carries the bytes and the other three are
        // slivers beside it, so they read as parts of a whole rather than as
        // four unrelated protocols that happen to appear together.
        "uTP" => Color32::from_rgb(90, 200, 190),
        "BitTorrent" => Color32::from_rgb(60, 160, 155),
        "DHT" => Color32::from_rgb(130, 220, 210),
        "BT Tracker" => Color32::from_rgb(45, 125, 120),
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

/// A monospace text entry whose OUTER width is exactly `width`, so a row of
/// controls can be laid out against a known total.
fn text_field(ui: &mut egui::Ui, buf: &mut String, width: f32, hint: &str) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(buf)
            .margin(egui::Margin::symmetric(EDIT_PAD, 2.0))
            .desired_width((width - 2.0 * EDIT_PAD).max(8.0))
            .hint_text(hint)
            .font(egui::TextStyle::Monospace),
    )
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

/// A record TTL as a duration, because "3600" answers a different question than
/// "1h" when you are deciding whether an answer is stale.
fn format_ttl(ttl: u32) -> String {
    if ttl >= 86400 {
        format!("{}d", ttl / 86400)
    } else if ttl >= 3600 {
        format!("{}h", ttl / 3600)
    } else if ttl >= 60 {
        format!("{}m", ttl / 60)
    } else {
        format!("{ttl}s")
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

    /// Every non-ASCII character the dashboard can draw: the em dash standing in
    /// for an unnamed service, and the ellipsis `truncate` appends. Add to this
    /// when adding a symbol to this file — egui's bundled fonts cover far less
    /// than a source file will hold, and the test below is what says so.
    const SPECIAL_GLYPHS: &str = "—…";

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
        // A very wide panel: REMOTE saturates at its 38-character cap and the
        // remaining 129 characters are shared among the OTHERS, so the row spans
        // the full width without one enormous gap after the address.
        let plan = fit(&FLOW_COLS, 210, 14, 38);
        assert_eq!(plan.len(), 6);
        assert_eq!(plan.iter().map(|c| c.width).sum::<usize>(), 210);
        assert_eq!(plan[0].width, 38);
        // Every other column shares in the slack; none is left at its base width.
        assert!(plan[1..].iter().all(|c| c.width > 11));

        // At the width a real FLOWS widget gets, no column runs away with the
        // slack: the widest is within a few characters of the second widest,
        // rather than 2.3x it as when the flexible column took a second helping.
        let plan = fit(&FLOW_COLS, 140, 14, 38);
        assert_eq!(plan.iter().map(|c| c.width).sum::<usize>(), 140);
        let mut widths: Vec<usize> = plan.iter().map(|c| c.width).collect();
        widths.sort_unstable();
        assert!(
            widths[5] - widths[4] <= 16,
            "one column took the slack: {widths:?}"
        );

        // A table narrowed to its flexible column alone still spans the cell.
        let one = fit(&[Col::new("DATA", 0, false, 0)], 40, 10, 60);
        assert_eq!(one[0].width, 40);
    }

    #[test]
    fn rows_and_their_seams_exactly_fill_the_window() {
        // The bug this pins: every band overran its allotment, so the last row
        // in the window lost its bottom edge behind the frame.
        for rows in [vec![360.0_f32, 250.0], vec![250.0; 4], vec![300.0]] {
            for avail_h in [380.0_f32, 740.0, 1400.0] {
                let n = rows.len();
                let sum: f32 = rows.iter().sum();
                let scale = height_scale(sum, n, avail_h);
                let drawn: f32 = rows.iter().map(|h| h * scale).sum::<f32>() + n as f32 * GAP;
                if scale > 1.0 {
                    // Stretching: the grid fills the window to the pixel, and
                    // the trailing seam of the last band is the bottom margin.
                    assert!(
                        (drawn - avail_h).abs() < 0.01,
                        "{rows:?} at {avail_h}: drew {drawn}"
                    );
                } else {
                    // Overflowing: it scrolls, and never shrinks a row to fit.
                    assert!(drawn >= avail_h - 0.01);
                    assert_eq!(scale, 1.0);
                }
            }
        }
    }

    #[test]
    fn a_widget_spends_its_whole_height_and_no_more() {
        // render_panel splits `height` into HEADER_H, the rule, and a content
        // box padded on both sides. The parts must sum back to the whole, or
        // every widget quietly overruns its cell by a padding.
        for height in [MIN_ROW_H, DEFAULT_ROW_H, DEFAULT_TOP_H, 900.0] {
            let content_h = (height - HEADER_H - 2.0 * PAD_Y).max(0.0);
            assert!(content_h > 0.0, "no content fits at {height}");
            assert!((HEADER_H + PAD_Y + content_h + PAD_Y - height).abs() < 0.01);
        }
        // The shortest row a drag can produce still leaves a usable table.
        assert!(MIN_ROW_H - HEADER_H - 2.0 * PAD_Y >= 80.0);
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
        for cols in [FLOW_COLS.as_slice(), PROBE_COLS.as_slice()] {
            assert_eq!(cols.iter().filter(|c| c.width == 0).count(), 1);
        }
    }

    #[test]
    fn the_probe_table_keeps_the_answer_when_the_cell_is_narrow() {
        // DATA is the answer; NAME echoes the question that is already on the
        // status line above. In a very narrow widget the answer is what survives.
        let narrow: Vec<&str> = fit(&PROBE_COLS, 26, PROBE_DATA_MIN, PROBE_DATA_MAX)
            .iter()
            .map(|c| c.title)
            .collect();
        assert!(narrow.contains(&"DATA"));
        assert!(!narrow.contains(&"TTL"));
    }

    #[test]
    fn the_probe_table_fits_a_reverse_dns_name() {
        // A PTR name is the long field and the whole point of the lookup, so it
        // has to fit at the width the widget actually gets (~78 characters in
        // the default five-widget layout) rather than be shortened to an ellipsis.
        let sample = "38.173.125.74.in-addr.arpa";
        let plan = fit(&PROBE_COLS, 78, PROBE_DATA_MIN, PROBE_DATA_MAX);
        let name = plan.iter().find(|c| c.title == "NAME").expect("NAME dropped at 78");
        assert_eq!(
            pad(sample, name.width, false, 1).trim_end(),
            sample,
            "NAME is {} wide, too narrow for a reverse-DNS name",
            name.width
        );

        // At the narrowest a widget can be, the name still survives: the TTL is
        // what goes, because it is the field you can most afford to lose.
        let narrow: Vec<&str> = fit(&PROBE_COLS, 54, PROBE_DATA_MIN, PROBE_DATA_MAX)
            .iter()
            .map(|c| c.title)
            .collect();
        assert_eq!(narrow, ["NAME", "TYPE", "DATA"]);
    }

    #[test]
    fn every_cell_ends_in_a_gutter_so_columns_cannot_touch() {
        // The bug this pins: a right-aligned cell reserved its blank on the LEFT,
        // so its last character sat flush against the next column. A 1h TTL
        // beside an answer rendered as `1hfra24s25-in-f6.1e100.net`.
        //
        // Rows are drawn with zero item spacing — the characters ARE the layout —
        // so this is the only thing keeping two columns apart.
        for right in [false, true] {
            for g in [1, 2] {
                for width in 2..14usize {
                    for value in ["", "x", "1h", "abcdefghijklmnopqrst", "24h"] {
                        let cell = pad(value, width, right, g);
                        assert_eq!(
                            cell.chars().count(),
                            width,
                            "{value:?} at width {width} (right={right}, gutter={g})"
                        );
                        assert!(
                            cell.ends_with(' '),
                            "{cell:?} would touch the next column (right={right})"
                        );
                    }
                }
            }
        }
        assert_eq!(pad("1h", 8, true, 2), "    1h  ");
        assert_eq!(pad("abc", 6, false, 1), "abc   ");

        // The wider gutter is spent only where it is needed.
        let right_then_left = (Col::new("TTL", 8, true, 0), Col::new("DATA", 8, false, 0));
        assert_eq!(gutter(&right_then_left.0, Some(&right_then_left.1)), 2);
        assert_eq!(gutter(&right_then_left.1, Some(&right_then_left.0)), 1);
        assert_eq!(gutter(&right_then_left.0, None), 1, "the last column has no neighbour");
    }

    #[test]
    fn a_probe_row_reads_as_four_separated_columns() {
        // The rendered result, not just the invariants behind it: this table is
        // a character grid, so the only honest check is what the grid says.
        let plan = fit(&PROBE_COLS, 78, PROBE_DATA_MIN, PROBE_DATA_MAX);
        let render = |v: &dyn Fn(&str) -> &str| -> String {
            plan.iter()
                .enumerate()
                .map(|(i, c)| pad(v(c.title), c.width, c.right, gutter(c, plan.get(i + 1))))
                .collect()
        };
        let row = render(&|title| match title {
            "NAME" => "38.173.125.74.in-addr.arpa",
            "TYPE" => "PTR",
            "TTL" => "1h",
            _ => "fra24s25-in-f6.1e100.net",
        });
        let head = render(&|title| title);

        assert_eq!(row.chars().count(), 78);
        assert_eq!(head.chars().count(), 78);
        assert_eq!(
            row.trim_end(),
            "38.173.125.74.in-addr.arpa  PTR        1h  fra24s25-in-f6.1e100.net"
        );
        assert_eq!(head.trim_end(), "NAME                        TYPE      TTL  DATA");
    }

    #[test]
    fn truncate_is_codepoint_safe() {
        assert_eq!(truncate("1.2.3.4:443", 20), "1.2.3.4:443");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
        // Multi-byte: a byte slice at 5 would land mid-codepoint and panic.
        assert_eq!(truncate("ααααα", 3), "αα…");
    }

    #[test]
    fn byte_rate_and_ttl_scales_step_at_the_right_boundaries() {
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes_short(1024 * 1024), "1M");
        assert_eq!(format_rate(0.0), "0 B/s");
        assert_eq!(format_rate(2048.0), "2.0 KB/s");
        assert_eq!(format_ttl(59), "59s");
        assert_eq!(format_ttl(60), "1m");
        assert_eq!(format_ttl(3600), "1h");
        assert_eq!(format_ttl(86_400 * 2), "2d");
    }

    #[test]
    fn every_view_is_reachable_from_the_selector() {
        for kind in View::ALL {
            assert!(!kind.label().is_empty());
        }
        assert_eq!(View::ALL.len(), 8);
        assert_eq!(Sort::ALL.len(), 3);
        // The probe widget must be offered, or the action it fronts is dead code.
        assert!(View::ALL.contains(&View::Probe));
    }

    // -----------------------------------------------------------------------
    // Layout
    // -----------------------------------------------------------------------

    fn app() -> TunnelApp {
        TunnelApp::new(Shared::new())
    }

    fn views(app: &TunnelApp) -> Vec<Vec<View>> {
        app.rows
            .iter()
            .map(|r| r.widgets.iter().map(|w| w.view).collect())
            .collect()
    }

    #[test]
    fn widths_sum_to_the_available_space_and_honour_the_floor() {
        let w = resolve_widths(&[1.0, 1.0, 1.0], 900.0, COL_MIN_W);
        assert!((w.iter().sum::<f32>() - 900.0).abs() < 0.01);
        assert!(w.iter().all(|x| (x - 300.0).abs() < 0.01));

        // One widget dragged very wide cannot squeeze its neighbours below the
        // width at which their tables stop being readable.
        let w = resolve_widths(&[10.0, 1.0, 1.0], 1200.0, COL_MIN_W);
        assert!((w.iter().sum::<f32>() - 1200.0).abs() < 0.01);
        assert!(w[1] >= COL_MIN_W - 0.01 && w[2] >= COL_MIN_W - 0.01);
        assert!(w[0] > w[1]);

        // Too narrow to honour the floor at all: share evenly rather than
        // overflow the band.
        let w = resolve_widths(&[3.0, 1.0], 400.0, COL_MIN_W);
        assert!((w.iter().sum::<f32>() - 400.0).abs() < 0.01);
        assert!(w.iter().all(|x| *x >= 199.0));

        assert!(resolve_widths(&[], 500.0, COL_MIN_W).is_empty());
        // A degenerate weight left by an odd drag still produces a real width.
        let w = resolve_widths(&[0.0, 0.0], 600.0, 0.0);
        assert!((w.iter().sum::<f32>() - 600.0).abs() < 0.01);
    }

    #[test]
    fn a_row_too_wide_for_the_window_wraps_instead_of_hiding_widgets() {
        let app = app();
        // Wide window: the default layout is exactly its two rows.
        let wide = bands_of(&app.rows, 3);
        assert_eq!(wide.len(), 2);
        assert_eq!(wide[1].len, 3);

        // Narrow window: every widget is still drawn, just on more bands.
        let narrow = bands_of(&app.rows, 1);
        assert_eq!(narrow.len(), 5);
        assert_eq!(narrow.iter().map(|b| b.len).sum::<usize>(), 5);
        // Two-per-band splits the second row 2 + 1, both at that row's height.
        let two = bands_of(&app.rows, 2);
        assert_eq!(two.iter().map(|b| b.len).collect::<Vec<_>>(), [2, 2, 1]);
        assert!(two.iter().filter(|b| b.row == 1).count() == 2);
    }

    #[test]
    fn the_default_layout_opens_with_a_distinct_id_per_widget() {
        let app = app();
        assert_eq!(
            views(&app),
            vec![
                vec![View::Throughput, View::Flows],
                vec![View::Protocols, View::Hosts, View::Probe],
            ]
        );
        // Every egui salt in this file is built from the widget id, so a
        // duplicate would silently join two widgets' scroll offsets and open
        // combos together.
        let mut ids: Vec<u64> = app.rows.iter().flat_map(|r| r.widgets.iter().map(|w| w.id)).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count);
    }

    // -----------------------------------------------------------------------
    // Headless rendering
    // -----------------------------------------------------------------------

    /// A snapshot with something in every table, so a render test exercises the
    /// row paths and not just the empty notes.
    fn populated() -> TrafficSnapshot {
        use crate::inspect::{AppRow, FlowRow, HostRow, PortRow};
        TrafficSnapshot {
            total_up: 1_000_000,
            total_down: 9_000_000,
            pkts_up: 900,
            pkts_down: 4_100,
            rate_up: 2048.0,
            rate_down: 65536.0,
            up_series: (0..120).map(|i| i as f64 * 10.0).collect(),
            down_series: (0..120).map(|i| i as f64 * 90.0).collect(),
            active_flows: 2,
            tcp_flows: 1,
            udp_flows: 1,
            archived_flows: 7,
            flows: vec![
                FlowRow {
                    remote: "1.1.1.1:53".into(),
                    proto: "UDP",
                    app: "DNS",
                    up: 300,
                    down: 900,
                    rate: 64.0,
                    idle_ms: 40,
                    status: "",
                },
                FlowRow {
                    remote: "93.184.216.34:443".into(),
                    proto: "TCP",
                    app: "TLS",
                    up: 9_000,
                    down: 800_000,
                    rate: 0.0,
                    idle_ms: 90_000,
                    status: "reaped",
                },
            ],
            hosts: vec![
                HostRow { ip: "1.1.1.1".into(), app: "DNS", flows: 1, up: 300, down: 900, rate: 64.0, idle_ms: 40 },
                HostRow { ip: "93.184.216.34".into(), app: "TLS", flows: 1, up: 9_000, down: 800_000, rate: 0.0, idle_ms: 90_000 },
            ],
            ports: vec![
                PortRow { port: 53, l4: "UDP", service: "dns", flows: 1, up: 300, down: 900, rate: 64.0 },
                PortRow { port: 443, l4: "TCP", service: "https", flows: 1, up: 9_000, down: 800_000, rate: 0.0 },
            ],
            apps: vec![
                AppRow { name: "TLS", bytes: 809_000, flows: 1 },
                AppRow { name: "DNS", bytes: 1_200, flows: 1 },
            ],
        }
    }

    /// Draw one full frame at `size` with no backend attached.
    ///
    /// egui panics on a layout it cannot satisfy and asserts on colliding widget
    /// ids, so a frame that completes is real coverage: it is the only check that
    /// the reflow rules, the per-widget id salts and the seam interactions
    /// survive contact with the layouter rather than just with the unit tests.
    fn render_frame(app: &mut TunnelApp, w: f32, h: f32) -> egui::FullOutput {
        let ctx = egui::Context::default();
        apply_theme(&ctx, &app.theme);
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(w, h),
            )),
            ..Default::default()
        };
        ctx.run(input, |ctx| app.frame(ctx))
    }

    #[test]
    fn every_glyph_the_dashboard_draws_has_a_font_behind_it() {
        // egui ships a narrow font set — Hack for monospace, Ubuntu-Light for
        // proportional — and renders anything they lack as a tofu box. A source
        // file will happily hold `✕`; the window will not. So the symbols and
        // fixed labels are checked against the fonts rather than eyeballed, in
        // both families, because hover text is drawn proportional even where the
        // cell it came from is monospace.
        let mut text = String::from(SPECIAL_GLYPHS);
        for v in View::ALL {
            text.push_str(v.label());
        }
        for s in Sort::ALL {
            text.push_str(s.label());
        }
        for r in probe::RecordType::ALL {
            text.push_str(r.label());
        }
        for s in [
            "QUORUM IO", "[ON]", "[OFF]", "[ERR]", "CONNECTED", "ENGINE STOPPED", "OFFLINE",
            "FWD IDLE ERR",
            // Protocol labels reach the screen from inspect.rs, so they belong
            // in this registry too — `uTP` is one keystroke from `µTP`.
            "BitTorrent uTP DHT BT Tracker Obfuscated WireGuard OpenVPN Shadowsocks",
            "LOOKUP", "ACTIVE", "filter", "live only", "resolver", "host or address",
            "no active hosts", "no traffic yet", "no flows match the filter", "no widgets",
            "no remote hosts yet", "no services yet", "no classified traffic yet",
            "no records in the answer section", "pick a host or type a name, then LOOKUP",
            "nameserver to ask; defaults to the resolver the tunnel pinned",
            "RX TX RATIO PKT MEAN TCP UDP LIVE ARCHIV HOSTS SVCS DOWN UP FLOWS PKTS peak",
            "REMOTE APP L4 RATE HOST BYTES FL PORT SERVICE PROTOCOL SHARE NAME TYPE TTL DATA",
            "NOERROR FORMERR SERVFAIL NXDOMAIN NOTIMP REFUSED ans ms udp tcp auth",
            "GBMKBds", // the byte, rate and TTL suffixes
        ] {
            text.push_str(s);
        }

        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            ctx.fonts(|f| {
                for family in [egui::FontFamily::Monospace, egui::FontFamily::Proportional] {
                    let font = egui::FontId::new(MONO_PT, family.clone());
                    for ch in text.chars() {
                        assert!(
                            f.has_glyphs(&font, &ch.to_string()),
                            "{ch:?} (U+{:04X}) has no glyph in {family:?} and will render as tofu",
                            ch as u32
                        );
                    }
                }
            });
        });
    }

    /// The rectangles the widget panels actually painted, in draw order.
    ///
    /// Read back out of the frame's shape list rather than recomputed, so the
    /// assertions below are about what lands on screen and not about what the
    /// layout code believes. Combo boxes carry the same fill and stroke, so
    /// panels are told apart by being at least a widget's minimum size.
    fn panel_rects(app: &mut TunnelApp, w: f32, h: f32) -> Vec<egui::Rect> {
        render_frame(app, w, h)
            .shapes
            .into_iter()
            .filter_map(|c| match c.shape {
                egui::Shape::Rect(r)
                    if r.fill == MONO_THEME.surface
                        && r.rect.width() >= COL_MIN_W - 1.0
                        && r.rect.height() >= MIN_ROW_H - 1.0 =>
                {
                    Some(r.rect)
                }
                _ => None,
            })
            .collect()
    }

    /// The view selectors, told apart from the panels by being exactly the width
    /// `view_selector` asks for.
    fn selector_rects(app: &mut TunnelApp, w: f32, h: f32) -> Vec<egui::Rect> {
        render_frame(app, w, h)
            .shapes
            .into_iter()
            .filter_map(|c| match c.shape {
                egui::Shape::Rect(r)
                    if r.fill == MONO_THEME.surface
                        && (r.rect.width() - 118.0).abs() < 1.0
                        && r.rect.height() < 30.0 =>
                {
                    Some(r.rect)
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_grid_fills_the_window_with_one_uniform_gap() {
        let mut app = app();
        app.traffic = Arc::new(populated());

        // Sizes the default layout fits in: two bands, stretched to fill.
        for (w, h) in [(1280.0_f32, 800.0_f32), (1600.0, 900.0), (1400.0, 700.0)] {
            let rects = panel_rects(&mut app, w, h);
            assert_eq!(rects.len(), 5, "expected five widgets at {w}x{h}, got {rects:#?}");

            // Nothing is cut off: the lowest widget's bottom edge is one gap
            // above the window's, exactly as the left and right edges are.
            let bottom = rects.iter().map(|r| r.bottom()).fold(f32::MIN, f32::max);
            assert!(bottom <= h - GAP + 1.0, "bottom edge at {bottom}, window {h}");
            assert!(bottom >= h - GAP - 1.0, "dead space below the last row: {bottom} vs {h}");

            let left = rects.iter().map(|r| r.left()).fold(f32::MAX, f32::min);
            let right = rects.iter().map(|r| r.right()).fold(f32::MIN, f32::max);
            assert!((left - GAP).abs() <= 1.0, "left margin {left}");
            assert!((right - (w - GAP)).abs() <= 1.0, "right margin {}", w - right);

            // Rows: two bands, and the space between them is one gap.
            let mut tops: Vec<f32> = rects.iter().map(|r| r.top()).collect();
            tops.sort_by(f32::total_cmp);
            tops.dedup_by(|a, b| (*a - *b).abs() < 1.0);
            assert_eq!(tops.len(), 2, "expected two rows, tops {tops:?}");
            let row0_bottom = rects
                .iter()
                .filter(|r| (r.top() - tops[0]).abs() < 1.0)
                .map(|r| r.bottom())
                .fold(f32::MIN, f32::max);
            assert!(
                (tops[1] - row0_bottom - GAP).abs() <= 1.0,
                "row gap is {}, want {GAP}",
                tops[1] - row0_bottom
            );

            // Columns: the seam between two widgets in a row is the same gap.
            let mut row1: Vec<egui::Rect> = rects
                .iter()
                .filter(|r| (r.top() - tops[1]).abs() < 1.0)
                .copied()
                .collect();
            row1.sort_by(|a, b| a.left().total_cmp(&b.left()));
            assert_eq!(row1.len(), 3);
            for pair in row1.windows(2) {
                let seam = pair[1].left() - pair[0].right();
                assert!((seam - GAP).abs() <= 1.0, "widget seam is {seam}, want {GAP}");
            }

            // The view selector sits on the middle of its header strip, with
            // equal air above and below. Drawn top-down it hugged the upper
            // border instead, with all the slack beneath it.
            let selectors = selector_rects(&mut app, w, h);
            assert_eq!(selectors.len(), 5, "expected one selector per widget");
            for sel in &selectors {
                let panel = rects
                    .iter()
                    .find(|p| p.contains(sel.center()))
                    .unwrap_or_else(|| panic!("selector at {sel:?} is outside every widget"));
                let want = panel.top() + HEADER_H * 0.5;
                assert!(
                    (sel.center().y - want).abs() <= 1.5,
                    "selector centre {} vs header centre {want}",
                    sel.center().y
                );
                // ...and starts at the same content padding as the table below.
                assert!((sel.left() - panel.left() - PAD_X).abs() <= 1.0);
            }
        }
    }

    #[test]
    fn a_grid_too_big_for_the_window_wraps_and_scrolls_but_never_shrinks() {
        let mut app = app();
        app.traffic = Arc::new(populated());

        // 900 wide holds two widgets per band, so the three-widget row wraps and
        // the grid no longer fits: it scrolls, and what is drawn keeps its full
        // size rather than being squeezed to make everything fit at once.
        let rects = panel_rects(&mut app, 900.0, 620.0);
        assert!(rects.len() >= 4, "{} widgets drawn", rects.len());

        let mut by_row: Vec<(f32, f32)> = rects.iter().map(|r| (r.top(), r.height())).collect();
        by_row.sort_by(|a, b| a.0.total_cmp(&b.0));
        assert!(
            (by_row[0].1 - DEFAULT_TOP_H).abs() <= 1.0,
            "first row was scaled to {} instead of its stored {DEFAULT_TOP_H}",
            by_row[0].1
        );
        assert!((by_row.last().unwrap().1 - DEFAULT_ROW_H).abs() <= 1.0);

        // Wrapped or not, every widget still clears the legibility floor and the
        // gaps are the same one gap.
        assert!(rects.iter().all(|r| r.width() >= COL_MIN_W - 1.0));
        let mut top_row: Vec<egui::Rect> = rects
            .iter()
            .filter(|r| (r.top() - by_row[0].0).abs() < 1.0)
            .copied()
            .collect();
        top_row.sort_by(|a, b| a.left().total_cmp(&b.left()));
        assert_eq!(top_row.len(), 2, "expected two widgets per band at 900px");
        assert!((top_row[1].left() - top_row[0].right() - GAP).abs() <= 1.0);
    }

    #[test]
    fn every_view_renders_at_every_window_size() {
        let mut app = app();
        app.traffic = Arc::new(populated());

        // One row holding every view at once: the widest layout the app can be
        // asked to draw, so each size below also exercises the wrap path.
        app.rows = vec![Row {
            height: DEFAULT_ROW_H,
            widgets: View::ALL
                .iter()
                .enumerate()
                .map(|(i, v)| Widget::new(i as u64 + 1, *v))
                .collect(),
        }];

        // The minimum window the viewport allows, the default, and a wide one.
        for (w, h) in [(460.0, 380.0), (1280.0, 800.0), (2560.0, 1440.0), (340.0, 240.0)] {
            render_frame(&mut app, w, h);
        }
    }

    #[test]
    fn a_finished_probe_renders_its_answers() {
        let mut app = app();
        app.traffic = Arc::new(populated());
        app.status.dns = Some(Ipv4Addr::new(9, 9, 9, 9));
        app.rows = vec![Row {
            height: DEFAULT_ROW_H,
            widgets: vec![Widget::new(1, View::Probe)],
        }];

        // Both terminal states of a probe, plus the pristine one, must draw.
        render_frame(&mut app, 900.0, 400.0);
        app.rows[0].widgets[0].probe.last = Some(Err("no response from 9.9.9.9:53".into()));
        render_frame(&mut app, 900.0, 400.0);
        app.rows[0].widgets[0].probe.last = Some(Ok(probe::Outcome {
            question: "34.216.184.93.in-addr.arpa".into(),
            record: probe::RecordType::Ptr,
            server: "9.9.9.9:53".parse().unwrap(),
            transport: "udp",
            elapsed: Duration::from_millis(24),
            rcode: "NOERROR",
            authoritative: false,
            answers: vec![probe::Answer {
                name: "34.216.184.93.in-addr.arpa".into(),
                kind: "PTR".into(),
                ttl: 3600,
                data: "example.com".into(),
            }],
            note: None,
        }));
        render_frame(&mut app, 900.0, 400.0);
        // ...including in a widget too narrow for the whole answer table.
        render_frame(&mut app, 460.0, 380.0);

        // The resolver field seeds itself from the engine's pinned resolver, so
        // the probe asks what the rest of the host asks.
        assert_eq!(app.rows[0].widgets[0].probe.server, "9.9.9.9");
    }

    #[test]
    fn the_resolver_field_accepts_the_forms_an_operator_types() {
        assert_eq!(parse_server("9.9.9.9").unwrap(), "9.9.9.9:53".parse().unwrap());
        assert_eq!(parse_server(" 9.9.9.9:5353 ").unwrap(), "9.9.9.9:5353".parse().unwrap());
        assert_eq!(parse_server("[2606:4700:4700::1111]:53").unwrap().port(), 53);
        assert_eq!(parse_server("2606:4700:4700::1111").unwrap().port(), 53);
        // Empty falls back rather than failing: the field is a refinement, not
        // a requirement.
        assert_eq!(parse_server("").unwrap(), SocketAddr::from((FALLBACK_DNS, 53)));
        assert!(parse_server("dns.example.com").is_err());
    }
}
