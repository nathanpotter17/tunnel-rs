//! Live dashboard for the egress engine.

use eframe::egui::{self, Align, Color32, Layout, Rounding, Stroke, Vec2};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::inspect::TrafficSnapshot;
use crate::probe;
use crate::probe::clamp_to;
use crate::state::{Forward, Shared, Status};

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
/// Amber, for in-progress: neither settled nor wrong. Out of [`Theme`] with the
/// other two, because the difference between "working on it" and "broken" is
/// the one thing a colour scheme must not be able to flatten.
const WARN_AMBER: Color32 = Color32::from_rgb(225, 180, 90);

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
    action: ProbeAction,
    record: ProbeRecord,
    server: String,
    /// Whether the resolver field has been filled from the engine's pinned
    /// resolver. Once seeded, an operator's own entry is never overwritten.
    server_seeded: bool,
    port_mode: PortMode,
    /// Custom port specification, only read when `port_mode` is `Custom`.
    ports: String,
    job: Option<probe::Job>,
    last: Option<Result<probe::Outcome, String>>,
}

/// Newtypes so [`ProbeUi`] can derive `Default` without `probe`'s enums having
/// to pick defaults that only make sense to the UI.
struct ProbeRecord(probe::RecordType);
struct ProbeAction(probe::Action);

impl Default for ProbeRecord {
    fn default() -> Self {
        ProbeRecord(probe::RecordType::Auto)
    }
}

impl Default for ProbeAction {
    fn default() -> Self {
        ProbeAction(probe::Action::Nslookup)
    }
}

/// Which ports a scan covers.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum PortMode {
    /// The curated top-100 list. The default because it answers the question
    /// in a couple of seconds.
    #[default]
    Top,
    Custom,
}

impl PortMode {
    const ALL: [PortMode; 2] = [PortMode::Top, PortMode::Custom];

    fn label(self) -> &'static str {
        match self {
            PortMode::Top => "TOP 100",
            PortMode::Custom => "CUSTOM",
        }
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

/// A table's columns, the bounds on its flexible column, and its scroll salt.
///
/// Declared together at module level because a column set means nothing without
/// the flex bounds `fit` sizes it against — and because the layout tests then
/// measure the real table rather than a copy that drifts from it.
struct Table {
    cols: &'static [Col],
    /// Floor and ceiling for the single `width: 0` column.
    flex: (usize, usize),
    salt: &'static str,
}

const FLOWS: Table = Table {
    cols: &[
        Col::new("REMOTE", 0, false, 0),
        Col::new("APP", 11, false, 2),
        Col::new("L4", 5, false, 4),
        Col::new("RX", 8, true, 1),
        Col::new("TX", 8, true, 3),
        Col::new("RATE", 11, true, 0),
    ],
    flex: (14, 38),
    salt: "flows_scroll",
};

const HOSTS: Table = Table {
    cols: &[
        Col::new("HOST", 0, false, 0),
        Col::new("APP", 10, false, 2),
        Col::new("FL", 4, true, 3),
        Col::new("BYTES", 8, true, 1),
        Col::new("RATE", 10, true, 0),
    ],
    flex: (12, 34),
    salt: "hosts_scroll",
};

const SERVICES: Table = Table {
    cols: &[
        Col::new("PORT", 7, false, 0),
        Col::new("SERVICE", 0, false, 0),
        Col::new("L4", 5, false, 4),
        Col::new("FL", 4, true, 3),
        Col::new("BYTES", 8, true, 2),
        Col::new("RATE", 10, true, 1),
    ],
    flex: (8, 20),
    salt: "services_scroll",
};

/// The one table NOT drawn through [`table_pane`]: each row leads with a painted
/// swatch, which is not a character cell, so it shares only [`table_cells`].
const LEGEND: Table = Table {
    cols: &[
        Col::new("PROTOCOL", 0, false, 0),
        Col::new("SHARE", 8, true, 0),
        Col::new("BYTES", 9, true, 1),
    ],
    flex: (8, 22),
    salt: "proto_legend",
};

/// NAME is sized for a reverse-DNS name (`38.173.125.74.in-addr.arpa` is 26
/// characters, and PTR lookups are most of what this widget is pointed at), TYPE
/// for the longest record label, and TTL for a formatted duration. `DATA` is
/// capped below the general flexible maximum so that a wide cell spreads its
/// slack across the other three rather than pouring all of it into the answer.
const ANSWERS: Table = Table {
    cols: &[
        Col::new("NAME", 28, false, 2),
        Col::new("TYPE", 7, false, 1),
        Col::new("TTL", 8, true, 3),
        Col::new("DATA", 0, false, 0),
    ],
    flex: (16, 45),
    salt: "probe_scroll",
};

/// Scan results. SERVICE is sized for the longest name in `inspect`'s table
/// (`shadowsocks`, 11) plus the gutter; BANNER takes the rest, capped so a
/// chatty service does not push PORT and SERVICE into the left margin.
const SCAN: Table = Table {
    cols: &[
        Col::new("PORT", 7, false, 2),
        Col::new("SERVICE", 14, false, 1),
        Col::new("BANNER", 0, false, 0),
    ],
    flex: (10, 60),
    salt: "scan_scroll",
};

/// The intel dossier. FIELD holds the longest label (`ALLOCATED`, 9) plus the
/// gutter; VALUE is sized for an org name, which is the long one.
const INTEL: Table = Table {
    cols: &[Col::new("FIELD", 11, false, 1), Col::new("VALUE", 0, false, 0)],
    flex: (16, 64),
    salt: "intel_scroll",
};

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
        format!("{:>inner$}{}", clamp_to(s, inner), " ".repeat(blanks), inner = inner)
    } else {
        format!("{:<width$}", clamp_to(s, inner), width = width)
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

/// Emit one row of padded cells into the CURRENT horizontal layout. Split from
/// [`table_row`] so the legend can prepend its colour swatch — which is not a
/// character cell — and still lay the rest of the row out by these rules.
/// `cell` is asked only for the columns that survived `fit`.
fn table_cells(ui: &mut egui::Ui, plan: &[Col], cell: impl Fn(&str) -> (String, Color32)) {
    for (i, c) in plan.iter().enumerate() {
        let (text, color) = cell(c.title);
        mono_cell(ui, pad(&text, c.width, c.right, gutter(c, plan.get(i + 1))), color);
    }
}

/// One row on its own baseline, zero item spacing — the characters are the layout.
fn table_row(ui: &mut egui::Ui, plan: &[Col], cell: impl Fn(&str) -> (String, Color32)) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        table_cells(ui, plan, cell);
    });
}

fn table_header(ui: &mut egui::Ui, plan: &[Col], theme: &Theme) {
    table_row(ui, plan, |title| (title.to_string(), theme.text_muted));
    header_rule(ui, theme);
}

/// Fit `spec` to the cell, draw its header, scroll its rows — the shape every
/// table in this window has.
///
/// `rows` is consumed lazily, so callers keep handing borrows into the shared
/// snapshot and nothing is collected or cloned on their behalf; emptiness is
/// peeked rather than counted, because a filter asked for its length walks
/// twice. Generic, not `dyn`: this runs once per widget per frame.
fn table_pane<I>(
    ui: &mut egui::Ui,
    spec: &Table,
    wid: u64,
    empty: &str,
    theme: &Theme,
    rows: I,
    cell: impl Fn(&I::Item, &str) -> (String, Color32),
) where
    I: IntoIterator,
{
    let plan = fit(spec.cols, char_budget(ui), spec.flex.0, spec.flex.1);
    table_header(ui, &plan, theme);

    let mut rows = rows.into_iter().peekable();
    if rows.peek().is_none() {
        empty_note(ui, empty, theme);
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt((spec.salt, wid))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for row in rows {
                table_row(ui, &plan, |title| cell(&row, title));
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
            concat!("Tunnel-RS ", env!("CARGO_PKG_VERSION")),
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
    let x = snap(ui, rect.center().x);
    ui.painter()
        .vline(x, rect.y_range(), Stroke::new(1.0, color));
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
        let y = snap(ui, rect.center().y);
        ui.painter()
            .hline(rect.x_range(), y, Stroke::new(1.0, theme.accent_hover));
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
                    let rule_y = snap(ui, rule.top());
                    ui.painter()
                        .hline(rule.x_range(), rule_y, Stroke::new(1.0, theme.border));

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

/// A combo box over a closed set of labelled variants — every selector here.
///
/// Options and labelling are passed in rather than demanded through a trait: all
/// five enums already carry an inherent `ALL` and `label()`, and two of them live
/// in `probe`, which has no business knowing what a selector is. `selected` is
/// caller-built because the closed text is deliberately not uniform — the view
/// selector is a widget title, the rest are subordinate controls.
fn enum_combo<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash,
    current: &mut T,
    options: &[T],
    label: impl Fn(T) -> &'static str,
    selected: egui::RichText,
    width: f32,
) -> egui::Response {
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected)
        .width(width)
        .show_ui(ui, |ui| {
            // No colour: options inherit the style override, which is what makes
            // the open list read as primary against the muted closed state.
            for option in options {
                ui.selectable_value(current, *option, mono(label(*option), MONO_PT));
            }
        })
        .response
}

fn view_selector(ui: &mut egui::Ui, wid: u64, kind: &mut View, theme: &Theme) {
    let selected = mono(kind.label(), MONO_PT).color(theme.text_muted).strong();
    enum_combo(ui, ("view", wid), kind, &View::ALL, View::label, selected, 118.0);
}

fn render_header(ui: &mut egui::Ui, status: &Status, traffic: &TrafficSnapshot, theme: &Theme) {
    ui.horizontal(|ui| {
        ui.label(mono("Tunnel-RS", 13.0).color(theme.text_primary).strong());

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

        mono_cell(ui, connstat.to_string(), status_color);
        mono_cell(ui, status_text.to_string(), status_color);

        if let Some(err) = &status.last_error {
            ui.add_space(GAP);
            ui.label(mono(clamp_to(err, 96), MONO_PT).color(ERROR_RED))
                .on_hover_text(err);
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(started) = status.started_at {
                mono_cell(ui, format_duration(started.elapsed()), theme.text_muted);
            }

            // Four states, because each asks something different of the operator
            // and only one of them is a fault:
            //
            //   FWD REQ     amber  — negotiating; nothing to do but wait
            //   FWD ERR     red    — gave up; the hover says what to fix
            //   FWD :P IDLE muted  — leased, but nothing has arrived on it
            //   FWD :P n    white  — leased and carrying inbound
            //
            // REQ exists because a lease takes seconds to negotiate and the
            // first attempt races the WireGuard handshake. Painting that red
            // reported a failure on every startup that then resolved itself.
            //
            // IDLE stays muted for the mirror-image reason: a port nobody has
            // dialled yet looks exactly like one that forwards nothing, and
            // calling that an error would cry wolf on every quiet start.
            if let Some(forward) = &status.forward {
                let live = status.forwarded_in > 0;
                let (text, colour, hover) = match forward {
                    Forward::Requesting(what) => (
                        "FWD REQ".to_string(),
                        WARN_AMBER,
                        what.clone(),
                    ),
                    Forward::Failed(why) => ("FWD ERR".to_string(), ERROR_RED, why.clone()),
                    Forward::Open(port) if live => (
                        format!("FWD :{port} {}", status.forwarded_in),
                        theme.text_primary,
                        "inbound packets accepted on the forwarded port".to_string(),
                    ),
                    Forward::Open(port) => (
                        format!("FWD :{port} IDLE"),
                        theme.text_muted,
                        "the port is leased but nothing has arrived on it — check the \
                         application listens on this exact port, and that the firewall \
                         permits inbound on the tunnel adapter"
                            .to_string(),
                    ),
                };
                ui.add_space(GAP * 2.0);
                ui.label(mono(text, MONO_PT).color(colour)).on_hover_text(hover);
            }

            let total = traffic.total_up + traffic.total_down;
            if total > 0 {
                ui.add_space(GAP * 2.0);
                mono_cell(ui, format_bytes(total), theme.text_secondary);
            }

            // The exit descriptor is long and least critical, so it sits between
            // the two anchored groups and is the first thing squeezed out.
            if status.running && !status.exit.is_empty() {
                ui.add_space(GAP * 2.0);
                mono_cell(ui, clamp_to(&status.exit, 42), theme.text_muted);
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
        let y = snap(ui, rect.bottom() - frac * (rect.height() - 4.0) - 2.0);
        painter.hline(rect.x_range(), y, Stroke::new(1.0, with_alpha(theme.border, 90)));
    }

    let plot = |series: &[f64], color: Color32, fill: bool| {
        if series.len() < 2 {
            return;
        }
        let n = series.len();
        let dx = rect.width() / (n - 1) as f32;
        let pts: Vec<egui::Pos2> = series
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let x = rect.left() + dx * i as f32;
                let y = rect.bottom() - (v / max) as f32 * (rect.height() - 4.0) - 2.0;
                egui::pos2(x, y)
            })
            .collect();

        // The area under the trace, as one mesh: a quad per sample interval,
        // its top edge the trace itself. Filling it with a translucent bar per
        // sample instead put a feathered edge every few pixels, and a hundred
        // of those printed a comb of vertical stripes across the whole chart —
        // and the bars were flat-topped, so the fill and the line they were
        // meant to sit under disagreed wherever the rate was moving.
        if fill {
            let mut mesh = egui::Mesh::default();
            let tint = with_alpha(color, 40);
            for w in pts.windows(2) {
                let floor = rect.bottom();
                mesh_quad(
                    &mut mesh,
                    w[0],
                    w[1],
                    egui::pos2(w[1].x, floor),
                    egui::pos2(w[0].x, floor),
                    tint,
                );
            }
            painter.add(egui::Shape::mesh(mesh));
        }
        // One path, not a segment per sample. Segments drawn one at a time are
        // each feathered to their own ends, so every joint is a double-painted
        // bead and a 1.5px trace reads as a string of them.
        painter.add(egui::Shape::line(pts, Stroke::new(1.5, color)));
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
        let selected = mono(state.sort.label(), 9.0).color(theme.text_muted);
        enum_combo(
            ui,
            ("flow_sort", wid),
            &mut state.sort,
            &Sort::ALL,
            Sort::label,
            selected,
            62.0,
        );
        // The caption is the checkbox's own label, not a neighbouring one, so
        // the words are part of the click target instead of a 12px box being
        // the only way to hit it. Dropped when narrow, as before.
        let live_label = if wide { "live only" } else { "" };
        ui.checkbox(&mut state.hide_idle, mono(live_label, 9.0).color(theme.text_muted));
    });
    ui.add_space(ROW_GAP);

    render_flows(ui, wid, traffic, state, theme);
}

fn render_flows(
    ui: &mut egui::Ui,
    wid: u64,
    traffic: &TrafficSnapshot,
    state: &FlowUi,
    theme: &Theme,
) {
    // Filter and sort by reference — the snapshot is shared, so the view is a
    // vector of borrows, never a clone of the rows.
    let needle = state.filter.to_lowercase();
    let mut rows: Vec<&crate::inspect::FlowRow> = traffic
        .flows
        .iter()
        .filter(|f| !state.hide_idle || f.idle_ms <= 5000)
        .filter(|f| {
            needle.is_empty()
                || f.remote.to_lowercase().contains(&needle)
                || f.app.to_lowercase().contains(&needle)
                || f.proto.to_lowercase().contains(&needle)
        })
        .collect();

    match state.sort {
        // `flows` arrives byte-sorted, so this branch is already ordered.
        Sort::Bytes => {}
        Sort::Rate => rows.sort_by(|a, b| b.rate.total_cmp(&a.rate)),
        Sort::Recent => rows.sort_by_key(|f| f.idle_ms),
    }

    let empty = if traffic.flows.is_empty() {
        "no traffic yet"
    } else {
        "no flows match the filter"
    };

    table_pane(ui, &FLOWS, wid, empty, theme, rows, |f, title| {
        // Shed / reaped rows are deliberate admission-control actions, not live
        // conversations — render the whole row muted and swap the rate cell for
        // a status badge so they don't read as anomalous up-only or half-open
        // flows.
        let tagged = !f.status.is_empty();
        let base = if tagged || f.idle_ms > 5000 {
            theme.text_muted
        } else {
            theme.text_secondary
        };
        match title {
            "REMOTE" => (f.remote.clone(), base),
            "APP" => (
                f.app.to_string(),
                if tagged { theme.text_muted } else { proto_color(f.app, theme) },
            ),
            "L4" => (f.proto.to_string(), theme.text_muted),
            "RX" => (format_bytes_short(f.down), base),
            "TX" => (format_bytes_short(f.up), base),
            _ if tagged => (f.status.to_string(), theme.text_muted),
            _ => rate_cell(f.rate, theme),
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
        } else if let Some(partial) = job.snapshot() {
            // A scan republishes after every port, so the table fills in as the
            // sweep runs instead of appearing all at once ten seconds later.
            p.last = Some(partial);
        }
    }

    let busy = p.job.is_some();
    let wide = ui.available_width() >= 420.0;
    let mut go = false;

    // Both control rows are laid out from one total, so their edges line up with
    // each other and with the table below whichever action is selected — the
    // fixed-width controls anchor the ends and the text field takes the slack.
    //
    //   row 1            [ target ........................ ][ ACTIVE ▼ ]
    //   row 2  LOOKUP    [ ACTION ▼ ][ AUTO ▼ ][ resolver .. ][ RUN ]
    //          SCAN      [ ACTION ▼ ][ TOP 100 ▼ ][ ports ... ][ RUN ]
    //          INTEL     [ ACTION ▼ ][ resolver ............ ][ RUN ]
    //
    // Sized in absolute terms rather than by letting each widget claim what it
    // wants, which is what left the two rows ragged against one another.
    let action = p.action.0;
    let has_sub = !matches!(action, probe::Action::Intel);
    let full_w = ui.available_width();
    let combo_w = 76.0;
    let button_w = 62.0;
    let target_w = (full_w - combo_w - GAP).max(60.0);
    let selectors = if has_sub { 2.0 } else { 1.0 };
    let field_w =
        (full_w - selectors * (combo_w + GAP) - button_w - GAP).max(60.0);
    // Narrow: the free-text field goes and the selectors plus the button are the
    // whole row, with the target field spanning the width above them.
    let field_w = if wide { Some(field_w) } else { None };

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        let entry = text_field(ui, &mut p.target, target_w, "host or address");
        if entry.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            go = true;
        }

        // Not an `enum_combo`: session data, not a closed variant set.
        egui::ComboBox::from_id_salt(("probe_host", wid))
            .selected_text(mono("ACTIVE", 9.0).color(theme.text_muted))
            .width(combo_w)
            .show_ui(ui, |ui| {
                if traffic.hosts.is_empty() {
                    ui.label(mono("no active hosts", MONO_PT).color(theme.text_muted));
                }
                for h in &traffic.hosts {
                    let line = format!(
                        "{:<22}{:>9} {}",
                        clamp_to(&h.ip, 22),
                        format_bytes_short(h.up + h.down),
                        h.app
                    );
                    if ui
                        .selectable_label(p.target == h.ip, mono(line, MONO_PT))
                        .clicked()
                    {
                        p.target = h.ip.clone();
                    }
                }
            });
    });

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;

        let selected = mono(action.label(), 9.0).color(theme.text_secondary);
        enum_combo(
            ui,
            ("probe_action", wid),
            &mut p.action.0,
            &probe::Action::ALL,
            probe::Action::label,
            selected,
            combo_w,
        )
        .on_hover_text("a DNS lookup, a TCP port scan, or who owns the address");

        match action {
            probe::Action::Nslookup => {
                let selected = mono(p.record.0.label(), 9.0).color(theme.text_muted);
                enum_combo(
                    ui,
                    ("probe_type", wid),
                    &mut p.record.0,
                    &probe::RecordType::ALL,
                    probe::RecordType::label,
                    selected,
                    combo_w,
                );
            }
            probe::Action::PortScan => {
                let selected = mono(p.port_mode.label(), 9.0).color(theme.text_muted);
                enum_combo(
                    ui,
                    ("probe_ports", wid),
                    &mut p.port_mode,
                    &PortMode::ALL,
                    PortMode::label,
                    selected,
                    combo_w,
                );
            }
            probe::Action::Intel => {}
        }

        if let Some(w) = field_w {
            match (action, p.port_mode) {
                (probe::Action::PortScan, PortMode::Custom) => {
                    text_field(ui, &mut p.ports, w, "22,80,443,8000-8100").on_hover_text(
                        format!("ports and ranges, at most {} per scan", probe::MAX_SCAN_PORTS),
                    );
                }
                (probe::Action::PortScan, PortMode::Top) => {
                    // The list is fixed, so the row keeps its shape with a
                    // statement of what will be swept rather than a dead field.
                    mono_cell(
                        ui,
                        format!("{} well-known ports", probe::TOP_PORTS.len()),
                        theme.text_muted,
                    );
                }
                _ => {
                    let edit = text_field(ui, &mut p.server, w, "resolver").on_hover_text(
                        "nameserver to ask; defaults to the resolver the tunnel pinned",
                    );
                    // An entry typed before the engine published its resolver is
                    // still the operator's choice: seeding must not come along
                    // later and overwrite it.
                    if edit.changed() {
                        p.server_seeded = true;
                    }
                }
            }
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui
                .add_enabled(
                    !busy,
                    egui::Button::new(mono(if busy { "…" } else { "RUN" }, MONO_PT))
                        .min_size(Vec2::new(button_w, 0.0)),
                )
                .clicked()
            {
                go = true;
            }
        });
    });

    if go && !busy {
        match build_request(p) {
            Ok(req) => {
                p.last = None;
                p.job = Some(probe::spawn(req));
            }
            Err(e) => p.last = Some(Err(e)),
        }
    }

    ui.add_space(ROW_GAP);
    probe_status(ui, p, theme);

    match &p.last {
        Some(Ok(probe::Outcome::Dns(o))) => probe_answers(ui, wid, o, theme),
        Some(Ok(probe::Outcome::Scan(o))) => scan_results(ui, wid, o, theme),
        Some(Ok(probe::Outcome::Intel(o))) => intel_results(ui, wid, o, theme),
        _ => {}
    }
}

/// Turn the widget's controls into a request, or say why it cannot.
///
/// The port list is parsed HERE rather than in the worker, so a bad
/// specification is a message under the controls instead of a thread that
/// starts and immediately fails — and so `MAX_SCAN_PORTS` is enforced before
/// anything opens a socket.
fn build_request(p: &ProbeUi) -> Result<probe::Request, String> {
    let ports = match (p.action.0, p.port_mode) {
        (probe::Action::PortScan, PortMode::Top) => probe::TOP_PORTS.to_vec(),
        (probe::Action::PortScan, PortMode::Custom) => probe::parse_ports(&p.ports)?,
        _ => Vec::new(),
    };
    Ok(probe::Request {
        action: p.action.0,
        target: p.target.clone(),
        record: p.record.0,
        server: parse_server(&p.server)?,
        timeout: probe::DEFAULT_TIMEOUT,
        ports,
    })
}

/// One or two compact lines saying what happened, above the results.
fn probe_status(ui: &mut egui::Ui, p: &ProbeUi, theme: &Theme) {
    // A scan publishes its own progress, so the generic pending line would only
    // repeat what the line below already says, less precisely.
    let scanning = matches!(&p.last, Some(Ok(probe::Outcome::Scan(_))));
    if let Some(job) = &p.job {
        if !scanning {
            mono_cell(
                ui,
                format!("… {} ({:.1}s)", job.summary, job.elapsed().as_secs_f32()),
                theme.text_secondary,
            );
            return;
        }
    }
    match &p.last {
        None => mono_cell(
            ui,
            "pick a host or type a name, then RUN".to_string(),
            theme.text_muted,
        ),
        Some(Err(e)) => {
            ui.label(mono(clamp_to(e, 220), MONO_PT).color(ERROR_RED))
                .on_hover_text(e);
        }
        Some(Ok(probe::Outcome::Scan(o))) => scan_status(ui, o, theme),
        Some(Ok(probe::Outcome::Intel(o))) => intel_status(ui, o, theme),
        Some(Ok(probe::Outcome::Dns(o))) => {
            let ok = o.rcode == "NOERROR" && !o.answers.is_empty();
            status_line(
                ui,
                o.rcode,
                if ok { OK_GREEN } else { ERROR_RED },
                format!(
                    "{:>3} ans  {:>5} ms  {}{}",
                    o.answers.len(),
                    o.elapsed.as_millis(),
                    o.transport,
                    if o.authoritative { "  auth" } else { "" }
                ),
                theme,
            );
            caption(
                ui,
                &format!("{} {} @ {}", o.record.label(), o.question, o.server),
                theme,
            );
            if let Some(note) = &o.note {
                caption(ui, note, theme).on_hover_text(note);
            }
        }
    }
}

/// Progress and totals for a scan. Rendered while it runs as well as after, so
/// the counts are the pending indicator.
fn scan_status(ui: &mut egui::Ui, o: &probe::ScanOutcome, theme: &Theme) {
    status_line(
        ui,
        &format!("{} OPEN", o.open.len()),
        if o.open.is_empty() { theme.text_secondary } else { OK_GREEN },
        format!(
            "{:>4}/{:<5} {:>5} ms  {} closed  {} filtered",
            o.done,
            o.total,
            o.elapsed.as_millis(),
            o.closed,
            o.filtered
        ),
        theme,
    );
    caption(
        ui,
        &format!(
            "{} {}",
            o.target,
            if o.complete() { "scan complete" } else { "scanning…" }
        ),
        theme,
    );
}

fn intel_status(ui: &mut egui::Ui, o: &probe::IntelOutcome, theme: &Theme) {
    let asn = o.asn.map(|n| format!("AS{n}"));
    status_line(
        ui,
        asn.as_deref().unwrap_or("NO ASN"),
        if asn.is_some() { OK_GREEN } else { ERROR_RED },
        format!("{:>5} ms  {}", o.elapsed.as_millis(), o.target),
        theme,
    );
    if let Some(note) = &o.note {
        caption(ui, note, theme).on_hover_text(note);
    }
}

/// Open ports. Closed and filtered are counted in the status line rather than
/// listed: a hundred rows saying "nothing here" is not a finding.
fn scan_results(ui: &mut egui::Ui, wid: u64, o: &probe::ScanOutcome, theme: &Theme) {
    ui.add_space(ROW_GAP);
    let empty = if o.complete() { "no open ports found" } else { "scanning…" };
    table_pane(ui, &SCAN, wid, empty, theme, &o.open, |r, title| match title {
        "PORT" => (r.port.to_string(), theme.text_primary),
        "SERVICE" => (r.service.to_string(), theme.text_secondary),
        _ => match &r.banner {
            Some(b) => (b.clone(), theme.text_muted),
            None => ("—".to_string(), theme.text_muted),
        },
    });
}

/// The dossier. Only fields that came back are listed — an absent ASN is a
/// missing row, not an empty one, so the panel never pads itself with unknowns.
fn intel_results(ui: &mut egui::Ui, wid: u64, o: &probe::IntelOutcome, theme: &Theme) {
    ui.add_space(ROW_GAP);

    let mut rows: Vec<(&str, String)> = vec![("ADDRESS", o.target.clone())];
    for (field, value) in [
        ("PTR", o.ptr.clone()),
        ("ASN", o.asn.map(|n| format!("AS{n}"))),
        ("ORG", o.org.clone()),
        ("PREFIX", o.prefix.clone()),
        ("COUNTRY", o.country.clone()),
        ("REGISTRY", o.registry.clone()),
        ("ALLOCATED", o.allocated.clone()),
    ] {
        if let Some(v) = value {
            rows.push((field, v));
        }
    }

    // The empty branch is unreachable: ADDRESS is always a row.
    table_pane(ui, &INTEL, wid, "", theme, rows, |(field, value), title| {
        match title {
            "FIELD" => ((*field).to_string(), theme.text_muted),
            _ => (value.clone(), theme.text_primary),
        }
    });
}

fn probe_answers(ui: &mut egui::Ui, wid: u64, outcome: &probe::DnsOutcome, theme: &Theme) {
    ui.add_space(ROW_GAP);
    table_pane(
        ui,
        &ANSWERS,
        wid,
        "no records in the answer section",
        theme,
        &outcome.answers,
        |a, title| match title {
            "NAME" => (a.name.clone(), theme.text_muted),
            "TYPE" => (a.kind.clone(), theme.text_secondary),
            "TTL" => (format_ttl(a.ttl), theme.text_muted),
            _ => (a.data.clone(), theme.text_primary),
        },
    );
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
    // Three characters are reserved for the colour swatch and its gap.
    const SWATCH: usize = 3;
    let budget = char_budget(ui).saturating_sub(SWATCH);
    let plan = fit(LEGEND.cols, budget, LEGEND.flex.0, LEGEND.flex.1);

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        mono_cell(ui, " ".repeat(SWATCH), theme.text_muted);
        table_cells(ui, &plan, |title| (title.to_string(), theme.text_muted));
    });
    header_rule(ui, theme);

    egui::ScrollArea::vertical()
        .id_salt((LEGEND.salt, wid))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for a in traffic.apps.iter().filter(|a| a.bytes > 0) {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let (sq, _) = ui.allocate_exact_size(Vec2::new(9.0, 9.0), egui::Sense::hover());
                    ui.painter()
                        .rect_filled(sq, Rounding::ZERO, proto_color(a.name, theme));
                    mono_cell(ui, " ".to_string(), theme.text_muted);
                    table_cells(ui, &plan, |title| match title {
                        "PROTOCOL" => (a.name.to_string(), theme.text_secondary),
                        "SHARE" => (
                            format!("{:.1}%", a.bytes as f64 * 100.0 / total as f64),
                            theme.text_primary,
                        ),
                        _ => (format_bytes_short(a.bytes), theme.text_muted),
                    });
                });
            }
        });
}

/// Donut: one mesh, walked once around the ring.
///
/// The ring is emitted as a strip of quads and nothing is ever painted on top of
/// anything else, which is the whole point. Painting sectors as separate shapes
/// cannot avoid seams: egui antialiases each shape by feathering its outline, so
/// two shapes sharing an edge each fade out across it and whatever is behind
/// them shows through as a hairline. Inside one mesh, neighbouring quads share
/// an exact edge and the rasteriser closes it — so a slice may start and end
/// anywhere, at any width, with no seam and no ordering rules.
///
/// Antialiasing is then done by the mesh itself: [`ring_band`] fades the inner
/// and outer rims to transparent, which also means the hole is a real hole
/// rather than a disc in the panel colour painted back over the middle.
fn draw_donut(ui: &mut egui::Ui, traffic: &TrafficSnapshot, total: u64, dia: f32, theme: &Theme) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(dia, dia), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let c = rect.center();
    let r_out = dia * 0.5 - 2.0;
    if r_out <= 6.0 || total == 0 {
        return;
    }
    let r_in = r_out * 0.58;
    // One physical pixel, which is what egui feathers its own shapes by. Fixing
    // it in points instead would blur the rims at the 125% and 150% desktop
    // scales, where a point is not a pixel. Capped at half the ring so the two
    // fades cannot cross over each other on a small donut.
    let rim = (1.0 / ui.ctx().pixels_per_point()).min((r_out - r_in) * 0.5);

    let mut mesh = egui::Mesh::default();
    // Angles come from a running byte total rather than from accumulated
    // sweeps, so the last slice ends on exactly one turn and the ring closes.
    let start = -std::f32::consts::FRAC_PI_2;
    let angle_at = |bytes: u64| start + bytes as f32 / total as f32 * std::f32::consts::TAU;
    let mut done: u64 = 0;

    for a in traffic.apps.iter().filter(|a| a.bytes > 0) {
        let (a0, a1) = (angle_at(done), angle_at(done + a.bytes));
        let color = proto_color(a.name, theme);
        // One quad per ~3 degrees, so the rim reads as a curve; at least one, so
        // a slice too thin to subdivide is still drawn.
        let bands = (((a1 - a0) / 0.052).ceil() as usize).max(1);
        for k in 0..bands {
            let lerp = |i: usize| a0 + (a1 - a0) * (i as f32 / bands as f32);
            ring_band(&mut mesh, c, r_in, r_out, rim, lerp(k), lerp(k + 1), color);
        }
        done += a.bytes;
    }

    painter.add(egui::Shape::mesh(mesh));
    painter.text(
        c,
        egui::Align2::CENTER_CENTER,
        format_bytes_short(total),
        egui::FontId::monospace(MONO_PT),
        theme.text_primary,
    );
}

/// Append one flat-coloured quad of the ring, spanning `a0` to `a1`.
///
/// Four radii per edge, not two: the innermost and outermost are the same colour
/// at zero alpha, so the rims fade over `rim` instead of stepping. The fade is
/// part of the geometry, which is what keeps the band free of an antialiased
/// outline of its own — see [`draw_donut`].
#[allow(clippy::too_many_arguments)]
fn ring_band(
    mesh: &mut egui::Mesh,
    c: egui::Pos2,
    r_in: f32,
    r_out: f32,
    rim: f32,
    a0: f32,
    a1: f32,
    color: Color32,
) {
    let stops = [
        (r_in, Color32::TRANSPARENT),
        (r_in + rim, color),
        (r_out - rim, color),
        (r_out, Color32::TRANSPARENT),
    ];
    let base = mesh.vertices.len() as u32;
    for angle in [a0, a1] {
        let (sin, cos) = angle.sin_cos();
        for (r, col) in stops {
            mesh.colored_vertex(c + Vec2::new(cos * r, sin * r), col);
        }
    }
    // Three quads stacked across the band: fade in, body, fade out.
    for k in 0..3 {
        mesh.add_triangle(base + k, base + k + 1, base + 4 + k);
        mesh.add_triangle(base + k + 1, base + 5 + k, base + 4 + k);
    }
}

/// Unique remote hosts: every conversation with one address on one row.
fn render_hosts(ui: &mut egui::Ui, wid: u64, traffic: &TrafficSnapshot, theme: &Theme) {
    table_pane(
        ui,
        &HOSTS,
        wid,
        "no remote hosts yet",
        theme,
        &traffic.hosts,
        |h, title| {
            let base = if h.idle_ms > 5000 {
                theme.text_muted
            } else {
                theme.text_secondary
            };
            match title {
                "HOST" => (h.ip.clone(), base),
                "APP" => (h.app.to_string(), proto_color(h.app, theme)),
                "FL" => (h.flows.to_string(), theme.text_muted),
                "BYTES" => (format_bytes_short(h.up + h.down), base),
                _ => rate_cell(h.rate, theme),
            }
        },
    );
}

/// Remote service ports: what this host is actually talking to, by destination.
fn render_services(ui: &mut egui::Ui, wid: u64, traffic: &TrafficSnapshot, theme: &Theme) {
    table_pane(
        ui,
        &SERVICES,
        wid,
        "no services yet",
        theme,
        &traffic.ports,
        |p, title| match title {
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
            _ => rate_cell(p.rate, theme),
        },
    );
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
    // Square, like the per-protocol tracks below it. Rounded, the stack's own
    // square ends sat proud of the track's corners.
    painter.rect_filled(bar, Rounding::ZERO, theme.surface_hover);

    // Same two rules as the donut, for the same two reasons: edges come from a
    // running byte total so the last segment lands exactly on the right edge
    // rather than wherever the accumulated widths drifted to, and the segments
    // go in one mesh so no seam between them can show the track behind.
    let mut mesh = egui::Mesh::default();
    let x_at = |bytes: u64| bar.left() + bytes as f32 / total as f32 * bar.width();
    let mut done: u64 = 0;
    for a in traffic.apps.iter().filter(|a| a.bytes > 0) {
        let (x0, x1) = (x_at(done), x_at(done + a.bytes));
        mesh_quad(
            &mut mesh,
            egui::pos2(x0, bar.top()),
            egui::pos2(x1, bar.top()),
            egui::pos2(x1, bar.bottom()),
            egui::pos2(x0, bar.bottom()),
            proto_color(a.name, theme),
        );
        done += a.bytes;
    }
    painter.add(egui::Shape::mesh(mesh));

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
    let y = snap(ui, rect.top());
    ui.painter()
        .hline(rect.x_range(), y, Stroke::new(1.0, theme.border));
    ui.add_space(ROW_GAP);
}

fn empty_note(ui: &mut egui::Ui, text: &str, theme: &Theme) {
    ui.vertical_centered(|ui| {
        ui.add_space(GAP);
        ui.label(mono(text, MONO_PT).color(theme.text_muted));
    });
}

fn stat_row(ui: &mut egui::Ui, label: &str, value: &str, value_color: Color32, theme: &Theme) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        mono_cell(ui, format!("{label:<8}"), theme.text_muted);
        ui.label(mono(value, MONO_PT).color(value_color).strong());
    });
}

/// The line above a probe's results: a nine-character verdict badge, then the
/// measurements. All three actions publish it, so the measurements stay put when
/// the action changes.
fn status_line(ui: &mut egui::Ui, badge: &str, badge_color: Color32, detail: String, theme: &Theme) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        mono_cell(ui, format!("{badge:<9}"), badge_color);
        mono_cell(ui, detail, theme.text_secondary);
    });
}

/// The muted line beneath a status row, clamped to what the widest widget shows
/// without wrapping. Returns the response so a caller can hang hover text on it.
fn caption(ui: &mut egui::Ui, text: &str, theme: &Theme) -> egui::Response {
    ui.label(mono(clamp_to(text, 120), 9.0).color(theme.text_muted))
}

/// Primary while the rate is moving, muted once it stops. Three tables, one answer.
fn rate_cell(rate: f64, theme: &Theme) -> (String, Color32) {
    let color = if rate > 0.0 { theme.text_primary } else { theme.text_muted };
    (format_rate(rate), color)
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

/// Append one flat-coloured quad, corners in order around the edge.
///
/// The reason anything in this file builds a mesh by hand is that quads in one
/// mesh share their edges exactly, so neighbours butt together with nothing
/// between them. Drawn as separate shapes they would each be feathered, and two
/// feathered edges over each other print a hairline of whatever is behind —
/// see [`draw_donut`], where that artefact is at its most visible.
fn mesh_quad(
    mesh: &mut egui::Mesh,
    a: egui::Pos2,
    b: egui::Pos2,
    c: egui::Pos2,
    d: egui::Pos2,
    color: Color32,
) {
    let base = mesh.vertices.len() as u32;
    for p in [a, b, c, d] {
        mesh.colored_vertex(p, color);
    }
    mesh.add_triangle(base, base + 1, base + 2);
    mesh.add_triangle(base, base + 2, base + 3);
}

/// Put a hairline on the pixel grid.
///
/// A 1px stroke at a fractional coordinate is spread across two rows of pixels
/// at partial coverage each, so it draws as a soft grey band instead of a rule.
/// egui hands out fractional coordinates all the time — a stretched row height
/// divided among bands rarely lands on an integer — and this window is mostly
/// rules, so they are worth snapping to a pixel centre.
fn snap(ui: &egui::Ui, v: f32) -> f32 {
    let ppp = ui.ctx().pixels_per_point();
    ((v * ppp).round() + 0.5) / ppp
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

/// The one place a `RichText` is given its family, so a cell and the hover text
/// beside it cannot drift apart. Colour and weight are chained on by the caller.
fn mono(text: impl Into<String>, size: f32) -> egui::RichText {
    egui::RichText::new(text).size(size).monospace()
}

fn mono_cell(ui: &mut egui::Ui, text: String, color: Color32) {
    ui.label(mono(text, MONO_PT).color(color));
}

/// The binary byte ladder, `suffix` glued to the unit: `""` for a quantity,
/// `"/s"` for a rate. One ladder, because a header reading `1.2 MB` beside a row
/// reading `1180 KB/s` for the same number is a discrepancy someone must resolve.
fn format_scaled(v: f64, suffix: &str) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    if v >= GB {
        format!("{:.2} GB{suffix}", v / GB)
    } else if v >= MB {
        format!("{:.2} MB{suffix}", v / MB)
    } else if v >= KB {
        format!("{:.1} KB{suffix}", v / KB)
    } else {
        format!("{v:.0} B{suffix}")
    }
}

fn format_rate(bps: f64) -> String {
    format_scaled(bps, "/s")
}

fn format_bytes(bytes: u64) -> String {
    format_scaled(bytes as f64, "")
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

    /// Fit a table by its own declared bounds — the same call `table_pane` makes,
    /// so what the tests measure is what the window draws.
    fn plan_of(t: &Table, budget: usize) -> Vec<Col> {
        fit(t.cols, budget, t.flex.0, t.flex.1)
    }

    fn titles(plan: &[Col]) -> Vec<&'static str> {
        plan.iter().map(|c| c.title).collect()
    }

    fn at(budget: usize) -> Vec<&'static str> {
        titles(&fit(FLOWS.cols, budget, 14, 30))
    }

    #[test]
    fn wide_budget_keeps_every_column_and_widens_the_flexible_one() {
        assert_eq!(at(80), ["REMOTE", "APP", "L4", "RX", "TX", "RATE"]);
        // 43 fixed characters; REMOTE takes the slack first, up to its cap.
        assert_eq!(plan_of(&FLOWS, 60)[0].width, 17);
        assert_eq!(plan_of(&FLOWS, 80)[0].width, 37);
    }

    #[test]
    fn slack_beyond_the_flexible_cap_is_spread_so_rows_fill_the_cell() {
        // A very wide panel: REMOTE saturates at its 38-character cap and the
        // remaining 129 characters are shared among the OTHERS, so the row spans
        // the full width without one enormous gap after the address.
        let plan = plan_of(&FLOWS, 210);
        assert_eq!(plan.len(), 6);
        assert_eq!(plan.iter().map(|c| c.width).sum::<usize>(), 210);
        assert_eq!(plan[0].width, 38);
        // Every other column shares in the slack; none is left at its base width.
        assert!(plan[1..].iter().all(|c| c.width > 11));

        // At the width a real FLOWS widget gets, no column runs away with the
        // slack: the widest is within a few characters of the second widest,
        // rather than 2.3x it as when the flexible column took a second helping.
        let plan = plan_of(&FLOWS, 140);
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
        let plan = fit(FLOWS.cols, 4, 14, 30);
        assert_eq!(plan.iter().find(|c| c.title == "REMOTE").unwrap().width, 14);
    }

    #[test]
    fn the_table_registry_is_well_formed() {
        // Two silent failures, checked over every table rather than a sample now
        // that they are declared in one place: `fit` gives all slack to the
        // single zero-width column, and two of them would split it and unalign
        // the header from the rows; a shared salt would join two widgets' scroll
        // offsets whenever both were on screen.
        let tables = [&FLOWS, &HOSTS, &SERVICES, &LEGEND, &ANSWERS, &SCAN, &INTEL];
        for t in tables {
            assert_eq!(
                t.cols.iter().filter(|c| c.width == 0).count(),
                1,
                "{} has the wrong number of flexible columns",
                t.salt
            );
            assert!(t.flex.0 <= t.flex.1, "{} has an inverted flex range", t.salt);
        }
        let mut salts: Vec<&str> = tables.iter().map(|t| t.salt).collect();
        let count = salts.len();
        salts.sort_unstable();
        salts.dedup();
        assert_eq!(salts.len(), count, "two tables share a scroll salt");
    }

    #[test]
    fn the_probe_table_keeps_the_answer_when_the_cell_is_narrow() {
        // DATA is the answer; NAME echoes the question that is already on the
        // status line above. In a very narrow widget the answer is what survives.
        let narrow = titles(&plan_of(&ANSWERS, 26));
        assert!(narrow.contains(&"DATA"));
        assert!(!narrow.contains(&"TTL"));
    }

    #[test]
    fn the_probe_table_fits_a_reverse_dns_name() {
        // A PTR name is the long field and the whole point of the lookup, so it
        // has to fit at the width the widget actually gets (~78 characters in
        // the default five-widget layout) rather than be shortened to an ellipsis.
        let sample = "38.173.125.74.in-addr.arpa";
        let plan = plan_of(&ANSWERS, 78);
        let name = plan.iter().find(|c| c.title == "NAME").expect("NAME dropped at 78");
        assert_eq!(
            pad(sample, name.width, false, 1).trim_end(),
            sample,
            "NAME is {} wide, too narrow for a reverse-DNS name",
            name.width
        );

        // At the narrowest a widget can be, the name still survives: the TTL is
        // what goes, because it is the field you can most afford to lose.
        assert_eq!(titles(&plan_of(&ANSWERS, 54)), ["NAME", "TYPE", "DATA"]);
    }

    /// Render one row of `cols` as the character grid it becomes on screen.
    fn grid_row(cols: &[Col], value: impl Fn(&str) -> String) -> String {
        cols.iter()
            .enumerate()
            .map(|(i, c)| pad(&value(c.title), c.width, c.right, gutter(c, cols.get(i + 1))))
            .collect()
    }

    #[test]
    fn the_scan_and_intel_tables_read_as_separated_columns() {
        // Same standard as the probe answer table: these are character grids, so
        // the grid is the only honest check.
        let scan = plan_of(&SCAN, 78);
        assert_eq!(scan.iter().map(|c| c.width).sum::<usize>(), 78);
        let row = grid_row(&scan, |t| match t {
            "PORT" => "22".into(),
            "SERVICE" => "ssh".into(),
            _ => "SSH-2.0-OpenSSH_9.6".into(),
        });
        assert_eq!(row.trim_end(), "22     ssh           SSH-2.0-OpenSSH_9.6");
        assert_eq!(
            grid_row(&scan, |t| t.to_string()).trim_end(),
            "PORT   SERVICE       BANNER"
        );

        // SERVICE must hold the longest name in inspect's table without an
        // ellipsis, or the scan disagrees with the SERVICES widget about a port.
        let service = scan.iter().find(|c| c.title == "SERVICE").unwrap();
        assert_eq!(pad("shadowsocks", service.width, false, 1).trim_end(), "shadowsocks");

        let intel = plan_of(&INTEL, 78);
        assert_eq!(intel.iter().map(|c| c.width).sum::<usize>(), 78);
        let dossier = grid_row(&intel, |t| match t {
            "FIELD" => "ALLOCATED".into(),
            _ => "1998-09-25".into(),
        });
        // FIELD renders wider than its base 11: VALUE saturates at its cap, and
        // the leftover is spread across the other columns rather than pooling in
        // the flexible one.
        assert_eq!(dossier.trim_end(), "ALLOCATED     1998-09-25");
        // The longest label this table uses must survive its column.
        let field = intel.iter().find(|c| c.title == "FIELD").unwrap();
        for label in ["ADDRESS", "PTR", "ASN", "ORG", "PREFIX", "COUNTRY", "REGISTRY", "ALLOCATED"] {
            assert_eq!(pad(label, field.width, false, 1).trim_end(), label);
        }
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
        let plan = plan_of(&ANSWERS, 78);
        let row = grid_row(&plan, |title| match title {
            "NAME" => "38.173.125.74.in-addr.arpa".into(),
            "TYPE" => "PTR".into(),
            "TTL" => "1h".into(),
            _ => "fra24s25-in-f6.1e100.net".into(),
        });
        let head = grid_row(&plan, |title| title.to_string());

        assert_eq!(row.chars().count(), 78);
        assert_eq!(head.chars().count(), 78);
        assert_eq!(
            row.trim_end(),
            "38.173.125.74.in-addr.arpa  PTR        1h  fra24s25-in-f6.1e100.net"
        );
        assert_eq!(head.trim_end(), "NAME                        TYPE      TTL  DATA");
    }

    #[test]
    fn clamping_is_codepoint_safe() {
        assert_eq!(clamp_to("1.2.3.4:443", 20), "1.2.3.4:443");
        assert_eq!(clamp_to("abcdefghij", 5), "abcd…");
        // Multi-byte: a byte slice at 5 would land mid-codepoint and panic.
        assert_eq!(clamp_to("ααααα", 3), "αα…");
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
        for a in probe::Action::ALL {
            text.push_str(a.label());
        }
        for m in PortMode::ALL {
            text.push_str(m.label());
        }
        for s in Sort::ALL {
            text.push_str(s.label());
        }
        for r in probe::RecordType::ALL {
            text.push_str(r.label());
        }
        for s in [
            "Tunnel-RS", "[ON]", "[OFF]", "[ERR]", "CONNECTED", "ENGINE STOPPED", "OFFLINE",
            "FWD IDLE ERR REQ",
            // Protocol labels reach the screen from inspect.rs, so they belong
            // in this registry too — `uTP` is one keystroke from `µTP`.
            "BitTorrent uTP DHT BT Tracker Obfuscated WireGuard OpenVPN Shadowsocks",
            "PORT SERVICE BANNER FIELD VALUE ADDRESS PTR ASN ORG PREFIX COUNTRY REGISTRY",
            "ALLOCATED OPEN closed filtered scanning scan complete TOP 100 CUSTOM RUN",
            "well-known ports no open ports found",
            "LOOKUP", "ACTIVE", "filter", "live only", "resolver", "host or address",
            "no active hosts", "no traffic yet", "no flows match the filter", "no widgets",
            "no remote hosts yet", "no services yet", "no classified traffic yet",
            "no records in the answer section", "pick a host or type a name, then RUN",
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

    /// The colour of the header's forward indicator, read back out of the
    /// frame's painted text rather than recomputed.
    fn forward_colour(app: &mut TunnelApp) -> Option<Color32> {
        render_frame(app, 1280.0, 800.0)
            .shapes
            .into_iter()
            .find_map(|c| match c.shape {
                egui::Shape::Text(t) if t.galley.job.text.starts_with("FWD") => {
                    t.galley.job.sections.first().map(|s| s.format.color)
                }
                _ => None,
            })
    }

    #[test]
    fn the_forward_indicator_tells_waiting_apart_from_failing() {
        // A lease takes seconds to negotiate and its first attempt races the
        // WireGuard handshake. Painting that red reported a failure on every
        // startup which then resolved itself — so "requesting" is its own state,
        // and it must not drift back into meaning "broken".
        let mut app = app();
        app.traffic = Arc::new(populated());

        assert_eq!(forward_colour(&mut app), None, "nothing shows when unconfigured");

        app.status.forward = Some(Forward::Requesting("negotiating".into()));
        assert_eq!(forward_colour(&mut app), Some(WARN_AMBER));

        app.status.forward = Some(Forward::Failed("not authorised".into()));
        assert_eq!(forward_colour(&mut app), Some(ERROR_RED));

        // Leased but unproven is muted, not red: a port nobody has dialled looks
        // the same as one that forwards nothing.
        app.status.forward = Some(Forward::Open(51413));
        app.status.forwarded_in = 0;
        assert_eq!(forward_colour(&mut app), Some(MONO_THEME.text_muted));

        app.status.forwarded_in = 42;
        assert_eq!(forward_colour(&mut app), Some(MONO_THEME.text_primary));

        // Four states, four distinct colours — the whole point is telling them
        // apart at a glance.
        let seen = [WARN_AMBER, ERROR_RED, MONO_THEME.text_muted, MONO_THEME.text_primary];
        for (i, a) in seen.iter().enumerate() {
            for b in &seen[i + 1..] {
                assert_ne!(a, b, "two states share a colour");
            }
        }
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
        app.rows[0].widgets[0].probe.last = Some(Ok(probe::Outcome::Dns(probe::DnsOutcome {
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
        })));
        render_frame(&mut app, 900.0, 400.0);
        // ...including in a widget too narrow for the whole answer table.
        render_frame(&mut app, 460.0, 380.0);

        // Every action's controls and every result shape must draw too — each
        // has its own row layout and its own table, so a widget that renders
        // one is no evidence about the others.
        for action in probe::Action::ALL {
            app.rows[0].widgets[0].probe.action = ProbeAction(action);
            app.rows[0].widgets[0].probe.last = None;
            render_frame(&mut app, 900.0, 400.0);
            render_frame(&mut app, 460.0, 380.0);
        }
        app.rows[0].widgets[0].probe.port_mode = PortMode::Custom;
        render_frame(&mut app, 900.0, 400.0);

        app.rows[0].widgets[0].probe.last = Some(Ok(probe::Outcome::Scan(probe::ScanOutcome {
            target: "93.184.216.34".parse().unwrap(),
            done: 100,
            total: 100,
            elapsed: Duration::from_millis(2400),
            open: vec![probe::PortResult {
                port: 22,
                service: "ssh",
                banner: Some("SSH-2.0-OpenSSH_9.6".into()),
            }],
            closed: 97,
            filtered: 2,
        })));
        render_frame(&mut app, 900.0, 400.0);
        render_frame(&mut app, 460.0, 380.0);

        app.rows[0].widgets[0].probe.last = Some(Ok(probe::Outcome::Intel(probe::IntelOutcome {
            target: "93.184.216.34".into(),
            ptr: Some("example.com".into()),
            asn: Some(15133),
            org: Some("EDGECAST, US".into()),
            prefix: Some("93.184.216.0/24".into()),
            country: Some("US".into()),
            registry: Some("ripencc".into()),
            allocated: Some("2008-06-02".into()),
            elapsed: Duration::from_millis(88),
            note: None,
        })));
        render_frame(&mut app, 900.0, 400.0);
        render_frame(&mut app, 460.0, 380.0);
        app.rows[0].widgets[0].probe.action = ProbeAction(probe::Action::Nslookup);

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
