#!/usr/bin/env python3
"""Visualize a tunnel flow CSV (the file written on engine shutdown).

Usage:
    python visualize_flows.py flows-YYYYMMDD-HHMMSS.csv

Reads the CSV emitted by the engine and renders four panels:
  1. Bytes per application protocol (up vs down), symlog-scaled and annotated
     so single-packet flows and zero-byte directions are both visible.
  2. Share of total bytes per protocol; the legend lists EVERY protocol with
     its exact byte count, including zero-byte ones.
  3. Top remote endpoints by total bytes, symlog-scaled and annotated.
  4. Session timeline — each flow as a bar from first_seen to last_seen,
     colored by protocol; bar height encodes log(total bytes).

Only the standard scientific stack is required: pandas, matplotlib, seaborn,
numpy.
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns

# Below this, the byte axes are linear so that 0 renders at the baseline
# instead of being undefined; above it, log so GB and KB coexist legibly.
SYMLOG_LINTHRESH = 1024


def human_bytes(n: float) -> str:
    """Format a byte count with binary units for axis/annotation labels."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def load(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    expected = {
        "first_seen", "last_seen", "remote", "l4", "app",
        "local_port", "up_bytes", "down_bytes", "packets",
    }
    missing = expected - set(df.columns)
    if missing:
        sys.exit(f"CSV missing columns: {', '.join(sorted(missing))}")
    df["first_seen"] = pd.to_datetime(df["first_seen"])
    df["last_seen"] = pd.to_datetime(df["last_seen"])
    df["total_bytes"] = df["up_bytes"] + df["down_bytes"]
    return df


def bytes_axis(ax) -> None:
    """symlog byte axis: zeros sit on the baseline, KB and GB both readable."""
    ax.set_xscale("symlog", linthresh=SYMLOG_LINTHRESH)
    ax.xaxis.set_major_formatter(lambda x, _: human_bytes(x))


def annotate_bars(ax) -> None:
    """Print the exact value on every bar — including '0 B', which would
    otherwise be an invisible zero-width bar with no explanation."""
    for container in ax.containers:
        ax.bar_label(
            container,
            labels=[human_bytes(v) for v in container.datavalues],
            padding=3,
            fontsize=9,
        )


def plot(df: pd.DataFrame) -> None:
    sns.set_theme(style="darkgrid", context="talk")

    total = human_bytes(df["total_bytes"].sum())

    # ------------------------------------------------------------------
    # Window 1: Bytes per protocol
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(11, 7))
    fig.canvas.manager.set_window_title("Bytes per Protocol")

    by_app = df.groupby("app")[["up_bytes", "down_bytes"]].sum()
    # Rank by total traffic, not download alone — upload-dominant protocols
    # were previously mis-sorted.
    by_app = by_app.loc[by_app.sum(axis=1).sort_values(ascending=False).index]

    by_app.plot(
        kind="barh",
        ax=ax,
        color=["#a78bfa", "#6ee7b7"],
        width=0.75,
    )

    ax.set_title(f"Bytes per Protocol\n{len(df)} flows, {total} total")
    ax.set_xlabel("Bytes (symlog)")
    ax.set_ylabel("")
    bytes_axis(ax)
    annotate_bars(ax)
    ax.legend(["Up", "Down"])
    ax.invert_yaxis()
    ax.margins(x=0.15)
    fig.tight_layout()

    # ------------------------------------------------------------------
    # Window 2: Traffic share
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(9, 8))
    fig.canvas.manager.set_window_title("Traffic Share")

    totals = (
        df.groupby("app")["total_bytes"]
        .sum()
        .sort_values(ascending=False)
    )

    # A zero-area wedge cannot be drawn, but nothing is hidden: the legend
    # below enumerates every protocol with its exact byte count.
    wedges = totals[totals > 0]

    labels = [
        app if pct >= 1.5 else ""
        for app, pct in zip(wedges.index, wedges / wedges.sum() * 100)
    ]

    ax.pie(
        wedges.values,
        labels=labels,
        startangle=90,
        counterclock=False,
        colors=sns.color_palette("mako", len(wedges)),
        autopct=lambda p: f"{p:.1f}%" if p >= 1.5 else "",
        pctdistance=0.78,
        labeldistance=1.15,
        wedgeprops=dict(width=0.45, edgecolor="white"),
    )

    ax.legend(
        [f"{app} — {human_bytes(v)}" for app, v in totals.items()],
        title="Protocols (all)",
        loc="center left",
        bbox_to_anchor=(1.0, 0.5),
        fontsize=10,
    )
    fig.tight_layout()

    # ------------------------------------------------------------------
    # Window 3: Top remotes
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(13, 7))
    fig.canvas.manager.set_window_title("Top Remote Endpoints")

    by_remote = (
        df.groupby("remote")["total_bytes"]
        .sum()
        .sort_values(ascending=False)
    )
    top = by_remote.head(15)
    rest = len(by_remote) - len(top)

    sns.barplot(
        x=top.values,
        y=top.index,
        hue=top.index,
        palette="rocket",
        legend=False,
        ax=ax,
    )

    subtitle = f" (+{rest} more, {human_bytes(by_remote.iloc[15:].sum())})" if rest > 0 else ""
    ax.set_title(f"Top Remote Endpoints by Volume{subtitle}")
    ax.set_xlabel("Total Bytes (symlog)")
    ax.set_ylabel("")
    bytes_axis(ax)
    annotate_bars(ax)
    ax.margins(x=0.15)
    fig.tight_layout()

    # ------------------------------------------------------------------
    # Window 4: Timeline
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(14, 8))
    fig.canvas.manager.set_window_title("Session Timeline")

    span = df.sort_values("first_seen").reset_index(drop=True)

    apps = sorted(span["app"].unique())
    cmap = dict(zip(apps, sns.color_palette("husl", len(apps))))

    # The CSV carries millisecond timestamps; only pad bars enough to render.
    min_w = pd.Timedelta(milliseconds=50)

    # Encode volume as bar height on a log scale so a 122 B probe and a
    # multi-GB stream are distinguishable at a glance.
    logb = np.log10(span["total_bytes"].clip(lower=1).astype(float))
    lo, hi = logb.min(), logb.max()
    if hi > lo:
        heights = 0.25 + 0.6 * (logb - lo) / (hi - lo)
    else:
        heights = pd.Series(0.85, index=span.index)

    for i, row in span.iterrows():
        start = row["first_seen"]
        width = max(row["last_seen"] - start, min_w)

        ax.barh(
            i,
            width,
            left=start,
            height=heights[i],
            color=cmap[row["app"]],
            edgecolor="none",
        )

    ax.set_title("Session Timeline")
    ax.set_ylabel("Flow")
    ax.set_xlabel("Time")
    ax.invert_yaxis()

    if len(span) > 40:
        ax.set_yticks([])

    ax.xaxis.set_major_formatter(
        mdates.DateFormatter("%H:%M:%S")
    )

    handles = [
        plt.Rectangle((0, 0), 1, 1, color=cmap[a])
        for a in apps
    ]

    ax.legend(handles, apps, fontsize=9, ncol=2)
    fig.tight_layout()

    plt.show()


def main() -> None:
    ap = argparse.ArgumentParser(description="Visualize a tunnel flow CSV.")
    ap.add_argument("csv", type=Path, help="flows-*.csv from engine shutdown")
    args = ap.parse_args()

    if not args.csv.exists():
        sys.exit(f"no such file: {args.csv}")

    df = load(args.csv)
    if df.empty:
        sys.exit("CSV has no flows to plot")
    plot(df)


if __name__ == "__main__":
    main()