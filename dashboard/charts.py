"""
charts.py
---------
Altair chart builders. Altair ships with Streamlit, so these add no
dependency to the Pi.

Form follows the data's job: magnitude comparisons are sequential (one hue,
more-is-darker), the three ensemble tiers are categorical (fixed slot order,
legend plus direct labels), and single-series trends use one hue. No chart
here has two y-scales.
"""

import altair as alt
import pandas as pd

import theme


# Bucket widths the timeline may snap to, shortest first.
_BUCKETS = ["1s", "2s", "5s", "10s", "30s", "1min", "2min", "5min",
            "15min", "30min", "1h", "3h", "6h", "1D"]


def _pick_bucket(timestamps, target=16):
    """Choose a bucket width that puts roughly `target` columns on screen.
    A batch run finishes in seconds and a live replay runs for minutes, so a
    fixed width would collapse one of them into a single bar."""
    span = (timestamps.max() - timestamps.min()).total_seconds()
    if not span or pd.isna(span):
        return _BUCKETS[0]
    for bucket in _BUCKETS:
        if span / pd.Timedelta(bucket).total_seconds() <= target:
            return bucket
    return _BUCKETS[-1]


def _time_format(timestamps):
    """Tick label format that suits the span shown, so labels never repeat
    (minute-only labels on 30-second ticks) or drop the date over days."""
    span = (timestamps.max() - timestamps.min()).total_seconds()
    if pd.isna(span) or span < 900:
        return "%H:%M:%S"
    if span < 2 * 86400:
        return "%H:%M"
    return "%b %d %H:%M"


def detections_over_time(detections, bucket=None):
    """Detections per time bucket: one series, so one hue.

    Threat types are categories, not magnitudes, and a stack of five
    similar blues could not be told apart. The per-type breakdown is in the
    tooltip, and the labelled "by type" bar chart is where types are compared.
    """
    if detections.empty:
        return None
    df = detections.dropna(subset=["timestamp"]).copy()
    if df.empty:
        return None
    bucket = bucket or _pick_bucket(df["timestamp"])
    df["bucket"] = df["timestamp"].dt.floor(bucket)
    df["threat_type"] = df["threat_type"].astype(str).str.replace("_", " ")
    grouped = (
        df.groupby("bucket")["threat_type"]
          .agg(detections="size",
               breakdown=lambda types: ", ".join(
                   f"{name} {count}" for name, count in types.value_counts().items()))
          .reset_index()
    )
    # Few columns would otherwise render as hairlines on a time axis.
    columns = len(grouped)
    size = 56 if columns <= 2 else (34 if columns <= 6 else 18)
    return (
        alt.Chart(grouped, height=200)
        .mark_bar(cornerRadiusEnd=4, size=size, color=theme.SINGLE_SERIES)
        .encode(
            x=alt.X("bucket:T", title=None,
                    axis=alt.Axis(format=_time_format(grouped["bucket"]),
                                  labelAngle=0),
                    scale=alt.Scale(padding=28)),
            y=alt.Y("detections:Q", title="Detections",
                    axis=alt.Axis(tickMinStep=1, format="d")),
            tooltip=[
                alt.Tooltip("bucket:T", title="From", format="%H:%M:%S"),
                alt.Tooltip("detections:Q", title="Detections"),
                alt.Tooltip("breakdown:N", title="By type"),
            ],
        )
    )


def type_counts(detections):
    """Detections per threat type, for horizontal_magnitude."""
    if detections.empty:
        return pd.DataFrame(columns=["type", "count"])
    counts = detections["threat_type"].astype(str).str.replace("_", " ").value_counts()
    return pd.DataFrame({"type": counts.index, "count": counts.values})


def tier_scores(detections, limit=40):
    """Per-tier confidence across recent detections.

    Three series whose identity is the point, so: categorical slots 1-3,
    legend present, and every series also directly labelled at its last
    point (identity never rests on colour alone).
    """
    tiers = [key for key in theme.TIERS if key in detections.columns]
    if detections.empty or not tiers:
        return None

    df = (detections.dropna(subset=["timestamp"])
                    .sort_values("timestamp").tail(limit).copy())
    df["order"] = range(len(df))
    tidy = df.melt(
        id_vars=["order", "timestamp", "threat_type", "device_id"],
        value_vars=tiers, var_name="tier", value_name="score",
    ).dropna(subset=["score"])
    if tidy.empty:
        return None
    tidy["tier"] = tidy["tier"].map(theme.TIER_LABELS)

    labels = [theme.TIER_LABELS[key] for key in tiers]
    color = alt.Color(
        "tier:N", title=None, sort=labels,
        scale=alt.Scale(domain=labels,
                        range=[theme.TIER_COLORS[name] for name in labels]),
        legend=alt.Legend(orient="top"),
    )
    base = alt.Chart(tidy, height=220).encode(
        x=alt.X("order:Q", title="Detection (oldest to newest)",
                axis=alt.Axis(tickMinStep=1, labels=False)),
        y=alt.Y("score:Q", title="Tier confidence",
                scale=alt.Scale(domain=[0, 1])),
        color=color,
    )
    line = base.mark_line(strokeWidth=2, point=alt.OverlayMarkDef(size=70))
    hover = base.mark_circle(size=120, opacity=0).encode(
        tooltip=[
            alt.Tooltip("tier:N", title="Tier"),
            alt.Tooltip("score:Q", title="Confidence", format=".2f"),
            alt.Tooltip("threat_type:N", title="Threat"),
            alt.Tooltip("device_id:N", title="Device"),
            alt.Tooltip("timestamp:T", title="Seen", format="%H:%M:%S"),
        ]
    )
    tips = (
        alt.Chart(tidy[tidy["order"] == tidy["order"].max()], height=220)
        .mark_text(align="left", dx=8, fontSize=11)
        .encode(
            x=alt.X("order:Q"), y=alt.Y("score:Q"), text="tier:N",
            color=color, detail="tier:N",
        )
    )
    return (line + hover + tips).resolve_scale(color="shared")


def heart_rate(readings):
    """Heart rate over time, with the readings the cloud model flagged as an
    attack marked on the line.

    One series, so one hue and no legend box (the panel title names it). The
    flagged points take the reserved critical colour; the panel note and the
    tooltip both say what they mean, so colour is never the only cue. Each
    flagged point has a 2px surface ring so it separates from the line.
    """
    if readings.empty:
        return None
    df = readings.dropna(subset=["timestamp"]).copy()
    df["hr_bpm"] = pd.to_numeric(df["hr_bpm"], errors="coerce")
    df = df.dropna(subset=["hr_bpm"]).sort_values("timestamp")
    if df.empty:
        return None
    df["verdict"] = df["ml_prediction"].map(
        lambda p: p.replace("_", " ") if isinstance(p, str) else "not judged")
    df["confidence"] = pd.to_numeric(df["ml_confidence"], errors="coerce")
    df["flag"] = df["is_attack"].astype(bool)

    base = alt.Chart(df, height=220).encode(
        x=alt.X("timestamp:T", title=None,
                axis=alt.Axis(format=_time_format(df["timestamp"]), labelAngle=0)),
        y=alt.Y("hr_bpm:Q", title="Heart rate (bpm)",
                scale=alt.Scale(zero=False, padding=12)),
    )
    line = base.mark_line(strokeWidth=2, color=theme.SINGLE_SERIES)
    flagged = base.transform_filter("datum.flag").mark_point(
        filled=True, size=80, color=theme.CRITICAL,
        stroke=theme.SURFACE, strokeWidth=2, opacity=1,
    )
    hover = base.mark_circle(size=140, opacity=0).encode(
        tooltip=[
            alt.Tooltip("timestamp:T", title="Time", format="%H:%M:%S"),
            alt.Tooltip("hr_bpm:Q", title="Heart rate", format=".0f"),
            alt.Tooltip("verdict:N", title="Model verdict"),
            alt.Tooltip("confidence:Q", title="Confidence", format=".0%"),
            alt.Tooltip("sdn_action:N", title="SDN request"),
        ]
    )
    return line + flagged + hover


def interval_history(samples, mean, tolerance, rejected=None):
    """A device's recent token intervals against the band the bridge
    accepts (learned mean ± tolerance). One series, so one hue; the band is
    a recessive wash and the mean a dashed rule, both named in the tooltip.

    `rejected` is the interval of the token that got the device revoked. It
    is drawn after the history in the reserved critical colour and labelled
    in text, so the reason for the revocation is visible, not just stated.
    """
    if not samples:
        return None
    df = pd.DataFrame({"token": range(1, len(samples) + 1),
                       "interval": [float(s) for s in samples]})
    base = alt.Chart(df, height=200).encode(
        x=alt.X("token:Q", title="Token (oldest to newest)",
                axis=alt.Axis(tickMinStep=1, format="d")),
    )
    layers = []
    if mean is not None and tolerance is not None:
        band = pd.DataFrame({"low": [max(0.0, mean - tolerance)],
                             "high": [mean + tolerance], "mean": [mean]})
        layers.append(alt.Chart(band).mark_rect(color=theme.GRID, opacity=0.9).encode(
            y="low:Q", y2="high:Q",
            tooltip=[alt.Tooltip("low:Q", title="Accepted from (s)", format=".2f"),
                     alt.Tooltip("high:Q", title="Accepted to (s)", format=".2f")]))
        layers.append(alt.Chart(band).mark_rule(
            color=theme.INK_MUTED, strokeDash=[4, 4], strokeWidth=1).encode(
            y="mean:Q",
            tooltip=[alt.Tooltip("mean:Q", title="Learned mean (s)", format=".2f")]))
    y = alt.Y("interval:Q", title="Seconds between tokens",
              scale=alt.Scale(zero=True, nice=True))
    layers.append(base.mark_line(strokeWidth=2, color=theme.SINGLE_SERIES).encode(y=y))
    layers.append(base.mark_point(filled=True, size=60, color=theme.SINGLE_SERIES,
                                  stroke=theme.SURFACE, strokeWidth=2, opacity=1)
                  .encode(y=y, tooltip=[
                      alt.Tooltip("token:Q", title="Token"),
                      alt.Tooltip("interval:Q", title="Interval (s)", format=".2f")]))
    if rejected is not None:
        hit = pd.DataFrame({"token": [len(samples) + 1], "interval": [rejected],
                            "label": [f"rejected: {rejected:g}s → revoked"]})
        point = alt.Chart(hit).encode(x="token:Q", y="interval:Q")
        layers.append(point.mark_point(
            filled=True, size=110, color=theme.CRITICAL, stroke=theme.SURFACE,
            strokeWidth=2, opacity=1).encode(tooltip=[
                alt.Tooltip("label:N", title="Token"),
                alt.Tooltip("interval:Q", title="Interval (s)", format=".2f")]))
        layers.append(point.mark_text(align="right", dx=-10, fontSize=11,
                                      color=theme.INK_SECOND).encode(text="label:N"))
    return alt.layer(*layers)


def horizontal_magnitude(df, value_col, label_col, value_title,
                         value_format=".2f", domain=None, height=None):
    """Sequential horizontal bars for a magnitude comparison (latency per
    stage, recall per attack class). One hue, more-is-darker, values
    directly labelled so the colour is never the only cue."""
    if df.empty:
        return None
    rows = len(df)
    percent = value_format.endswith("%")
    whole = value_format in (".0f", "d")     # counts: no "0.5 readings" ticks
    if domain:
        # Leave room for the value label past the end of the longest bar.
        low, high = domain
        scale = alt.Scale(domain=[low, high + (high - low) * 0.12], nice=False)
    else:
        scale = alt.Undefined
    base = alt.Chart(df, height=height or max(110, 34 * rows)).encode(
        y=alt.Y(f"{label_col}:N", title=None, sort="-x"),
        x=alt.X(f"{value_col}:Q", title=value_title, scale=scale,
                axis=alt.Axis(format="%", values=[0, 0.25, 0.5, 0.75, 1.0])
                if percent else
                alt.Axis(format="d", tickMinStep=1) if whole else alt.Undefined),
    )
    bars = base.mark_bar(cornerRadiusEnd=4, height=14).encode(
        color=alt.Color(f"{value_col}:Q", legend=None,
                        scale=alt.Scale(range=theme.SEQ_RANGE)),
        tooltip=[
            alt.Tooltip(f"{label_col}:N", title=""),
            alt.Tooltip(f"{value_col}:Q", title=value_title, format=value_format),
        ],
    )
    labels = base.mark_text(align="left", dx=6, fontSize=11,
                            color=theme.INK_SECOND).encode(
        text=alt.Text(f"{value_col}:Q", format=value_format)
    )
    return bars + labels


def device_status_bar(counts):
    """Devices by enforcement state: a reserved status palette, each slice
    labelled, so this never reads as three anonymous series."""
    rows = [
        {"status": label, "devices": counts.get(key, 0), "key": key}
        for key, label in (("quarantined", "Quarantined"),
                           ("rate_limited", "Rate-limited"),
                           ("active", "Active"))
    ]
    df = pd.DataFrame(rows)
    if df["devices"].sum() == 0:
        return None
    return (
        alt.Chart(df, height=120)
        .mark_bar(cornerRadiusEnd=4, height=18)
        .encode(
            y=alt.Y("status:N", title=None, sort=[r["status"] for r in rows]),
            x=alt.X("devices:Q", title="Devices", axis=alt.Axis(tickMinStep=1)),
            color=alt.Color(
                "key:N", legend=None,
                scale=alt.Scale(domain=list(theme.STATUS_COLORS),
                                range=list(theme.STATUS_COLORS.values())),
            ),
            tooltip=[alt.Tooltip("status:N", title=""),
                     alt.Tooltip("devices:Q", title="Devices")],
        )
    )
