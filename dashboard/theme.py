"""
theme.py
--------
Palette and chart styling. The dashboard ships dark (it is read on a wall
display / projector during demos), so every value below is the dark step of
its ramp, chosen for the dark chart surface rather than flipped from light.

The three tier colours are categorical slots 1-3 and were validated as a set
against this surface: worst all-pairs CVD dE 9.4, normal-vision dE 20.9.
Status colours are reserved roles and always ship with an icon + label, so
colour never carries meaning on its own.
"""

# ── Surfaces and ink ───────────────────────────────────────────────────────
PAGE        = "#0d0d0d"
SURFACE     = "#1a1a19"
INK         = "#f0efec"
INK_SECOND  = "#c3c2b7"
INK_MUTED   = "#898781"
GRID        = "#2c2c2a"
BASELINE    = "#383835"

# ── Categorical: the three ensemble tiers (fixed order, never cycled) ─────
TIERS = {
    "isolation_forest": ("Isolation Forest", "#3987e5"),   # slot 1 blue
    "autoencoder":      ("AutoEncoder",      "#d95926"),   # slot 2 orange
    "lstm":             ("LSTM",             "#199e70"),   # slot 3 aqua
}
TIER_LABELS = {key: label for key, (label, _) in TIERS.items()}

# A lone series (heart rate) takes slot 1; it has no legend, the title names it.
SINGLE_SERIES = "#3987e5"
TIER_COLORS = {label: color for _, (label, color) in TIERS.items()}

# ── Sequential (magnitude): one blue hue, light -> dark ────────────────────
# On the dark surface an ordinal ramp goes no darker than step 600.
SEQ_BLUE = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95"]
SEQ_RANGE = ["#184f95", "#86b6ef"]   # low -> high for continuous scales

# ── Status (reserved; icon + label always accompany these) ────────────────
GOOD     = "#0ca30c"
WARNING  = "#fab219"
SERIOUS  = "#ec835a"
CRITICAL = "#d03b3b"

STATUS_COLORS = {
    "quarantined":  CRITICAL,
    "rate_limited": WARNING,
    "active":       GOOD,
}


def altair_theme():
    """Registered as the global Altair theme so every chart inherits it."""
    label = {"labelColor": INK_MUTED, "titleColor": INK_SECOND,
             "labelFontSize": 11, "titleFontSize": 11, "titleFontWeight": "normal"}
    return {
        "config": {
            "background": SURFACE,
            "font": 'system-ui, -apple-system, "Segoe UI", sans-serif',
            "view": {"stroke": None, "continuousHeight": 220},
            "axis": {
                **label,
                "domainColor": BASELINE,
                "tickColor": BASELINE,
                "gridColor": GRID,
                "gridWidth": 1,
                "labelPadding": 6,
                "titlePadding": 10,
            },
            "axisX": {"grid": False},
            "legend": {**label, "symbolType": "circle", "symbolSize": 90,
                       "orient": "top", "direction": "horizontal",
                       "offset": 4, "title": None},
            "title": {"color": INK, "fontSize": 13, "fontWeight": 600,
                      "anchor": "start", "offset": 10},
            "line": {"strokeWidth": 2},
            "point": {"size": 70, "filled": True},
            "bar": {"cornerRadiusEnd": 4},
            "range": {"heatmap": SEQ_RANGE, "ramp": SEQ_RANGE},
        }
    }
