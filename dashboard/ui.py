"""
ui.py
-----
Widgets shared by the dashboard pages: the password gate, stat tiles, the
device table, and the chart wrapper that applies the project's Altair theme.
"""

import hmac

import altair as alt
import pandas as pd
import streamlit as st

import settings
import theme

STATUS_LABELS = {
    "quarantined": "🔴 Quarantined",
    "rate_limited": "🟠 Rate-limited",
    "active": "🟢 Active",
}

_CSS = f"""
<style>
  /* Tighter header: the demo view starts at the data, not at whitespace. */
  .block-container {{ padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1400px; }}
  div[data-testid="stMetricValue"] {{ font-size: 1.9rem; }}

  .tile {{
    background: {theme.SURFACE};
    border: 1px solid rgba(255,255,255,0.10);
    border-left: 3px solid var(--accent, {theme.INK_MUTED});
    border-radius: 10px;
    padding: 0.85rem 1rem;
    height: 100%;
  }}
  .tile-label {{
    color: {theme.INK_MUTED}; font-size: 0.74rem; font-weight: 600;
    letter-spacing: 0.04em; text-transform: uppercase;
  }}
  .tile-value {{
    color: {theme.INK}; font-size: 2rem; line-height: 1.25; margin-top: 0.15rem;
  }}
  .tile-note {{ color: {theme.INK_SECOND}; font-size: 0.78rem; }}
  .panel-title {{
    color: {theme.INK}; font-size: 0.95rem; font-weight: 600; margin: 0.4rem 0 0.2rem;
  }}
  .panel-note {{ color: {theme.INK_MUTED}; font-size: 0.78rem; margin-bottom: 0.5rem; }}
</style>
"""


def setup_page(title, subtitle=None):
    st.set_page_config(page_title=f"{title} · Secure MediNet", page_icon="🛡️",
                       layout="wide")
    try:                              # Altair 5.5+ / 6
        alt.theme.register("secure_medinet", enable=True)(theme.altair_theme)
    except AttributeError:            # Altair 5.0-5.4
        alt.themes.register("secure_medinet", theme.altair_theme)
        alt.themes.enable("secure_medinet")
    st.markdown(_CSS, unsafe_allow_html=True)
    _require_password()
    st.title(title)
    if subtitle:
        st.markdown(f"<div class='panel-note'>{subtitle}</div>",
                    unsafe_allow_html=True)


def _require_password():
    """Stops the page until the viewer enters settings.PASSWORD (if one is set)."""
    if not settings.PASSWORD or st.session_state.get("authenticated"):
        return
    with st.form("login"):
        password = st.text_input("Dashboard password", type="password")
        if st.form_submit_button("Sign in"):
            if hmac.compare_digest(password.encode(), settings.PASSWORD.encode()):
                st.session_state["authenticated"] = True
                st.rerun()
            st.error("Wrong password.")
    st.stop()


def panel(title, note=None):
    st.markdown(f"<div class='panel-title'>{title}</div>", unsafe_allow_html=True)
    if note:
        st.markdown(f"<div class='panel-note'>{note}</div>", unsafe_allow_html=True)


def tile(column, label, value, note="", accent=None):
    """A stat tile: the right form for a single headline number."""
    accent = accent or theme.INK_MUTED
    column.markdown(
        f"<div class='tile' style='--accent:{accent}'>"
        f"<div class='tile-label'>{label}</div>"
        f"<div class='tile-value'>{value}</div>"
        f"<div class='tile-note'>{note or '&nbsp;'}</div></div>",
        unsafe_allow_html=True,
    )


def chart(figure, note=None):
    """Renders an Altair chart, or a placeholder when there is no data."""
    if figure is None:
        st.markdown(f"<div class='panel-note'>{note or 'No data yet.'}</div>",
                    unsafe_allow_html=True)
        return
    try:
        st.altair_chart(figure, width="stretch")
    except TypeError:        # Streamlit older than the width= parameter
        st.altair_chart(figure, use_container_width=True)


def dataframe(df, **kwargs):
    try:
        st.dataframe(df, width="stretch", **kwargs)
    except TypeError:
        st.dataframe(df, use_container_width=True, **kwargs)


def connection_banner(name, live):
    if not live:
        st.warning(
            f"{name} API unreachable at {settings.SDN_API_URL}: showing the last saved "
            "snapshot. Actions are disabled.",
            icon="⚠️",
        )


def sdn_tiles(counts):
    cols = st.columns(4)
    tile(cols[0], "Devices", counts["total"], "discovered on the hotspot")
    tile(cols[1], "Active", counts["active"], "traffic allowed", theme.GOOD)
    tile(cols[2], "Rate-limited", counts["rate_limited"], "throttled", theme.WARNING)
    tile(cols[3], "Quarantined", counts["quarantined"], "all traffic dropped",
         theme.CRITICAL)


def devices_table(devices):
    """Renders devices sorted most-severe first."""
    if not devices:
        st.info("No devices discovered yet.")
        return
    order = {s: i for i, s in enumerate(STATUS_LABELS)}
    df = pd.DataFrame(
        [{"mac": mac, **info} for mac, info in devices.items()],
        columns=["mac", "status", "hostname", "ip", "rate_kbps", "first_seen", "last_seen"],
    )
    df = df.sort_values(["status", "last_seen"], key=lambda c: c.map(order) if c.name == "status" else c,
                        ascending=[True, False])
    df["status"] = df["status"].map(STATUS_LABELS).fillna(df["status"])
    for col in ("first_seen", "last_seen"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    dataframe(
        df,
        hide_index=True,
        column_config={
            "mac": "MAC address",
            "status": "Status",
            "hostname": "Hostname",
            "ip": "IP",
            "rate_kbps": st.column_config.NumberColumn("Rate limit (kbps)"),
            "first_seen": st.column_config.DatetimeColumn("First seen", format="YYYY-MM-DD HH:mm:ss"),
            "last_seen": st.column_config.DatetimeColumn("Last seen", format="YYYY-MM-DD HH:mm:ss"),
        },
    )
