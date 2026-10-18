"""
ui.py
-----
Widgets shared by the dashboard pages.
"""

import hmac

import pandas as pd
import streamlit as st

import settings

STATUS_LABELS = {
    "quarantined": "🔴 Quarantined",
    "rate_limited": "🟠 Rate-limited",
    "active": "🟢 Active",
}


def setup_page(title):
    st.set_page_config(page_title=f"{title} · Secure MediNet", page_icon="🛡️", layout="wide")
    _require_password()
    st.title(title)


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


def connection_banner(name, live):
    if not live:
        st.warning(
            f"{name} API unreachable at {settings.SDN_API_URL}: showing the last saved "
            "snapshot. Actions are disabled.",
            icon="⚠️",
        )


def sdn_metrics(counts):
    cols = st.columns(4)
    cols[0].metric("Devices", counts["total"])
    cols[1].metric("Active", counts["active"])
    cols[2].metric("Rate-limited", counts["rate_limited"])
    cols[3].metric("Quarantined", counts["quarantined"])


def devices_table(devices):
    """Renders devices sorted most-severe first. Returns nothing."""
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
    st.dataframe(
        df,
        hide_index=True,
        width="stretch",
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
