"""
4_Token_Binding.py
------------------
Behavioural token binding: which devices are trusted, still learning, or
revoked, each device's learned rhythm, and recent token decisions.
"""

import pandas as pd
import streamlit as st

import charts
import settings
import theme
import ui
from sources import tokens

STATE_LABELS = {"revoked": "🔴 Revoked", "learning": "⏳ Learning",
                "trusted": "🟢 Trusted"}

ui.setup_page(
    "Behavioural token binding",
    "HMAC-signed tokens over MQTT, accepted only when each device keeps to "
    "the timing rhythm it has been learned to have.",
)


@st.fragment(run_every=settings.REFRESH_SEC)
def live_view():
    devices = tokens.get_devices()
    decisions = tokens.get_decisions()
    if devices.empty and decisions.empty:
        found = tokens.status()
        st.error(
            "No token-binding state found. The bridge writes "
            "`behavior_profile.json`, `revoked_devices.json`, and "
            "`token_decisions.jsonl` in its user's home folder; set "
            "`TOKEN_PROFILES` / `TOKEN_REVOKED` / `TOKEN_DECISIONS` for the "
            "dashboard service if they live elsewhere. Looked for: "
            + ", ".join(f"`{settings.TOKEN_FILES[k]}` → {v or 'not found'}"
                        for k, v in found.items()),
            icon="📁",
        )
        return

    stats = tokens.summarize(devices)
    last = stats["last_seen"]
    cols = st.columns(4)
    ui.tile(cols[0], "Devices", stats["devices"],
            "last token " + last.strftime("%Y-%m-%d %H:%M UTC") if last is not None else "")
    ui.tile(cols[1], "Trusted", stats["trusted"], "timing profile learned", theme.GOOD)
    ui.tile(cols[2], "Learning", stats["learning"], "too few tokens to judge yet",
            theme.WARNING if stats["learning"] else None)
    ui.tile(cols[3], "Revoked", stats["revoked"], "blocked by token binding",
            theme.CRITICAL if stats["revoked"] else theme.GOOD)

    st.divider()

    # ── One device's rhythm against its acceptance band ───────────────────
    profiled = devices[devices["samples"].map(len) > 0]
    left, right = st.columns([3, 2])
    with left:
        ui.panel("Learned timing",
                 "Recent intervals between a device's tokens. The shaded band "
                 "is what the bridge accepts; the dashed line is the learned mean.")
        if profiled.empty:
            st.markdown("<div class='panel-note'>No device has a timing "
                        "history yet.</div>", unsafe_allow_html=True)
        else:
            device_id = st.selectbox(
                "Device", profiled["device_id"].tolist(),
                format_func=lambda d: f"{d} ({STATE_LABELS[profiled.set_index('device_id').loc[d, 'state']]})",
                label_visibility="collapsed",
            )
            row = profiled.set_index("device_id").loc[device_id]
            ui.chart(charts.interval_history(
                row["samples"], row["mean_interval"], row["tolerance"],
                row["rejected_interval"] if pd.notna(row["rejected_interval"]) else None))
    with right:
        ui.panel("Revoked devices", "Restoring a token device does not clear SDN policy.")
        revoked = devices[devices["state"] == "revoked"]
        if revoked.empty:
            st.success("No devices are revoked.", icon="✅")
        else:
            ui.dataframe(revoked[["device_id", "reason"]], hide_index=True,
                         column_config={"device_id": "Device", "reason": "Reason"})
            chosen = st.selectbox("Device to restore", revoked["device_id"].tolist(),
                                  index=None, placeholder="Choose a revoked device")
            confirmed = st.checkbox("I confirm this restores token access")
            if st.button("Restore token device", disabled=not chosen or not confirmed):
                ok, message = tokens.restore_device(chosen)
                (st.success if ok else st.error)(message)
                if ok:
                    st.rerun()

    st.divider()
    ui.panel("Token decisions", "Most recent verification and timing outcomes.")
    if decisions.empty:
        st.info("No decision log yet. Start the updated MQTT bridge to record outcomes.")
    else:
        accepted = int((decisions["decision"] == "accepted").sum())
        rejected = int((decisions["decision"] == "rejected").sum())
        errors = int((decisions["decision"] == "error").sum())
        cols = st.columns(3)
        ui.tile(cols[0], "Accepted", accepted, "in the loaded log", theme.GOOD)
        ui.tile(cols[1], "Rejected", rejected, "in the loaded log",
                theme.CRITICAL if rejected else theme.GOOD)
        ui.tile(cols[2], "Errors", errors, "verification or profile unavailable",
                theme.WARNING if errors else theme.GOOD)
        left, right = st.columns([2, 3])
        with left:
            ui.panel("Rejection reasons")
            ui.chart(charts.horizontal_magnitude(
                tokens.rejection_counts(decisions), "count", "reason", "Rejected tokens",
                value_format="d"), "No rejected tokens in the loaded log.")
        with right:
            ui.panel("Recent decisions")
            ui.dataframe(decisions.head(30), hide_index=True,
                         column_config={
                             "timestamp": st.column_config.DatetimeColumn(
                                 "Time", format="YYYY-MM-DD HH:mm:ss"),
                             "device_id": "Device", "decision": "Decision",
                             "stage": "Stage", "reason": "Reason",
                             "revoked": "Revoked", "sdn_status": "SDN HTTP",
                         })

    # ── All devices ───────────────────────────────────────────────────────
    st.divider()
    ui.panel("Devices", "A token is accepted when its interval lands within "
             "the tolerance of the learned mean.")
    table = devices.copy()
    table["state"] = table["state"].map(STATE_LABELS)
    ui.dataframe(
        table[["device_id", "state", "mean_interval", "std_interval",
               "tolerance", "sample_count", "last_seen", "reason"]],
        hide_index=True,
        column_config={
            "device_id": "Device",
            "state": "State",
            "mean_interval": st.column_config.NumberColumn("Mean interval (s)", format="%.2f"),
            "std_interval": st.column_config.NumberColumn("Std dev (s)", format="%.2f"),
            "tolerance": st.column_config.NumberColumn("Tolerance ± (s)", format="%.2f"),
            "sample_count": "Samples",
            "last_seen": st.column_config.DatetimeColumn("Last token", format="YYYY-MM-DD HH:mm:ss"),
            "reason": "Revocation reason",
        },
    )


live_view()
