"""
3_ECG_HIDS.py
-------------
ECG HIDS detail view: the patient's heart rate with the readings the cloud
model flagged, attacks by type, watchdog alerts, cloud-model availability,
and each reading's SDN request joined to the device's live gateway status.
Patient identity is never read (see sources/hids.py).
"""

import pandas as pd
import streamlit as st

import charts
import settings
import theme
import ui
from sources import hids, sdn

ui.setup_page(
    "ECG HIDS",
    "Host-based detection on the ECG sensor: watchdog rules on the edge, a "
    "privacy-preserving cloud model, and SDN enforcement.",
)


@st.fragment(run_every=settings.REFRESH_SEC)
def live_view():
    found = hids.status()
    readings = hids.get_readings()

    if readings.empty:
        if not any(found.values()):
            roots = ", ".join(f"`{root}`" for root in settings.HIDS_SEARCH_ROOTS)
            st.error(
                f"No HIDS logs found under {roots or 'any search folder'}. Set "
                "`HIDS_DIR` for the dashboard service to the HIDS folder (for "
                "example `/home/chega/HIDS`) and restart it. If the path is "
                "right, the dashboard user may be blocked from a parent folder: "
                "`chmod o+x /home/chega`.",
                icon="📁",
            )
        else:
            st.info("HIDS logs found, but they contain no readings yet.", icon="💤")
        return

    stats = hids.summarize(readings)
    if not stats["streaming"]:
        st.info(
            f"Showing the last recorded session: the newest reading is "
            f"{hids.describe_age(stats['age_sec'])}. Start the HIDS "
            "(`demo_stream.py` or `esp32_listener.py`, plus `orchestrator.py`) "
            "to stream live.",
            icon="⏸️",
        )

    # ── Headline numbers ──────────────────────────────────────────────────
    cols = st.columns(4)
    ui.tile(cols[0], "Readings", stats["readings"],
            f"newest {hids.describe_age(stats['age_sec'])}",
            theme.GOOD if stats["streaming"] else None)
    ui.tile(cols[1], "Attacks detected", stats["attacks"],
            "flagged by the cloud model",
            theme.CRITICAL if stats["attacks"] else theme.GOOD)
    ui.tile(cols[2], "SDN requests", stats["drop"] + stats["rate_limit"],
            f"{stats['drop']} drop · {stats['rate_limit']} rate-limit",
            theme.WARNING if stats["drop"] + stats["rate_limit"] else None)
    ui.tile(cols[3], "Watchdog alerts", stats["watchdog"],
            "edge rules: timeouts, implausible HR",
            theme.SERIOUS if stats["watchdog"] else theme.GOOD)

    st.divider()

    # ── The signal, and the attacks against it ────────────────────────────
    flagged = hids.attacks(readings)
    left, right = st.columns([1, 1])
    with left:
        ui.panel("Heart rate",
                 "Red points are readings the cloud model flagged as an attack.")
        ui.chart(charts.heart_rate(readings), "No heart-rate readings yet.")
    with right:
        ui.panel("Attacks over time", "Hover a bar for the attack types in it.")
        ui.chart(charts.detections_over_time(flagged),
                 "No attacks detected in the recent readings.")

    st.divider()
    left, right = st.columns([1, 1])
    with left:
        ui.panel("Attacks by type")
        ui.chart(charts.horizontal_magnitude(
            charts.type_counts(flagged), "count", "type", "Readings",
            value_format=".0f"), "No attacks detected in the recent readings.")
    with right:
        ui.panel("Cloud model & privacy",
                 "Only 6 anonymised features leave the edge for the cloud model.")
        judged = stats["ml_judged"]
        available = (judged - stats["ml_unavailable"]) / judged if judged else 0
        cols = st.columns(2)
        ui.tile(cols[0], "Cloud model reachable",
                f"{available:.0%}" if judged else "—",
                f"{stats['ml_unavailable']} of {judged} readings got no verdict",
                theme.GOOD if available >= 0.9 else theme.SERIOUS)
        ui.tile(cols[1], "Patient identity shown", "None",
                "name, ID, age and location are never read", theme.GOOD)

    # ── Readings, joined to live SDN state ────────────────────────────────
    st.divider()
    ui.panel("Recent readings",
             "Newest first. 'SDN request' is what the HIDS asked the gateway "
             "to do; 'SDN now' is the device's current gateway status.")
    devices, _ = sdn.get_devices()
    table = readings.head(30).copy()
    table["sdn_now"] = table["device_mac"].map(
        lambda mac: ui.STATUS_LABELS.get(
            (devices.get(mac or "", {}) or {}).get("status"), "—"))
    table["verdict"] = table.apply(
        lambda row: ("🔴 " if row["is_attack"] else "") + (
            str(row["ml_prediction"]).replace("_", " ")
            if isinstance(row["ml_prediction"], str) else "—"),
        axis=1,
    )
    table["watchdog"] = table["watchdog_alerts"].map(
        lambda alerts: "; ".join(alerts) if alerts else "")
    table["ml_confidence"] = pd.to_numeric(table["ml_confidence"], errors="coerce")
    ui.dataframe(
        table[["timestamp", "device_mac", "hr_bpm", "verdict", "ml_confidence",
               "watchdog", "sdn_action", "sdn_now"]],
        hide_index=True,
        column_config={
            "timestamp": st.column_config.DatetimeColumn("Seen", format="HH:mm:ss"),
            "device_mac": "Device MAC",
            "hr_bpm": st.column_config.NumberColumn("HR (bpm)", format="%.0f"),
            "verdict": "Model verdict",
            "ml_confidence": st.column_config.ProgressColumn(
                "Confidence", min_value=0.0, max_value=1.0, format="%.2f"),
            "watchdog": "Watchdog",
            "sdn_action": "SDN request",
            "sdn_now": "SDN now",
        },
    )

    alerts = hids.get_watchdog_alerts()
    if not alerts.empty:
        st.divider()
        ui.panel("Watchdog alerts", "Rule-based checks that run on the edge "
                 "without the cloud model.")
        ui.dataframe(
            alerts.head(20),
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn(
                    "Seen", format="YYYY-MM-DD HH:mm:ss"),
                "alert": "Alert",
            },
        )


live_view()

with st.expander("Where this data comes from"):
    for kind, path in hids.status().items():
        st.markdown(f"- **{settings.HIDS_FILES[kind]}**: `{path or 'not found'}`")
    st.caption("Patient identity fields in full_log.jsonl (name, ID, age, sex, "
               "location, device IP, raw ECG) are dropped as each line is read.")
