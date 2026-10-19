"""
Home.py
-------
Overview across the Secure MediNet modules. Run from this directory, so
.streamlit/config.toml is picked up:

    streamlit run Home.py
"""

import pandas as pd
import streamlit as st

import charts
import settings
import theme
import ui
from sources import hids, ids, sdn, tokens

ui.setup_page(
    "Secure MediNet",
    "Detection on the edge, enforcement on the gateway — one view of both.",
)


@st.fragment(run_every=settings.REFRESH_SEC)
def overview():
    devices, live = sdn.get_devices()
    counts = sdn.status_counts(devices)
    detections = ids.get_detections()
    stats = ids.summarize(detections)

    ui.connection_banner("SDN Gateway", live)

    ids_state, ids_folder = ids.log_status()
    if ids_state in ("missing", "unreadable"):
        st.warning(
            f"Edge IDS logs are not reachable ({ids_state}: `{ids_folder}`). "
            "Open the Edge IDS page for the fix.",
            icon="⚠️",
        )

    # ── One row that spans both modules ───────────────────────────────────
    cols = st.columns(4)
    ui.tile(cols[0], "Devices", counts["total"], "on the IoT hotspot")
    ui.tile(cols[1], "Under enforcement",
            counts["quarantined"] + counts["rate_limited"],
            f"{counts['quarantined']} dropped · {counts['rate_limited']} throttled",
            theme.CRITICAL if counts["quarantined"] else theme.WARNING)
    ui.tile(cols[2], "IDS detections", stats["detections"],
            "confirmed by the ensemble",
            theme.CRITICAL if stats["detections"] else theme.GOOD)
    ui.tile(cols[3], "Detections not enforced", stats["unenforced"],
            "no gateway action taken",
            theme.SERIOUS if stats["unenforced"] else theme.GOOD)

    st.divider()

    # ── SDN ───────────────────────────────────────────────────────────────
    left, right = st.columns([1, 1])
    with left:
        ui.panel("SDN Gateway", "Devices by enforcement state.")
        ui.chart(charts.device_status_bar(counts), "No devices discovered yet.")
        st.page_link("pages/1_SDN_Gateway.py", label="Open SDN Gateway",
                     icon="➡️")
    with right:
        ui.panel("Edge IDS ensemble", "Confirmed threats over time.")
        ui.chart(charts.detections_over_time(detections),
                 "No detections yet — run `inference.py --live` to stream them here.")
        st.page_link("pages/2_Edge_IDS.py", label="Open Edge IDS", icon="➡️")

    # ── ECG HIDS ──────────────────────────────────────────────────────────
    readings = hids.get_readings()
    st.divider()
    left, right = st.columns([1, 1])
    with left:
        ui.panel("ECG HIDS", "Heart rate; red points are readings the cloud "
                 "model flagged as an attack.")
        ui.chart(charts.heart_rate(readings), "No ECG readings found yet.")
        st.page_link("pages/3_ECG_HIDS.py", label="Open ECG HIDS", icon="➡️")
    with right:
        ecg = hids.summarize(readings)
        ui.panel("Sensor status",
                 "Live" if ecg["streaming"] else
                 f"Not streaming · newest reading {hids.describe_age(ecg['age_sec'])}")
        cols = st.columns(2)
        ui.tile(cols[0], "ECG attacks", ecg["attacks"], "flagged by the cloud model",
                theme.CRITICAL if ecg["attacks"] else theme.GOOD)
        ui.tile(cols[1], "Watchdog alerts", ecg["watchdog"], "edge rule checks",
                theme.SERIOUS if ecg["watchdog"] else theme.GOOD)

    # ── Behavioural token binding ─────────────────────────────────────────
    token_stats = tokens.summarize(tokens.get_devices())
    st.divider()
    ui.panel("Behavioural token binding",
             "Devices whose signed tokens keep to their learned timing.")
    cols = st.columns(4)
    ui.tile(cols[0], "Devices", token_stats["devices"], "seen by the MQTT bridge")
    ui.tile(cols[1], "Trusted", token_stats["trusted"], "timing profile learned",
            theme.GOOD)
    ui.tile(cols[2], "Learning", token_stats["learning"], "not enough tokens yet",
            theme.WARNING if token_stats["learning"] else None)
    ui.tile(cols[3], "Revoked", token_stats["revoked"], "abnormal timing",
            theme.CRITICAL if token_stats["revoked"] else theme.GOOD)
    st.page_link("pages/4_Token_Binding.py", label="Open token binding", icon="➡️")

    # ── Devices under enforcement, with what flagged them ─────────────────
    st.divider()
    flagged = {mac: d for mac, d in devices.items() if d.get("status") != "active"}
    ui.panel("Devices under enforcement",
             "Live gateway state, annotated with the most recent threat that "
             "implicated each device (IDS or ECG HIDS).")
    if not flagged:
        st.success("No devices are quarantined or rate-limited.", icon="✅")
    else:
        threats = {}   # newest first within each source; IDS takes precedence
        if not detections.empty:
            for _, row in detections.iterrows():
                mac = ids.device_mac(row)
                if mac and mac not in threats:
                    threats[mac] = f"IDS: {row['threat_type']} ({row['fused_confidence']:.2f})"
        for _, row in hids.attacks(readings).iterrows():
            mac = row["device_mac"]
            if mac and mac not in threats:
                threats[mac] = (f"ECG: {str(row['threat_type']).replace('_', ' ')} "
                                f"({float(row['ml_confidence'] or 0):.2f})")
        annotated = {
            mac: {**info, "hostname": info.get("hostname") or threats.get(mac, "")}
            for mac, info in flagged.items()
        }
        ui.devices_table(annotated)

    # ── Recent detections, newest first ───────────────────────────────────
    if not detections.empty:
        st.divider()
        ui.panel("Latest IDS detections")
        recent = detections.head(8)[
            [c for c in ("timestamp", "device_id", "threat_type",
                         "fused_confidence", "enforced") if c in detections.columns]
        ].copy()
        recent["enforced"] = recent["enforced"].map({True: "✅ Yes", False: "⚠️ No"})
        ui.dataframe(
            recent,
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Seen", format="HH:mm:ss"),
                "device_id": "Device",
                "threat_type": "Threat",
                "fused_confidence": st.column_config.ProgressColumn(
                    "Confidence", min_value=0.0, max_value=1.0, format="%.2f"),
                "enforced": "Enforced",
            },
        )


overview()
