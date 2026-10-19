"""
2_Edge_IDS.py
-------------
Edge IDS ensemble detail view: confirmed threats, which of them the SDN
gateway actually enforced, per-tier confidence, gating and latency, and the
current model's evaluation.
"""

import pandas as pd
import streamlit as st

import charts
import settings
import theme
import ui
from sources import ids, sdn

ui.setup_page(
    "Edge IDS ensemble",
    "Isolation Forest → AutoEncoder → LSTM, fused into one confirm decision, "
    "then handed to the SDN gateway for enforcement.",
)


@st.fragment(run_every=settings.REFRESH_SEC)
def live_view():
    detections = ids.get_detections()
    runs = ids.get_runs()
    stats = ids.summarize(detections)

    if detections.empty and runs.empty:
        state, folder = ids.log_status()
        if state == "missing":
            st.error(
                f"The IDS log folder `{folder}` was not found. Set `IDS_LOG_DIR` "
                "for the dashboard service to the `logs` folder inside your IDS "
                "directory (e.g. `/home/chega/NIDS/logs`) and restart the service. "
                "If the path is right, the dashboard user may be blocked from a "
                "parent folder: `chmod o+x /home/chega`.",
                icon="📁",
            )
        elif state == "unreadable":
            st.error(
                f"The dashboard is not allowed to read `{folder}`. The service "
                "runs as the `dashboard` user, so it must be able to enter every "
                "folder on that path (for a path under `/home/<user>`, run "
                "`chmod o+x /home/<user>`).",
                icon="🔒",
            )
        else:
            st.info(
                f"Reading `{folder}`, but the IDS has not written anything yet. "
                "Run `./venv/bin/python inference.py --live` in the IDS folder to "
                "stream detections here.",
                icon="💤",
            )
        return

    # ── Headline numbers ──────────────────────────────────────────────────
    last_run = None if runs.empty else runs.iloc[0]
    cols = st.columns(4)
    seen = stats["last_seen"]
    ui.tile(cols[0], "Confirmed threats", stats["detections"],
            "last " + seen.strftime("%H:%M:%S UTC") if pd.notna(seen) else "",
            theme.CRITICAL if stats["detections"] else theme.GOOD)
    ui.tile(cols[1], "Devices implicated", stats["devices"], "distinct device IDs")
    ui.tile(cols[2], "Enforced by SDN", stats["enforced"],
            "quarantined or throttled", theme.GOOD)
    ui.tile(cols[3], "Not enforced", stats["unenforced"],
            "no MAC mapping, or gateway unreachable",
            theme.SERIOUS if stats["unenforced"] else theme.GOOD)

    if stats["unenforced"]:
        st.warning(
            f"{stats['unenforced']} detection(s) never became a network action. "
            "Map each device_id to its MAC in `config.SDN_DEVICE_MACS` so the "
            "gateway can act on them.",
            icon="⚠️",
        )

    st.divider()

    # ── Detections over time + per-tier confidence ────────────────────────
    left, right = st.columns([1, 1])
    with left:
        ui.panel("Detections over time", "Hover a bar for the threat types in it.")
        ui.chart(charts.detections_over_time(detections))
        ui.panel("Detections by type")
        ui.chart(charts.horizontal_magnitude(
            charts.type_counts(detections), "count", "type", "Detections",
            value_format=".0f"))
    with right:
        ui.panel("Tier confidence per detection",
                 "Which tier drove each confirmation.")
        ui.chart(charts.tier_scores(detections))

    # ── Gating + latency: the cost side of the same pipeline ──────────────
    st.divider()
    left, right = st.columns([1, 1])
    with left:
        ui.panel("Latency by stage", "Mean milliseconds in the most recent run.")
        latency_df, latest = ids.latest_latency(runs)
        ui.chart(charts.horizontal_magnitude(
            latency_df, "mean_ms", "stage", "Mean ms", value_format=".2f"))
    with right:
        ui.panel("Tier 1 gate", "How often Tier 1 escalated a window to Tier 2.")
        if last_run is not None:
            windows = int(last_run.get("windows_processed") or 0)
            opened = int(last_run.get("gate_open_count") or 0)
            share = opened / windows if windows else 0
            cols = st.columns(3)
            ui.tile(cols[0], "Windows", windows, "in the last run")
            ui.tile(cols[1], "Escalated", opened, f"{share:.0%} of windows",
                    theme.WARNING)
            ui.tile(cols[2], "Tier 2 skipped", windows - opened,
                    f"{1 - share:.0%} ran Tier 1 only", theme.GOOD)
            st.caption(
                f"Mode: {last_run.get('mode', 'batch')} · "
                f"gated={last_run.get('gated')} · "
                f"total {last_run.get('total_ms', 0):.0f} ms"
            )
        else:
            st.markdown("<div class='panel-note'>No runs recorded yet.</div>",
                        unsafe_allow_html=True)

    # ── The detections themselves, joined to live SDN state ───────────────
    st.divider()
    ui.panel("Confirmed threats",
             "Newest first. 'SDN now' is each device's current gateway status.")
    if detections.empty:
        st.markdown(
            "<div class='panel-note'>No threats confirmed yet — the ensemble is "
            "running and has not flagged anything so far.</div>",
            unsafe_allow_html=True,
        )
        return
    devices, _ = sdn.get_devices()
    table = detections.copy()
    table["sdn_now"] = table.apply(
        lambda row: ui.STATUS_LABELS.get(
            (devices.get(ids.device_mac(row), {}) or {}).get("status"), "—"),
        axis=1,
    )
    table["enforced"] = table["enforced"].map({True: "✅ Yes", False: "⚠️ No"})
    columns = [c for c in ("timestamp", "device_id", "device_mac", "threat_type",
                           "fused_confidence", "isolation_forest", "autoencoder",
                           "lstm", "enforced", "sdn_action", "sdn_now",
                           "sdn_detail") if c in table.columns]
    ui.dataframe(
        table[columns],
        hide_index=True,
        column_config={
            "timestamp": st.column_config.DatetimeColumn("Seen", format="HH:mm:ss"),
            "device_id": "Device",
            "device_mac": "MAC",
            "threat_type": "Threat",
            "fused_confidence": st.column_config.ProgressColumn(
                "Fused confidence", min_value=0.0, max_value=1.0, format="%.2f"),
            "isolation_forest": st.column_config.NumberColumn("Tier 1 IF", format="%.2f"),
            "autoencoder": st.column_config.NumberColumn("Tier 2a AE", format="%.2f"),
            "lstm": st.column_config.NumberColumn("Tier 2b LSTM", format="%.2f"),
            "enforced": "Enforced",
            "sdn_action": "SDN action",
            "sdn_now": "SDN now",
            "sdn_detail": "Detail",
        },
    )


live_view()

# ── Model card: static until train.py runs again ──────────────────────────
report = ids.get_model_report()
st.divider()
ui.panel("Model card", "From the most recent training run.")
if not report:
    st.markdown(
        "<div class='panel-note'>No training report yet. Run "
        "<code>python3 train.py</code> in <code>secure_medinet_ids/</code>.</div>",
        unsafe_allow_html=True,
    )
else:
    cols = st.columns(4)
    ui.tile(cols[0], "Trained", str(report.get("trained_at", ""))[:16].replace("T", " "),
            f"{report.get('rows', 0):,} rows")
    ui.tile(cols[1], "Fusion", str(report.get("fusion_mode", "—")).title(),
            "tier score combination")
    attack = (report.get("binary_report") or {}).get("attack_window") or {}
    ui.tile(cols[2], "Attack recall", f"{attack.get('recall', 0):.0%}",
            "of attack windows confirmed", theme.GOOD)
    ui.tile(cols[3], "Attack precision", f"{attack.get('precision', 0):.0%}",
            "of confirmations were real")

    left, right = st.columns([1, 1])
    with left:
        ui.panel("Recall per attack type")
        recall = report.get("per_attack_recall") or {}
        recall_df = pd.DataFrame(
            [{"attack": name, "recall": vals.get("recall", 0),
              "windows": vals.get("windows", 0)}
             for name, vals in recall.items()]
        )
        ui.chart(charts.horizontal_magnitude(
            recall_df, "recall", "attack", "Recall", value_format=".0%",
            domain=[0, 1]), "No per-attack figures in the report.")
    with right:
        ui.panel("Confusion matrix", "Rows = truth, columns = decision.")
        matrix = report.get("confusion_matrix")
        labels = report.get("confusion_labels") or ["normal", "attack"]
        if matrix:
            ui.dataframe(
                pd.DataFrame(matrix, index=labels,
                             columns=[f"called {l}" for l in labels]))
        thresholds = report.get("thresholds") or {}
        st.caption(" · ".join(f"{k}={v}" for k, v in thresholds.items()))
