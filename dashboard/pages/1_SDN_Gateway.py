"""
1_SDN_Gateway.py
----------------
SDN Gateway detail view: all devices, filtering, and manual enforcement.
"""

import streamlit as st

import charts
import settings
import ui
from sources import sdn

ui.setup_page(
    "SDN Gateway",
    "Faucet-enforced policy per device MAC on the IoT hotspot.",
)


@st.fragment(run_every=settings.REFRESH_SEC)
def devices_view():
    devices, live = sdn.get_devices()
    counts = sdn.status_counts(devices)
    ui.connection_banner("SDN Gateway", live)
    ui.sdn_tiles(counts)
    ui.chart(charts.device_status_bar(counts))

    ui.panel("Devices")
    left, right = st.columns([1, 2])
    statuses = left.multiselect(
        "Status", sdn.STATUSES, default=sdn.STATUSES, format_func=lambda s: ui.STATUS_LABELS[s]
    )
    query = right.text_input("Search MAC, hostname or IP").strip().lower()
    shown = {
        mac: d for mac, d in devices.items()
        if d.get("status") in statuses
        and (not query or any(query in str(v).lower() for v in (mac, d.get("hostname"), d.get("ip"))))
    }
    st.caption(f"Showing {len(shown)} of {len(devices)} devices · refreshes every {settings.REFRESH_SEC}s")
    ui.devices_table(shown)
    return devices, live


devices, live = devices_view()

st.divider()
st.subheader("Manual enforcement")
if "result" in st.session_state:  # outcome of the last action, kept across the rerun
    ok, message = st.session_state.pop("result")
    (st.success if ok else st.error)(message)

with st.form("enforce"):
    known = sorted(devices)
    picked = st.selectbox("Device", known, index=None, placeholder="Choose a discovered device")
    typed = st.text_input("…or enter a MAC address", placeholder="aa:bb:cc:dd:ee:ff")
    action = st.radio(
        "Action",
        ("restore", "rate_limit", "quarantine"),
        format_func={"restore": "Restore (allow all traffic)", "rate_limit": "Rate-limit",
                     "quarantine": "Quarantine (drop all traffic)"}.get,
        horizontal=True,
    )
    confirmed = st.checkbox("I confirm this changes live network policy")
    submitted = st.form_submit_button("Apply", disabled=not live, type="primary")

if submitted:
    mac = sdn.normalize_mac(typed) if typed.strip() else picked
    if not mac:
        st.error("Choose a device or enter a valid MAC address.")
    elif not confirmed:
        st.error("Tick the confirmation box to apply the action.")
    else:
        st.session_state["result"] = {"restore": sdn.restore, "rate_limit": sdn.rate_limit,
                                      "quarantine": sdn.quarantine}[action](mac)
        st.rerun()  # reload the device list so the change shows immediately
