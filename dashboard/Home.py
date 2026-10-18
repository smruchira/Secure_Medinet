"""
Home.py
-------
Overview of all Secure MediNet modules. Run from this directory, so
.streamlit/config.toml is picked up:

    streamlit run Home.py
"""

import streamlit as st

import settings
import ui
from sources import sdn

ui.setup_page("Secure MediNet")


@st.fragment(run_every=settings.REFRESH_SEC)
def overview():
    devices, live = sdn.get_devices()
    counts = sdn.status_counts(devices)

    st.subheader("SDN Gateway")
    ui.connection_banner("SDN Gateway", live)
    ui.sdn_metrics(counts)

    flagged = {mac: d for mac, d in devices.items() if d.get("status") != "active"}
    st.markdown("**Devices under enforcement**")
    if flagged:
        ui.devices_table(flagged)
    else:
        st.success("No devices are quarantined or rate-limited.")
    st.page_link("pages/1_SDN_Gateway.py", label="Open SDN Gateway details", icon="➡️")


overview()

st.divider()
st.subheader("Other modules")
cols = st.columns(3)
for col, name in zip(cols, ("ECG HIDS", "Behavioural token binding", "Edge IDS ensemble")):
    col.container(border=True).markdown(f"**{name}**  \nNot connected yet.")
