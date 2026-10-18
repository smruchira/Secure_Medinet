# Secure Medinet

An integrated research codebase for secure medical IoT monitoring, ECG anomaly detection, behavioral token binding, and software-defined network response.

## Components

- `behavioural_token_binding/`: behavioral profiling, token verification, revocation, and MQTT integration.
- `ecg_hids_final/`: ECG monitoring pipeline with edge processing and a cloud detection service.
- `SDN/`: SDN gateway, device discovery, access controls, and quarantine API.
- `secure_medinet_ids/`: multimodel intrusion detection, feature processing, fusion, and SDN integration.

## Getting started

Each component has its own dependencies and setup instructions. See its `README.md` and `requirements.txt` where present. Some SDN deployment steps require Raspberry Pi OS, Open vSwitch, and Faucet.

## Sensitive and generated files

Runtime JSONL logs are excluded because they can contain patient or device identifiers. Python caches and local environment files are also excluded. Model artifacts and project source files are included.

The SDN setup script requires `SDN_WIFI_PASSWORD` to be set to a WPA passphrase (8 to 63 characters) before it runs; do not commit real credentials.