"""
config.py
=========
Single source of truth for the Secure-MediNet edge IDS module (Member 3 component).

Edit FEATURE_COLUMNS to match the exact schema exported by the Mininet-WiFi
gateway metadata pipeline (Member 1/2's dataset). Nothing else in the codebase
needs to change if the feature list changes -- every module reads from here.
"""

import os

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "saved_models")

RAW_DATA_PATH = os.path.join(DATA_DIR, "gateway_metadata.csv")

# ---------------------------------------------------------------------------
# Feature schema
# ---------------------------------------------------------------------------
# NOTE: These are placeholder names representative of typical gateway-level
# network metadata (packet timing/size stats, protocol flags, TLS/MQTT
# handshake features). REPLACE with the exact column names produced by the
# Mininet-WiFi extraction pipeline before training on the real dataset.
NUMERIC_FEATURES = [
    "packet_size",
    "inter_arrival_time",
    "flow_duration",
    "src_port",
    "dst_port",
    "tls_handshake_time",
    "mqtt_qos",
    "packet_count_window",
    "byte_rate",
    "retransmission_count",
]

CATEGORICAL_FEATURES = [
    "protocol",          # e.g. TCP / UDP / MQTT / TLS
    "tcp_flags",         # e.g. SYN / ACK / FIN / RST combinations
    "direction",         # inbound / outbound
]

FEATURE_COLUMNS = NUMERIC_FEATURES + CATEGORICAL_FEATURES

LABEL_COLUMN = "label"          # multi-class string label
DEVICE_ID_COLUMN = "device_id"  # which IoMT device the flow belongs to
TIMESTAMP_COLUMN = "timestamp"

ATTACK_CLASSES = ["mitm", "replay", "spoofing", "ddos"]
BENIGN_CLASS = "normal"
ALL_CLASSES = [BENIGN_CLASS] + ATTACK_CLASSES

# ---------------------------------------------------------------------------
# Sliding window (LSTM input) parameters
# ---------------------------------------------------------------------------
WINDOW_SIZE = 50        # timesteps per window
WINDOW_STRIDE = 10      # step between consecutive windows
# Labeling rule for a window: "any" = attack if ANY packet in window is an
# attack (favors recall on rare attacks); "majority" = attack if >50% of
# packets are attack. Given the project targets RARE attack detection,
# "any" is the safer default -- see README for rationale.
WINDOW_LABEL_RULE = "any"

# ---------------------------------------------------------------------------
# Class imbalance handling
# ---------------------------------------------------------------------------
USE_SMOTE = True                  # oversample rare attack classes for IF/AE tier
MIN_SAMPLES_FOR_SMOTE = 6         # SMOTE needs >= k_neighbors+1 samples/class
LSTM_CLASS_WEIGHTING = True       # apply inverse-frequency class weights in LSTM loss

# ---------------------------------------------------------------------------
# Tier 1: Isolation Forest
# ---------------------------------------------------------------------------
IFOREST_PARAMS = dict(
    n_estimators=200,
    contamination="auto",
    max_samples="auto",
    random_state=42,
    n_jobs=-1,
)
# Confidence threshold above which Tier 1 flags a sample for Tier 2 scrutiny
IFOREST_GATE_THRESHOLD = 0.55

# ---------------------------------------------------------------------------
# Tier 2: AutoEncoder
# ---------------------------------------------------------------------------
AE_HIDDEN_DIMS = [32, 16, 8, 16, 32]   # symmetric bottleneck architecture
AE_EPOCHS = 30
AE_BATCH_SIZE = 64
AE_LEARNING_RATE = 1e-3
# Reconstruction-error percentile (on validation NORMAL data) used to set
# the anomaly threshold -- calibrated, not guessed.
AE_THRESHOLD_PERCENTILE = 95

# ---------------------------------------------------------------------------
# Tier 2: LSTM
# ---------------------------------------------------------------------------
LSTM_HIDDEN_SIZE = 64
LSTM_NUM_LAYERS = 2
LSTM_DROPOUT = 0.3
LSTM_EPOCHS = 25
LSTM_BATCH_SIZE = 32
LSTM_LEARNING_RATE = 1e-3

# ---------------------------------------------------------------------------
# Decision engine (fusion)
# ---------------------------------------------------------------------------
# Fixed weighted-voting fallback weights (used only if the learned
# meta-learner is unavailable / untrained).
FUSION_WEIGHTS = dict(isolation_forest=0.2, autoencoder=0.35, lstm=0.45)
FUSION_CONFIRM_THRESHOLD = 0.6     # fused confidence needed to confirm a threat
USE_STACKED_META_LEARNER = True    # logistic-regression fusion over tier outputs

# Gating: if True, Tier 2 (AE + LSTM) only runs when Tier 1 flags the sample.
# This is the latency-vs-recall tradeoff central to the edge deployment claim.
GATED_PIPELINE = True

# ---------------------------------------------------------------------------
# SDN integration
# ---------------------------------------------------------------------------
SDN_TRANSPORT = "rest"   # "rest" | "mqtt" | "socket"
SDN_REST_ENDPOINT = "http://<sdn-controller-host>:8080/api/v1/quarantine"
SDN_REST_TIMEOUT_SEC = 3
SDN_REST_MAX_RETRIES = 3

SDN_MQTT_BROKER = "<mqtt-broker-host>"
SDN_MQTT_PORT = 8883
SDN_MQTT_TOPIC = "secure-medinet/sdn/quarantine"

SDN_SOCKET_HOST = "<sdn-controller-host>"
SDN_SOCKET_PORT = 9999

# Random seed for reproducibility across the whole module
RANDOM_SEED = 42
