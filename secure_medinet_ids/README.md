# Secure-MediNet — Edge IDS Ensemble (Member 3 Component)

Real-time, edge-resident machine learning module for the Secure-MediNet home-IoMT
project. Extracts gateway-level network metadata, runs a three-tier ensemble
(Isolation Forest -> AutoEncoder -> LSTM) to confirm threats flagged by the cloud
detector, and triggers the SDN controller (`smruchira/SDN`) to quarantine the
offending device.

This is a **working, tested pipeline running on synthetic data** standing in for
the real Mininet-WiFi export. Every module below has been executed end-to-end in
development — it is not untested scaffolding. Swap in the real dataset (see
"Moving to real data") and retrain before reporting any numbers.

---

## 1. Novelty framing (for your writeup)

Combining Isolation Forest + AutoEncoder + LSTM is **not**, by itself, a novel
contribution — this ensemble pattern appears throughout IDS literature. Claim
novelty in the places this codebase actually earns it:

1. **Rare-attack recall under severe class imbalance.** The project's stated goal
   is detecting *rare* MITM/replay/spoofing/DDoS events. This codebase treats that
   as a first-class design constraint, not an afterthought:
   - class-weighted LSTM loss (`config.LSTM_CLASS_WEIGHTING`)
   - percentile-calibrated AutoEncoder threshold from held-out normal data, not a
     guessed constant
   - a stacked meta-learner (logistic regression) instead of hand-tuned voting
     weights, so "how did you pick the weights" has a real answer
   - per-attack-class recall reporting (not just accuracy, which is meaningless
     under this imbalance — see `utils/metrics.py`)

2. **Latency-aware edge deployment.** The hierarchical gating
   (`config.GATED_PIPELINE`) only runs the expensive Tier 2 models when Tier 1
   flags a window. `inference.py` measures and reports the actual compute-time
   saving of this design on real hardware — that empirical latency/accuracy
   tradeoff is a legitimate systems contribution independent of the ML novelty
   claim.

3. **Closed-loop cloud-alert -> edge-confirm -> SDN-quarantine architecture.**
   Separate from the ML contribution: an end-to-end automated mitigation loop for
   a home-IoMT-over-WiFi threat model is less saturated in the literature than
   enterprise/industrial IoT IDS work.

Do **not** claim novelty for "we used three ML models" alone — reviewers will
find prior art immediately.

---

## 2. Architecture

```
raw gateway metadata (CSV)
        |
        v
FeatureExtractor  (preprocessing/feature_extraction.py)
  - encodes categoricals, scales numerics
        |
        +--------------------------------------------------+
        v                                                   v
Tier 1: Isolation Forest                          sliding windows (LSTM input)
  (models/isolation_forest_model.py)               (preprocessing/windowing.py)
  - runs on EVERY sample, cheap                             |
  - gates Tier 2 (config.GATED_PIPELINE)                    v
        |                                          Tier 2b: LSTM
        | (if gate open)                            (models/lstm_model.py)
        v                                            - class-weighted binary
Tier 2a: AutoEncoder                                  attack/normal classifier
  (models/autoencoder_model.py)                              |
  - trained on NORMAL traffic only                           |
  - reconstruction error -> anomaly score                    |
        |                                                     |
        +----------------------+------------------------------+
                               v
              window-level score alignment (fusion/align.py)
                               v
                DecisionEngine (fusion/decision_engine.py)
              - stacked logistic-regression fusion (or fixed weights)
              - outputs: fused confidence + confirmed (bool)
                               |
                 (only if confirmed == True)
                               v
        ThreatTypeClassifier (fusion/threat_classifier.py)
      - best-effort attack-type label from ensemble outputs only
      - NEVER uses ground truth (none exists at real inference time)
                               v
              SDN trigger (sdn_integration/sdn_trigger.py)
            - REST POST (default) / MQTT / raw socket
            - sends {device_id, threat_type, confidence, timestamp}
                               v
                 smruchira/SDN controller -> quarantines device
```

---

## 3. Project layout

```
secure_medinet_ids/
├── config.py                       # single source of truth for schema/params
├── requirements.txt
├── train.py                        # end-to-end training orchestrator
├── inference.py                    # real-time gateway simulation loop
├── data/
│   ├── synthetic_data_generator.py # demo dataset (DELETE once real data lands)
│   └── gateway_metadata.csv        # generated demo data
├── preprocessing/
│   ├── feature_extraction.py       # encode/scale, persisted with joblib
│   └── windowing.py                # sliding windows for LSTM input
├── models/
│   ├── isolation_forest_model.py   # Tier 1
│   ├── autoencoder_model.py        # Tier 2a (PyTorch)
│   └── lstm_model.py               # Tier 2b (PyTorch)
├── fusion/
│   ├── align.py                    # per-packet -> per-window score alignment
│   ├── decision_engine.py          # weighted voting / stacked meta-learner
│   └── threat_classifier.py        # post-confirmation attack-type labeling
├── sdn_integration/
│   └── sdn_trigger.py              # REST / MQTT / socket transport to SDN
├── utils/
│   └── metrics.py                  # per-class reports, latency profiling
└── saved_models/                   # joblib/state_dict artifacts after train.py
```

---

## 4. Running it

```bash
pip install -r requirements.txt

# 1. Generate demo data (skip once you have the real Mininet-WiFi export)
python3 data/synthetic_data_generator.py

# 2. Train the full ensemble + fusion + threat classifier
python3 train.py

# 3. Simulate the real-time gateway loop (gated vs ungated latency comparison,
#    fires SDN trigger calls -- will fail gracefully against the placeholder
#    endpoint in config.py until you set a real one)
python3 inference.py
```

---

## 5. Moving to real data

1. Replace the placeholder names in `config.NUMERIC_FEATURES` /
   `CATEGORICAL_FEATURES` with the exact column names your Mininet-WiFi
   extraction pipeline (Member 1/2) produces. Nothing else needs to change —
   every downstream module reads from `config.py`.
2. Point `config.RAW_DATA_PATH` at the real CSV export, or overwrite
   `data/gateway_metadata.csv`.
3. Delete or stop calling `data/synthetic_data_generator.py`.
4. Re-run `train.py`. Do not report the numbers currently produced by the
   synthetic demo data as project results — they exist only to prove the
   pipeline runs correctly end-to-end.
5. Set the real values for `config.SDN_REST_ENDPOINT` (or the MQTT/socket
   equivalents) once `smruchira/SDN`'s controller API is finalized.

---

## 6. Known limitations of the current demo run (read before your next meeting)

These are genuine findings from testing this codebase, not hypothetical caveats:

- **LSTM generalization gap on `replay`.** With only ~3 synthetic training
  bursts for the replay pattern (a genuinely subtle temporal signature — low
  timing variance rather than a loud statistical spike), the LSTM scores
  training-set replay windows well but the held-out test burst nearly at zero.
  This is very likely overfitting to burst-specific artifacts rather than the
  general pattern, and should be re-evaluated once the real dataset supplies
  more distinct replay instances. Consider also: per-attack-type auxiliary
  losses instead of binary attack/normal supervision, so a loud attack type
  (e.g. DDoS) doesn't dominate the gradient and starve subtler ones.
- **Precision is currently mediocre (~0.48) at the default fusion threshold**
  on this tiny synthetic set — recall on attacks is prioritized by design, but
  this trades off false positives on normal traffic. Worth tuning
  `config.FUSION_CONFIRM_THRESHOLD` against a real validation set once you have
  more data than this demo provides.
- **The threat-type classifier (`fusion/threat_classifier.py`) is a genuinely
  separate, optional add-on** to correctly avoid label leakage (see below) —
  it is not part of the core three-tier ensemble described in the original
  spec, and its accuracy (~48% on the demo set) reflects how little labeled
  attack data currently exists, not a flaw in the ensemble's core confirm/deny
  decision.
- **A real bug caught and fixed during development, worth mentioning in your
  report as evidence of testing rigor**: an early version of `inference.py`
  filled the SDN payload's `threat_type` field from ground-truth labels, which
  is unavailable at real inference time. Fixed by adding the post-confirmation
  `ThreatTypeClassifier`, which uses only the ensemble's own outputs.
- **Tier 1 was the actual latency bottleneck in profiling, not Tier 2 — the
  opposite of the design's starting assumption.** `inference.py`'s gated vs.
  ungated comparison measured Isolation Forest's per-window `decision_function`
  call at ~14ms, versus ~0.4ms (AutoEncoder) and ~0.7ms (LSTM) combined. Gating
  therefore saved close to nothing in this run, because the thing being gated
  (Tier 2) was never the expensive part — sklearn's per-call Python overhead on
  a 50-row micro-batch dominates. This is a genuinely useful empirical result:
  before claiming a latency benefit from hierarchical gating in your report,
  re-profile on the real SBC hardware and consider batching multiple windows
  into a single Isolation Forest call to amortize that per-call overhead,
  rather than assuming Tier 1 is "cheap" by construction.

---

## 7. Extension points if you have time before submission

- Swap the stacked logistic-regression fusion for a small MLP if the three
  tier scores turn out to have non-linear interactions worth capturing.
- Add per-device baselining (separate AutoEncoder thresholds per
  `device_id`) if different IoMT device types have very different normal
  traffic profiles.
- Add a lightweight explainability layer (e.g. which raw feature drove the
  AutoEncoder's reconstruction error) for the SDN payload / audit log.
