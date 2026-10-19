"""
event_log.py
============
Append-only JSONL/JSON writers so an external viewer (the Secure MediNet
dashboard) can see what the IDS did. This module is LOGGING ONLY -- nothing
here influences a detection decision, and a failed write is swallowed with a
warning so logging can never take the detection pipeline down.

Files written (paths come from config, all env-overridable):
  ids_events.jsonl      one line per confirmed threat
  ids_runs.jsonl        one line per inference run
  ids_model_report.json overwritten by train.py each time it runs
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def _write(path: str, line: str, mode: str = "a") -> bool:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, mode, encoding="utf-8") as fh:
            fh.write(line)
        return True
    except OSError as exc:
        print(f"[event_log] could not write {path}: {exc}")
        return False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_sdn_detail(detail):
    """Pull the action/status the SDN gateway chose out of its reply string
    (e.g. "action=block risk=0.905 status=quarantined"). Returns (action,
    status), either of which may be None for an error or skipped send."""
    text = str(detail or "")
    action = re.search(r"action=(\w+)", text)
    status = re.search(r"status=(\w+)", text)
    return (action.group(1) if action else None,
            status.group(1) if status else None)


def log_detection(window_index, device_id, threat_type, fused_confidence,
                  tier_scores, device_mac=None, sdn_ok=None, sdn_detail=None,
                  path=None):
    """Append one confirmed threat. tier_scores maps tier name -> score or
    None (None = that tier was gated off for this window). device_mac is the
    address the SDN gateway enforces on, or None when the device_id has no
    mapping -- it is what lets a viewer line a detection up against the
    gateway's live device state."""
    sdn_action, sdn_status = _parse_sdn_detail(sdn_detail)
    record = {
        "timestamp": _now(),
        "window_index": int(window_index),
        "device_id": str(device_id),
        "device_mac": None if device_mac is None else str(device_mac),
        "threat_type": str(threat_type),
        "fused_confidence": round(float(fused_confidence), 4),
        "tier_scores": {
            name: (None if score is None else round(float(score), 4))
            for name, score in tier_scores.items()
        },
        # What the SDN gateway did with it. enforced=False means this
        # detection never became a network action (unreachable gateway, or
        # the device has no MAC mapping in config.SDN_DEVICE_MACS).
        "enforced": bool(sdn_ok),
        "sdn_action": sdn_action,
        "sdn_status": sdn_status,
        "sdn_detail": None if sdn_detail is None else str(sdn_detail),
    }
    _write(path or config.EVENTS_LOG_PATH, json.dumps(record) + "\n")
    return record


def log_run(windows_processed, gated, confirmed_count, gate_open_count,
            latency_summary, mode="batch", path=None):
    """Append one run summary (latency + gating evidence for the run)."""
    total_ms = sum(
        stage.get("mean", 0.0) * stage.get("n", 0)
        for stage in (latency_summary or {}).values()
    )
    record = {
        "timestamp": _now(),
        "mode": mode,
        "windows_processed": int(windows_processed),
        "gated": bool(gated),
        "confirmed_count": int(confirmed_count),
        "gate_open_count": int(gate_open_count),
        "latency_ms": latency_summary or {},
        "total_ms": round(total_ms, 3),
    }
    _write(path or config.RUNS_LOG_PATH, json.dumps(record) + "\n")
    return record


def write_model_report(report: dict, path=None):
    """Overwrite the training report (one current model state, not history)."""
    record = {"trained_at": _now(), **report}
    _write(path or config.MODEL_REPORT_PATH,
           json.dumps(record, indent=2, default=str), mode="w")
    return record
