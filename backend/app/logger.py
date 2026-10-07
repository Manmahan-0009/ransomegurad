"""
RansomGuard - Structured Live Prediction Logger (backend/app/logger.py)

Logs every live prediction window to persistent local JSONL format (logs/live_predictions.jsonl).
Captures features, ML probabilities, rule triggers, scores, severity, debounce status, and configuration metadata.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from .config import config, DetectionConfig


class LivePredictionLogger:
    """
    Appends structured prediction JSON objects to logs/live_predictions.jsonl.
    """

    def __init__(self, log_file: Optional[Path] = None, cfg: Optional[DetectionConfig] = None):
        self.cfg = cfg or config
        self.log_file = log_file or self.cfg.log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log(self, record: Dict[str, Any]) -> None:
        """
        Formats and writes a single prediction window entry to JSONL.
        """
        try:
            version_info = record.get("version_info", {})
            ml_info = record.get("ml", {})
            rules_info = record.get("rules", {})
            debounce_info = record.get("debounce", {})

            entry = {
                "timestamp": record.get("timestamp") or datetime.now().isoformat(),
                "window_start": record.get("window_start"),
                "window_end": record.get("window_end"),
                "scenario_id": record.get("scenario_id", "live"),
                "prediction": record.get("prediction"),
                "threat_probability": ml_info.get("threat_probability"),
                "benign_probability": ml_info.get("benign_probability"),
                "rule_score": rules_info.get("rule_score"),
                "final_threat_score": record.get("threat_score"),
                "severity": record.get("severity"),
                "debounced_severity": debounce_info.get("debounced_severity"),
                "debounced_alert": debounce_info.get("debounced_alert"),
                "triggered_rules": [r["rule"] for r in rules_info.get("triggered_rules", [])],
                "features": record.get("features", {}),
                "model_version": version_info.get("model_version", self.cfg.model_version),
                "feature_schema_version": version_info.get("feature_schema_version", self.cfg.feature_schema_version),
                "rf_threshold": version_info.get("rf_threshold", self.cfg.rf_threshold),
                "ml_weight": version_info.get("ml_weight", self.cfg.ml_weight),
                "rule_weight": version_info.get("rule_weight", self.cfg.rule_weight),
            }

            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

        except Exception as err:
            print(f"[LOGGER WARNING] Failed to record live prediction log: {err}")
