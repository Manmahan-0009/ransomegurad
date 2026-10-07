"""
RansomGuard - Centralized Detection & System Configuration (backend/app/config.py)

Single source of truth for detection thresholds, fusion weights,
severity boundaries, and debounce settings.

CALIBRATED VERSION: rf_v2 (Trained on 30-run expanded dataset, calibrated on validation).
"""

from pathlib import Path
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parents[2]


class DetectionConfig(BaseModel):
    # Model Metadata & Versioning
    model_version: str = "rf_v2"
    feature_schema_version: str = "v1"

    # ML Inference Parameters (Calibrated on Validation)
    rf_threshold: float = Field(default=0.20, description="Random Forest classification threshold (v2 Calibrated)")
    ml_weight: float = Field(default=0.70, description="Fusion weight for ML score (v2 Calibrated)")
    rule_weight: float = Field(default=0.30, description="Fusion weight for Rule Engine score (v2 Calibrated)")

    # Rule Engine Pilot Thresholds (Calibrated on Validation)
    writes_per_sec_thresh: float = Field(default=20.0, description="Writes per second threshold")
    files_modified_thresh: int = Field(default=30, description="Mass modification file count threshold")
    mean_entropy_thresh: float = Field(default=7.0, description="Shannon entropy threshold 0-8 scale")
    entropy_change_thresh: float = Field(default=1.5, description="Entropy increase threshold")
    ext_change_count_thresh: int = Field(default=3, description="Extension change count threshold")
    rename_ratio_thresh: float = Field(default=0.50, description="Rename ratio threshold")
    min_rename_count: int = Field(default=5, description="Minimum rename count to trigger HIGH_RENAME_ACTIVITY")

    # Severity Score Boundaries (Calibrated on Validation)
    critical_thresh: float = Field(default=80.0, description="Score threshold for CRITICAL severity")
    high_thresh: float = Field(default=60.0, description="Score threshold for HIGH severity")
    medium_thresh: float = Field(default=30.0, description="Score threshold for MEDIUM severity")

    # Debounce / Consecutive Window Confirmation
    consecutive_windows_required: int = Field(default=2, description="Required consecutive HIGH windows for confirmed alert")
    immediate_critical_score: float = Field(default=85.0, description="Threat score threshold for immediate alert bypass")

    # Persistent Live Prediction Logging Path
    log_dir: Path = Field(default_factory=lambda: BASE_DIR / "logs")
    log_file: Path = Field(default_factory=lambda: BASE_DIR / "logs" / "live_predictions.jsonl")


# Global default configuration instance
config = DetectionConfig()
