"""
RansomGuard - Hybrid Threat Score Engine (backend/app/threat_score.py)

Combines ML threat probability and deterministic rule engine score into a single 0-100 threat score.
Uses pilot weights and severity boundaries from centralized config.
"""

from typing import Dict, Any, Optional
from .config import config, DetectionConfig


class ThreatScoreEngine:
    """
    Combines ML probability and deterministic rule score
    into a single 0-100 threat score.
    """

    def __init__(
        self,
        ml_weight: Optional[float] = None,
        rule_weight: Optional[float] = None,
        critical_thresh: Optional[float] = None,
        high_thresh: Optional[float] = None,
        medium_thresh: Optional[float] = None,
        cfg: Optional[DetectionConfig] = None,
    ):
        c = cfg or config
        self.ml_weight = ml_weight if ml_weight is not None else c.ml_weight
        self.rule_weight = rule_weight if rule_weight is not None else c.rule_weight
        self.critical_thresh = critical_thresh if critical_thresh is not None else c.critical_thresh
        self.high_thresh = high_thresh if high_thresh is not None else c.high_thresh
        self.medium_thresh = medium_thresh if medium_thresh is not None else c.medium_thresh

    def calculate(
        self,
        threat_probability: float,
        rule_score: int,
    ) -> Dict[str, Any]:

        # Convert ML probability from 0-1 to 0-100
        ml_score = threat_probability * 100

        # Combine the two sources of evidence using configurable weights
        combined_score = (
            (ml_score * self.ml_weight)
            + (rule_score * self.rule_weight)
        )

        # Keep score between 0 and 100
        combined_score = min(
            max(combined_score, 0),
            100
        )

        # Determine severity using configurable pilot thresholds
        if combined_score >= self.critical_thresh:
            severity = "CRITICAL"
        elif combined_score >= self.high_thresh:
            severity = "HIGH"
        elif combined_score >= self.medium_thresh:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "threat_score": round(
                combined_score,
                2
            ),
            "severity": severity,
        }