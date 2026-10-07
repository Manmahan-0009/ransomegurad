"""
RansomGuard - Deterministic Behavioral Rule Engine (backend/app/rule_engine.py)

Evaluates numerical telemetry using configurable pilot thresholds from centralized config.
Unit correction: mean_entropy is evaluated on a 0-8 Shannon entropy scale
(high entropy >= 7.0 bits/byte).
"""

from typing import Dict, Any, Optional
from .config import config, DetectionConfig


class RuleEngine:
    """
    Deterministic behavioral rules for RansomGuard.
    """

    def __init__(
        self,
        writes_per_sec_thresh: Optional[float] = None,
        files_modified_thresh: Optional[int] = None,
        mean_entropy_thresh: Optional[float] = None,
        entropy_change_thresh: Optional[float] = None,
        ext_change_count_thresh: Optional[int] = None,
        rename_ratio_thresh: Optional[float] = None,
        min_rename_count: Optional[int] = None,
        cfg: Optional[DetectionConfig] = None,
    ):
        c = cfg or config
        self.writes_per_sec_thresh = writes_per_sec_thresh if writes_per_sec_thresh is not None else c.writes_per_sec_thresh
        self.files_modified_thresh = files_modified_thresh if files_modified_thresh is not None else c.files_modified_thresh
        self.mean_entropy_thresh = mean_entropy_thresh if mean_entropy_thresh is not None else c.mean_entropy_thresh
        self.entropy_change_thresh = entropy_change_thresh if entropy_change_thresh is not None else c.entropy_change_thresh
        self.ext_change_count_thresh = ext_change_count_thresh if ext_change_count_thresh is not None else c.ext_change_count_thresh
        self.rename_ratio_thresh = rename_ratio_thresh if rename_ratio_thresh is not None else c.rename_ratio_thresh
        self.min_rename_count = min_rename_count if min_rename_count is not None else c.min_rename_count

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered_rules = []
        rule_score = 0

        # ----------------------------------------------------
        # Rule 1: High write rate
        # ----------------------------------------------------
        if features.get("writes_per_second", 0.0) >= self.writes_per_sec_thresh:
            triggered_rules.append({
                "rule": "HIGH_WRITE_RATE",
                "description": f"Unusually high file write activity ({features.get('writes_per_second', 0.0):.1f} w/s)",
                "points": 20,
            })
            rule_score += 20

        # ----------------------------------------------------
        # Rule 2: Mass file modification
        # ----------------------------------------------------
        if features.get("files_modified", 0) >= self.files_modified_thresh:
            triggered_rules.append({
                "rule": "MASS_FILE_MODIFICATION",
                "description": f"Large number of files modified ({features.get('files_modified', 0)} files)",
                "points": 20,
            })
            rule_score += 20

        # ----------------------------------------------------
        # Rule 3: High entropy (0-8 Shannon entropy scale)
        # ----------------------------------------------------
        if features.get("mean_entropy", 0.0) >= self.mean_entropy_thresh:
            triggered_rules.append({
                "rule": "HIGH_ENTROPY",
                "description": f"Files show unusually high entropy ({features.get('mean_entropy', 0.0):.3f} bits/byte)",
                "points": 20,
            })
            rule_score += 20

        # ----------------------------------------------------
        # Rule 4: Entropy increase
        # ----------------------------------------------------
        if features.get("entropy_change", 0.0) >= self.entropy_change_thresh:
            triggered_rules.append({
                "rule": "ENTROPY_INCREASE",
                "description": f"Significant increase in file entropy (+{features.get('entropy_change', 0.0):.3f})",
                "points": 15,
            })
            rule_score += 15

        # ----------------------------------------------------
        # Rule 5: Extension changes
        # ----------------------------------------------------
        if features.get("extension_change_count", 0) >= self.ext_change_count_thresh:
            triggered_rules.append({
                "rule": "EXTENSION_CHANGES",
                "description": f"Multiple file extension changes detected ({features.get('extension_change_count', 0)} changes)",
                "points": 10,
            })
            rule_score += 10

        # ----------------------------------------------------
        # Rule 6: High rename activity (Requires BOTH ratio >= thresh AND count >= min_rename_count)
        # ----------------------------------------------------
        if (
            features.get("rename_ratio", 0.0) >= self.rename_ratio_thresh
            and features.get("files_renamed", 0) >= self.min_rename_count
        ):
            triggered_rules.append({
                "rule": "HIGH_RENAME_ACTIVITY",
                "description": f"High rename ratio ({features.get('rename_ratio', 0.0):.2f}) with >={self.min_rename_count} files renamed",
                "points": 10,
            })
            rule_score += 10

        # ----------------------------------------------------
        # Keep score between 0 and 100
        # ----------------------------------------------------
        rule_score = min(rule_score, 100)

        return {
            "rule_score": rule_score,
            "triggered_rules": triggered_rules,
            "rules_triggered": len(triggered_rules),
        }