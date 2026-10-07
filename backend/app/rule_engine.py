class RuleEngine:
    """
    Deterministic behavioral rules for RansomGuard.

    Evaluates numerical telemetry using configurable pilot thresholds.
    Unit correction: mean_entropy is evaluated on a 0-8 Shannon entropy scale
    (high entropy >= 7.0 bits/byte).
    """

    def __init__(
        self,
        writes_per_sec_thresh: float = 20.0,
        files_modified_thresh: int = 30,
        mean_entropy_thresh: float = 7.0,  # Pilot threshold (0-8 Shannon entropy scale)
        entropy_change_thresh: float = 1.5,  # Pilot threshold (0-8 bits/byte scale)
        ext_change_count_thresh: int = 3,
        rename_ratio_thresh: float = 0.50,
    ):
        self.writes_per_sec_thresh = writes_per_sec_thresh
        self.files_modified_thresh = files_modified_thresh
        self.mean_entropy_thresh = mean_entropy_thresh
        self.entropy_change_thresh = entropy_change_thresh
        self.ext_change_count_thresh = ext_change_count_thresh
        self.rename_ratio_thresh = rename_ratio_thresh

    def evaluate(self, features: dict) -> dict:

        triggered_rules = []
        rule_score = 0

        # ----------------------------------------------------
        # Rule 1: High write rate
        # ----------------------------------------------------

        if features["writes_per_second"] >= self.writes_per_sec_thresh:

            triggered_rules.append({
                "rule": "HIGH_WRITE_RATE",
                "description": "Unusually high file write activity",
                "points": 20,
            })

            rule_score += 20

        # ----------------------------------------------------
        # Rule 2: Mass file modification
        # ----------------------------------------------------

        if features["files_modified"] >= self.files_modified_thresh:

            triggered_rules.append({
                "rule": "MASS_FILE_MODIFICATION",
                "description": "Large number of files modified",
                "points": 20,
            })

            rule_score += 20

        # ----------------------------------------------------
        # Rule 3: High entropy (0-8 Shannon entropy scale)
        # ----------------------------------------------------

        if features["mean_entropy"] >= self.mean_entropy_thresh:

            triggered_rules.append({
                "rule": "HIGH_ENTROPY",
                "description": "Files show unusually high entropy (encryption candidate)",
                "points": 20,
            })

            rule_score += 20

        # ----------------------------------------------------
        # Rule 4: Entropy increase
        # ----------------------------------------------------

        if features["entropy_change"] >= self.entropy_change_thresh:

            triggered_rules.append({
                "rule": "ENTROPY_INCREASE",
                "description": "Significant increase in file entropy",
                "points": 15,
            })

            rule_score += 15

        # ----------------------------------------------------
        # Rule 5: Extension changes
        # ----------------------------------------------------

        if features["extension_change_count"] >= self.ext_change_count_thresh:

            triggered_rules.append({
                "rule": "EXTENSION_CHANGES",
                "description": "Multiple file extension changes detected",
                "points": 10,
            })

            rule_score += 10

        # ----------------------------------------------------
        # Rule 6: High rename activity
        # ----------------------------------------------------

        if features["rename_ratio"] >= self.rename_ratio_thresh:

            triggered_rules.append({
                "rule": "HIGH_RENAME_ACTIVITY",
                "description": "Large proportion of files renamed",
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