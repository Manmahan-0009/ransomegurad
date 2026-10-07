class ThreatScoreEngine:
    """
    Combines ML probability and deterministic rule score
    into a single 0-100 threat score.

    Weights and severity thresholds are configurable pilot values.
    """

    def __init__(
        self,
        ml_weight: float = 0.60,
        rule_weight: float = 0.40,
        critical_thresh: float = 80.0,
        high_thresh: float = 60.0,
        medium_thresh: float = 30.0,
    ):
        self.ml_weight = ml_weight
        self.rule_weight = rule_weight
        self.critical_thresh = critical_thresh
        self.high_thresh = high_thresh
        self.medium_thresh = medium_thresh

    def calculate(
        self,
        threat_probability: float,
        rule_score: int,
    ) -> dict:

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