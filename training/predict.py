"""
RansomGuard Stage 4C
Standalone ML prediction.

Loads the trained Random Forest and converts
one behavioral telemetry window into:

- benign probability
- threat probability
- classification
"""

from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "ransomguard_rf.joblib"
)

METADATA_PATH = (
    PROJECT_ROOT
    / "models"
    / "model_metadata.json"
)


# ============================================================
# LOAD MODEL CONFIGURATION
# ============================================================

model = joblib.load(MODEL_PATH)

metadata = pd.read_json(
    METADATA_PATH,
    typ="series",
)

FEATURE_COLUMNS = metadata["feature_columns"]
THRESHOLD = float(
    metadata["selected_threshold"]
)


# ============================================================
# PREDICTION FUNCTION
# ============================================================

def predict_window(features: dict) -> dict:
    """
    Predict whether one telemetry window
    looks benign or ransomware-like.
    """

    missing_features = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in features
    ]

    if missing_features:
        raise ValueError(
            f"Missing features: {missing_features}"
        )

    row = {
        feature: features[feature]
        for feature in FEATURE_COLUMNS
    }

    dataframe = pd.DataFrame(
        [row],
        columns=FEATURE_COLUMNS,
    )

    probabilities = model.predict_proba(
        dataframe
    )[0]

    benign_probability = float(
        probabilities[0]
    )

    threat_probability = float(
        probabilities[1]
    )

    is_threat = (
        threat_probability >= THRESHOLD
    )

    return {
        "benign_probability": benign_probability,
        "threat_probability": threat_probability,
        "threshold": THRESHOLD,
        "prediction": (
            "THREAT"
            if is_threat
            else "BENIGN"
        ),
    }


# ============================================================
# TEST PREDICTIONS
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("RANSOMGUARD STAGE 4C")
    print("Standalone ML Predictor")
    print("=" * 60)

    # --------------------------------------------------------
    # Benign example
    # --------------------------------------------------------

    benign_window = {
        "files_created": 0,
        "files_modified": 1,
        "files_deleted": 0,
        "files_renamed": 0,
        "writes_per_second": 0.2,
        "unique_extensions": 1,
        "unique_directories": 1,
        "extension_change_count": 0,
        "rename_ratio": 0.0,
        "mean_entropy": 4.73,
        "entropy_change": 0.0,
    }

    benign_result = predict_window(
        benign_window
    )

    print("\nBENIGN TEST WINDOW")
    print("-" * 40)

    print(
        f"Prediction: "
        f"{benign_result['prediction']}"
    )

    print(
        f"Benign probability: "
        f"{benign_result['benign_probability']:.4f}"
    )

    print(
        f"Threat probability: "
        f"{benign_result['threat_probability']:.4f}"
    )

    # --------------------------------------------------------
    # Attack-like example
    # --------------------------------------------------------

    attack_window = {
        "files_created": 1,
        "files_modified": 10,
        "files_deleted": 0,
        "files_renamed": 8,
        "writes_per_second": 5.0,
        "unique_extensions": 6,
        "unique_directories": 5,
        "extension_change_count": 5,
        "rename_ratio": 0.8,
        "mean_entropy": 7.5,
        "entropy_change": 2.5,
    }

    attack_result = predict_window(
        attack_window
    )

    print("\nATTACK-LIKE TEST WINDOW")
    print("-" * 40)

    print(
        f"Prediction: "
        f"{attack_result['prediction']}"
    )

    print(
        f"Benign probability: "
        f"{attack_result['benign_probability']:.4f}"
    )

    print(
        f"Threat probability: "
        f"{attack_result['threat_probability']:.4f}"
    )

    print("\n" + "=" * 60)
    print("STAGE 4C PREDICTOR TEST COMPLETE")
    print("=" * 60)