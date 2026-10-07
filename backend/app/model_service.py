import json
from pathlib import Path

import joblib
import pandas as pd


class ModelService:
    """
    Handles loading the trained RansomGuard model
    and making predictions.
    """

    def __init__(self):
        # ----------------------------------------------------
        # Find the project root
        # ----------------------------------------------------

        self.project_root = Path(__file__).resolve().parent.parent.parent

        # ----------------------------------------------------
        # Model files
        # ----------------------------------------------------

        self.model_path = (
            self.project_root
            / "models"
            / "ransomguard_rf.joblib"
        )

        self.metadata_path = (
            self.project_root
            / "models"
            / "model_metadata.json"
        )

        # ----------------------------------------------------
        # Load model
        # ----------------------------------------------------

        self.model = joblib.load(self.model_path)

        # ----------------------------------------------------
        # Load metadata
        # ----------------------------------------------------

        with open(
            self.metadata_path,
            "r",
            encoding="utf-8"
        ) as file:
            self.metadata = json.load(file)

        # ----------------------------------------------------
        # Extract configuration
        # ----------------------------------------------------

        self.feature_columns = self.metadata[
            "feature_columns"
        ]

        self.threshold = float(
            self.metadata[
                "selected_threshold"
            ]
        )

    def predict(self, features: dict) -> dict:
        """
        Run the trained model against one behavioral
        feature window.
        """

        # ----------------------------------------------------
        # Make sure every required feature exists
        # ----------------------------------------------------

        missing_features = [
            feature
            for feature in self.feature_columns
            if feature not in features
        ]

        if missing_features:
            raise ValueError(
                f"Missing features: {missing_features}"
            )

        # ----------------------------------------------------
        # Put features into the exact order expected
        # by the model
        # ----------------------------------------------------

        feature_data = {
            feature: features[feature]
            for feature in self.feature_columns
        }

        dataframe = pd.DataFrame(
            [feature_data]
        )

        # ----------------------------------------------------
        # Get probabilities
        # ----------------------------------------------------

        probabilities = self.model.predict_proba(
            dataframe
        )[0]

        benign_probability = float(
            probabilities[0]
        )

        threat_probability = float(
            probabilities[1]
        )

        # ----------------------------------------------------
        # Apply saved threshold
        # ----------------------------------------------------

        prediction = (
            "THREAT"
            if threat_probability >= self.threshold
            else "BENIGN"
        )

        # ----------------------------------------------------
        # Return clean result
        # ----------------------------------------------------

        return {
            "prediction": prediction,
            "benign_probability": benign_probability,
            "threat_probability": threat_probability,
            "threshold": self.threshold,
        }