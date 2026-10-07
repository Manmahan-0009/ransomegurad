"""
RansomGuard - Model Service (backend/app/model_service.py)

Handles loading the trained RansomGuard model and executing predictions against feature vectors.
Attaches model metadata and version information to every prediction response.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
import joblib
import pandas as pd
from .config import config, DetectionConfig


class ModelService:
    """
    Handles loading the trained RansomGuard Random Forest model
    and making predictions.
    """

    def __init__(self, cfg: Optional[DetectionConfig] = None):
        self.cfg = cfg or config
        self.project_root = Path(__file__).resolve().parent.parent.parent

        self.model_path = self.project_root / "models" / "ransomguard_rf_v2.joblib"
        if not self.model_path.exists():
            self.model_path = self.project_root / "models" / "ransomguard_rf.joblib"

        self.metadata_path = self.project_root / "models" / "model_metadata_v2.json"
        if not self.metadata_path.exists():
            self.metadata_path = self.project_root / "models" / "model_metadata.json"

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Trained Random Forest model binary not found at '{self.model_path}'. "
                "Please generate datasets and train the model first by running:\n"
                "  python main.py generate-data --all --runs-per-class 3 --seed 42 --fresh\n"
                "  python main.py split-data --seed 42\n"
                "  python main.py train"
            )

        # Load model
        self.model = joblib.load(self.model_path)

        # Load metadata
        with open(self.metadata_path, "r", encoding="utf-8") as file:
            self.metadata = json.load(file)

        # Extract configuration
        self.feature_columns = self.metadata["feature_columns"]
        # Use threshold from metadata if present, else fallback to config
        self.threshold = float(self.metadata.get("selected_threshold", self.cfg.rf_threshold))
        self.model_version = self.metadata.get("model_version", self.cfg.model_version)
        self.feature_schema_version = self.metadata.get("feature_schema_version", self.cfg.feature_schema_version)

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run the trained model against one behavioral feature window.
        """
        missing_features = [
            feature
            for feature in self.feature_columns
            if feature not in features
        ]

        if missing_features:
            raise ValueError(f"Missing features: {missing_features}")

        # Put features into the exact order expected by the model
        feature_data = {
            feature: features[feature]
            for feature in self.feature_columns
        }

        dataframe = pd.DataFrame([feature_data])

        # Get probabilities
        probabilities = self.model.predict_proba(dataframe)[0]
        benign_probability = float(probabilities[0])
        threat_probability = float(probabilities[1])

        # Apply saved threshold
        prediction = (
            "THREAT"
            if threat_probability >= self.threshold
            else "BENIGN"
        )

        return {
            "prediction": prediction,
            "benign_probability": benign_probability,
            "threat_probability": threat_probability,
            "threshold": self.threshold,
            "model_version": self.model_version,
            "feature_schema_version": self.feature_schema_version,
        }