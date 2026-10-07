"""
RansomGuard - Model Training Pipeline v2 (training/train_model_v2.py)

Trains Random Forest Classifier v2 ONLY on the training split (data/splits/train.csv).
Saves candidate artifacts separately:
- models/ransomguard_rf_v2.joblib
- models/model_metadata_v2.json
- models/feature_importance_v2.json

Preserves v1 baseline artifacts untouched.
"""

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SPLITS_DIR = PROJECT_ROOT / "data" / "splits"
MODELS_DIR = PROJECT_ROOT / "models"

TRAIN_FILE = SPLITS_DIR / "train.csv"
VALIDATION_FILE = SPLITS_DIR / "validation.csv"
TEST_FILE = SPLITS_DIR / "test.csv"

RANDOM_SEED = 42
FEATURE_COLUMNS = [
    "files_created",
    "files_modified",
    "files_deleted",
    "files_renamed",
    "writes_per_second",
    "unique_extensions",
    "unique_directories",
    "extension_change_count",
    "rename_ratio",
    "mean_entropy",
    "entropy_change",
]
TARGET_COLUMN = "label"


def train_v2_model() -> None:
    print("=" * 60)
    print("      RANSOMGUARD MODEL V2 TRAINING (EXPANDED DATASET)      ")
    print("=" * 60)

    train_df = pd.read_csv(TRAIN_FILE)
    val_df = pd.read_csv(VALIDATION_FILE)
    test_df = pd.read_csv(TEST_FILE)

    print(f"Train Rows      : {len(train_df)} (Positives: {train_df['label'].sum()})")
    print(f"Validation Rows : {len(val_df)} (Positives: {val_df['label'].sum()})")
    print(f"Test Rows       : {len(test_df)} (Positives: {test_df['label'].sum()})")

    X_train = train_df[FEATURE_COLUMNS]
    y_train = train_df[TARGET_COLUMN]

    model_v2 = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    model_v2.fit(X_train, y_train)
    print("\n[SUCCESS] Random Forest v2 fit on train split complete.")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path_v2 = MODELS_DIR / "ransomguard_rf_v2.joblib"
    metadata_path_v2 = MODELS_DIR / "model_metadata_v2.json"
    importance_path_v2 = MODELS_DIR / "feature_importance_v2.json"

    # Save model
    joblib.dump(model_v2, model_path_v2)

    # Feature importances
    feature_importance = {
        feature: float(importance)
        for feature, importance in zip(FEATURE_COLUMNS, model_v2.feature_importances_)
    }
    feature_importance = dict(
        sorted(feature_importance.items(), key=lambda item: item[1], reverse=True)
    )

    with open(importance_path_v2, "w", encoding="utf-8") as f:
        json.dump(feature_importance, f, indent=2)

    metadata = {
        "model_version": "rf_v2",
        "feature_schema_version": "v1",
        "model_family": "RandomForestClassifier",
        "random_seed": RANDOM_SEED,
        "n_estimators": 200,
        "class_weight": "balanced",
        "feature_columns": FEATURE_COLUMNS,
        "target_column": TARGET_COLUMN,
        "train_rows": int(len(train_df)),
        "validation_rows": int(len(val_df)),
        "test_rows": int(len(test_df)),
        "train_positive": int(y_train.sum()),
        "validation_positive": int(val_df["label"].sum()),
        "test_positive": int(test_df["label"].sum()),
    }

    with open(metadata_path_v2, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("\nSaved v2 Artifacts:")
    print(f"  Model      : {model_path_v2}")
    print(f"  Metadata   : {metadata_path_v2}")
    print(f"  Importance : {importance_path_v2}")
    print("=" * 60)


if __name__ == "__main__":
    train_v2_model()
