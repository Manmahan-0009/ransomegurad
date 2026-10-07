"""
RansomGuard Stage 4A
Random Forest model training and evaluation.

Pipeline:

dataset splits
    ↓
feature selection
    ↓
Random Forest
    ↓
validation threshold selection
    ↓
untouched test evaluation
    ↓
model + metrics + metadata
"""

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SPLITS_DIR = PROJECT_ROOT / "data" / "splits"
MODELS_DIR = PROJECT_ROOT / "models"

TRAIN_FILE = SPLITS_DIR / "train.csv"
VALIDATION_FILE = SPLITS_DIR / "validation.csv"
TEST_FILE = SPLITS_DIR / "test.csv"


# ============================================================
# MODEL CONFIGURATION
# ============================================================

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


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def load_split(path: Path) -> pd.DataFrame:
    """Load one dataset split."""

    if not path.exists():
        raise FileNotFoundError(f"Dataset split not found: {path}")

    df = pd.read_csv(path)

    missing_features = [
        column
        for column in FEATURE_COLUMNS
        if column not in df.columns
    ]

    if missing_features:
        raise ValueError(
            f"Missing feature columns in {path.name}: "
            f"{missing_features}"
        )

    if TARGET_COLUMN not in df.columns:
        raise ValueError(
            f"Missing target column '{TARGET_COLUMN}' "
            f"in {path.name}"
        )

    return df


def evaluate_predictions(
    y_true,
    y_probability,
    threshold,
):
    """Calculate classification metrics for a threshold."""

    y_pred = (y_probability >= threshold).astype(int)

    cm = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    )

    return {
        "threshold": float(threshold),
        "accuracy": float(
            accuracy_score(y_true, y_pred)
        ),
        "precision": float(
            precision_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "f1": float(
            f1_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "roc_auc": float(
            roc_auc_score(
                y_true,
                y_probability,
            )
        ),
        "confusion_matrix": cm.tolist(),
    }


def choose_threshold(y_true, y_probability):
    """
    Choose the validation threshold with the best F1.

    We deliberately choose this using VALIDATION only.
    The test set remains untouched until final evaluation.
    """

    thresholds = np.arange(
        0.10,
        0.96,
        0.05,
    )

    results = []

    for threshold in thresholds:

        metrics = evaluate_predictions(
            y_true,
            y_probability,
            threshold,
        )

        results.append(metrics)

    best = max(
        results,
        key=lambda result: (
            result["f1"],
            result["recall"],
            result["precision"],
        ),
    )

    return best["threshold"], results


# ============================================================
# MAIN TRAINING PIPELINE
# ============================================================

def main():

    print("=" * 60)
    print("RANSOMGUARD STAGE 4A")
    print("Random Forest Model Training")
    print("=" * 60)

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    print("\n[1/7] Loading dataset splits...")

    train_df = load_split(TRAIN_FILE)
    validation_df = load_split(VALIDATION_FILE)
    test_df = load_split(TEST_FILE)

    print(f"Train:      {train_df.shape}")
    print(f"Validation: {validation_df.shape}")
    print(f"Test:       {test_df.shape}")

    # --------------------------------------------------------
    # Prepare features
    # --------------------------------------------------------

    print("\n[2/7] Preparing approved ML features...")

    X_train = train_df[FEATURE_COLUMNS]
    y_train = train_df[TARGET_COLUMN]

    X_validation = validation_df[FEATURE_COLUMNS]
    y_validation = validation_df[TARGET_COLUMN]

    X_test = test_df[FEATURE_COLUMNS]
    y_test = test_df[TARGET_COLUMN]

    print(f"Features: {len(FEATURE_COLUMNS)}")

    for index, feature in enumerate(FEATURE_COLUMNS, start=1):
        print(f"  {index:2}. {feature}")

    # --------------------------------------------------------
    # Train Random Forest
    # --------------------------------------------------------

    print("\n[3/7] Training Random Forest...")

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    model.fit(
        X_train,
        y_train,
    )

    print("Random Forest training complete.")

    # --------------------------------------------------------
    # Validation predictions
    # --------------------------------------------------------

    print("\n[4/7] Evaluating validation set...")

    validation_probability = model.predict_proba(
        X_validation
    )[:, 1]

    validation_auc = roc_auc_score(
        y_validation,
        validation_probability,
    )

    print(
        f"Validation ROC-AUC: "
        f"{validation_auc:.4f}"
    )

    # --------------------------------------------------------
    # Threshold selection
    # --------------------------------------------------------

    print("\n[5/7] Selecting detection threshold...")

    threshold, threshold_results = choose_threshold(
        y_validation,
        validation_probability,
    )

    validation_metrics = evaluate_predictions(
        y_validation,
        validation_probability,
        threshold,
    )

    print(
        f"Selected threshold: "
        f"{threshold:.2f}"
    )

    print(
        f"Validation precision: "
        f"{validation_metrics['precision']:.4f}"
    )

    print(
        f"Validation recall: "
        f"{validation_metrics['recall']:.4f}"
    )

    print(
        f"Validation F1: "
        f"{validation_metrics['f1']:.4f}"
    )

    # --------------------------------------------------------
    # Final test evaluation
    # --------------------------------------------------------

    print("\n[6/7] Evaluating untouched test set...")

    test_probability = model.predict_proba(
        X_test
    )[:, 1]

    test_metrics = evaluate_predictions(
        y_test,
        test_probability,
        threshold,
    )

    print("\nFINAL TEST RESULTS")
    print("-" * 40)

    print(
        f"Accuracy:  "
        f"{test_metrics['accuracy']:.4f}"
    )

    print(
        f"Precision: "
        f"{test_metrics['precision']:.4f}"
    )

    print(
        f"Recall:    "
        f"{test_metrics['recall']:.4f}"
    )

    print(
        f"F1 Score:  "
        f"{test_metrics['f1']:.4f}"
    )

    print(
        f"ROC-AUC:   "
        f"{test_metrics['roc_auc']:.4f}"
    )

    print(
        "\nConfusion Matrix:"
    )

    print(
        np.array(
            test_metrics["confusion_matrix"]
        )
    )

    # --------------------------------------------------------
    # Save artifacts
    # --------------------------------------------------------

    print("\n[7/7] Saving model artifacts...")

    MODELS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    model_path = (
        MODELS_DIR /
        "ransomguard_rf.joblib"
    )

    metadata_path = (
        MODELS_DIR /
        "model_metadata.json"
    )

    metrics_path = (
        MODELS_DIR /
        "metrics.json"
    )

    importance_path = (
        MODELS_DIR /
        "feature_importance.json"
    )

    # Save model
    joblib.dump(
        model,
        model_path,
    )

    # Feature importance
    feature_importance = {
        feature: float(importance)
        for feature, importance
        in zip(
            FEATURE_COLUMNS,
            model.feature_importances_,
        )
    }

    feature_importance = dict(
        sorted(
            feature_importance.items(),
            key=lambda item: item[1],
            reverse=True,
        )
    )

    with open(
        importance_path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            feature_importance,
            file,
            indent=2,
        )

    # Metrics
    metrics = {
        "validation": validation_metrics,
        "test": test_metrics,
        "threshold_search": threshold_results,
    }

    with open(
        metrics_path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metrics,
            file,
            indent=2,
        )

    # Metadata
    metadata = {
        "model": "RandomForestClassifier",
        "random_seed": RANDOM_SEED,
        "n_estimators": 200,
        "class_weight": "balanced",
        "feature_columns": FEATURE_COLUMNS,
        "target_column": TARGET_COLUMN,
        "selected_threshold": float(threshold),
        "train_rows": int(len(train_df)),
        "validation_rows": int(len(validation_df)),
        "test_rows": int(len(test_df)),
        "train_positive": int(y_train.sum()),
        "validation_positive": int(
            y_validation.sum()
        ),
        "test_positive": int(
            y_test.sum()
        ),
    }

    with open(
        metadata_path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metadata,
            file,
            indent=2,
        )

    print("\nSaved:")
    print(f"  {model_path}")
    print(f"  {metadata_path}")
    print(f"  {metrics_path}")
    print(f"  {importance_path}")

    print("\n" + "=" * 60)
    print("STAGE 4A MODEL TRAINING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()