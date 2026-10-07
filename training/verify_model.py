import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)


# ============================================================
# RANSOMGUARD STAGE 4D
# Independent Model Verification
# ============================================================

print("=" * 60)
print("RANSOMGUARD STAGE 4D")
print("Independent Model Verification")
print("=" * 60)


# ------------------------------------------------------------
# 1. PROJECT PATHS
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = PROJECT_ROOT / "models" / "ransomguard_rf.joblib"
METADATA_PATH = PROJECT_ROOT / "models" / "model_metadata.json"
TEST_PATH = PROJECT_ROOT / "data" / "splits" / "test.csv"


# ------------------------------------------------------------
# 2. LOAD MODEL
# ------------------------------------------------------------

print("\n[1] Loading saved model...")

model = joblib.load(MODEL_PATH)

print("Model loaded successfully.")
print(f"Model type: {type(model).__name__}")


# ------------------------------------------------------------
# 3. LOAD METADATA
# ------------------------------------------------------------

print("\n[2] Loading model metadata...")

with open(METADATA_PATH, "r", encoding="utf-8") as f:
    metadata = json.load(f)

FEATURE_COLUMNS = metadata["feature_columns"]
THRESHOLD = float(metadata["selected_threshold"])

print("Metadata loaded successfully.")
print(f"Features: {len(FEATURE_COLUMNS)}")
print(f"Decision threshold: {THRESHOLD:.2f}")


# ------------------------------------------------------------
# 4. LOAD TEST DATA
# ------------------------------------------------------------

print("\n[3] Loading untouched test set...")

test_df = pd.read_csv(TEST_PATH)

print(f"Test rows: {len(test_df)}")


# ------------------------------------------------------------
# 5. CHECK FEATURES
# ------------------------------------------------------------

print("\n[4] Checking feature schema...")

missing_features = [
    feature
    for feature in FEATURE_COLUMNS
    if feature not in test_df.columns
]

if missing_features:
    raise ValueError(
        f"Missing required features: {missing_features}"
    )

X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["label"]


# ------------------------------------------------------------
# 6. CHECK FOR MISSING VALUES
# ------------------------------------------------------------

print("\n[5] Checking for missing values...")

missing_values = X_test.isna().sum().sum()

if missing_values > 0:
    raise ValueError(
        f"Found {missing_values} missing feature values."
    )

print("No missing feature values found.")


# ------------------------------------------------------------
# 7. MODEL PREDICTIONS
# ------------------------------------------------------------

print("\n[6] Running model predictions...")

probabilities = model.predict_proba(X_test)[:, 1]

predictions = (
    probabilities >= THRESHOLD
).astype(int)

print("Predictions generated successfully.")


# ------------------------------------------------------------
# 8. CALCULATE METRICS
# ------------------------------------------------------------

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)
recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)
f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)
roc_auc = roc_auc_score(
    y_test,
    probabilities
)

matrix = confusion_matrix(
    y_test,
    predictions
)


# ------------------------------------------------------------
# 9. DISPLAY RESULTS
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("INDEPENDENT TEST RESULTS")
print("=" * 60)

print(f"Accuracy:  {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1 Score:  {f1:.4f}")
print(f"ROC-AUC:   {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(matrix)


# ------------------------------------------------------------
# 10. VERIFY EXPECTED RESULTS
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("VERIFICATION")
print("=" * 60)

expected_matrix = [
    [42, 0],
    [0, 5]
]

if matrix.tolist() == expected_matrix:
    print("PASS: Confusion matrix matches Stage 4A.")
else:
    print("WARNING: Confusion matrix differs from Stage 4A.")

if (
    accuracy == 1.0
    and precision == 1.0
    and recall == 1.0
    and f1 == 1.0
    and roc_auc == 1.0
):
    print("PASS: All test metrics match Stage 4A.")
else:
    print("WARNING: Metrics differ from Stage 4A.")


# ------------------------------------------------------------
# 11. PER-RUN SUMMARY
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("RUN-LEVEL SUMMARY")
print("=" * 60)

summary = (
    test_df.assign(
        threat_probability=probabilities,
        prediction=predictions
    )
    .groupby("run_id")
    .agg(
        windows=("label", "count"),
        actual_threats=("label", "sum"),
        predicted_threats=("prediction", "sum"),
        max_threat_probability=(
            "threat_probability",
            "max"
        )
    )
)

print(summary.to_string())


# ------------------------------------------------------------
# 12. FINAL STATUS
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("STAGE 4D VERIFICATION COMPLETE")
print("=" * 60)