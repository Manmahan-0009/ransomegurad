"""
RansomGuard - Presentation Chart Generator (results/generate_charts.py)

Generates clean, high-resolution presentation charts for the RansomGuard v2 evaluation:
1. Confusion Matrix
2. Feature Importance Breakdown
3. Detection & Response Latency (TTD_raw, TTD_confirmed, TTC)
4. Files Affected vs. Protected by Attack Speed
5. Protection Percentage by Attack Speed
6. Live Scenario Threat Score Comparison
"""

import os
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

# Style settings
plt.style.use('ggplot')
plt.rcParams['font.sans-serif'] = 'Arial'
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['figure.autolayout'] = True

OUT_DIR = Path(__file__).resolve().parent / "charts"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def generate_confusion_matrix():
    fig, ax = plt.subplots(figsize=(6, 5), dpi=300)
    cm = np.array([[83, 0], [0, 16]])
    im = ax.imshow(cm, cmap="Greens", alpha=0.85)

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Non-Attack", "Attack"], fontsize=11, fontweight="bold")
    ax.set_yticklabels(["Non-Attack", "Attack"], fontsize=11, fontweight="bold")
    ax.set_xlabel("Predicted Label", fontsize=12, fontweight="bold", labelpad=10)
    ax.set_ylabel("True Label", fontsize=12, fontweight="bold", labelpad=10)
    ax.set_title("RansomGuard v2 Confusion Matrix (Untouched Test Set)", fontsize=13, fontweight="bold", pad=15)

    # Colorbar
    fig.colorbar(im, ax=ax)

    # Annotate numbers
    labels = [["TN = 83\n(100%)", "FP = 0\n(0%)"], ["FN = 0\n(0%)", "TP = 16\n(100%)"]]
    for i in range(2):
        for j in range(2):
            text_color = "white" if cm[i, j] > 40 else "black"
            ax.text(j, i, labels[i][j], ha="center", va="center", color=text_color, fontsize=12, fontweight="bold")

    save_path = OUT_DIR / "confusion_matrix.png"
    plt.savefig(save_path, bbox_inches="tight")
    plt.close()
    print(f"[CHART] Saved: {save_path}")


def generate_feature_importance():
    features = [
        "mean_entropy",
        "extension_change_count",
        "rename_ratio",
        "files_created",
        "unique_extensions",
        "writes_per_second",
        "files_renamed",
        "files_modified",
        "unique_directories",
        "entropy_change",
        "files_deleted",
    ]
    importance = [0.3219, 0.3072, 0.1511, 0.0492, 0.0478, 0.0455, 0.0343, 0.0243, 0.0141, 0.0048, 0.0000]

    # Reverse for top-to-bottom bar chart
    features.reverse()
    importance.reverse()

    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=300)
    colors = ["#2b5c8f" if imp < 0.1 else "#c0392b" for imp in importance]
    bars = ax.barh(features, [imp * 100 for imp in importance], color=colors, edgecolor="black", height=0.65)

    ax.set_xlabel("Gini Feature Importance (%)", fontsize=12, fontweight="bold", labelpad=10)
    ax.set_title("RansomGuard v2 Feature Importance Breakdown", fontsize=13, fontweight="bold", pad=15)
    ax.set_xlim(0, 38)

    for bar in bars:
        w = bar.get_width()
        if w > 0.1:
            ax.text(w + 0.5, bar.get_y() + bar.get_height()/2.0, f"{w:.2f}%", ha="left", va="center", fontsize=10, fontweight="bold")

    save_path = OUT_DIR / "feature_importance.png"
    plt.savefig(save_path, bbox_inches="tight")
    plt.close()
    print(f"[CHART] Saved: {save_path}")


def generate_detection_latency():
    metrics = ["TTD (Raw Detection)", "TTD (Confirmed Alert)", "TTC (Containment Time)"]
    durations = [1.0877, 2.1567, 0.0136]

    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
    bars = ax.bar(metrics, durations, color=["#3498db", "#e67e22", "#2ecc71"], edgecolor="black", width=0.55)

    ax.set_ylabel("Duration (Seconds)", fontsize=12, fontweight="bold", labelpad=10)
    ax.set_title("RansomGuard Response Latency (TTD & TTC)", fontsize=13, fontweight="bold", pad=15)
    ax.set_ylim(0, 2.6)

    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, h + 0.06, f"{h:.3f} s", ha="center", va="bottom", fontsize=11, fontweight="bold")

    save_path = OUT_DIR / "detection_latency.png"
    plt.savefig(save_path, bbox_inches="tight")
    plt.close()
    print(f"[CHART] Saved: {save_path}")


def generate_files_affected_vs_protected():
    speeds = ["Slow Burst (0.4s)", "Medium Burst (0.1s)", "Fast Burst (0.02s)"]
    affected = [6, 19, 19]
    protected = [14, 1, 1]

    x = np.arange(len(speeds))
    width = 0.35

    fig, ax = plt.subplots(figsize=(7.5, 5), dpi=300)
    rects1 = ax.bar(x - width/2, affected, width, label="Files Affected (Encrypted)", color="#e74c3c", edgecolor="black")
    rects2 = ax.bar(x + width/2, protected, width, label="Files Protected (Saved)", color="#27ae60", edgecolor="black")

    ax.set_ylabel("Number of Files (Out of 20)", fontsize=12, fontweight="bold", labelpad=10)
    ax.set_title("Files Affected vs. Protected Across Attack Speeds", fontsize=13, fontweight="bold", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(speeds, fontsize=11, fontweight="bold")
    ax.legend(fontsize=11, loc="upper right")
    ax.set_ylim(0, 23)

    for r in rects1:
        h = r.get_height()
        ax.text(r.get_x() + r.get_width()/2.0, h + 0.4, f"{int(h)}", ha="center", va="bottom", fontsize=10, fontweight="bold")
    for r in rects2:
        h = r.get_height()
        ax.text(r.get_x() + r.get_width()/2.0, h + 0.4, f"{int(h)}", ha="center", va="bottom", fontsize=10, fontweight="bold")

    save_path = OUT_DIR / "files_affected_vs_protected.png"
    plt.savefig(save_path, bbox_inches="tight")
    plt.close()
    print(f"[CHART] Saved: {save_path}")


def generate_protection_percentage():
    speeds = ["Slow (0.4s/file)", "Medium (0.1s/file)", "Fast (0.02s/file)"]
    percentages = [70.0, 5.0, 5.0]

    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
    colors = ["#2ecc71" if p > 50 else "#e74c3c" for p in percentages]
    bars = ax.bar(speeds, percentages, color=colors, edgecolor="black", width=0.5)

    ax.set_ylabel("Files Protected (%)", fontsize=12, fontweight="bold", labelpad=10)
    ax.set_title("Protection Rate Trade-off Across Attack Burst Speeds", fontsize=13, fontweight="bold", pad=15)
    ax.set_ylim(0, 85)

    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, h + 1.5, f"{h:.1f}%", ha="center", va="bottom", fontsize=11, fontweight="bold")

    save_path = OUT_DIR / "protection_percentage_by_speed.png"
    plt.savefig(save_path, bbox_inches="tight")
    plt.close()
    print(f"[CHART] Saved: {save_path}")


def generate_threat_score_comparison():
    scenarios = ["Normal User", "Benign Bulk Activity", "Ransomware Burst"]
    scores = [0.0, 12.35, 79.0]
    severities = ["LOW", "LOW", "HIGH"]

    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
    colors = ["#2ecc71", "#f39c12", "#c0392b"]
    bars = ax.bar(scenarios, scores, color=colors, edgecolor="black", width=0.5)

    ax.set_ylabel("Peak Final Threat Score (0 - 100)", fontsize=12, fontweight="bold", labelpad=10)
    ax.set_title("Live Validation Peak Threat Score Comparison", fontsize=13, fontweight="bold", pad=15)
    ax.axhline(y=30, color="orange", linestyle="--", alpha=0.7, label="Medium Threshold (30)")
    ax.axhline(y=60, color="red", linestyle="--", alpha=0.7, label="High Threshold (60)")
    ax.set_ylim(0, 95)
    ax.legend(fontsize=10, loc="upper left")

    for bar, sev in zip(bars, severities):
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, h + 1.8, f"{h:.1f}\n({sev})", ha="center", va="bottom", fontsize=10, fontweight="bold")

    save_path = OUT_DIR / "live_threat_score_comparison.png"
    plt.savefig(save_path, bbox_inches="tight")
    plt.close()
    print(f"[CHART] Saved: {save_path}")


def main():
    print("Generating RansomGuard Presentation Charts...")
    generate_confusion_matrix()
    generate_feature_importance()
    generate_detection_latency()
    generate_files_affected_vs_protected()
    generate_protection_percentage()
    generate_threat_score_comparison()
    print("All charts generated successfully in results/charts/")


if __name__ == "__main__":
    main()
