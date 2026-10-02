"""
RansomGuard - Window Ground-Truth Labeling Module (training/label_windows.py)

Assigns accurate, timestamp-correct ground-truth binary labels (0 or 1) to feature windows.

LABELING RULES:
- Normal runs: label = 0
- Benign runs: label = 0
- Attack runs:
    label = 1 ONLY if at least one ground-truth attack operation occurred inside
    the window time interval [window_start, window_end).
    Otherwise label = 0.

Interval Convention: [window_start, window_end) - inclusive start, exclusive end.
"""

from typing import List, Dict, Any, Optional


def compute_window_label(
    window_start: float,
    window_end: float,
    run_class: str,
    attack_ops: Optional[List[Dict[str, Any]]] = None,
) -> int:
    """
    Computes the ground-truth binary label (0 or 1) for a time window.

    Args:
        window_start: Window start timestamp (epoch float).
        window_end: Window end timestamp (epoch float).
        run_class: Run class designation ('normal', 'benign', 'attack').
        attack_ops: List of ground-truth attack operation dicts for attack runs.

    Returns:
        int: 1 if window contains attack operations, else 0.
    """
    cls_lower = run_class.lower()

    # Normal and Benign runs are always labeled 0
    if cls_lower in ["normal", "benign"]:
        return 0

    if cls_lower == "attack":
        if not attack_ops:
            return 0

        # Check if any ground-truth attack operation timestamp falls inside [window_start, window_end)
        for op in attack_ops:
            op_time = op.get("operation_time", 0.0)
            if window_start <= op_time < window_end:
                return 1

    return 0


def label_window_row(
    row_data: Dict[str, Any],
    run_class: str,
    attack_ops: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Enriches a feature dictionary row with 'label'.
    """
    w_start = row_data["window_start"]
    w_end = row_data["window_end"]
    label = compute_window_label(w_start, w_end, run_class, attack_ops)
    
    # Return dictionary with label inserted
    enriched = dict(row_data)
    enriched["label"] = label
    return enriched
