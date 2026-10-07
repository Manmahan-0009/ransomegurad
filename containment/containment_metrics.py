"""
RansomGuard - Containment & Response Metrics Calculator (containment/containment_metrics.py)

Precise ground-truth calculation of detection latencies (TTD), containment duration (TTC),
and affected/protected file metrics.
"""

from typing import Dict, Any, List, Optional
from pathlib import Path


def extract_base_filename(rel_path: str) -> str:
    """Normalizes relative path by stripping .locked extension if present."""
    p = Path(rel_path)
    name = p.name
    if name.endswith(".locked"):
        name = name[:-7]
    return str(p.parent / name) if str(p.parent) != "." else name


def compute_containment_metrics(
    attack_start_time: Optional[float],
    raw_detection_time: Optional[float],
    confirmed_alert_time: Optional[float],
    containment_request_time: Optional[float],
    containment_complete_time: Optional[float],
    ground_truth_ops: List[Dict[str, Any]],
    total_files_targeted: int = 20,
) -> Dict[str, Any]:
    """
    Computes precise ground-truth containment and response metrics.
    """
    # 1. Latency calculations
    ttd_raw = (
        round(raw_detection_time - attack_start_time, 4)
        if (raw_detection_time and attack_start_time and raw_detection_time >= attack_start_time)
        else None
    )

    ttd_confirmed = (
        round(confirmed_alert_time - attack_start_time, 4)
        if (confirmed_alert_time and attack_start_time and confirmed_alert_time >= attack_start_time)
        else None
    )

    ttc = (
        round(containment_complete_time - confirmed_alert_time, 4)
        if (containment_complete_time and confirmed_alert_time and containment_complete_time >= confirmed_alert_time)
        else None
    )

    total_response_time = (
        round(containment_complete_time - attack_start_time, 4)
        if (containment_complete_time and attack_start_time and containment_complete_time >= attack_start_time)
        else None
    )

    # 2. File impact calculations using ground truth operations
    files_before_raw = set()
    files_before_confirmed = set()
    files_before_containment = set()
    all_affected_files = set()

    for op in ground_truth_ops:
        op_time = op.get("operation_time", 0.0)
        base_file = extract_base_filename(op.get("relative_path", ""))
        all_affected_files.add(base_file)

        if raw_detection_time and op_time <= raw_detection_time:
            files_before_raw.add(base_file)

        if confirmed_alert_time and op_time <= confirmed_alert_time:
            files_before_confirmed.add(base_file)

        if containment_complete_time and op_time <= containment_complete_time:
            files_before_containment.add(base_file)

    n_raw = len(files_before_raw)
    n_confirmed = len(files_before_confirmed)
    n_contained = len(files_before_containment)
    target_count = max(total_files_targeted, len(all_affected_files), 1)

    protected_count = max(0, target_count - n_contained)
    protection_pct = round((protected_count / target_count) * 100.0, 2)

    return {
        "TTD_raw": ttd_raw,
        "TTD_confirmed": ttd_confirmed,
        "TTC": ttc,
        "total_response_time": total_response_time,
        "files_affected_before_raw_detection": n_raw,
        "files_affected_before_confirmed_alert": n_confirmed,
        "files_affected_before_containment": n_contained,
        "total_target_files": target_count,
        "files_protected": protected_count,
        "percentage_files_protected": protection_pct,
    }
