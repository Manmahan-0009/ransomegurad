"""
RansomGuard - Canary Manager (canary/canary_manager.py)

Manages safe creation, hash baseline verification, path safety validation,
and controlled reset of canary/decoy files.
"""

import math
import hashlib
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from utils.sandbox_manager import get_demo_dir
from .canary_config import canary_config
from .canary_models import CanaryRecord
from .canary_registry import canary_registry, CanaryRegistry


CANARY_TEMPLATES = [
    ("Financial_Records_2026.xlsx", "xlsx", "SYNTHETIC FINANCIAL DECOY DATA - RANSOMGUARD PROTECTED CANARY\n" * 15),
    ("Employee_Backup.docx", "docx", "SYNTHETIC EMPLOYEE BACKUP DOCUMENT - RANSOMGUARD PROTECTED CANARY\n" * 15),
    ("Customer_Archive.csv", "csv", "id,name,email,synthetic_note\n1,Demo User,user@example.test,RansomGuard Canary\n" * 15),
    ("Project_Backup.zip", "zip", "PK\x03\x04RANSOMGUARD_SYNTHETIC_ZIP_CANARY_HEADER_DATA_1234567890\n" * 10),
    ("Report_Q4_2026.pdf", "pdf", "%PDF-1.4 %SYNTHETIC RANSOMGUARD PDF CANARY FILE\n" * 15),
]


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of byte content."""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    entropy = 0.0
    length = len(data)
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_file_hash_size_entropy(file_path: Path) -> Tuple[str, int, float]:
    """Computes SHA-256 hash, size in bytes, and Shannon entropy for file."""
    if not file_path.exists():
        return "", 0, 0.0
    content = file_path.read_bytes()
    h = hashlib.sha256(content).hexdigest()
    size = len(content)
    ent = calculate_entropy(content)
    return h, size, ent


def validate_canary_path(path: Path, approved_roots: Optional[List[Path]] = None) -> Path:
    """
    Strict Path Safety Guard:
    Ensures canary path does not contain traversal ('..'), symlink escape,
    and resides strictly under an approved sandbox/monitored root directory.
    """
    resolved_path = path.resolve()
    roots = approved_roots or [get_demo_dir().resolve(), (get_demo_dir().parent).resolve()]
    
    # Check traversal attempts
    if ".." in str(path):
        raise ValueError(f"Path traversal '..' detected in canary path: {path}")

    # Check containment under at least one approved root
    is_safe = False
    for root in roots:
        try:
            resolved_path.relative_to(root.resolve())
            is_safe = True
            break
        except ValueError:
            continue

    if not is_safe:
        raise ValueError(f"Canary path '{resolved_path}' is outside approved monitored roots ({roots})")

    return resolved_path


class CanaryManager:
    """
    High-level API for creating, verifying, auditing, and resetting canary files.
    """

    def __init__(self, registry: Optional[CanaryRegistry] = None):
        self.registry = registry or canary_registry

    def setup_canaries(
        self,
        device_id: str,
        target_dir: Optional[Path] = None,
        count: int = 5,
        approved_roots: Optional[List[Path]] = None,
    ) -> List[CanaryRecord]:
        """
        Creates synthetic canary files inside configured target directory and registers them.
        """
        base_dir = target_dir or (get_demo_dir() / canary_config.relative_canary_dir)
        base_dir.mkdir(parents=True, exist_ok=True)

        created_records: List[CanaryRecord] = []
        templates = CANARY_TEMPLATES[:min(count, len(CANARY_TEMPLATES))]

        # If count > templates, repeat with numeric index
        idx = 0
        while len(created_records) < count:
            tmpl_name, tmpl_type, tmpl_content = templates[idx % len(templates)]
            if idx >= len(templates):
                fname = f"{Path(tmpl_name).stem}_{idx // len(templates)}{Path(tmpl_name).suffix}"
            else:
                fname = tmpl_name

            file_path = base_dir / fname
            # Validate path safety before writing
            safe_path = validate_canary_path(file_path, approved_roots=approved_roots)

            # Write harmless synthetic content
            safe_path.write_text(tmpl_content, encoding="utf-8")

            # Calculate baseline metrics
            h_val, size_val, ent_val = calculate_file_hash_size_entropy(safe_path)

            canary_id = f"canary-{device_id[:8]}-{uuid.uuid4().hex[:6]}"
            record = CanaryRecord(
                canary_id=canary_id,
                device_id=device_id,
                file_path=str(safe_path),
                filename=fname,
                file_type=tmpl_type,
                created_at=time.time(),
                baseline_hash=h_val,
                baseline_size=size_val,
                baseline_entropy=ent_val,
                enabled=True,
                last_verified_at=time.time(),
            )
            self.registry.register_canary(record)
            created_records.append(record)
            idx += 1

        print(f"[CANARY MANAGER] Created {len(created_records)} canary files in {base_dir}")
        return created_records

    def verify_canary(self, record: CanaryRecord) -> Dict[str, Any]:
        """
        Checks current file state against baseline record.
        Returns dictionary describing integrity state and event type if modified.
        """
        p = Path(record.file_path)
        if not p.exists():
            return {
                "intact": False,
                "event_type": "DELETED",
                "canary_id": record.canary_id,
                "reason": "File missing/deleted",
            }

        cur_h, cur_size, cur_ent = calculate_file_hash_size_entropy(p)
        if cur_h != record.baseline_hash:
            # Check extension change
            if p.suffix.lower() != Path(record.filename).suffix.lower() or p.suffix.lower() == ".locked":
                evt = "EXTENSION_CHANGED"
            else:
                evt = "MODIFIED"
            return {
                "intact": False,
                "event_type": evt,
                "canary_id": record.canary_id,
                "reason": f"Hash mismatch (baseline={record.baseline_hash[:8]}, current={cur_h[:8]})",
            }

        return {
            "intact": True,
            "event_type": "NONE",
            "canary_id": record.canary_id,
            "reason": "Intact",
        }

    def reset_canaries(
        self,
        device_id: str,
        target_dir: Optional[Path] = None,
        count: int = 5,
    ) -> List[CanaryRecord]:
        """
        Safely clears and re-creates canaries for device.
        """
        self.registry.clear(device_id=device_id)
        return self.setup_canaries(device_id=device_id, target_dir=target_dir, count=count)


canary_manager = CanaryManager()
