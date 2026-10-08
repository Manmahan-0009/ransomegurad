"""
RansomGuard - Canary Registry (canary/canary_registry.py)

Thread-safe persistent inventory of registered canary files per device.
Maintains fast path lookup map for sub-millisecond measured processing overhead Watchdog event matching.
"""

import json
import os
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

from .canary_models import CanaryRecord

REGISTRY_PATH = Path(__file__).resolve().parents[1] / "data" / "canary_registry.json"


class CanaryRegistry:
    """
    Manages persistent inventory of canary files and fast-path lookup maps.
    """

    def __init__(self, registry_file: Optional[Path] = None):
        self.registry_file = registry_file or REGISTRY_PATH
        self._lock = threading.Lock()
        self._canaries: Dict[str, CanaryRecord] = {}  # canary_id -> CanaryRecord
        self._path_map: Dict[str, str] = {}  # normalized_file_path -> canary_id
        self._filename_map: Dict[str, str] = {}  # filename -> canary_id
        self._load()

    def _normalize_path(self, file_path: str) -> str:
        try:
            return str(Path(file_path).resolve()).lower()
        except Exception:
            return str(file_path).lower()

    def _load(self) -> None:
        with self._lock:
            self._canaries.clear()
            self._path_map.clear()
            self._filename_map.clear()
            if self.registry_file.exists():
                try:
                    with open(self.registry_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for item in data.get("canaries", []):
                            record = CanaryRecord.from_dict(item)
                            self._canaries[record.canary_id] = record
                            norm_path = self._normalize_path(record.file_path)
                            self._path_map[norm_path] = record.canary_id
                            self._filename_map[record.filename.lower()] = record.canary_id
                except Exception as e:
                    print(f"[CANARY REGISTRY WARNING] Failed to load registry: {e}")

    def _save(self) -> None:
        self.registry_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "canaries": [rec.to_dict() for rec in self._canaries.values()]
        }
        with open(self.registry_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def register_canary(self, record: CanaryRecord) -> None:
        with self._lock:
            self._canaries[record.canary_id] = record
            norm_path = self._normalize_path(record.file_path)
            self._path_map[norm_path] = record.canary_id
            self._filename_map[record.filename.lower()] = record.canary_id
            self._save()

    def unregister_canary(self, canary_id: str) -> bool:
        with self._lock:
            if canary_id in self._canaries:
                rec = self._canaries.pop(canary_id)
                norm_path = self._normalize_path(rec.file_path)
                self._path_map.pop(norm_path, None)
                self._filename_map.pop(rec.filename.lower(), None)
                self._save()
                return True
            return False

    def get_by_id(self, canary_id: str) -> Optional[CanaryRecord]:
        with self._lock:
            return self._canaries.get(canary_id)

    def get_by_path(self, file_path: str) -> Optional[CanaryRecord]:
        norm_path = self._normalize_path(file_path)
        with self._lock:
            cid = self._path_map.get(norm_path)
            if cid:
                return self._canaries.get(cid)
            # Fallback check by filename if parent folder structure matches
            fname = Path(file_path).name.lower()
            if fname in self._filename_map:
                candidate_cid = self._filename_map[fname]
                candidate = self._canaries.get(candidate_cid)
                if candidate and Path(file_path).name.lower() == candidate.filename.lower():
                    return candidate
            return None

    def list_canaries(self, device_id: Optional[str] = None) -> List[CanaryRecord]:
        with self._lock:
            if device_id:
                return [c for c in self._canaries.values() if c.device_id == device_id]
            return list(self._canaries.values())

    def clear(self, device_id: Optional[str] = None) -> None:
        with self._lock:
            if device_id:
                to_remove = [cid for cid, c in self._canaries.items() if c.device_id == device_id]
                for cid in to_remove:
                    rec = self._canaries.pop(cid)
                    norm_path = self._normalize_path(rec.file_path)
                    self._path_map.pop(norm_path, None)
                    self._filename_map.pop(rec.filename.lower(), None)
            else:
                self._canaries.clear()
                self._path_map.clear()
                self._filename_map.clear()
            self._save()


canary_registry = CanaryRegistry()
