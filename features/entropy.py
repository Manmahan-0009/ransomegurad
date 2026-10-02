"""
RansomGuard - Shannon Entropy Calculation Module (features/entropy.py)

Calculates file entropy (0.0 to 8.0 bits/byte) to quantify randomness / encryption.
Includes path-safety validation and an in-memory EntropyTracker to record entropy deltas.
"""

import math
from pathlib import Path
from typing import Optional, Dict
from utils.sandbox_manager import is_safe_path, get_demo_dir


def calculate_file_entropy(path: Path, max_bytes: int = 65536) -> Optional[float]:
    """
    Safely calculates Shannon Entropy for a file inside sandbox/demo_folder.

    Returns:
        float: Entropy value in bits per byte (0.0 to 8.0), or None if unreadable.
    """
    if not is_safe_path(path):
        return None

    if not path.exists() or not path.is_file():
        return None

    try:
        # Read up to max_bytes (default 64 KB sample)
        with open(path, "rb") as f:
            data = f.read(max_bytes)

        if not data:
            return 0.0

        length = len(data)
        # Byte frequency count
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1

        # Shannon Entropy formula: H = -sum(p * log2(p))
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    except (FileNotFoundError, PermissionError, OSError):
        return None
    except Exception:
        return None


class EntropyTracker:
    """
    Maintains prior entropy measurements for files in sandbox/demo_folder.
    Enables computation of entropy delta (entropy_change).
    """

    def __init__(self):
        # Map: relative_file_path_str -> last_known_entropy
        self._history: Dict[str, float] = {}

    def get_last_entropy(self, rel_path: str) -> Optional[float]:
        return self._history.get(rel_path)

    def update_entropy(self, rel_path: str, new_entropy: float) -> Optional[float]:
        """
        Updates entropy for rel_path and returns the delta (new - old) if old existed.
        """
        old_entropy = self._history.get(rel_path)
        self._history[rel_path] = new_entropy
        
        if old_entropy is not None:
            return round(new_entropy - old_entropy, 4)
        return 0.0

    def clear(self) -> None:
        self._history.clear()


# Default global tracker instance
_GLOBAL_ENTROPY_TRACKER = EntropyTracker()


def get_entropy_tracker() -> EntropyTracker:
    return _GLOBAL_ENTROPY_TRACKER
