"""
RansomGuard - Canary Configuration (canary/canary_config.py)

Centralized configuration settings for Canary / Decoy File Early-Warning Protection.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class CanaryConfig:
    enabled: bool = field(
        default_factory=lambda: os.getenv("RANSOMGUARD_CANARY_ENABLED", "true").lower() == "true"
    )
    early_confirm_enabled: bool = field(
        default_factory=lambda: os.getenv("RANSOMGUARD_CANARY_EARLY_CONFIRM_ENABLED", "true").lower() == "true"
    )
    rf_threshold: float = field(
        default_factory=lambda: float(os.getenv("RANSOMGUARD_CANARY_RF_THRESHOLD", "0.45"))
    )
    require_extension_signal: bool = field(
        default_factory=lambda: os.getenv("RANSOMGUARD_CANARY_REQUIRE_EXTENSION_SIGNAL", "false").lower() == "true"
    )
    require_entropy_signal: bool = field(
        default_factory=lambda: os.getenv("RANSOMGUARD_CANARY_REQUIRE_ENTROPY_SIGNAL", "false").lower() == "true"
    )
    canary_count: int = field(
        default_factory=lambda: int(os.getenv("RANSOMGUARD_CANARY_COUNT", "5"))
    )
    healthcheck_interval: float = field(
        default_factory=lambda: float(os.getenv("RANSOMGUARD_CANARY_HEALTHCHECK_INTERVAL", "60.0"))
    )
    relative_canary_dir: str = ".ransomguard_canaries"


canary_config = CanaryConfig()
