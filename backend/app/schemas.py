from typing import Optional
from pydantic import BaseModel, Field


class FeatureWindow(BaseModel):
    """
    Behavioral features produced by RansomGuard telemetry.
    """

    files_created: int = Field(ge=0)
    files_modified: int = Field(ge=0)
    files_deleted: int = Field(ge=0)
    files_renamed: int = Field(ge=0)

    writes_per_second: float = Field(ge=0)

    unique_extensions: int = Field(ge=0)
    unique_directories: int = Field(ge=0)

    extension_change_count: int = Field(ge=0)

    rename_ratio: float = Field(
        ge=0,
        le=1
    )

    mean_entropy: float = Field(
        ge=0
    )

    entropy_change: float

    # Optional metadata fields for live prediction logging and scenario tracking
    scenario_id: Optional[str] = "live"
    window_start: Optional[str] = None
    window_end: Optional[str] = None