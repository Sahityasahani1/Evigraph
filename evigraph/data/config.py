"""
Data Pipeline Configuration & Settings
Uses Pydantic BaseSettings for type-safe environment and configuration management.
"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DataPipelineSettings(BaseSettings):
    """Configuration settings for Member 1 Data & Traffic Pipeline."""

    model_config = SettingsConfigDict(
        env_prefix="EVIGRAPH_DATA_",
        env_file=".env",
        extra="ignore"
    )

    # Base workspace paths
    base_dir: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent.parent
    )
    raw_dir: Path = Field(default=Path("data/raw"))
    evidence_dir: Path = Field(default=Path("data/evidence"))
    processed_dir: Path = Field(default=Path("data/processed"))
    samples_dir: Path = Field(default=Path("data/samples"))

    # Evidence integrity & catalog paths
    audit_log_path: Path = Field(default=Path("data/processed/audit_log.jsonl"))
    evidence_parquet_path: Path = Field(default=Path("data/processed/evidence_files.parquet"))
    duckdb_catalog_path: Path = Field(default=Path("data/processed/catalog.duckdb"))
    manifest_path: Path = Field(default=Path("data/evidence/manifest.json"))
    cleaning_report_path: Path = Field(default=Path("data/processed/cleaning_report.json"))
    taxonomy_path: Path = Field(default=Path("evigraph/data/taxonomy_v1.yaml"))

    # Streaming & time-window hyperparameters (aligned with Member 2)
    window_size_secs: int = Field(default=300, description="Graph time-slice window in seconds (5m)")
    correlation_window_secs: int = Field(default=300, description="Alert correlation temporal window")
    seed: int = Field(default=42, description="Reproducibility random seed")
    chunk_size: int = Field(default=50_000, description="Streaming chunk row count for big data")

    # Network protocol standards
    default_protocol: int = Field(default=6, description="Default IANA protocol (6 = TCP)")
    flow_duration_units: str = Field(default="microseconds", description="Duration metric ('microseconds' or 'seconds')")

    def resolve_path(self, path: Path) -> Path:
        """Resolves relative paths against base_dir."""
        if path.is_absolute():
            return path
        return self.base_dir / path

    def ensure_directories(self) -> None:
        """Ensures all standard data directories exist on disk."""
        for p in [self.raw_dir, self.evidence_dir, self.processed_dir, self.samples_dir]:
            self.resolve_path(p).mkdir(parents=True, exist_ok=True)


# Global settings instance
settings = DataPipelineSettings()
