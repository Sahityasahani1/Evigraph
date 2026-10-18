"""
Versioned Taxonomy Engine
Loads attack taxonomies from versioned YAML files and standardizes raw intrusion detection labels.
"""

from pathlib import Path
from typing import Dict, Optional

import pandas as pd
import yaml

from data.config import settings

# Built-in fallback taxonomy mapping
FALLBACK_TAXONOMY: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "Normal": "BENIGN",
    "PortScan": "PortScan",
    "SSH-Patator": "Brute-Force",
    "FTP-Patator": "Brute-Force",
    "Patator": "Brute-Force",
    "DoS Slowloris": "DoS",
    "DoS-Slowloris": "DoS",
    "DoS Hulk": "DoS",
    "DoS-Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS-GoldenEye": "DoS",
    "DoS slowhttptest": "DoS",
    "Heartbleed": "Heartbleed",
    "Web Attack - Brute Force": "Web-Attack",
    "Web Attack - XSS": "Web-Attack",
    "Web Attack - Sql Injection": "Web-Attack",
    "Infiltration": "Infiltration",
    "Bot": "Botnet",
    "Botnet": "Botnet",
    "DDoS": "DDoS",
}


class TaxonomyMapper:
    """
    Manages versioned attack taxonomies loaded from YAML specifications.
    Standardizes label_raw into canonical label_family.
    """

    def __init__(self, yaml_path: Optional[Path | str] = None):
        self.yaml_path = Path(yaml_path) if yaml_path else settings.resolve_path(settings.taxonomy_path)
        self.version = "1.0"
        self.default_family = "Unknown"
        self.mappings: Dict[str, str] = dict(FALLBACK_TAXONOMY)
        self._load_taxonomy()

    def _load_taxonomy(self) -> None:
        if not self.yaml_path.exists():
            # If specified file doesn't exist, try relative to package directory
            pkg_yaml = Path(__file__).parent / "taxonomy_v1.yaml"
            if pkg_yaml.exists():
                self.yaml_path = pkg_yaml
            else:
                return

        try:
            with open(self.yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    self.version = str(data.get("version", "1.0"))
                    self.default_family = data.get("default_family", "Unknown")
                    yaml_maps = data.get("mappings", {})
                    if isinstance(yaml_maps, dict):
                        self.mappings.update(yaml_maps)
        except Exception:
            # Retain fallback mappings on YAML parse failure
            pass

    def map_family(self, label_raw: Optional[str]) -> str:
        """Maps a single raw label to its canonical family."""
        if not label_raw or pd.isna(label_raw):
            return self.default_family
        clean = str(label_raw).strip()
        return self.mappings.get(clean, self.mappings.get(clean.upper(), self.default_family))

    def map_series(self, series: pd.Series) -> pd.Series:
        """Vectorized mapping of a Series of raw labels to canonical families."""
        return series.astype(str).str.strip().map(
            lambda x: self.mappings.get(x, self.mappings.get(x.upper(), self.default_family))
        )


# Global default taxonomy instance
default_taxonomy = TaxonomyMapper()
