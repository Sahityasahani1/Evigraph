"""
Run reproducibility manifest.

A forensic report is only reproducible if the exact inputs, model artifacts, and
outputs can be identified after the fact. This module writes a manifest that
binds a pipeline run to:

- the input data file hash (or an explicit "in-memory / no stable source" marker),
- git commit + dirty-tree state,
- Python and ML library versions,
- model artifact hashes,
- output artifact hashes,
- the Merkle root / scheme and incident IDs.

It deliberately records missing artifacts as missing instead of omitting them.
"""

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from src.config import BASE_DIR, MODELS_DIR, OUTPUTS_DIR

MANIFEST_NAME = "run_manifest.json"
HASH_CHUNK_SIZE = 1024 * 1024
MAX_HASH_FILE_BYTES = 512 * 1024 * 1024  # avoid hashing multi-GB raw captures inline
ARTIFACT_SUFFIXES = {".json", ".md"}
MODEL_SUFFIXES = {".joblib", ".pt", ".onnx", ".bin"}


def sha256_file(path: Path) -> Optional[str]:
    """Return the SHA-256 of a file, or None when it is too large/unreadable."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_HASH_FILE_BYTES:
        return None

    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _git(*args: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _library_versions() -> Dict[str, Optional[str]]:
    versions: Dict[str, Optional[str]] = {}
    for name in ("numpy", "pandas", "scikit-learn", "xgboost", "torch"):
        try:
            module = __import__(name.replace("-", "_"))
            versions[name] = getattr(module, "__version__", None)
        except Exception:
            versions[name] = None
    return versions


def _hash_tree(directory: Path, suffixes: Iterable[str], exclude: Optional[Path] = None) -> Dict[str, Any]:
    entries: Dict[str, Any] = {}
    if not directory.exists():
        return entries
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if exclude is not None and path.resolve() == exclude.resolve():
            continue
        digest = sha256_file(path)
        entries[path.name] = {
            "sha256": digest,
            "size_bytes": path.stat().st_size,
            "hashed": digest is not None,
        }
    return entries


def _load_bundle_metadata() -> Dict[str, Any]:
    bundle_path = OUTPUTS_DIR / "incident_cases.json"
    if not bundle_path.exists():
        return {"present": False}
    try:
        with bundle_path.open(encoding="utf-8") as handle:
            bundle = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {"present": True, "readable": False}
    incidents = bundle.get("incidents", [])
    return {
        "present": True,
        "readable": True,
        "merkle_root": bundle.get("merkle_root"),
        "merkle_scheme": bundle.get("merkle_scheme"),
        "merkle_leaves_count": bundle.get("merkle_leaves_count"),
        "incident_ids": [
            inc.get("incident_id") for inc in incidents if inc.get("incident_id")
        ],
    }


def write_run_manifest(
    data_path: Optional[Path] = None,
    raw_rows: Optional[int] = None,
    raw_columns: Optional[int] = None,
    model_type: str = "unknown",
    run_agent: bool = False,
    split_protocol: str = "per_class_temporal",
) -> Path:
    """Write outputs/run_manifest.json and return its path."""
    manifest_path = OUTPUTS_DIR / MANIFEST_NAME
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    data_entry: Dict[str, Any] = {
        "source": str(data_path) if data_path else None,
        "stable_source": bool(data_path and Path(data_path).exists()),
        "rows": raw_rows,
        "columns": raw_columns,
        "sha256": None,
        "hash_status": "NO_STABLE_SOURCE",
    }
    if data_path and Path(data_path).exists():
        digest = sha256_file(Path(data_path))
        data_entry["sha256"] = digest
        data_entry["hash_status"] = "HASHED" if digest else "SKIPPED_LARGE_FILE"

    dirty = _git("status", "--porcelain")
    bundle_meta = _load_bundle_metadata()

    outputs = _hash_tree(OUTPUTS_DIR, ARTIFACT_SUFFIXES, exclude=manifest_path)
    models = _hash_tree(MODELS_DIR, MODEL_SUFFIXES)

    warnings = []
    if not data_entry["stable_source"]:
        warnings.append(
            "Input data has no stable file source (in-memory or combined dataset); "
            "the run cannot be byte-for-byte reproduced from this manifest alone."
        )
    elif data_entry["hash_status"] != "HASHED":
        warnings.append("Input data hash was skipped because the file is too large or unreadable.")
    if not bundle_meta.get("present"):
        warnings.append("incident_cases.json is missing; no evidence root was recorded.")
    if not models:
        warnings.append("No model artifacts were found in models/.")
    if dirty:
        warnings.append("Git working tree was dirty at run time; outputs may not match HEAD.")
    if split_protocol == "per_class_temporal":
        warnings.append(
            "Metrics use a per-class temporal split; every test class was seen in "
            "training. Do not cite zero-day or unseen-family performance from this run."
        )

    manifest = {
        "manifest_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pipeline": {
            "model_type": model_type,
            "agent_invoked": bool(run_agent),
            "entrypoint": "main.py",
            "split_protocol": split_protocol,
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "libraries": _library_versions(),
        },
        "git": {
            "commit": _git("rev-parse", "HEAD"),
            "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": bool(dirty),
            "status_porcelain": dirty,
        },
        "input_data": data_entry,
        "evidence_bundle": bundle_meta,
        "model_artifacts": models,
        "output_artifacts": outputs,
        "warnings": warnings,
    }

    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)

    print(f"[RunManifest] Reproducibility manifest written to: {manifest_path}")
    for warning in warnings:
        print(f"[RunManifest] WARNING: {warning}")
    return manifest_path
