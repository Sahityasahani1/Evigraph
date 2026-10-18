"""
Evidence Integrity, Immutable Store & Cryptographic Audit Ledger (FR-1.2 to 1.5)
Implements:
1. Streaming SHA-256 evidence registration into data/evidence/<sha256>/<name> (read-only 0o444).
2. Idempotent Parquet evidence catalog appending (data/processed/evidence_files.parquet).
3. Cryptographic append-only audit log with canonical JSON hash chaining (data/processed/audit_log.jsonl).
4. Strict verify_chain() asserting zero evidence tampering and zero audit log modification.
"""

import hashlib
import json
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from pydantic import BaseModel, Field

from data.config import settings


class IntegrityError(Exception):
    """Raised when evidence tampering, hash mismatch, or audit chain breakage is detected."""
    pass


class EvidenceRecord(BaseModel):
    """Metadata record for a registered forensic evidence artifact."""
    evidence_id: str
    sha256: str
    size: int
    received_at: str
    source_description: str
    stored_path: Optional[str] = None


def canonical_json(data: Dict[str, Any]) -> str:
    """Returns canonical, deterministic JSON string with sorted keys and compact separators."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_file_sha256(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Computes SHA-256 hash by streaming file in 1 MB chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def make_read_only(path: Path) -> None:
    """Sets file permission to read-only (0o444 / S_IREAD) across Unix and Windows."""
    try:
        path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except Exception:
        pass


def make_writable(path: Path) -> None:
    """Restores write permissions on file."""
    try:
        path.chmod(stat.S_IWRITE | stat.S_IREAD)
    except Exception:
        pass


class AuditLogEntry(BaseModel):
    """Schema for each tamper-evident entry in data/processed/audit_log.jsonl."""
    actor: str = "Member 1 (Data & Traffic Pipeline)"
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)
    tool_versions: Dict[str, str] = Field(default_factory=dict)
    input_hashes: List[str] = Field(default_factory=list)
    output_hashes: List[str] = Field(default_factory=list)
    ts: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    prev_hash: str = "0" * 64
    entry_hash: str = ""

    def compute_entry_hash(self) -> str:
        """
        Computes entry_hash = sha256(canonical_json(entry w/o entry_hash) + prev_hash).
        """
        data = self.model_dump()
        data.pop("entry_hash", None)
        canonical_str = canonical_json(data)
        payload = (canonical_str + self.prev_hash).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


class AuditLogger:
    """Append-only audit log manager backed by data/processed/audit_log.jsonl."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = settings.resolve_path(log_path or settings.audit_log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def get_last_entry(self) -> Optional[AuditLogEntry]:
        """Reads the last line of the audit log to retrieve the previous entry."""
        if not self.log_path.exists():
            return None
        last_line = None
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if not last_line:
            return None
        try:
            return AuditLogEntry.model_validate_json(last_line)
        except Exception:
            return None

    def log(
        self,
        action: str,
        actor: str = "Member 1 (Data & Traffic Pipeline)",
        params: Optional[Dict[str, Any]] = None,
        input_hashes: Optional[List[str]] = None,
        output_hashes: Optional[List[str]] = None,
        tool_versions: Optional[Dict[str, str]] = None
    ) -> AuditLogEntry:
        """Appends a new cryptographically chained audit log entry."""
        last_entry = self.get_last_entry()
        prev_hash = last_entry.entry_hash if last_entry else ("0" * 64)

        versions = tool_versions or {
            "evigraph": "0.1.0",
            "python": sys.version.split()[0],
            "pyarrow": pa.__version__,
            "pandas": pd.__version__
        }

        entry = AuditLogEntry(
            actor=actor,
            action=action,
            params=params or {},
            tool_versions=versions,
            input_hashes=input_hashes or [],
            output_hashes=output_hashes or [],
            prev_hash=prev_hash
        )
        entry.entry_hash = entry.compute_entry_hash()

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(entry.model_dump_json() + "\n")

        return entry

    def log_action(
        self,
        action: str,
        actor: str = "Member 1 (Data & Traffic Pipeline)",
        params: Optional[Dict[str, Any]] = None,
        input_files: Optional[List[Any]] = None,
        output_files: Optional[List[Any]] = None,
        tool_versions: Optional[Dict[str, str]] = None,
        input_hashes: Optional[List[str]] = None,
        output_hashes: Optional[List[str]] = None
    ) -> AuditLogEntry:
        """Alias for log() accepting input_files/output_files or input_hashes/output_hashes."""
        in_h = input_hashes or []
        out_h = output_hashes or []
        for f in (input_files or []):
            fp = Path(f)
            if fp.exists() and fp.is_file():
                in_h.append(compute_file_sha256(fp))
        for f in (output_files or []):
            fp = Path(f)
            if fp.exists() and fp.is_file():
                out_h.append(compute_file_sha256(fp))

        return self.log(
            action=action,
            actor=actor,
            params=params,
            input_hashes=in_h,
            output_hashes=out_h,
            tool_versions=tool_versions
        )


def register_evidence(
    path: Path | str,
    source_description: str = "",
    evidence_base_dir: Optional[Path] = None,
    parquet_path: Optional[Path] = None,
    audit_log_path: Optional[Path] = None
) -> EvidenceRecord:
    """
    Registers raw evidence with SHA-256 verification and immutable storage:
    1. Streams the file in 1 MB chunks, computes SHA-256 while copying into data/evidence/<sha256>/<original_name>.
    2. Chmods the copy read-only (0o444). Never modifies the original.
    3. Idempotently persists record to data/processed/evidence_files.parquet.
    4. Records the action in the append-only audit log.
    """
    source_path = Path(path)
    if not source_path.exists() or not source_path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {source_path}")

    ev_dir = settings.resolve_path(evidence_base_dir or settings.evidence_dir)
    proc_pq = settings.resolve_path(parquet_path or settings.evidence_parquet_path)
    logger = AuditLogger(log_path=audit_log_path)

    # 1. Stream in 1 MB chunks and compute SHA-256 in memory first
    chunk_size = 1024 * 1024
    hasher = hashlib.sha256()
    total_size = 0

    with open(source_path, "rb") as f_in:
        while chunk := f_in.read(chunk_size):
            hasher.update(chunk)
            total_size += len(chunk)

    file_sha256 = hasher.hexdigest()
    evidence_id = "ev_" + file_sha256[:12]

    # Destination in immutable store: data/evidence/<sha256>/<original_name>
    target_dir = ev_dir / file_sha256
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / source_path.name

    # Check if existing record already exists in Parquet
    proc_pq.parent.mkdir(parents=True, exist_ok=True)
    existing_record = None
    if proc_pq.exists():
        try:
            pq_df = pd.read_parquet(proc_pq)
            matched = pq_df[pq_df["sha256"] == file_sha256]
            if not matched.empty:
                row = matched.iloc[0]
                existing_record = EvidenceRecord(
                    evidence_id=str(row["evidence_id"]),
                    sha256=str(row["sha256"]),
                    size=int(row["size"]),
                    received_at=str(row["received_at"]),
                    source_description=str(row["source_description"]),
                    stored_path=str(target_file)
                )
        except Exception:
            pass

    if existing_record is not None and target_file.exists():
        # Idempotent return without duplicate registration
        return existing_record

    # Copy to target file if not already present or needs copy
    if not target_file.exists():
        with open(source_path, "rb") as f_in, open(target_file, "wb") as f_out:
            while chunk := f_in.read(chunk_size):
                f_out.write(chunk)
        # Chmod read-only (0o444)
        make_read_only(target_file)

    now_iso = datetime.now(timezone.utc).isoformat()
    record = EvidenceRecord(
        evidence_id=evidence_id,
        sha256=file_sha256,
        size=total_size,
        received_at=now_iso,
        source_description=source_description,
        stored_path=str(target_file)
    )

    # Persist to data/processed/evidence_files.parquet (append)
    new_row = pd.DataFrame([{
        "evidence_id": record.evidence_id,
        "sha256": record.sha256,
        "size": record.size,
        "received_at": record.received_at,
        "source_description": record.source_description
    }])

    if proc_pq.exists():
        try:
            curr_df = pd.read_parquet(proc_pq)
            if file_sha256 not in curr_df["sha256"].values:
                updated_df = pd.concat([curr_df, new_row], ignore_index=True)
            else:
                updated_df = curr_df
        except Exception:
            updated_df = new_row
    else:
        updated_df = new_row

    table = pa.Table.from_pandas(updated_df, preserve_index=False)
    pq.write_table(table, proc_pq, compression="snappy")

    # Audit log
    logger.log(
        action="REGISTER_EVIDENCE",
        params={
            "evidence_id": evidence_id,
            "filename": source_path.name,
            "size": total_size,
            "source_description": source_description
        },
        input_hashes=[file_sha256],
        output_hashes=[file_sha256]
    )

    return record


def verify_chain(
    audit_log_path: Optional[Path] = None,
    evidence_parquet_path: Optional[Path] = None,
    evidence_base_dir: Optional[Path] = None
) -> bool:
    """
    Recomputes the cryptographic audit chain and re-hashes every registered evidence file.
    Raises IntegrityError loudly on any mismatch.
    """
    log_p = settings.resolve_path(audit_log_path or settings.audit_log_path)
    pq_p = settings.resolve_path(evidence_parquet_path or settings.evidence_parquet_path)
    ev_dir = settings.resolve_path(evidence_base_dir or settings.evidence_dir)

    # 1. Verify Audit Log Hash Chain
    if log_p.exists():
        prev_hash = "0" * 64
        with open(log_p, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = AuditLogEntry.model_validate_json(line)
                except Exception as e:
                    raise IntegrityError(f"Audit log line {line_no} failed JSON validation: {e}") from e

                if entry.prev_hash != prev_hash:
                    raise IntegrityError(
                        f"Audit log chain broken at line {line_no}: expected prev_hash {prev_hash}, got {entry.prev_hash}"
                    )

                recomputed = entry.compute_entry_hash()
                if entry.entry_hash != recomputed:
                    raise IntegrityError(
                        f"Audit log line {line_no} tampered! Recorded entry_hash {entry.entry_hash} != recomputed {recomputed}"
                    )

                prev_hash = entry.entry_hash

    # 2. Re-hash every evidence file from Parquet catalog
    if pq_p.exists():
        try:
            df = pd.read_parquet(pq_p)
        except Exception as e:
            raise IntegrityError(f"Evidence parquet catalog {pq_p} is corrupted: {e}") from e

        for _idx, row in df.iterrows():
            expected_sha = str(row["sha256"])
            expected_size = int(row["size"])
            ev_id = str(row["evidence_id"])

            # Search in data/evidence/<sha256>/
            sha_dir = ev_dir / expected_sha
            if not sha_dir.exists():
                raise IntegrityError(
                    f"Evidence directory missing for {ev_id}: {sha_dir}"
                )

            files = list(sha_dir.glob("*"))
            if not files:
                raise IntegrityError(
                    f"No evidence file stored in {sha_dir}"
                )

            actual_file = files[0]
            actual_size = actual_file.stat().st_size
            if actual_size != expected_size:
                raise IntegrityError(
                    f"Evidence file {actual_file.name} size mismatch: expected {expected_size} bytes, got {actual_size}"
                )

            actual_sha = compute_file_sha256(actual_file)
            if actual_sha.lower() != expected_sha.lower():
                raise IntegrityError(
                    f"Evidence file {actual_file.name} ({ev_id}) TAMPERED! "
                    f"Expected hash {expected_sha}, recomputed {actual_sha}"
                )

    # 3. Also scan any subdirectories in data/evidence/ to ensure no orphan tampering
    if ev_dir.exists():
        for sha_folder in ev_dir.iterdir():
            if sha_folder.is_dir() and len(sha_folder.name) == 64:
                expected_sha = sha_folder.name
                for target_f in sha_folder.iterdir():
                    if target_f.is_file():
                        computed = compute_file_sha256(target_f)
                        if computed.lower() != expected_sha.lower():
                            raise IntegrityError(
                                f"Evidence file {target_f} failed integrity check: "
                                f"directory hash {expected_sha} != actual hash {computed}"
                            )

    return True


class EvidenceStore:
    """Wrapper class providing object-oriented access to evidence operations."""

    def __init__(
        self,
        evidence_dir: Optional[Path] = None,
        parquet_path: Optional[Path] = None,
        audit_log_path: Optional[Path] = None
    ):
        self.evidence_dir = settings.resolve_path(evidence_dir or settings.evidence_dir)
        self.parquet_path = settings.resolve_path(parquet_path or settings.evidence_parquet_path)
        self.audit_log_path = settings.resolve_path(audit_log_path or settings.audit_log_path)
        self.logger = AuditLogger(log_path=self.audit_log_path)

    def register(self, path: Path | str, source_description: str = "") -> EvidenceRecord:
        return register_evidence(
            path=path,
            source_description=source_description,
            evidence_base_dir=self.evidence_dir,
            parquet_path=self.parquet_path,
            audit_log_path=self.audit_log_path
        )

    def verify(self) -> bool:
        return verify_chain(
            audit_log_path=self.audit_log_path,
            evidence_parquet_path=self.parquet_path,
            evidence_base_dir=self.evidence_dir
        )
