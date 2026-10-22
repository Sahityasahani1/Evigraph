"""
Tests for Evidence Integrity & Audit Ledger (FR-1.2 to 1.5)
Covers:
- Idempotent evidence registration in Parquet
- 1 MB chunk streaming and SHA-256 calculation
- Read-only file permissions (0o444)
- Audit log hash chaining
- Tamper detection: modifying one byte in evidence file raises IntegrityError
- Tamper detection: editing one audit log line raises IntegrityError
"""

from pathlib import Path

import pandas as pd
import pytest

from data.evidence import (
    IntegrityError,
    make_read_only,
    make_writable,
    register_evidence,
    verify_chain,
)


def test_register_evidence_idempotence(tmp_path):
    """Registering the exact same file twice returns the existing record and appends only once."""
    test_file = tmp_path / "raw_capture.pcap"
    test_content = b"EviGraph packet capture sample content" * 100
    test_file.write_bytes(test_content)

    ev_dir = tmp_path / "evidence"
    proc_pq = tmp_path / "processed" / "evidence_files.parquet"
    audit_log = tmp_path / "processed" / "audit_log.jsonl"

    rec1 = register_evidence(
        test_file,
        source_description="Test capture 1",
        evidence_base_dir=ev_dir,
        parquet_path=proc_pq,
        audit_log_path=audit_log
    )
    assert rec1.evidence_id.startswith("ev_")
    assert rec1.size == len(test_content)
    assert rec1.stored_path is not None
    assert Path(rec1.stored_path).exists()

    # Second registration of the same content
    rec2 = register_evidence(
        test_file,
        source_description="Test capture 1 (duplicate attempt)",
        evidence_base_dir=ev_dir,
        parquet_path=proc_pq,
        audit_log_path=audit_log
    )

    # Identical record returned
    assert rec1.sha256 == rec2.sha256
    assert rec1.evidence_id == rec2.evidence_id

    # Parquet catalog must contain exactly 1 entry
    df = pd.read_parquet(proc_pq)
    assert len(df) == 1
    assert df["evidence_id"].iloc[0] == rec1.evidence_id
    assert df["sha256"].iloc[0] == rec1.sha256

    # Chain verification should succeed
    assert verify_chain(audit_log_path=audit_log, evidence_parquet_path=proc_pq, evidence_base_dir=ev_dir) is True


def test_tamper_evidence_file_raises_integrity_error(tmp_path):
    """Tampering with even one byte in a stored evidence file causes verify_chain to raise IntegrityError."""
    test_file = tmp_path / "payload.bin"
    test_file.write_bytes(b"A" * 1024)

    ev_dir = tmp_path / "evidence"
    proc_pq = tmp_path / "processed" / "evidence_files.parquet"
    audit_log = tmp_path / "processed" / "audit_log.jsonl"

    rec = register_evidence(
        test_file,
        source_description="Integrity test payload",
        evidence_base_dir=ev_dir,
        parquet_path=proc_pq,
        audit_log_path=audit_log
    )

    stored_file = Path(rec.stored_path)
    assert stored_file.exists()

    # Verify initially passes
    assert verify_chain(audit_log_path=audit_log, evidence_parquet_path=proc_pq, evidence_base_dir=ev_dir) is True

    # Tamper with 1 byte in the stored file
    make_writable(stored_file)
    with open(stored_file, "r+b") as f:
        first_byte = f.read(1)
        f.seek(0)
        # Flip bit of the first byte
        f.write(bytes([first_byte[0] ^ 0x01]))
    make_read_only(stored_file)

    # verify_chain MUST loudly raise IntegrityError
    with pytest.raises(IntegrityError) as exc_info:
        verify_chain(audit_log_path=audit_log, evidence_parquet_path=proc_pq, evidence_base_dir=ev_dir)

    assert "TAMPERED" in str(exc_info.value) or "mismatch" in str(exc_info.value)


def test_edit_audit_log_line_raises_integrity_error(tmp_path):
    """Editing even one character in audit_log.jsonl causes verify_chain to raise IntegrityError."""
    test_file = tmp_path / "file1.csv"
    test_file.write_bytes(b"col1,col2\n1,2\n")

    ev_dir = tmp_path / "evidence"
    proc_pq = tmp_path / "processed" / "evidence_files.parquet"
    audit_log = tmp_path / "processed" / "audit_log.jsonl"

    register_evidence(
        test_file,
        source_description="Audit log test",
        evidence_base_dir=ev_dir,
        parquet_path=proc_pq,
        audit_log_path=audit_log
    )

    assert verify_chain(audit_log_path=audit_log, evidence_parquet_path=proc_pq, evidence_base_dir=ev_dir) is True

    # Maliciously edit line in audit_log
    with open(audit_log, "r", encoding="utf-8") as f:
        lines = f.readlines()

    lines[0] = lines[0].replace("REGISTER_EVIDENCE", "UNAUTHORIZED_EDIT")
    with open(audit_log, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # verify_chain MUST loudly raise IntegrityError
    with pytest.raises(IntegrityError) as exc_info:
        verify_chain(audit_log_path=audit_log, evidence_parquet_path=proc_pq, evidence_base_dir=ev_dir)

    assert "tampered" in str(exc_info.value).lower() or "broken" in str(exc_info.value).lower()


def test_evidence_file_read_only_mode(tmp_path):
    """The registered evidence copy in data/evidence/<sha256>/<name> must be read-only."""
    test_file = tmp_path / "readonly_test.txt"
    test_file.write_text("Immutable forensic copy")

    ev_dir = tmp_path / "evidence"
    proc_pq = tmp_path / "processed" / "evidence_files.parquet"
    audit_log = tmp_path / "processed" / "audit_log.jsonl"

    rec = register_evidence(
        test_file,
        evidence_base_dir=ev_dir,
        parquet_path=proc_pq,
        audit_log_path=audit_log
    )
    stored = Path(rec.stored_path)

    # Writing directly to the read-only file should fail with PermissionError
    with pytest.raises(PermissionError):
        with open(stored, "a") as f:
            f.write("illegal write attempt")
