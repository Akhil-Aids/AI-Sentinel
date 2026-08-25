"""Defensive backup protection workflow.

Records backup health snapshots for high-confidence incidents.  This module
is strictly DEFENSIVE: it reads file metadata and records state.  It never
modifies, encrypts, deletes, creates, or restores any file.

Backup targets are configured via the SENTINEL_BACKUP_TARGETS environment
variable (semicolon-separated absolute paths).
"""
import hashlib
import os
from typing import Optional

from app import db


def _get_backup_targets() -> list[str]:
    raw = os.getenv("SENTINEL_BACKUP_TARGETS", "")
    return [p.strip() for p in raw.split(";") if p.strip()]


def _file_metadata_hash(path: str) -> str:
    """Return a sha256 digest of a file's metadata (size + mtime).

    This deliberately avoids reading file contents.
    """
    try:
        st = os.stat(path)
        blob = f"{st.st_size}|{st.st_mtime}"
        return hashlib.sha256(blob.encode()).hexdigest()
    except OSError:
        return ""


def verify_backup_targets(targets: list[str]) -> list[dict]:
    """Check whether each target path exists and return its status."""
    results: list[dict] = []
    for path in targets:
        try:
            exists = os.path.isfile(path)
            status = "HEALTHY" if exists else "MISSING"
            meta_hash = _file_metadata_hash(path) if exists else ""
        except OSError:
            status = "MISSING"
            meta_hash = ""
        results.append({
            "path": path,
            "status": status,
            "metadata_hash": meta_hash,
        })
    return results


def check_backup_protection(incident_id: str, affected_files: Optional[list[str]] = None) -> dict:
    """Create a backup-protection snapshot for *incident_id* if none exists yet.

    The snapshot records the health of every configured backup target at this
    point in time.  It is idempotent — calling it twice for the same incident
    is a no-op on the second call.

    Returns the (new or existing) snapshot dict.
    """
    existing = db.get_backup_protection(incident_id)
    if existing:
        return {"snapshot": existing[0], "created": False}

    targets = _get_backup_targets()
    verifications = verify_backup_targets(targets) if targets else []

    snapshot = {
        "incident_id": incident_id,
        "affected_files": affected_files or [],
        "backup_targets": verifications,
    }

    saved = db.save_backup_protection(snapshot)
    return {"snapshot": saved, "created": True}


def list_backup_protection(incident_id: str) -> list[dict]:
    """Return all backup-protection snapshots for a given incident."""
    return db.get_backup_protection(incident_id)
