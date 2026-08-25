"""Safe test lab — controlled harmless activity for testing AI Sentinel.

This module creates harmless test artifacts to verify that the detection
pipeline works end-to-end WITHOUT performing any real attack activity.

Run: python -m test_lab.run

All activity is confined to backend/test_lab/artifacts/.
"""
import hashlib
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"


def setup():
    """Create the test lab directory."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[test_lab] Artifacts directory: {ARTIFACTS_DIR}")


def create_files(count: int = 5):
    """Create harmless test files with random content."""
    for i in range(count):
        name = f"test_{uuid.uuid4().hex[:8]}.txt"
        path = ARTIFACTS_DIR / name
        content = f"Safe test file {i} created at {datetime.now(timezone.utc).isoformat()}\n"
        content += f"This is harmless test content for verifying file monitoring.\n"
        path.write_text(content, encoding="utf-8")
        h = hashlib.sha256(content.encode()).hexdigest()[:16]
        print(f"  Created: {name} (sha256:{h})")
    return count


def rename_files():
    """Rename some test files to test rename detection."""
    renamed = 0
    for f in list(ARTIFACTS_DIR.glob("test_*.txt"))[:2]:
        new_name = f.parent / f"renamed_{f.name}"
        f.rename(new_name)
        renamed += 1
        print(f"  Renamed: {f.name} -> {new_name.name}")
    return renamed


def delete_files():
    """Delete test files to test deletion detection."""
    deleted = 0
    for f in list(ARTIFACTS_DIR.glob("test_*.txt"))[:3]:
        f.unlink()
        deleted += 1
        print(f"  Deleted: {f.name}")
    return deleted


def clean_artifacts():
    """Remove all test artifacts."""
    count = 0
    for f in ARTIFACTS_DIR.iterdir():
        if f.is_file():
            f.unlink()
            count += 1
    print(f"[test_lab] Cleaned {count} artifacts")


def run():
    """Run a complete test lab cycle: create, rename, delete."""
    setup()
    print("\n=== Safe Test Lab ===")
    print("Creating test files...")
    create_files(5)
    time.sleep(1)
    print("\nRenaming test files...")
    rename_files()
    time.sleep(1)
    print("\nDeleting test files...")
    delete_files()
    print(f"\nRemaining artifacts: {len(list(ARTIFACTS_DIR.iterdir()))}")
    print("Test lab cycle complete. All activity was harmless and confined to:")
    print(f"  {ARTIFACTS_DIR}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        setup()
        clean_artifacts()
    else:
        run()
