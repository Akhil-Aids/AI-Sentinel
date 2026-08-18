import os
import sys
from pathlib import Path

MODEL_DIR = Path(os.getenv("MODEL_DIR", "backend/models"))
MODEL_PATH = MODEL_DIR / "anomaly_model.joblib"

print(f"CWD: {os.getcwd()}")
print(f"MODEL_PATH: {MODEL_PATH}")
print(f"MODEL_PATH exists: {MODEL_PATH.exists()}")

if not MODEL_PATH.exists():
    # Check if models/ exists in CWD
    print(f"\nTrying models/ instead of backend/models/:")
    alt_path = Path("models/anomaly_model.joblib")
    print(f"Alt path: {alt_path}")
    print(f"Alt path exists: {alt_path.exists()}")
    if alt_path.exists():
        print(f"Files in models/:")
        for f in Path("models").iterdir():
            print(f"  - {f.name}")
