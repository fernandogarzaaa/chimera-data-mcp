import sys
from pathlib import Path

# src/main.py imports sibling modules as top-level (`from database import ...`),
# matching how the server is launched (`python src/main.py`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
