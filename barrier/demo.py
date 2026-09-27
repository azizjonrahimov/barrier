"""Entry point so `python -m barrier.demo` runs the scripted story."""

import runpy
from pathlib import Path

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).resolve().parent.parent / "demo" / "demo.py"),
                   run_name="__main__")
