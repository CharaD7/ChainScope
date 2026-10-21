#!/usr/bin/env python3
"""Automation wrapper for HackenProof programs.

Calls the shared ``run_pipeline`` from ``automation/common.py`` on the
ChainScope repository root.  Platform‑specific fetching is left to the
user (e.g. ``cs_hacken list`` then checkout the target directory).  This
script provides a convenient entry point that runs the full analysis
pipeline and produces a markdown report.
"""

import argparse
from pathlib import Path
from datetime import datetime

from .common import run_pipeline

def main() -> None:
    parser = argparse.ArgumentParser(description="Run ChainScope analysis on HackenProof programs.")
    parser.add_argument("--chain", default="mainnet", help="Chain identifier (e.g., mainnet, goerli)")
    parser.add_argument("--out", type=Path, default=None, help="Custom report path")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    out_path = args.out or (Path(__file__).resolve().parent / f"hacken_report_{args.chain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md")
    run_pipeline(repo_root, args.chain, out_path)
    print(f"HackenProof report written to {out_path}")

if __name__ == "__main__":
    main()
