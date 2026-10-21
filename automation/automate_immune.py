#!/usr/bin/env python3
"""Automation wrapper for Immunefi programs.

Uses the generic pipeline from ``automation/common.py``.
All arguments are forwarded to the pipeline:
* ``--chain`` – blockchain/network (default ``mainnet``)
* ``--out`` – optional custom report path (defaults to a timestamped file in this directory).
"""

import argparse
from pathlib import Path

# Import the shared pipeline helper
from .common import run_pipeline

def main() -> None:
    parser = argparse.ArgumentParser(description="Run ChainScope analysis on Immunefi programs.")
    parser.add_argument("--chain", default="mainnet", help="Chain identifier (e.g., mainnet, goerli)")
    parser.add_argument("--out", type=Path, default=None, help="Custom report path")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]  # ChainScope repo root
    out_path = args.out or (Path(__file__).resolve().parent / f"immunefi_report_{args.chain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md")
    run_pipeline(repo_root, args.chain, out_path)
    print(f"Immunefi report written to {out_path}")

if __name__ == "__main__":
    main()
