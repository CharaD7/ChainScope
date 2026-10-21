#!/usr/bin/env python3
"""Automation wrapper for Bugcrowd programs.

Runs the generic ChainScope pipeline on the repository root.  Users are
expected to fetch a Bugcrowd program (e.g. via ``cs_bugcrowd list``) and
place the source under the ChainScope repo before invoking this script.
"""

import argparse
from pathlib import Path
from datetime import datetime

from .common import run_pipeline

def main() -> None:
    parser = argparse.ArgumentParser(description="Run ChainScope analysis on Bugcrowd programs.")
    parser.add_argument("--chain", default="mainnet", help="Chain identifier (e.g., mainnet, goerli)")
    parser.add_argument("--out", type=Path, default=None, help="Custom report path")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    out_path = args.out or (Path(__file__).resolve().parent / f"bugcrowd_report_{args.chain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md")
    run_pipeline(repo_root, args.chain, out_path)
    print(f"Bugcrowd report written to {out_path}")

if __name__ == "__main__":
    main()
