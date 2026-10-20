#!/usr/bin/env python3
"""Fetch in-scope Cronos (chain 25) sources via Sourcify and index them.

Usage:
    ./.venv/bin/python tools/cronos_fetch.py            # coverage probe only
    ./.venv/bin/python tools/cronos_fetch.py --fetch    # download verified sources
"""
from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import deploy_source  # noqa: E402

SCOPE_RE = re.compile(r"0x[0-9a-fA-F]{40}")

# Newest additions to the scope table (Fulcrom + Cronos Launch), from the program page.
NEW_TARGETS = [
    "0x629A8dd6BfF07844b25130ed659990d65e22Baaa",  # Fulcrom StakedFlpDistributor
    "0xA461fA4BF68C72369DB4fA8eD7cba4796598F2B0",  # Fulcrom FulVester
    "0x27E51D2B5A3283bEF4014519F095AB8dDCf023F6",  # Fulcrom FlpVester
    "0x133B7f9570b3be8e51CCd5DA4654C3DDe7657Ae1",  # Fulcrom RewardRouter
    "0x227205a020bD5522E45436176d85603d2dCC43C5",  # Cronos Launch Factory
    "0xE39873Ffe547CeCdBA62e032B08c332c597Ea695",  # Cronos Launch Router
    "0xA18f14a35853bC619132bA9e126Bf2Ec63183C8E",  # Cronos Launch Bonding
]


def main() -> int:
    addrs = [a.lower() for a in NEW_TARGETS]
    specs = [f"25:{a}" for a in addrs]
    print(f"targets: {len(specs)}", file=sys.stderr)

    cov = deploy_source.coverage(specs, timeout=25)
    summary = {k: (len(v) if isinstance(v, list) else v) for k, v in cov.items()}
    print(json.dumps(summary, indent=2))
    for k in ("verified", "unverified", "unreachable"):
        for item in cov.get(k, []) or []:
            print(f"  {k}: {item}")

    if "--fetch" in sys.argv:
        verified = cov.get("verified") or []
        targets = verified or specs
        results = deploy_source.fetch_many(
            targets if targets and targets[0].startswith("25:") else [f"25:{a}" for a in targets],
            base_out=".chainsource/cronos_new",
            timeout=90,
        )
        print(json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
