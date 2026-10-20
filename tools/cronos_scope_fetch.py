#!/usr/bin/env python3
"""Coverage-probe then fetch the in-scope Cronos (chain 25) scope targets.

Scope list is taken live from the HackenProof program detail, so the fetch always
tracks the current in-scope table rather than a stale hard-coded list.
"""
from __future__ import annotations

import json
import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import deploy_source  # noqa: E402

SCOPE_RE = re.compile(r"0x[0-9a-fA-F]{40}")


def scope_addresses() -> list[str]:
    """Pull 0x addresses out of the program detail scope, de-duplicated, order-stable."""
    from cli import cs_hacken
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            cs_hacken.details("cronos-smart-contracts", json_output=True)
        except SystemExit:
            pass
    text = buf.getvalue()
    seen, out = set(), []
    for m in SCOPE_RE.findall(text):
        a = m.lower()
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out


def main() -> int:
    addrs = scope_addresses()
    print(f"scope addresses: {len(addrs)}", file=sys.stderr)
    specs = [f"25:{a}" for a in addrs]

    cov = deploy_source.coverage(specs, timeout=25)
    print(json.dumps({k: (v if not isinstance(v, list) else len(v)) for k, v in cov.items()}, indent=2))
    verified = cov.get("verified", [])
    print(f"\nverified: {len(verified)}", file=sys.stderr)

    if "--fetch" in sys.argv:
        results = deploy_source.fetch_many(
            [f"25:{a}" for a in (verified or addrs)],
            base_out=".chainsource/hacken-cronos-scope",
            timeout=90,
        )
        print(json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
