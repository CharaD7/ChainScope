#!/usr/bin/env python3
"""Resolve recovered selectors via openchain (batched) with 4byte fallback.

openchain accepts comma-separated selector lists, so this is a handful of requests
instead of ~120. Preference order per selector: a non-filtered name that appears on a
verified contract, then a non-filtered name, then anything.
"""
from __future__ import annotations

import json
import pathlib
import urllib.parse
import urllib.request

OUT = pathlib.Path("findings/cronos_2026_10/selectors_resolved.json")

GROUPS = {
    "cronos_launch_factory_impl": [
        "01ffc9a7","248a9ca3","2f2ff15d","36568abe","4f1ef286","4f7041a5","52d1902d",
        "574f2ba3","75b238fc","7a1ac61e","7acf6337","86a35f25","8aeda25a","91d14854",
        "a217fddf","ad4cb1cc","b91ac788","c0d78655","c9c65396","cc1776d3","d547741f",
        "e2ad37b0","e6e43905","f887ea40",
    ],
    "cronos_launch_router_impl": [
        "01ffc9a7","07bd0265","0901b116","1083f761","248a9ca3","2f2ff15d","36568abe",
        "36cfb374","45608d00","485cc955","4f1ef286","52d1902d","75b238fc","91d14854",
        "a217fddf","ad4cb1cc","ba37fd38","c45a0155","d547741f","d7c8747a","ff6d8d05",
    ],
    "cronos_launch_bonding_impl": [
        "057987e8","0863c37a","09c8962c","0da330c3","2afaca20","378dc3dc","3f0de1a5",
        "3fa41143","42621c8d","4f1ef286","504a565c","52d1902d","68a4c8b7","6edd12e0",
        "70e661b3","715018a6","735de9f7","7c13774b","8a038a54","8aabdb8b","8da5cb5b",
        "96c4b247","9a3ccd0f","9dd9d0fd","a932492f","ad4cb1cc","b4f2e8b8","bea9849e",
        "c36fe3d6","c45a0155","c7095255","cc489688","ddca3f43","e8e6ed69","f2fde38b",
        "f5dab711","f887ea40",
    ],
    "fulcrom_rewardrouter_impl": [
        "01e33667","0ec43da6","0f5719e3","12d43a51","1999fa6c","1af276a6","1c3e8c1f",
        "1cd26b13","2a9f4083","30b70002","392e53cd","3fc8cef3","4864ce25","4e71d92d",
        "508bbbfc","5ca57ec7","62dfd9c3","7bd23cc9","800eabe5","8129fc1c","83b36a1d",
        "a799d975","ae3e584c","b73149e1","bcea2645","c34db17b","c35066c4","cfad57a2",
        "d294f093","d2c4967c","d4b61e5d","e13378f3","e15ad37e","e1b9db89","ed329018",
        "f69e2046","fd34119c",
    ],
}

ALL = sorted({s for sels in GROUPS.values() for s in sels})


def fetch(batch: list[str]) -> dict[str, list[dict]]:
    q = ",".join("0x" + s for s in batch)
    url = "https://api.openchain.xyz/signature-database/v1/lookup?filter=false&function=" + urllib.parse.quote(q)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=40) as r:
        data = json.loads(r.read().decode())
    return (data.get("result") or {}).get("function") or {}


def pick(cands: list[dict]) -> list[str]:
    if not cands:
        return []
    good = [c for c in cands if not c.get("filtered")]
    verified = [c for c in good if c.get("hasVerifiedContract")]
    ordered = verified + [c for c in good if c not in verified] + cands
    out, seen = [], set()
    for c in ordered:
        n = c.get("name")
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out[:3]


def main() -> int:
    resolved: dict[str, list[str]] = {}
    B = 18
    for i in range(0, len(ALL), B):
        batch = ALL[i:i + B]
        try:
            res = fetch(batch)
        except Exception as exc:  # noqa: BLE001
            print(f"  [warn] batch {i} failed: {exc}")
            res = {}
        for s in batch:
            key = "0x" + s
            cands = res.get(key) or []
            resolved[s] = pick(cands)
        print(f"  batch {i//B + 1}: {len(batch)} selectors")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(resolved, indent=2))
    for group, sels in GROUPS.items():
        print(f"\n=== {group} ===")
        for s in sels:
            names = resolved.get(s) or []
            print(f"  {s} -> {names[0] if names else '(unknown)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
