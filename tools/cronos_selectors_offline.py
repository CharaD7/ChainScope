#!/usr/bin/env python3
"""Offline selector/storage extraction from the cached Cronos bytecode (evmole)."""
from __future__ import annotations

import json
import pathlib

import evmole

CACHE = pathlib.Path("findings/cronos_2026_10/bytecode")

TARGETS = [
    ("cronos_launch_factory_impl", "0x823ee5d7765faa241a23b1e73244527321485f15"),
    ("cronos_launch_router_impl", "0xbb5660616864e13550700ae985545c29b8959e2e"),
    ("cronos_launch_bonding_impl", "0x188ea72a26448012431be4d4caabe78421fa36b6"),
    ("fulcrom_rewardrouter_impl", "0x57b775d25aa88e398bd0f69d74f078805ebccb1d"),
]


def main() -> int:
    for name, addr in TARGETS:
        f = CACHE / f"{name}.hex"
        if not f.exists():
            print(f"[skip] {name}: no cached bytecode")
            continue
        code = f.read_text().strip()
        if code == "0x":
            print(f"[skip] {name}: no code")
            continue
        print(f"\n===== {name}  {addr}  ({(len(code)-2)//2} bytes) =====")
        info = evmole.contract_info(code, selectors=True, state_mutability=True, storage=True)
        for fn in sorted(info.functions, key=lambda x: x.selector):
            mut = getattr(fn, "state_mutability", "?")
            print(f"  {fn.selector}  {mut}")
        print(f"  -- {len(info.functions)} selectors")
        st = getattr(info, "storage", None) or []
        for s in st:
            print(f"  slot {s.slot}: {s.type} bits={getattr(s, 'bits', '?')}")
        if st:
            print(f"  -- {len(st)} storage slots")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
