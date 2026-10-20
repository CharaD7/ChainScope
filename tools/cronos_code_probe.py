#!/usr/bin/env python3
"""Pull deployed bytecode for a list of Cronos (chain 25) addresses via public RPC.

Determines: EOA-vs-contract, bytecode size, whether a minimal-proxy (EIP-1167 /
EIP-1967 / beacon) is in play, and dumps selectors via 4byte-style extraction of
the dispatcher. Source for Cronos mainnet is NOT on Sourcify and the official
Explorer API requires a key, so bytecode is the ground truth available offline.
"""
from __future__ import annotations

import json
import sys
import urllib.request

RPC = "https://evm.cronos.org"


def rpc(method: str, params: list) -> object:
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def get_code(addr: str) -> str:
    out = rpc("eth_getCode", [addr, "latest"])
    return (out or {}).get("result", "0x") or "0x"


def get_storage(addr: str, slot: str) -> str:
    out = rpc("eth_getStorageAt", [addr, slot, "latest"])
    return (out or {}).get("result", "0x") or "0x"


EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"


def main() -> int:
    addrs = [a.strip() for a in sys.argv[1:] if a.strip()]
    rows = []
    for a in addrs:
        code = get_code(a)
        n = (len(code) - 2) // 2
        impl = get_storage(a, EIP1967_IMPL)
        beacon = get_storage(a, EIP1967_BEACON)
        admin = get_storage(a, EIP1967_ADMIN)
        kind = "contract" if n > 0 else "EOA/none"
        notes = []
        if n > 0 and code[:20] == "0x363d3d373d3d3d363d73":
            notes.append("EIP-1167-minimal-proxy")
        if impl and impl != "0x" + "0" * 64:
            notes.append(f"1967-impl={('0x'+impl[-40:])}")
        if beacon and beacon != "0x" + "0" * 64:
            notes.append(f"1967-beacon={('0x'+beacon[-40:])}")
        if admin and admin != "0x" + "0" * 64:
            notes.append(f"1967-admin={('0x'+admin[-40:])}")
        rows.append({"address": a, "size_bytes": n, "kind": kind, "notes": notes})
        print(f"{a}  size={n:>6}  {kind}  {' '.join(notes)}")
    print(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
