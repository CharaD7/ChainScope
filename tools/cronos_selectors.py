#!/usr/bin/env python3
"""Recover selectors + mutability + storage layout from Cronos deployed bytecode via evmole."""
from __future__ import annotations
import json, sys, urllib.request
RPC = "https://cronos-evm-rpc.publicnode.com"

def get_code(addr: str) -> str:
    body = json.dumps({"jsonrpc":"2.0","method":"eth_getCode","params":[addr,"latest"],"id":1}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return (json.loads(r.read().decode()) or {}).get("result","0x") or "0x"

def main() -> int:
    import evmole
    for a in [x.strip() for x in sys.argv[1:] if x.strip()]:
        code = get_code(a)
        size = (len(code)-2)//2
        print(f"\n===== {a}  ({size} bytes) =====")
        if not size:
            print("  no code"); continue
        info = evmole.contract_info(code, selectors=True, state_mutability=True, storage=True)
        for f in info.functions:
            print(f"  {f.selector}  {f.state_mutability}")
        print(f"  -- {len(info.functions)} functions")
        for s in getattr(info, "storage", []) or []:
            print(f"  storage slot {s.slot} -> {s.type} ({s.size} bytes)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
