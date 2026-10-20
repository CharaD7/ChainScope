#!/usr/bin/env python3
"""Cache deployed Cronos bytecode to disk (once), with retry + endpoint rotation.

Source for the newest in-scope Cronos targets is not published to Sourcify and the
official Explorer API requires a key, so bytecode is the durable offline artifact.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import time
import urllib.request

RPCS = [
    "https://evm.cronos.org",
    "https://cronos-evm-rpc.publicnode.com",
]
CACHE = pathlib.Path("findings/cronos_2026_10/bytecode")

TARGETS = {
    # Cronos Launch (impls behind the 3 EIP-1967 proxies)
    "cronos_launch_factory_impl": "0x823ee5d7765faa241a23b1e73244527321485f15",
    "cronos_launch_router_impl": "0xbb5660616864e13550700ae985545c29b8959e2e",
    "cronos_launch_bonding_impl": "0x188ea72a26448012431be4d4caabe78421fa36b6",
    # Cronos Launch proxies (for storage/impl re-check)
    "cronos_launch_factory_proxy": "0x227205a020bD5522E45436176d85603d2dCC43C5",
    "cronos_launch_router_proxy": "0xE39873Ffe547CeCdBA62e032B08c332c597Ea695",
    "cronos_launch_bonding_proxy": "0xA18f14a35853bC619132bA9e126Bf2Ec63183C8E",
    # Fulcrom newest (impls)
    "fulcrom_stakedflpdistributor_impl": "0x20d6e81f229fb180af83c6c2eb5d4df4e2ae9714",
    "fulcrom_fulvester_flpvester_impl": "0x499a141701297252aea150033fc3f36a20e9f62d",
    "fulcrom_rewardrouter_impl": "0x57b775d25aa88e398bd0f69d74f078805ebccb1d",
    # Fulcrom proxies
    "fulcrom_stakedflpdistributor_proxy": "0x629A8dd6BfF07844b25130ed659990d65e22Baaa",
    "fulcrom_fulvester_proxy": "0xA461fA4BF68C72369DB4fA8eD7cba4796598F2B0",
    "fulcrom_flpvester_proxy": "0x27E51D2B5A3283bEF4014519F095AB8dDCf023F6",
    "fulcrom_rewardrouter_proxy": "0x133B7f9570b3be8e51CCd5DA4654C3DDe7657Ae1",
}


def rpc_call(method: str, params: list) -> object:
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    last = None
    for attempt in range(6):
        rpc = RPCS[attempt % len(RPCS)]
        try:
            req = urllib.request.Request(rpc, data=body,
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(2 + attempt * 2)
    raise RuntimeError(f"rpc failed for {method}: {last}")


def main() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    out = {}
    for name, addr in TARGETS.items():
        f = CACHE / f"{name}.hex"
        if f.exists() and f.read_text().strip().startswith("0x"):
            code = f.read_text().strip()
        else:
            res = rpc_call("eth_getCode", [addr, "latest"])
            code = (res or {}).get("result", "0x") or "0x"
            f.write_text(code)
            time.sleep(1)
        out[name] = {"address": addr, "size": (len(code) - 2) // 2}
        print(f"{name:<42} {addr}  size={(len(code)-2)//2}")
    (CACHE / "index.json").write_text(json.dumps({"targets": TARGETS, "sizes": out}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
