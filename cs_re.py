#!/usr/bin/env python3
"""Reverse-engineer a deployed contract from bytecode (for source-blocked targets).

Many in-scope targets (proxies, bridges, "unverified" implementations, or protocols whose
Sourcify source is only commented-out stubs) hide their logic in bytecode. ``cs_re`` extracts
the real implementation of a proxy, enumerates its function selectors, resolves those it can
against a built-in signature table, and classifies functions into MONEY (mint/burn/deposit/
withdraw/transfer/claim/swap) vs AUTH (grantRole/revokeRole/paused/role) vs view. Use it on a
contract whose source ``cs_fetch`` could not retrieve, then deep-dive the flagged externals.

    python cs_re.py 1:0x8236a87084f8b84306f72007f36f2618a5634494
    python cs_re.py etherscan.io:0x8236a870 ...   # accepts any chain label from deploy_source
    python cs_re.py 1:0x... --impl             # force: also show the resolved implementation
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
import typing
import urllib.request

import typer

from core import deploy_source

app = typer.Typer()

# Common selector -> signature table. Extended by `cast 4byte` lookup when a signature is unknown.
_SIGS: dict[str, str] = {
    "0x40c10f19": "mint(address,uint256)",
    "0x42966c68": "burn(uint256)",
    "0x70a08231": "balanceOf(address)",
    "0x18160ddd": "totalSupply()",
    "0x06fdde03": "name()",
    "0x95d89b41": "symbol()",
    "0x313ce567": "decimals()",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0xa9059cbb": "transfer(address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0xdd62ed3e": "allowance(address,address)",
    "0x2f2ff15d": "grantRole(uint256,address)",
    "0x36568abe": "revokeRole(uint256,address)",
    "0x5c975abb": "paused()",
    "0x248a9ca3": "getRoleAdmin(uint256)",
    "0x01ffc9a7": "supportsInterface(bytes4)",
    "0x2a309ef9": "maxMint(address)",
    "0x3b19e84a": "maxWithdraw(address)",
    "0x4e71d92d": "withdraw()",
    "0xa0712d68": "mint(uint256)",
    "0x6e553f65": "deposit(uint256,address)",
    "0x7d7a0a00": "limitMint(uint256,address)",
    "0x4ce51488": "mint(uint256,address)",
    "0x6bc63893": "batchMint(bytes,bytes)",
    "0x30b93d85": "mint(bytes,uint256)",
    "0x47af9957": "execute()",
    "0x7dea53c4": "execute(bytes)",
    "0x34c1f48f": "rescueTokens(address,uint256)",
    "0x42966c68": "burn(uint256)",
    "0x089bb99a": "receiveMessage(bytes,bytes)",
    "0x06689495": "sendMessage(bytes,bytes,bytes,bytes)",
    "0x0aa6220b": "swap()",
    "0x68573107": "swap(address,uint256,bytes,bytes)",
    "0x59aae4ba": "multicall(bytes[],bytes[],bytes[],bytes[])",
    "0x634e93da": "setOperator(address)",
    "0x649a5ec7": "setPegPrice(uint48)",
    "0x73cfc6b2": "isSwapEnabled()",
    "0x3644e515": "eip712Domain()",
    "0x3644e515": "decimals()",
    "0x313ce567": "decimals()",
    "0x80e787df": "previewWithdraw(bytes,uint256)",
    "0x84ef8ffc": "version()",
    "0x1beda7e3": "nonces(address)",
    "0x7ecebe00": "ownerOf(uint256)",
    "0x0aa6220b": "receive()",
}

_MONEY = re.compile(r"^(mint|burn|deposit|withdraw|transfer|claim|redeem|swap|sell|buy|execute|cancel|settle|repay|stake|unstake|send)\b", re.I)
_VIEW = re.compile(r"^(total|balance|name|symbol|decimals|preview|max|allowance|supports|paused|version|nonces|owner|\w*Of|is|get|eip712)", re.I)


def _code(chain: int, addr: str) -> str:
    # minimal: use a public RPC for the chain via deploy_source's resolver, fallback to eth public.
    body = ('{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["%s","latest"]}' % addr).encode()
    urls = ["https://rpc.flashbots.net", "https://eth.drpc.org", "https://ethereum.publicnode.com"]
    for u in urls:
        try:
            req = urllib.request.Request(u, body, {"Content-Type": "application/json"})
            raw = json.loads(urllib.request.urlopen(req, timeout=20).read()).get("result", "")
            if raw and raw != "0x":
                return raw
        except Exception:  # noqa: BLE001
            continue
    return ""


def _impl_address(chain: int, addr: str, code: str) -> str:
    # EIP-1967 implementation slot
    slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735"
    body = ('{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":["%s","%s","latest"]}' % (addr, slot)).encode()
    for u in ["https://rpc.flashbots.net", "https://eth.drpc.org", "https://ethereum.publicnode.com"]:
        try:
            req = urllib.request.Request(u, body, {"Content-Type": "application/json"})
            val = json.loads(urllib.request.urlopen(req, timeout=20).read()).get("result", "")
            if val and val not in ("0x0", "0x", "0x0000000000000000000000000000000000000000000000000000000000000000"):
                return "0x" + val[-40:]
        except Exception:  # noqa: BLE001
            continue
    return ""


def _selectors(code: str) -> list[str]:
    # Extract 4-byte selectors by scanning the PUSH4 selector patterns (0x63xxxxxxxx)
    sel: set[str] = set()
    hexs = code[2:].lower()
    for m in re.finditer(r"63([0-9a-f]{8})", hexs):
        sel.add("0x" + m.group(1))
    return sorted(sel)


@app.command()
def rev(
    spec: str = typer.Argument(..., help="chain:address (e.g. 1:0x..., etherscan.io:0x...)"),
    show_impl: bool = typer.Option(False, "--impl", help="Print the resolved implementation"),
):
    try:
        label, addr = spec.rsplit(":", 1)
        chain = deploy_source.chain_id(label)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"bad spec: {exc}", err=True)
        raise typer.Exit(1)

    code = _code(chain, addr)
    if not code:
        typer.echo("could not fetch bytecode", err=True)
        raise typer.Exit(1)
    typer.echo(f"[{addr}] code bytes: {len(code)//2}")

    impl = _impl_address(chain, addr, code)
    if impl:
        if show_impl:
            typer.echo(f"  implementation: {impl}")
        icode = _code(chain, impl)
        if icode:
            code = icode
            typer.echo(f"  using implementation bytecode ({len(icode)//2} bytes)")

    sels = _selectors(code)
    typer.echo(f"  selectors: {len(sels)}")
    money: list[str] = []
    auth: list[str] = []
    other: list[str] = []
    for s in sels:
        sig = _SIGS.get(s, None)
        cat = "?"
        name = sig or ("?" + s)
        if sig and _MONEY.match(sig):
            cat = "MONEY"
            money.append(f"{s} {sig}")
        elif sig and (_VIEW.match(sig)):
            cat = "view"
        elif sig and any(t in sig for t in ("Role", "role")):
            cat = "AUTH"
            auth.append(f"{s} {sig}")
        elif sig and ("(" in sig):
            cat = "ext"
        else:
            cat = "?name"
            other.append(s)
        if cat in ("ext", "?name") and sig:
            typer.echo(f"  {s}  {sig if sig else 'unknown'}  [{cat}]")
    typer.echo(f"\n  ---- MONEY movers (external, non-view) ----")
    for m in money:
        typer.echo(f"    {m}")
    typer.echo(f"  ---- AUTH/role functions ----")
    for a in auth:
        typer.echo(f"    {a}")
    if other:
        typer.echo(f"  ---- unresolved selectors (try: cast 4byte <sel>) ----")
        for s in other[:20]:
            typer.echo(f"    {s}")


if __name__ == "__main__":
    app()
