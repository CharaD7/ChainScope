#!/usr/bin/env python3
"""Fetch Sourcify-verified deployed source for a contract and lay it out as a local
repo so it can be indexed by ChainScope.

ChainScope is local-first: ``cs_build`` consumes a source directory. Many long-tail
bug-bounty targets publish only a *deployed* (Sourcify-verified) contract and keep
their repo private or deployments-only. This module fetches the verified source tree
from Sourcify and materialises it (preserving relative import paths) so the graph can
be built without any repository access.
"""
from __future__ import annotations

import json
import os
import pathlib
import typing
import urllib.parse
import urllib.request

# Explorer host -> EVM chain id, used to normalise a human chain label.
CHAIN_BY_HOST: dict[str, int] = {
    "etherscan.io": 1,
    "basescan.org": 8453,
    "arbiscan.io": 42161,
    "optimistic.etherscan.io": 10,
    "polygonscan.com": 137,
    "zkevm.polygonscan.com": 1101,
    "scrollscan.com": 534352,
    "avascan.info": 43114,
    "ftmscan.com": 250,
    "bscscan.com": 56,
    "lineascan.build": 59144,
    "etherscan.io-xlayer": 196,
    "snowtrace.io": 43114,
    "hyperevmscan.io": 999,
}

_CHAIN_IDS: dict[str, int] = {
    "1": 1, "eth": 1, "mainnet": 1,
    "8453": 8453, "base": 8453,
    "42161": 42161, "arbitrum": 42161, "arb": 42161,
    "10": 10, "optimism": 10, "op": 10,
    "137": 137, "polygon": 137,
    "999": 999, "hyperevm": 999, "hyperliquid": 999,
}


def chain_id(value: str) -> int:
    """Resolve a chain token (e.g. '1', 'etherscan.io', 'hyperevm') to an EVM chain id."""
    v = value.strip().lower()
    if v in _CHAIN_IDS:
        return _CHAIN_IDS[v]
    host = urllib.parse.urlparse(value if "://" in value else f"https://{value}").netloc
    if host in CHAIN_BY_HOST:
        return CHAIN_BY_HOST[host]
    if v.isdigit():
        return int(v)
    raise ValueError(f"unrecognised chain: {value}")


def fetch_sourcify_source(
    chain: str | int,
    address: str,
    out_dir: str | os.PathLike[str],
    *,
    timeout: int = 60,
) -> dict[str, typing.Any]:
    """Fetch the Sourcify-verified source for ``address`` on ``chain`` and write the
    full source tree (preserving relative import paths) under ``out_dir``.

    Returns a small metadata dict (match status, verifiedAt, files written, total sources).
    """
    chain = int(chain)
    address = address.strip().lower()
    if not address.startswith("0x") or len(address) != 42:
        raise ValueError(f"invalid contract address: {address}")

    url = f"https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=all"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    if not isinstance(payload, dict):
        raise RuntimeError(f"unexpected Sourcify response for {chain}:{address}")

    match = payload.get("match")
    if match in (None, "null", ""):
        raise RuntimeError(
            f"{chain}:{address} is not Sourcify-verified (match={match!r}) "
            f"-> use Etherscan/Blockscout instead"
        )

    sources = (payload.get("sources") or {})
    if not sources:
        # Some responses nest under payload["source"]["sources"].
        sources = ((payload.get("source") or {}).get("sources") or {})

    out = pathlib.Path(out_dir)
    written = 0
    for path, blob in sources.items():
        content = (blob or {}).get("content")
        if content is None:
            continue
        target = (out / path).resolve()
        # Guard against path traversal from a malformed source path.
        if not str(target).startswith(str(out.resolve())) and os.path.isabs(path):
            raise ValueError(f"unsafe source path: {path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        written += 1

    if not written:
        raise RuntimeError(f"Sourcify returned no source content for {chain}:{address}")

    fmt = os.path.join(str(out), ".chainsource.json")
    pathlib.Path(fmt).write_text(
        json.dumps(
            {
                "source": "sourcify",
                "chain": chain,
                "address": address,
                "match": match,
                "verifiedAt": payload.get("verifiedAt"),
                "files": written,
                "compiler": (payload.get("metadata") or {}).get("compiler"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return {
        "chain": chain,
        "address": address,
        "match": match,
        "verifiedAt": payload.get("verifiedAt"),
        "files": written,
        "files_available": len(sources),
        "out_dir": str(out),
    }


def fetch_many(
    specs: list[str],
    base_out: str | os.PathLike[str],
    *,
    timeout: int = 90,
    **_unused: typing.Any,
) -> list[dict[str, typing.Any]]:
    """Fetch several ``chain:address`` specs into sibling directories under base_out."""
    results = []
    for spec in specs:
        try:
            chain_token, _, addr = spec.partition(":")
            results.append(
                fetch_sourcify_source(
                    chain_id(chain_token),
                    addr,
                    os.path.join(str(base_out), str(chain_id(chain_token)), addr.lower()),
                    timeout=timeout,
                )
            )
        except Exception as exc:  # noqa: BLE001 - report per-spec and continue
            results.append({"spec": spec, "error": str(exc)})
    return results
