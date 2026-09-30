"""RPC endpoint resolution: optional authenticated keys, verified public fallbacks.

Nothing here is required. Free public endpoints answer everything the sweep
needs for targeted work; an authenticated endpoint only helps when probing
thousands of addresses, where public nodes rate-limit.

The failure this module exists to prevent: a sweep once reported "no code" for
all 240 targets because `polygon-rpc.com` began answering HTTP 401 without an
API key. Every result was "unreachable", which looks exactly like a finding of
"nothing there" and is the worst possible kind of silent failure - a sweep that
appears to work and returns all zeros.

So: every fallback endpoint below is one that has been verified to answer
`eth_getCode` unauthenticated, and `scan_scope.py` treats a 100%-unreachable
sweep as an endpoint fault rather than a result.
"""
from __future__ import annotations

import os
from pathlib import Path

# verified free, no key required
PUBLIC_FALLBACK = {
    "1": "https://ethereum.publicnode.com",
    "42161": "https://arbitrum-one-rpc.publicnode.com",
    "10": "https://optimism-rpc.publicnode.com",
    "137": "https://polygon-bor-rpc.publicnode.com",
    "8453": "https://base-rpc.publicnode.com",
    "56": "https://bsc-rpc.publicnode.com",
    "43114": "https://avalanche-c-chain-rpc.publicnode.com",
}

# env var consulted per chain, highest priority first
AUTH_ENV = {
    "1": ("ALCHEMY_MAINNET", "RPC_MAINNET"),
    "42161": ("ALCHEMY_ARBITRUM", "RPC_ARBITRUM"),
    "10": ("ALCHEMY_OPTIMISM", "RPC_OPTIMISM"),
    "137": ("ALCHEMY_POLYGON", "RPC_POLYGON"),
    "8453": ("ALCHEMY_BASE", "RPC_BASE"),
}

_ENV_NAME = {
    "1": "ALCHEMY_MAINNET",
    "42161": "ALCHEMY_ARBITRUM",
    "10": "ALCHEMY_OPTIMISM",
    "137": "ALCHEMY_POLYGON",
    "8453": "ALCHEMY_BASE",
}


def load_dotenv(root: Path | None = None) -> dict[str, str]:
    """Read a .env into os.environ without overwriting real environment values.

    Deliberately minimal - no dependency, no export side effects beyond this
    process. A malformed line is skipped rather than raising, because a broken
    .env must never be the reason a scan silently uses the wrong endpoint.
    """
    root = root or Path(__file__).resolve().parent.parent  # core/ -> ChainScope/
    path = root / ".env"
    loaded: dict[str, str] = {}
    if not path.exists():
        return loaded
    try:
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip("'\"")
            if not val:
                continue
            loaded[key] = val
            os.environ.setdefault(key, val)
    except OSError:
        return loaded
    return loaded


def rpc_for(chain: str) -> str | None:
    """Resolve an RPC for a chain token, preferring an authenticated endpoint."""
    chain = str(chain)
    for var in AUTH_ENV.get(chain, ()):
        val = os.environ.get(var, "").strip()
        if val:
            return val
    return PUBLIC_FALLBACK.get(chain)


def has_auth() -> dict[str, bool]:
    return {
        chain: bool(os.environ.get(env, "").strip())
        for chain, env in _ENV_NAME.items()
    }
