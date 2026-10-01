"""Bytecode reverse engineering for target triage.

Most of the interesting surface is not published as source. Gamma, MetaLend and
Arcadia's live versions all served bytecode with no verifiable source, and that
is where triage stalled repeatedly: we could not tell whether a program was
reviewable at all, and burned real time finding out. Sourcify coverage exists but
is patchy, and a Sourcify entry is not proof the entry matches what is live -
Arcadia's AccountV4 verified on Sourcify while the deployed bytecode differed from
the repository.

So this module reconstructs *structure* from deployed bytecode:

  * function selector extraction and 4byte resolution
  * interface inference (ERC20/721/1155/4626/7579/Ownable/AccessControl/Proxy)
  * proxy resolution: EIP-1967, EIP-1167 minimal, EIP-1822 UUPS, beacon, clones
  * EIP-2535 diamond facets - the case that byte-for-byte selector matching
    cannot see through, because the logic lives in facet contracts registered in
    storage and appears in no reachable bytecode
  * dangerous opcode usage (DELEGATECALL, SELFDESTRUCT, CREATE2, CALLCODE)
  * storage slot inventory, constructor immutables, opcode histograms
  * differential comparison of two contracts' bytecode

The honest limit, stated once here because it governs every result: this recovers
structure, not meaning. It can tell you a contract exposes an unguarded sweep; it
cannot tell you whether the sweep is safe. Every function here is a filter for
what a human then reads.

Nothing in this module infers a verdict. It reports what is present and what is
absent, and marks UNKNOWN where the bytecode cannot decide.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import typing as t
from pathlib import Path

# --------------------------------------------------------------------------- #
# known interfaces
# --------------------------------------------------------------------------- #

# Required signature sets used for inference. A signature must be matched exactly
# after 4byte resolution; a name-only match is not evidence, because thousands of
# contracts share `owner()` while plenty of unverified contracts also expose a
# `name()` and nothing else.
INTERFACES: dict[str, dict[str, t.Any]] = {
    "ERC4626": {
        "required": [
            "totalAssets()", "convertToShares(uint256)", "convertToAssets(uint256)",
            "maxDeposit(address)", "previewDeposit(uint256)", "maxMint(address)",
            "previewMint(uint256)", "maxWithdraw(address)", "previewWithdraw(uint256)",
            "maxRedeem(address)", "previewRedeem(uint256)",
        ],
        "threshold": 0.8,
    },
    "ERC20": {
        "required": [
            "totalSupply()", "balanceOf(address)", "transfer(address,uint256)",
            "transferFrom(address,address,uint256)", "approve(address,uint256)",
            "allowance(address,address)",
        ],
        "threshold": 0.85,
    },
    "ERC721": {
        "required": [
            "balanceOf(address)", "ownerOf(uint256)", "approve(address,uint256)",
            "getApproved(uint256)", "setApprovalForAll(address,bool)",
            "isApprovedForAll(address,address)",
        ],
        "threshold": 0.85,
    },
    "ERC1155": {
        "required": [
            "balanceOf(address,uint256)", "balanceOfBatch(address[],uint256[])",
            "setApprovalForAll(address,bool)", "isApprovedForAll(address,address)",
            "safeTransferFrom(address,address,uint256,uint256,bytes)",
        ],
        "threshold": 0.8,
    },
    "Ownable": {
        "required": ["owner()", "renounceOwnership()", "transferOwnership(address)"],
        "threshold": 0.99,
    },
    "AccessControl": {
        "required": [
            "hasRole(bytes32,address)", "getRoleAdmin(bytes32)",
            "grantRole(bytes32,address)", "revokeRole(bytes32,address)",
            "renounceRole(bytes32,address)",
        ],
        "threshold": 0.8,
    },
    "Pausable": {
        "required": ["paused()", "pause()", "unpause()"],
        "threshold": 0.99,
    },
    "UUPSProxy": {
        "required": ["upgradeTo(address)", "upgradeToAndCall(address,bytes)"],
        "threshold": 0.99,
    },
    "ERC7579": {
        "required": [
            "execute(address,uint256,bytes)", "executeFromExecutor(bytes32,bytes)",
        ],
        "threshold": 0.99,
    },
    "Permit2": {
        "required": ["permit(address,address,address,uint256,uint256,bytes)",
                     "transferFrom(address,address,uint160,address)"],
        "threshold": 0.5,
    },
}

# Selectors, not names, are what we can trust from a bare function list.
DANGEROUS_OPS = {
    "DELEGATECALL": 0xF4,
    "CALLCODE": 0xF2,
    "SELFDESTRUCT": 0xFF,
    "CREATE2": 0xF5,
    "CREATE": 0xF0,
    "SSTORE": 0x55,
    "CALL": 0xF1,
}
DANGEROUS_REASONS = {
    "DELEGATECALL": "runs external code in this contract's storage",
    "CALLCODE": "deprecated, executes foreign code in caller storage",
    "SELFDESTRUCT": "can destroy the contract and force-send its balance",
    "CREATE2": "deterministic deployment; relevant to clone/factory front-running",
    "CREATE": "deploys a child contract",
    "SSTORE": "state write",
    "CALL": "value or control transfer",
}

# EIP-1967 / EIP-1822 / beacon slots
SLOT_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
# EIP-1167 minimal proxy runtime: 363d3d373d3d3d363d73<impl>5af43d82803e903d91602b57fd5bf3
# EIP-1167 minimal proxy runtime is a fixed 45-byte shape:
#   363d3d373d3d3d363d73 <20-byte impl> 5af43d82803e903d91602b57fd5bf3
# Some clones (OpenZeppelin/0age variants) differ only by an extra PUSH prefix,
# so a second shape is accepted.
_HEX40 = r"[0-9a-fA-F]{40}"
# Anchored at BOTH ends on purpose. An EIP-1167 runtime is exactly 45 bytes;
# a longer contract merely starting with that prefix is something else, and
# calling it an immutable proxy would understate an upgradeable one.
_MP_TAIL = r"5af43d82803e903d91602b57fd5bf3"
MINIMAL_PROXY_RE = re.compile(rf"^363d3d373d3d3d363d73({_HEX40}){_MP_TAIL}$", re.I)
CLONE_RE = re.compile(rf"^(?:3d3d3d3d)?363d3d37363d73({_HEX40}){_MP_TAIL}$", re.I)


class REError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# bytecode parsing
# --------------------------------------------------------------------------- #

def _strip_hex(h: str) -> str:
    h = (h or "").strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return re.sub(r"[^0-9a-fA-F]", "", h)


def iter_opcodes(code_hex: str) -> t.Iterator[tuple[int, str]]:
    """Yield exactly one (opcode, push_data) pair per instruction.

    Skipping PUSH payload is the whole game: a naive scan of hex pairs reports
    payload bytes as opcodes, which is how selector extraction ends up with
    nonsense.

    One yield per instruction, not two. Yielding PUSH twice (once bare, once with
    its data) makes any consumer that tallies opcodes count every PUSH twice, which
    quietly inflates opcode histograms and distorts the differential deltas.
    """
    h = _strip_hex(code_hex)
    i = 0
    n = len(h)
    while i + 2 <= n:
        op = int(h[i:i + 2], 16)
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            size = op - 0x5F
            data = h[i + 2:i + 2 + size * 2]
            yield op, data
            i += 2 + size * 2
        else:
            yield op, ""
            i += 2


def extract_selectors(code_hex: str, dispatcher_fraction: float = 0.5) -> dict[str, t.Any]:
    """Pull PUSH4 constants, split into dispatcher candidates and other constants.

    A real dispatcher compares the calldata selector against a small table near
    the top of the runtime code. PUSH4 values deeper in the code are usually
    coincidental 4-byte windows of other data, so the two are reported separately
    rather than merged into one confident-looking set.
    """
    h = _strip_hex(code_hex)
    total = len(h) // 2
    cutoff = max(64, int(total * dispatcher_fraction))
    dispatcher: list[str] = []
    elsewhere: list[str] = []
    seen: set[str] = set()
    for idx, (op, data) in enumerate(iter_opcodes(code_hex)):
        if op == 0x63 and data and len(data) == 8:  # PUSH4
            sel = "0x" + data.lower()
            if sel in seen:
                continue
            seen.add(sel)
            if idx <= cutoff:
                dispatcher.append(sel)
            else:
                elsewhere.append(sel)
    return {
        "dispatcher": sorted(dispatcher),
        "other_constants": sorted(elsewhere),
        "code_bytes": total,
    }


def opcode_histogram(code_hex: str) -> dict[str, int]:
    hist: dict[str, int] = {}
    for op, _ in iter_opcodes(code_hex):
        hist[f"0x{op:02x}"] = hist.get(f"0x{op:02x}", 0) + 1
    return hist


def dangerous_ops(code_hex: str) -> list[dict[str, t.Any]]:
    hist = opcode_histogram(code_hex)
    out = []
    for name, opc in DANGEROUS_OPS.items():
        n = hist.get(f"0x{opc:02x}", 0)
        if n:
            out.append({"op": name, "count": n, "why": DANGEROUS_REASONS[name]})
    out.sort(key=lambda d: d["count"], reverse=True)
    return out


def storage_slots(code_hex: str) -> list[dict[str, t.Any]]:
    """Slots written by PUSHn immediately preceding an SLOAD/SSTORE.

    A map or array access compiles to a hash/plus of a base slot, so the pushed
    constant is the storage base, which is what a storage-collision review needs.
    """
    h = _strip_hex(code_hex)
    out: list[dict[str, t.Any]] = []
    pending: str | None = None
    for op, data in iter_opcodes(code_hex):
        if 0x60 <= op <= 0x7F and data:
            pending = data
            continue
        if op in (0x54, 0x55) and pending:  # SLOAD / SSTORE
            trimmed = pending.lower().lstrip("0")
            out.append({
                # 0x00 must render as 0x0, not the empty string after stripping
                "slot": ("0x" + trimmed) if trimmed else "0x0",
                "op": "SLOAD" if op == 0x54 else "SSTORE",
            })
        pending = None
    return out


def is_minimal_proxy(code_hex: str) -> str | None:
    h = _strip_hex(code_hex).lower()
    m = MINIMAL_PROXY_RE.match(h) or CLONE_RE.match(h)
    return "0x" + m.group(1) if m else None


def trailing_immutables(code_hex: str, assume: int = 32) -> list[str]:
    """Constructor-set immutables appended to the end of runtime code."""
    h = _strip_hex(code_hex)
    n = len(h)
    if assume <= 0 or n < assume * 2:
        return []
    tail = h[-assume * 2:]
    return ["0x" + tail.lower()]


# --------------------------------------------------------------------------- #
# chain interaction
# --------------------------------------------------------------------------- #

def _env() -> dict[str, str]:
    foundry = Path.home() / ".foundry" / "bin"
    return {**os.environ, "PATH": f"{foundry}:{os.environ.get('PATH', '')}"}


def _cast(args: list[str], timeout: int = 90) -> tuple[bool, str]:
    try:
        p = subprocess.run(["cast", *args], capture_output=True, text=True,
                           timeout=timeout, env=_env())
        return p.returncode == 0, (p.stdout or p.stderr).strip()
    except Exception:  # noqa: BLE001
        return False, ""


def rpc_for(chain: str) -> str | None:
    from .cs_rpc import rpc_for as _r

    return _r(str(chain))


def runtime_code(chain: str, address: str) -> str:
    url = rpc_for(chain)
    if not url:
        raise REError(f"no rpc for chain {chain}")
    ok, code = _cast(["code", address, "--rpc-url", url], timeout=120)
    if not ok:
        raise REError(f"cast code failed for {address}: {code[:80]}")
    return code if code.startswith("0x") else "0x" + code


def _storage(chain: str, address: str, slot: str) -> str | None:
    url = rpc_for(chain)
    if not url:
        return None
    ok, val = _cast(["storage", address, slot, "--rpc-url", url], timeout=90)
    if not ok or not val or val == "0x":
        return None
    val = val.strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", val):
        return None
    addr = "0x" + val[-40:]
    return None if int(addr, 16) == 0 else addr


def _call(chain: str, address: str, sig: str, args: str = "") -> tuple[bool, str]:
    url = rpc_for(chain)
    if not url:
        return False, ""
    a = [f"{address}", sig]
    if args:
        a += args.split()
    return _cast(["call", *a, "--rpc-url", url], timeout=90)


def resolve_proxy(chain: str, address: str) -> dict[str, t.Any]:
    """Classify how an address reaches its logic, following every chain we know.

    Order matters: a minimal proxy's implementation is in its runtime code, a
    diamond's logic is in facets that appear in NO reachable bytecode, and a
    beacon's implementation moves without the address changing. All three look
    like "a contract" from the outside, and each was a dead end in practice.
    """
    out: dict[str, t.Any] = {
        "address": address,
        "chain": str(chain),
        "kind": "DIRECT",
        "implementations": [],
        "beacon": None,
        "facets": [],
        "notes": [],
    }
    try:
        code = runtime_code(chain, address)
    except REError as exc:
        out["kind"] = "UNREACHABLE"
        out["notes"].append(str(exc))
        return out

    out["code_bytes"] = len(_strip_hex(code)) // 2

    minimal = is_minimal_proxy(code)
    if minimal:
        out["kind"] = "EIP1167_MINIMAL_PROXY"
        out["implementations"].append(minimal)
        out["notes"].append(
            "EIP-1167 minimal proxy: the implementation is hardcoded in the "
            "runtime code, so it can never be upgraded."
        )
        return out

    impl = _storage(chain, address, SLOT_IMPL)
    if impl:
        out["kind"] = "EIP1967_PROXY"
        out["implementations"].append(impl)

    beacon = _storage(chain, address, SLOT_BEACON)
    if beacon:
        out["kind"] = "BEACON"
        out["beacon"] = beacon
        ok, bimpl = _call(chain, beacon, "implementation()(address)")
        if ok and re.fullmatch(r"0x[0-9a-fA-F]{40}", bimpl.strip()):
            out["implementations"].append(bimpl.strip())
        out["notes"].append(
            "beacon proxy: the implementation can change without this address "
            "changing, so a review of today's implementation may not hold tomorrow"
        )

    # EIP-2535 diamond: loupe() reports facets; facet logic is in facet
    # contracts, NOT in this contract's bytecode.
    ok_loupe, loupe = _call(chain, address, "facets()(address[])")
    if ok_loupe:
        facets = re.findall(r"0x[0-9a-fA-F]{40}", loupe)
        if facets:
            out["kind"] = "EIP2535_DIAMOND" if not impl else out["kind"]
            out["facets"] = sorted(set(facets))
            out["notes"].append(
                "EIP-2535 diamond: logic lives in facet contracts registered in "
                "storage, so selectors and dangerous opcodes in THIS bytecode "
                "understate the real surface. Read the facets, not this."
            )

    if not impl and not out["facets"] and not beacon and not minimal:
        out["notes"].append(
            "no proxy slot, no facets, no minimal-proxy runtime: logic is "
            "directly in this address's bytecode"
        )
    return out


# --------------------------------------------------------------------------- #
# selector resolution and interface inference
# --------------------------------------------------------------------------- #

_4BYTE_CACHE: dict[str, list[str]] = {}


def resolve_selectors(selectors: list[str]) -> dict[str, list[str]]:
    """Reverse-resolve 4-byte selectors to candidate signatures via openchain.

    A selector can map to several signatures, so every result is a list. Treating
    it as a single answer is how a detector ends up confidently wrong: plenty of
    selectors collide.
    """
    out: dict[str, list[str]] = {}
    todo = [s for s in selectors if s not in _4BYTE_CACHE]
    for sel in todo:
        ok, txt = _cast(["4byte", sel], timeout=60)
        sigs = []
        if ok:
            for line in txt.splitlines():
                line = line.strip()
                if "(" in line and ")" in line:
                    sigs.append(line.split(" ")[0])
        _4BYTE_CACHE[sel] = sigs
    for sel in selectors:
        out[sel] = _4BYTE_CACHE.get(sel, [])
    return out


def infer_interfaces(resolved: dict[str, list[str]]) -> dict[str, t.Any]:
    """Name the standards a contract implements, with the evidence for each.

    A match requires most of an interface's required signatures, compared exactly.
    `owner()` alone proves nothing - thousands of contracts expose it.
    """
    present: set[str] = set()
    for sigs in resolved.values():
        for s in sigs:
            present.add(s.replace(" ", ""))
    found: dict[str, t.Any] = {}
    for name, spec in INTERFACES.items():
        req = [r.replace(" ", "") for r in spec["required"]]
        have = [r for r in req if r in present]
        ratio = len(have) / len(req)
        if ratio >= spec["threshold"]:
            found[name] = {
                "confidence": round(ratio, 2),
                "matched": have,
                "missing": [r for r in req if r not in present],
            }
    return {
        "interfaces": found,
        "unresolved_selectors": [s for s, v in resolved.items() if not v],
    }


# --------------------------------------------------------------------------- #
# differential analysis
# --------------------------------------------------------------------------- #

def diff_bytecode(code_a: str, code_b: str) -> dict[str, t.Any]:
    """Structural difference between two contracts' runtime bytecode.

    This exists because most exploited contracts are a one-line change from a
    known-good sibling, and because a Sourcify entry is not proof that what is
    deployed matches what is published. Arcadia's AccountV4 verified on Sourcify
    while its live bytecode differed from the repository - 12 hunks, all comment
    removals and a pragma bump, adjudicated by hand. That adjudication is the part
    worth automating.

    Reports a selector-level diff (added/removed functions) and an opcode-level
    diff, and separately whether the runtime differs only in metadata - which is
    the common benign case (different IPFS hash, same logic).
    """
    ha, hb = _strip_hex(code_a).lower(), _strip_hex(code_b).lower()
    sa = extract_selectors(code_a)
    sb = extract_selectors(code_b)

    only_a = sorted(set(sa["dispatcher"]) - set(sb["dispatcher"]))
    only_b = sorted(set(sb["dispatcher"]) - set(sa["dispatcher"]))
    common = sorted(set(sa["dispatcher"]) & set(sb["dispatcher"]))

    hist_a = opcode_histogram(code_a)
    hist_b = opcode_histogram(code_b)

    # strip the CBOR metadata blob: it ends with a2 64 69 70 66 73 58 22 <34 bytes>
    def without_metadata(h: str) -> str:
        marker = "a264697066735822"
        i = h.rfind(marker)
        return h[:i] if i > 0 else h

    logic_a, logic_b = without_metadata(ha), without_metadata(hb)

    return {
        "same_length": len(ha) == len(hb),
        "identical": ha == hb,
        "logic_identical": logic_a == logic_b,
        "metadata_only_difference": logic_a == logic_b and ha != hb,
        "selectors_only_in_a": only_a,
        "selectors_only_in_b": only_b,
        "selectors_shared": len(common),
        "opcode_delta": {
            k: hist_a.get(k, 0) - hist_b.get(k, 0)
            for k in set(hist_a) | set(hist_b)
            if hist_a.get(k, 0) != hist_b.get(k, 0)
        },
        "dangerous_delta": {
            d["op"]: dangerous_ops(code_b)[i]["count"] - d["count"]
            for i, d in enumerate(dangerous_ops(code_a))
            if i < len(dangerous_ops(code_b))
            and dangerous_ops(code_b)[i]["count"] != d["count"]
        },
    }


def summarize(addr_info: dict[str, t.Any]) -> str:
    """One-screen summary of an address, for a human deciding whether to read it."""
    L: list[str] = []
    code = addr_info.get("code_hex")
    L.append(f"address     : {addr_info.get('address')}")
    L.append(f"chain       : {addr_info.get('chain')}")
    L.append(f"kind        : {addr_info.get('proxy', {}).get('kind')}")
    if addr_info.get("proxy", {}).get("implementations"):
        L.append(f"impls       : {', '.join(addr_info['proxy']['implementations'])}")
    if addr_info.get("proxy", {}).get("facets"):
        L.append(f"facets      : {len(addr_info['proxy']['facets'])} (diamond - read the facets)")
    for n in addr_info.get("proxy", {}).get("notes", []):
        L.append(f"note        : {n}")
    if code:
        sel = addr_info.get("selectors", {})
        L.append(f"code bytes  : {sel.get('code_bytes')}")
        L.append(f"selectors   : {len(sel.get('dispatcher', []))} in dispatcher")
        ifs = addr_info.get("inference", {}).get("interfaces", {})
        if ifs:
            L.append("interfaces  : " + ", ".join(
                f"{k} ({v['confidence']})" for k, v in ifs.items()))
        unresolved = addr_info.get("inference", {}).get("unresolved_selectors", [])
        if unresolved:
            L.append(f"unresolved  : {len(unresolved)} selectors (custom or unindexed)")
        ops = addr_info.get("dangerous_ops", [])
        if ops:
            L.append("opcodes     : " + ", ".join(f"{d['op']}x{d['count']}" for d in ops[:6]))
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #

def analyze(chain: str, address: str, *, resolve_4byte: bool = True,
            max_selectors: int = 200) -> dict[str, t.Any]:
    """Full structural analysis of one deployed address.

    Always answers: is this reachable, is it a proxy (and of what kind), what
    interfaces does the bytecode support, and what dangerous opcodes does it use.
    Returns UNKNOWN rather than guessing wherever the bytecode cannot decide, so
    a caller cannot mistake absence of evidence for absence of a surface.
    """
    info: dict[str, t.Any] = {"address": address, "chain": str(chain)}
    proxy = resolve_proxy(chain, address)
    info["proxy"] = proxy

    targets = list(proxy["implementations"])
    if proxy["beacon"]:
        targets.append(proxy["beacon"])

    analyses: list[dict[str, t.Any]] = []
    for tgt in targets or [address]:
        try:
            code = runtime_code(chain, tgt)
        except REError as exc:
            analyses.append({"address": tgt, "error": str(exc)})
            continue
        sel = extract_selectors(code)
        resolved = resolve_selectors(sel["dispatcher"][:max_selectors]) if resolve_4byte else {}
        entry: dict[str, t.Any] = {
            "address": tgt,
            "code_hex": code,
            "selectors": sel,
            "opcode_histogram": opcode_histogram(code),
            "dangerous_ops": dangerous_ops(code),
            "storage_slots": storage_slots(code)[:64],
            "minimal_proxy_impl": is_minimal_proxy(code),
        }
        if resolved:
            entry["resolved"] = resolved
            entry["inference"] = infer_interfaces(resolved)
        analyses.append(entry)

    info["implementations"] = analyses
    primary = analyses[0] if analyses else {}
    if primary:
        info["code_hex"] = primary.get("code_hex")
        info["selectors"] = primary.get("selectors", {})
        info["dangerous_ops"] = primary.get("dangerous_ops", [])
        info["inference"] = primary.get("inference", {})
        info["storage_slots"] = primary.get("storage_slots", [])

    # Diamonds hide their surface: say so rather than let a thin selector list
    # imply the contract is small.
    if proxy["facets"]:
        info["surface_caveat"] = (
            f"EIP-2535 diamond with {len(proxy['facets'])} facet(s). The selector "
            "and opcode findings above describe the proxy shell only; the real "
            "logic is in the facets and must be analysed separately."
        )
    if proxy["beacon"]:
        info["surface_caveat"] = (
            "beacon proxy: the implementation can be swapped without this address "
            "changing, so any conclusion is tied to the implementation hash, not "
            "the address."
        )
    return info


def analyze_many(chain: str, addresses: list[str], **kw: t.Any) -> list[dict[str, t.Any]]:
    """Analyse several addresses, keeping per-address failures isolated."""
    out = []
    for a in addresses:
        try:
            out.append(analyze(chain, a, **kw))
        except Exception as exc:  # noqa: BLE001
            out.append({"address": a, "chain": chain, "error": f"{type(exc).__name__}: {exc}"})
    return out


# --------------------------------------------------------------------------- #
# source <-> bytecode differential
# --------------------------------------------------------------------------- #

_FUNC_DECL = re.compile(r"\bfunction\s+(\w+)\s*\(([^)]*)\)", re.S)


def selectors_from_source(root: Path) -> dict[str, list[str]]:
    """Map file -> the 4-byte selectors its function declarations would produce.

    This is the missing half of deployed-source verification. Sourcify tells you
    whether source was published; it does not tell you whether the published
    source is what is deployed. Arcadia's AccountV4 verified on Sourcify while the
    live bytecode differed from the repository, and sDAI taught the same lesson
    from the other direction - I inferred a diamond by searching SOURCE TEXT for
    selector hex, which of course it cannot contain.

    Comparing declared selectors against the deployed dispatcher is cheap, needs
    no compiler, and catches the exact failure those two cases share: a repo that
    is newer than, older than, or simply different from the deployment.
    """
    from . import cs_re as _self  # noqa: F401  (self-reference keeps imports explicit)

    out: dict[str, list[str]] = {}
    for sol in Path(root).rglob("*.sol"):
        if any(part in {"node_modules", "lib", "out", "cache", ".git"} for part in sol.parts):
            continue
        try:
            text = _strip_comments(sol.read_text(errors="replace"))
        except OSError:
            continue
        sels: list[str] = []
        for m in _FUNC_DECL.finditer(text):
            name, args = m.group(1), m.group(2)
            # normalise: strip names, keep types, collapse whitespace
            types = [re.sub(r"\s+", "", a.split()[0]) if a.split() else ""
                     for a in args.split(",") if a.strip()]
            sig = f"{name}({','.join(types)})"
            ok, sel = _cast(["sig", sig], timeout=45)
            if ok and sel.startswith("0x") and len(sel) == 10:
                sels.append(sel.lower())
        if sels:
            out[str(sol.relative_to(root))] = sorted(set(sels))
    return out


def compare_source_to_deployed(chain: str, address: str, source_root: Path,
                               resolve_4byte: bool = True) -> dict[str, t.Any]:
    """Diff a source tree's declared selectors against a deployed contract."""
    code = runtime_code(chain, address)
    deployed = extract_selectors(code)
    dep = set(deployed["dispatcher"])
    per_file = selectors_from_source(Path(source_root))
    src_all: set[str] = set()
    for sels in per_file.values():
        src_all.update(sels)

    only_src = sorted(src_all - dep)
    only_dep = sorted(dep - src_all)
    shared = sorted(dep & src_all)

    resolved: dict[str, list[str]] = {}
    if resolve_4byte and (only_src or only_dep):
        resolved = resolve_selectors(only_dep[:60])

    return {
        "address": address,
        "source_root": str(source_root),
        "deployed_selector_count": len(dep),
        "source_selector_count": len(src_all),
        "shared": len(shared),
        "only_in_source": only_src,
        "only_in_deployed": only_dep,
        "only_in_deployed_resolved": resolved,
        "per_file_source_selectors": {k: len(v) for k, v in list(per_file.items())[:20]},
        "verdict": (
            "SOURCE MATCHES DEPLOYED"
            if not only_src and not only_dep
            else "DIVERGES - deployed exposes selectors the source does not declare"
            if only_dep else "DIVERGES - source declares selectors the deployment does not expose"
        ),
    }


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)
