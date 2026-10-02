"""Rust-native Critical detectors for Substrate/FRAME pallets.

The 21 Veck classes are Solidity-only (`_SOL = {".sol"}`), so they provide zero
coverage of a Substrate chain. That matters now that Hydration - the largest
Immunefi ceiling in the catalog at 222,222 - is 71 `.rs` files, 35,849 lines, and
nothing in this toolchain read any of it.

Two classes here, both earning their place by having actually found something:

R1  debug_assert standing in for a security invariant.

    A Substrate production runtime is release WASM, and `debug_assert!` compiles
    out of it. So a `debug_assert!` that is the *only* enforcement of an
    invariant protects nothing in production. Hydration's stableswap had exactly
    this on the share ledger until commit 50a55673c4 (2026-07-15).

    The discrimination is the hard part and the reason a grep is not enough.
    This is a **false positive**:

        let r: DispatchResult = (|| { ensure!(x >= y, Err); Ok(()) })();
        debug_assert!(r.is_ok(), "invariant");
        r                                  // the Result is returned and enforced

    and this is a **real finding**:

        fn ensure_issuance_in_sync(id) {
            debug_assert_eq!(tracked, total, "...");   // returns ()
        }

    Both contain `debug_assert`. The difference is whether an `ensure!`/`?`
    produces a value the caller receives. So R1 requires the guarded function to
    return unit, or to return something that never carries the check.

R2  Share price derived from a raw balance (donation / first-depositor).

    The Solidity class 19 translated into Rust, and the family this hunt hit three
    times: IPOR PowerToken, Gamma Hypervisor, Gamma xGamma. All three died on the
    same economics - the attacker needs f -> 1 of supply - so R2 exists to find
    the *instances*, not to imply they are exploitable.
"""

from __future__ import annotations

import re
import typing as t
from pathlib import Path

RUST = {".rs"}

_RUST_SKIP_DIRS = frozenset({
    "target", "node_modules", ".git", "vendor", "out", "dist", "build",
    "tests", "test", "benches", "fixtures", "__pycache__",
})

# --------------------------------------------------------------------- R1

# A function that returns unit cannot propagate a check, so a debug_assert inside
# it is the sole enforcement. Matches `-> ()`, `fn f(...) {`, and `pub fn`.
_UNIT_FN = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?:->\s*\(\s*\)\s*)?\{")
_DEBUG_ASSERT = re.compile(r"\bdebug_assert(?:!|_eq!|_ne!)\s*\(")
# Something that could carry a failure out of the function.
_ENFORCING = re.compile(r"\bensure!\s*\(|\?;|\.ok_or|->\s*Result|->\s*DispatchResult|Err\(")

# `#[cfg(not(debug_assertions))]`-only tests tell you a panic path was deliberately
# split out; that is a strong hint the authors knew the production path differed.
_CFG_RELEASE_ONLY = re.compile(r"#\s*\[\s*cfg\s*\(\s*not\s*\(\s*debug_assertions\s*\)\s*\)\s*\]")


def rust_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if p.suffix not in RUST or not p.is_file():
            continue
        rel = p.relative_to(root)
        if set(rel.parts[:-1]) & _RUST_SKIP_DIRS:
            continue
        out.append(p)
    return out


def _fn_bodies(text: str) -> t.Iterator[tuple[str, int, str]]:
    """Yield (fn_name, 1-based line of the signature, body) for brace-matched fns."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _UNIT_FN.search(line)
        if not m:
            continue
        depth = 0
        started = False
        body: list[str] = []
        for ln in lines[i:]:
            body.append(ln)
            for ch in ln:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth <= 0:
                break
        yield m.group(1), i + 1, "\n".join(body)


def scan_debug_assert(root: Path) -> list[dict[str, t.Any]]:
    """R1: a `debug_assert!` that is the only enforcement in a unit-returning fn."""
    hits: list[dict[str, t.Any]] = []
    for f in rust_files(root):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for name, line_no, body in _fn_bodies(text):
            if not _DEBUG_ASSERT.search(body):
                continue
            # If the body can carry a failure out, the debug_assert is diagnostic.
            if _ENFORCING.search(body):
                continue
            # A bare `debug_assert!(false, ...)` is usually an unreachable arm,
            # not an invariant. Keep it but mark it lower-confidence.
            snippet = ""
            for ln in body.splitlines():
                if _DEBUG_ASSERT.search(ln):
                    snippet = ln.strip()
                    break
            hits.append({
                "class_id": "R1",
                "class": "debug_assert as sole invariant enforcement (absent from release WASM)",
                "fn": name,
                "file": str(f),
                "line": line_no,
                "snippet": snippet,
                "severity_hint": "low" if "debug_assert!(false" in body else "high",
            })
    return hits


# --------------------------------------------------------------------- R2

# A division whose divisor is an issuance/supply figure.
_SHARE_MATH = re.compile(
    r"(?:checked_div|\.div\(|\bsdiv\b|\bper_shares?\b|\/\s*)",
    re.I,
)
# Names of figures that must not be used as a share-price denominator.
_ISSUANCE_NAME = re.compile(
    r"(?:total_supply|total_issuance|share_issuance|total_shares|total_stake|"
    r"total_bonded|issuance|supply)",
    re.I,
)
# `let supply = T::Currency::total_issuance(pool_id);` - the indirection that a
# purely syntactic scan misses. Without this the detector only fires when the
# call reads `checked_div(total_supply())` inline, which is rare in real pallet
# code and was the reason my own fixture failed.
_ISSUE_BINDING = re.compile(
    r"\blet\s+(?:mut\s+)?(\w+)\b[^=\n]*=\s*[^;\n]*?"
    r"(?:total_supply|total_issuance|share_issuance|total_shares|total_stake|issuance)\b",
    re.I,
)
# `calculate_shares(..., share_issuance: Balance)` - issuance handed in as a
# parameter rather than read from storage, as in Hydration's Curve-style math.
_ISSUE_PARAM = re.compile(r"\b(\w*(?:issuance|supply|shares)\w*)\s*:\s*(?:Balance|u128|u64|i128)", re.I)
# ... or a live balance read, which is the "total assets" side.
_BALANCE_READ = re.compile(
    r"(?:free_balance|reserved_balance|balance|total_issuance)\s*(?:\(|of\b)|\b\w+\.balance\b",
    re.I,
)
_MINIMUM_LIQUIDITY = re.compile(
    r"MINIMUM_LIQUIDITY|minimum_liquidity|virtual_shares|VIRTUAL_SHARES|VIRTUAL_ASSETS|"
    r"virtual_assets|dead_shares|burn_from_address|MINIMUM_LIQUIDITY",
    re.I,
)
_FIRST_DEPOSITOR_GUARD = re.compile(
    r"total_supply\(\)\s*(?:==|is_)\s*zero|total_issuance\s*\(\s*\)\s*(?:==|\.is_zero)|"
    r"if\s+\w*[Tt]otal\w*\s*(?:==|<=|==)\s*0",
    re.I,
)


def scan_donation_shape(root: Path) -> list[dict[str, t.Any]]:
    """R2: share/issuance math dividing by a raw balance, minus known mitigations."""
    hits: list[dict[str, t.Any]] = []
    for f in rust_files(root):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        # A file that declares a virtual-offset mitigation is largely exonerated.
        if _MINIMUM_LIQUIDITY.search(text):
            continue
        stripped = re.sub(r"//.*|/\*.*?\*/", "", text, flags=re.S)
        lines = stripped.splitlines()
        # Resolve issuance held in a local, and issuance passed as a parameter.
        # Without this the detector only fires on inline `checked_div(total_supply())`,
        # which real pallet code almost never writes.
        issuance_names = {m.group(1).lower() for m in _ISSUE_BINDING.finditer(stripped)}
        issuance_names |= {m.group(1).lower() for m in _ISSUE_PARAM.finditer(stripped)}
        for i, line in enumerate(lines, 1):
            if not _SHARE_MATH.search(line):
                continue
            window = "\n".join(lines[max(0, i - 12) : i + 2])
            if not _BALANCE_READ.search(window):
                continue
            if _FIRST_DEPOSITOR_GUARD.search(window):
                continue
            window_words = {w.lower() for w in re.findall(r"\w+", window)}
            # The mitigation has to be resolved through the same indirection as
            # the flag, or `let supply = total_supply(); if supply == 0` reads as
            # unguarded when it is exactly the guard.
            if re.search(r"\bif\s+\w+\s*(?:==|<=)\s*0\b", window) and (
                issuance_names & window_words
            ):
                continue
            # the divisor is either named in-line or one of the resolved names
            divisor_is_issuance = bool(_ISSUANCE_NAME.search(window)) and (
                bool(issuance_names & window_words)
                or bool(_ISSUANCE_NAME.search(line))
            )
            if not divisor_is_issuance:
                continue
            hits.append({
                "class_id": "R2",
                "class": "share price from raw balance, no virtual offset found in file",
                "file": str(f),
                "line": i,
                "snippet": line.strip()[:200],
                "severity_hint": "medium",
            })
    return hits


# ------------------------------------------------------------------- driver

SCANNERS = {"R1": scan_debug_assert, "R2": scan_donation_shape}


def scan(
    root: Path, classes: list[str] | None = None
) -> list[dict[str, t.Any]]:
    out: list[dict[str, t.Any]] = []
    for cid, fn in SCANNERS.items():
        if classes and cid not in classes:
            continue
        try:
            out.extend(fn(root))
        except Exception as exc:  # never let one bad file kill the sweep
            out.append({"class_id": cid, "error": f"{type(exc).__name__}: {exc}"})
    return out


def summary(root: Path, classes: list[str] | None = None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for h in scan(root, classes):
        key = str(h.get("class_id"))
        counts[key] = counts.get(key, 0) + 1
    return counts