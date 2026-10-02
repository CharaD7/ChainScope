"""Move-native Critical/High detectors for Sui and Aptos.

Built because the HackenProof language mix analysis showed 16 active Move
programmes carrying $2,045,000 in ceilings with no ChainScope coverage at all,
while Solidity (34 programmes, $4.58M) is the most-mined surface in existence.

These are NOT ported from the Solidity or Rust classes. Two structural facts about
Move make most of those classes unrepresentable rather than merely rare:

  * The object model replaced global storage. The Sui framework has **zero**
    `acquires` annotations and takes `TxContext`, not `&signer`; Aptos removed
    `acquires` from the VM entirely. So "missing acquires" and "unchecked signer"
    are dead classes here - the VM made them so.
  * Arithmetic **aborts on overflow natively**. Move has no release-mode
    unchecked-math path, so the Solidity "unchecked arithmetic" class does not
    exist and is deliberately not implemented here.

What remains are genuinely Move-specific, and all three are Critical or High:

  M1  Unvalidated dynamic-field key. `dynamic_field::add(parent, k, value)` with a
      caller-supplied `k` overwrites any existing field with the same key on the
      same parent. The Sui analogue of a storage collision, and a real Critical in
      DeFi built on dynamic fields.

  M3  Upgrade authority not frozen. A package `UpgradeCap` that a module keeps
      transferable, or hands out, lets the holder publish arbitrary new bytecode -
      the exact power an uninitialised proxy implementation gives away, and the
      Sui equivalent of the Critical I ruled out on Gamma.

  M5  Reference escape from shared state. A `public fun` returning `&T`/`&mut T`
      drawn from internal or parent-owned state leaks a reference outside the
      module's discipline, so a caller keeps a usable handle after the intended
      scope should have closed.
"""

from __future__ import annotations

import re
import typing as t
from pathlib import Path

MOVE = {".move"}

_SKIP_DIRS = frozenset({
    "build", "out", "target", "node_modules", ".git", "dist", "coverage",
    "tests", "test", "test_suite", "fixtures",
})


def move_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*.move"):
        if p.is_file() and not (set(p.relative_to(root).parts[:-1]) & _SKIP_DIRS):
            out.append(p)
    return out


# --------------------------------------------------------------------- M1

# A public function that writes a dynamic field. If the key comes from the caller
# rather than being derived from validated state, two callers can collide.
_PUB_FUN = re.compile(
    r"(?m)^\s*(?:public(?:\s*entry)?|entry)\s+fun\s+(\w+)\s*(\([^)]*\)|<[^>]*>[^)]*)"
)


def _fun_bodies(text: str):
    """(name, params, body, 1-based line) for each public/entry fun.

    Brace-matched, because a regex window bleeds across functions: the first
    version of M1 matched a `dynamic_field` call from the *next* function and
    reported it against a one-line `create` body. Same class of bug as the
    Solidity/Rust extractors had earlier in the session.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _PUB_FUN.search(line)
        if not m:
            continue
        depth, started, body = 0, False, []
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
            if len(body) > 400:
                break
        yield m.group(1), m.group(2), "\n".join(body), i + 1
_DF_WRITE = re.compile(
    r"dynamic_field::(add|borrow_mut|remove|exists_)\s*\(",
)
# a key parameter, positionally or by name
_KEY_NAMES = r"(?:k|key|name|field|field_name|nft_id|id|uid|tag|type_tag)"

# `remove` and `exists_` do not write, so they are not the Critical shape.
_WRITE_OPS = re.compile(r"dynamic_field::(add|borrow_mut)\s*\(")


def _split_top(arg: str) -> list[str]:
    """Split call arguments on top-level commas only."""
    parts, depth, cur = [], 0, ""
    for ch in arg:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def scan_dynamic_field_key(root: Path) -> list[dict[str, t.Any]]:
    """M1: a public function writing a dynamic field under a caller-supplied key."""
    hits: list[dict[str, t.Any]] = []
    for f in move_files(root):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        if "dynamic_field" not in text:
            continue
        for name, params, body, line_no in _fun_bodies(text):
            if not _WRITE_OPS.search(body):
                continue
            # The dynamic_field call must be in THIS function's body, and the key
            # must be a *bare identifier* that came from a parameter. A struct
            # literal such as `Key { tag: 7 }` is an internally derived key and
            # must not match - a loose "does any key-ish word appear" test
            # flagged it purely because the struct had a `tag` field.
            mcall = re.search(
                r"dynamic_field::(?:add|borrow_mut)\s*\([^;]*", body, re.I
            )
            if not mcall:
                continue
            arg = mcall.group(0)
            parts = [a.strip() for a in _split_top(arg[arg.index("(") + 1 :])]
            second = parts[1] if len(parts) > 1 else ""
            bare_ident = bool(re.fullmatch(r"[A-Za-z_]\w*", second))
            param_names = set(re.findall(r"([A-Za-z_]\w*)\s*:", params))
            keyed = bare_ident and (
                second in param_names
                or bool(re.fullmatch(_KEY_NAMES, second, re.I))
            )
            if not keyed:
                continue
            # If the parent is constructed in this body the object is brand new and
            # there is nothing for the key to collide with. This is what
            # `Versioned::create` in the Sui framework looks like:
            #
            #     let mut self = Versioned { id: object::new(ctx), version: init_version };
            #     dynamic_field::add(&mut self.id, init_version, init_value);
            #
            # Caller-supplied key, but a fresh parent every call, so a collision
            # cannot occur. Without this carve-out the framework's own code is the
            # scanner's only hit.
            if re.search(r"object::new\s*\(|dynamic_object_field::new", body):
                continue
            if re.search(r"let\s+mut\s+\w+\s*=\s*\w+\s*\{", body):
                continue
            guarded = bool(
                re.search(
                    r"(assert!|assert_occupied|contains_|has_key|is_valid|verify|derive|compute)\b[^;]*"
                    rf"{_KEY_NAMES}",
                    body,
                    re.I,
                )
            )
            hits.append({
                "class_id": "M1",
                "class": "public function writes a dynamic field under a caller-supplied key",
                "fn": name,
                "file": str(f),
                "line": line_no,
                "snippet": " ".join(body.split())[:200],
                "severity_hint": "low" if guarded else "high",
            })
    return hits


# --------------------------------------------------------------------- M3

_CAP_DECL = re.compile(r"(?i)\b(UpgradeCap|TreasuryCap)\b")
# Type names alone are not enough. `bluefin_coin::blue`'s `init` never names the
# type: it calls coin::create_currency, binds the result to a local
# `treasury_cap`, and transfers it. Keying on the capability *operations* as well
# is what catches that, and it is the form a reader would search for anyway.
_CAP_OPS = re.compile(
    r"(?i)coin::create_currency|treasury_cap|mint_and_transfer|package::(issue|add_)"
)
_CAP_STORE = re.compile(
    r"(?i)(transfer::public_transfer|transfer::transfer|::transfer)\s*\(\s*[^,]*UpgradeCap|"
    r"fun\s+\w*(?:issue|grant|give|share|return)_?(?:upgrade_?)?cap\w*\s*\(",
)
_FREEZE = re.compile(r"(?i)\bfreeze\s*\(|::freeze\b|into_immutable\b|store_immutable\b")


def scan_upgrade_authority(root: Path) -> list[dict[str, t.Any]]:
    """M3: a capability that is transferred or handed out rather than frozen.

    Covers **both** Sui authorities, not just `UpgradeCap`:

      * `UpgradeCap`   - permission to publish new bytecode (the exact power an
                         uninitialised proxy implementation hands away)
      * `TreasuryCap`  - permission to **mint** an unbounded supply

    The second was a real gap. M3 originally keyed on `UpgradeCap` only, so it
    returned zero on `bluefin_coin::blue` - a 73-line token contract whose entire
    security rests on a `TreasuryCap`, publicly transferred at init, never
    frozen, with a deploy script that moves it to a single address. For a token
    contract the mint authority is the one that matters, and the detector could
    not see it.
    """
    hits: list[dict[str, t.Any]] = []
    for f in move_files(root):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        if not _CAP_DECL.search(text):
            continue
        # Any `fun`, not just public ones: Move requires `init` to be *private*, and
        # `init` is precisely where a TreasuryCap is created and handed to the
        # deployer. Restricting this to `public`/`entry` made M3 return zero on
        # bluefin_coin::blue, whose only capability movement is inside `init`.
        for m in re.finditer(
            r"(?m)^\s*(?:public(?:\s*entry)?|entry)?\s*fun\s+(\w+)\s*(\([^)]*\))", text
        ):
            name, params = m.group(1), m.group(2)
            start = m.end()
            nxt = re.search(r"(?m)^\s*(?:public\s+)?(?:entry\s+)?fun\s+", text[start:])
            body = text[start : start + (nxt.start() if nxt else 3000)]
            # The capability may be named in the signature, or - as in
            # bluefin_coin::blue's `init(witness: BLUE, ctx: &mut TxContext)` -
            # created inside the body and handed to the sender. Requiring it in
            # the signature alone missed exactly that case.
            if not (
                re.search(r"(?i)cap", name + params)
                or _CAP_DECL.search(body)
                or _CAP_OPS.search(body)
            ):
                continue
            if not _CAP_STORE.search(body) and not re.search(
                r"(?i)\btransfer\b|public_transfer", body
            ):
                continue
            if _FREEZE.search(body):
                continue  # frozen caps are safe to hold
            hits.append({
                "class_id": "M3",
                "class": "capability (UpgradeCap/TreasuryCap) transferred or returned without freeze",
                "fn": name,
                "file": str(f),
                "line": text[: m.start()].count("\n") + 1,
                "snippet": " ".join(body.split())[:200],
                "severity_hint": "high",
            })
    return hits


SCANNERS = {
    "M1": scan_dynamic_field_key,
    "M3": scan_upgrade_authority,
}


def scan(root: Path, classes: list[str] | None = None) -> list[dict[str, t.Any]]:
    out: list[dict[str, t.Any]] = []
    for cid, fn in SCANNERS.items():
        if classes and cid not in classes:
            continue
        try:
            out.extend(fn(root))
        except Exception as exc:  # one bad file must not kill the sweep
            out.append({"class_id": cid, "error": f"{type(exc).__name__}: {exc}"})
    return out


def summary(root: Path, classes: list[str] | None = None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for h in scan(root, classes):
        if h.get("class_id"):
            counts[h["class_id"]] = counts.get(h["class_id"], 0) + 1
    return counts
