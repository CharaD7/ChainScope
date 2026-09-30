#!/usr/bin/env python3
"""Scan a contract tree for the 15 Critical-severity web3 vulnerability classes.

This exists because the classes below are what actually convert to a Critical
on Immunefi/Sherlock/Cantina: drain or insolvency, permanent lock, or
unrecoverable governance takeover. Anything short of that (gas waste,
temporary griefing, best practice) is not payable, so a triage that spends its
whole budget on low-severity hunting is wasted.

The scanner is a *triage aid, not an oracle*. Every hit is a prompt to read the
code and adjudicate; the output deliberately carries no severity, because a
regex cannot know whether a real exploit path exists. Several hits will be
false positives by construction (e.g. every proxy has an upgrade function).

Usage:
    python -m cli veck scan path/to/contracts --top 40
    python -m cli veck scan path/to/contracts --class 1 --class 6
    python -m cli veck list
    python -m cli veck checklist
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import re
import typing

import typer

app = typer.Typer()

_SOL = {".sol"}


# Each class: id, name, why it is Critical, where to look, and the evidence
# patterns that justify escalating it. `strong` patterns are much less likely
# to be benign than `weak` ones.
CLASSES: list[dict[str, typing.Any]] = [
    {
        "id": 1,
        "name": "Uninitialized proxies & logic contracts",
        "why": "Attacker calls initialize() on the implementation, takes ownership, then selfdestructs or upgrades the proxy into a state they control.",
        "look": "Any OZ Initializable / UUPS / custom proxy factory. Wormhole $10M was paid for exactly this.",
        "strong": [
            r"function\s+initialize\s*\([^)]*\)\s*external(?!.*only)",
        ],
        "weak": [
            r"selfdestruct\s*\(",
            r"_disableInitializers\s*\(\s*\)",   # mitigation, not a bug
        ],
    },
    {
        "id": 2,
        "name": "Cross-function / cross-contract read-only reentrancy",
        "why": "State is updated after an external call; a third party reads mid-flight state (virtual price, balances) and acts on skewed values.",
        "look": "Curve/Uniswap/vault integrations; state written after raw transfers.",
        "strong": [],
        "weak": [
            r"get_virtual_price",
            r"balanceOf\s*\(\s*address\(this\)",
        ],
    },
    {
        "id": 3,
        "name": "Oracle manipulation via spot/DEX reserves",
        "why": "Collateral, swap rate or liquidation threshold derived from spot price; flash loan skews the pool, acts, then unwinds.",
        "look": "getReserves, slot0, spot tick, or a spot-based TWAP substitute.",
        "strong": [
            r"getReserves\s*\(",
            r"slot0\s*\(",
            r"get_virtual_price\s*\(",
        ],
        "weak": [r"latestRoundData\s*\("],
    },
    {
        "id": 4,
        "name": "Rounding / inflation attack in share-to-asset ratios (4626)",
        "why": "Empty or first-deposit vault: 1 wei gets 1 share, donation inflates totalAssets, victims round down to 0 shares and the attacker takes their deposit.",
        "look": "ERC4626, yield aggregators, first-deposit paths.",
        "strong": [
            r"totalSupply\s*\(\s*\)\s*==\s*0",
            r"if\s*\(\s*_totalSupply\s*==\s*0\s*\)",
            r"decimalsOffset",
        ],
        "weak": [r"convertToShares", r"previewDeposit"],
    },
    {
        "id": 5,
        "name": "Storage collisions in upgradable contracts",
        "why": "A child contract adds/reorders state without matching the deployed layout, overwriting owner/balances and taking control or corrupting accounting.",
        "look": "Multiple inheritance, v1->v2 upgrade deltas, missing __gap.",
        "strong": [],
        "weak": [
            r"struct\s+\w+Storage",
            r"__gap\s*\[\s*\d+\s*\]",
        ],
    },
    {
        "id": 6,
        "name": "Cross-chain replay & signature malleability",
        "why": "EIP-712 domain omits chainid, so a signature replays on another chain; or s-value not bounded, giving a second valid signature.",
        "look": "Cross-chain messaging, permit, bridges, meta-transactions.",
        "strong": [
            r"ecrecover\s*\(\s*[^,]+,\s*v\s*,\s*r\s*,\s*s\s*\)",
        ],
        "weak": [
            r"EIP712Domain",
            r"DOMAIN_SEPARATOR",
        ],
    },
    {
        "id": 7,
        "name": "Missing/improper access control on admin functions",
        "why": "mint/burn/upgradeTo/withdrawFees/setOracle reachable without a guard -> unrestricted theft.",
        "look": "intended-internal marked public/external; AccessControl init that forgets the admin role.",
        "strong": [
            r"function\s+(upgradeTo|upgradeToAndCall|setOwner|changeOwner|setOracle|withdrawFees|setFeeRecipient)\s*\([^)]*\)\s*(external|public)(?![^{;]*only)",
        ],
        "weak": [r"onlyOwner|onlyRole|_checkOwner"],
    },
    {
        "id": 8,
        "name": "First-in / zero-supply precision in reward accrual",
        "why": "rewardPerToken divides by totalSupply; at zero supply rewards mis-accumulate to the first staker, who claims everything.",
        "look": "StakingRewards clones, reward-per-token accumulators, distribution pools.",
        "strong": [
            r"rewardPerTokenStored\s*\+=",
            r"accRewardPerShare\s*\+=",
        ],
        "weak": [r"accEthPerShare", r"rewardPerToken"],
    },
    {
        "id": 9,
        "name": "Incorrect token handling (fee-on-transfer, ERC-777, rebasing)",
        "why": "Code assumes transferFrom moved exactly `amount`; with a 2% fee the balance grows slower than accounting and the contract goes insolvent.",
        "look": "Multi-token pools, vaults, CDPs accepting arbitrary ERC-20s.",
        "strong": [
            r"balanceOf\([^)]*\)\s*-\s*\w+\s*(?!\s*//)",
        ],
        "weak": [
            r"safeTransferFrom",
            r"transferFrom\s*\(",
        ],
    },
    {
        "id": 10,
        "name": "Flash-loan governance hijack",
        "why": "Voting power read from live balance with no snapshot; flash-borrow tokens, pass a proposal/vote in one tx, drain the treasury.",
        "look": "Governor contracts, ERC20Votes without checkpoints, weighted voting pools.",
        "strong": [],
        "weak": [r"getVotes\s*\(", r"getPastVotes", r"Governor"],
    },
    {
        "id": 11,
        "name": "Flawed liquidation math / health factor",
        "why": "Liquidation omits the penalty or lets a liquidator take 100% of collateral for less than the debt -> bad debt, or reserves are drained.",
        "look": "Lending markets, isolated debt pools, synthetic minting.",
        "strong": [r"healthFactor", r"liquidateBorrow"],
        "weak": [r"liquidationThreshold", r"closeFactor"],
    },
    {
        "id": 12,
        "name": "delegatecall to untrusted / user-controlled target",
        "why": "delegatecall runs attacker code in this contract's storage; writing slot 0 overrides owner and hands over control.",
        "look": "Routers, ERC-4337 accounts, multisig implementations, execution proxies.",
        "strong": [
            r"delegatecall\s*\(\s*(?![\"'])",
        ],
        "weak": [r"function\s+execute\s*\("],
    },
    {
        "id": 13,
        "name": "Bridge proof verification / relayer logic",
        "why": "Malformed proof, replayed receipt hash, or a verifier bypass mints bridged tokens with no backing deposit.",
        "look": "Merkle/ZK/threshold-sig bridges, L2 lock-and-mint, LayerZero/Wormhole.",
        "strong": [
            r"verifyCalldata\s*\(|MerkleProof\.verify|processProof\s*\(",
            r"finalizeDeposit|finalizeWithdrawal|completeDeposit",
        ],
        "weak": [r"nonce", r"relayer"],
    },
    {
        "id": 14,
        "name": "Unchecked return values / silent failures",
        "why": "Low-level call returns (bool, bytes) instead of reverting; ignored, execution continues assuming the transfer worked.",
        "look": "Batchers, multicall wrappers, splitters, non-standard tokens (USDT).",
        "strong": [
            r"\.call\s*\{\s*value",
            r"\.call\s*\([^)]*\)\s*;",
        ],
        "weak": [r"requireCallResult|verifyCallResult|checkReturn"],
    },
    {
        "id": 15,
        "name": "Accounting mismatch in flash mint / flash lending",
        "why": "Fee, supply update or burn validation happens after control returns, so minted tokens are retained without burning them.",
        "look": "Custom ERC-20, native stablecoins, bespoke lending.",
        "strong": [r"flashMint|_flashLoan"],
        "weak": [r"flash\s*loan|onFlashLoan"],
    },
    {
        "id": 16,
        "name": "Flash-loan-assisted price / collateral manipulation",
        "why": "A protocol prices collateral, rates or thresholds off an instantaneous pool value. A flash loan skews that value within one transaction, the protocol acts on it, the attacker unwinds and keeps the difference.",
        "look": "Pricing helpers that read live reserves/tick instead of a TWAP. Distinct from class 3: this is the *valuation* use, not a raw pool read.",
        "strong": [
            r"function\s+\w*[Pp]rice\w*\s*\([^)]*\)[^{;]*\{\s*[^}]*(getReserves|slot0|observe|getSqrtRatioAtTick)",
        ],
        "weak": [
            r"twap|TWAP|timeWeightedAveragePrice",   # the MITIGATION - shows intent
            r"getAmountOut\s*\(",
        ],
    },
    {
        "id": 17,
        "name": "Concentrated-liquidity position / pool math",
        "why": "Uniswap V3/V4-style positions are valued by walking ticks and fee growth. Off-by-one tick ranges, wrong fee accounting, or mishandled sqrtPrice precision lets a position be over-valued, or value be extracted by a rebalancer.",
        "look": "Asset managers and strategies that rebalance or compound concentrated-liquidity positions.",
        "strong": [
            r"sqrtPriceX96",
            r"getSqrtRatioAtTick",
            r"feeGrowthInside",
            r"slot0\(\)\.tick|slot0\(\)[^;]*\btick\b",
        ],
        "weak": [
            r"tickLower|tickUpper|positions\(",
            r"TickMath|PositionInfo|CLPool|IClPool",
            r"liquidity\(\)",
        ],
    },
    {
        "id": 18,
        "name": "Swap slippage / sandwich / MEV",
        "why": "A swap is routed without a binding minimum-out or deadline, or a user-facing quote is computed off-manifold. An attacker sandwiches the transaction and extracts the difference from the user.",
        "look": "Routers, zappers, swap-periphery, and any user-facing quote the protocol then trusts.",
        "strong": [
            r"swapExactTokensFor(Token|ETH)SupportingFeeOnTransferTokens",
            r"amountOutMin(imum)?\s*=\s*0\b",
            r"getAmountOut\s*\([^)]*reserve",
        ],
        "weak": [
            r"deadline",
            r"amountOutMinimum|minAmountOut|minimumOut",
            r"\bswap\b|SwapRouter|amountOut\b",
        ],
    },
    {
        "id": 19,
        "name": "Vault donation / first-depositor inflation",
        "why": "An empty or first-depositor vault mints a trivially small share balance. A donation inflates totalAssets, later deposits round down to 0 shares, and the first depositor withdraws everyone's money.",
        "look": "ERC-4626 vaults, share/reward tokens with a raw totalSupply division. Distinct from class 4: that is generic rounding; this is the donation inflation attack specifically.",
        "strong": [
            r"convertToShares\s*\([^)]*\+\s*1",
            r"virtualShares|virtualAssets|VIRTUAL_SHARES",
        ],
        "weak": [
            r"totalSupply\s*\(\s*\)\s*==\s*0",     # first-depositor guard = the MITIGATION
            r"previewMint|previewDeposit",
            r"donat|\bskim\b",
        ],
    },
]

_BY_ID = {c["id"]: c for c in CLASSES}


def _sol_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.suffix in _SOL and p.is_file()]


def _strip(line: str) -> str:
    """Remove line comments so commented-out code does not produce hits."""
    out = re.sub(r"//.*$", "", line)
    return out.split("/*")[0]


def scan(root: Path, class_ids: list[int] | None = None) -> list[dict[str, typing.Any]]:
    """Return ranked hits: {class_id, class, strength, file, line, snippet}."""
    hits: list[dict[str, typing.Any]] = []
    wanted = class_ids or [c["id"] for c in CLASSES]
    for f in _sol_files(root):
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            code = _strip(line)
            if not code.strip():
                continue
            for cid in wanted:
                cls = _BY_ID[cid]
                for strength in ("strong", "weak"):
                    for pat in cls[strength]:
                        if re.search(pat, code):
                            hits.append({
                                "class_id": cid,
                                "class": cls["name"],
                                "strength": strength,
                                "file": str(f.relative_to(root)) if root in f.parents else str(f),
                                "line": i,
                                "snippet": code.strip()[:160],
                            })
                            break
    # strong first, then fewer hits per class (rarer class = more signal)
    hits.sort(key=lambda h: (h["strength"] != "strong", h["class_id"]))
    return hits


@app.command(name="list")
def list_classes():
    """Show the 15 Critical classes this scanner looks for."""
    typer.echo(f"{len(CLASSES)} Critical-severity web3 vulnerability classes:\n")
    for c in CLASSES:
        typer.echo(f"  {c['id']:>2}. {c['name']}")
        typer.echo(f"      why : {c['why']}")
        typer.echo(f"      look: {c['look']}")


@app.command(name="checklist")
def checklist():
    """Print the methodology that turns a hit into a submittable report."""
    typer.echo(
        "\n".join(
            [
                "Method to convert a hit into a Critical submission:",
                "",
                "1. Invariant mapping",
                "   State the single condition that must never break, e.g.",
                "   'vault assets >= totalShareBalances * pricePerShare'.",
                "",
                "2. State-shift analysis",
                "   For every path that moves value, diff internal accounting",
                "   against actual token balance. A mismatch is the bug.",
                "",
                "3. Fork execution",
                "   Reproduce on a local fork of mainnet at a pinned block",
                "   (forge test --fork-url). Show >= USD 50k at risk and that",
                "   the loss path actually executes. A PoC is a condition",
                "   precedent for reward on most programs.",
                "",
                "Bar to clear: loss of protocol funds, permanent lock, or",
                "governance takeover. Not gas waste, not temporary griefing.",
            ]
        )
    )


@app.command(name="scan")
def scan_cmd(
    path: str = typer.Argument(..., help="Path to a contract directory"),
    class_id: list[int] = typer.Option([], "--class", "-c", help="Only this class id (repeatable)"),
    strong_only: bool = typer.Option(False, "--strong-only", help="Only strong-evidence patterns"),
    top: int = typer.Option(40, "--top", help="Max hits to show"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Scan a contract tree and rank hits across the 15 Critical classes."""
    import json as _json

    root = Path(path).resolve()
    if not root.exists():
        typer.echo(f"no such path: {root}", err=True)
        raise typer.Exit(1)
    ids = list(class_id) or None
    if ids:
        bad = [i for i in ids if i not in _BY_ID]
        if bad:
            typer.echo(f"unknown class id(s): {bad}; valid 1..{len(CLASSES)}", err=True)
            raise typer.Exit(1)
    hits = scan(root, ids)
    if strong_only:
        hits = [h for h in hits if h["strength"] == "strong"]

    files = len(_sol_files(root))
    by_class: dict[int, int] = {}
    for h in hits:
        by_class[h["class_id"]] = by_class.get(h["class_id"], 0) + 1

    typer.echo(f"{files} .sol file(s) under {root}")
    typer.echo(f"{len(hits)} hit(s) across {len(by_class)}/{len(CLASSES)} classes\n")
    if by_class:
        typer.echo("classes touched (lower count = rarer = usually more signal):")
        for cid, n in sorted(by_class.items(), key=lambda kv: kv[1]):
            typer.echo(f"  {cid:>2}. {n:>4d}  {_BY_ID[cid]['name']}")
        typer.echo("")
    typer.echo("hits (strong evidence first):")
    for h in hits[: int(top)]:
        mark = "**" if h["strength"] == "strong" else "  "
        typer.echo(f"  {mark} [{h['class_id']:>2}] {h['file']}:{h['line']}")
        typer.echo(f"        {h['snippet']}")
    typer.echo(
        "\nReminder: a regex cannot prove exploitability. For each survivor, state\n"
        "the invariant, show the state shift, and build a fork PoC before writing up."
    )
    if json_output:
        typer.echo(_json.dumps({"root": str(root), "files": files, "hits": hits}, indent=2))


if __name__ == "__main__":
    app()
