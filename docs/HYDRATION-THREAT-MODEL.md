# Hydration — the repo ships its own threat model

The most valuable thing found in the Hydration work is not a bug. It is
`ai_skills/hydration_cl0wdit/` — a **security-audit skill the project itself
maintains**, including `references/attack-vectors/hydration-attack-vectors.md`
(410 lines) and `substrate-attack-vectors-1.md` (298 lines), plus a **Bug Bounty
Post Mortem** section.

This changes the shape of the problem. The catalogue lists 10 categories, a
**"Recurring Themes (Priority Checklist for Auditors)"** of 14 items, the audit
history, and four post-mortems with payouts.

## It pays, and it pays large

| Post-mortem | Severity | Payout |
|---|---|---|
| Oracle manipulation via DCA + batch call | High | **$25,000** |
| aToken liquidity addition in Stableswap | Critical | **$500,000** |
| Omnipool single-sided liquidity manipulation | Critical | — |
| Cross-pool LP share theft in XYK liquidity mining | Critical | ~$200k at risk |

Reported via Immunefi, and the $500k one is dated **18 June 2025** with a public
write-up. So the ceiling on this programme is not theoretical.

## The $500k root cause is a grep away

The aToken Critical was not a subtle invariant break. It was:

```rust
let diff = atoken_balance.saturating_sub(amount);   // amount is caller-supplied
```

`saturating_sub` returns 0 instead of erroring when `amount > balance`, which
selected a "withdraw all" dust-cleanup branch. Consequence: **aToken transfers
never failed for insufficient balance.** `Stableswap::add_liquidity_shares` mints
user-specified shares then transfers the matching amount, so a user could specify
more shares than their balance supported — shares minted, transfer silently
succeeded for less. Arbitrary unbacked stablepool shares, up to $22M at risk.

Their own remediation: *"Disabled the aToken rounding fix. **Proper fix to be
audited separately.**"* Funds were secured in **2 hours** via a liquidity-addition
pause; a stealth runtime upgrade followed ~7 hours after the report.

## Two corrections to my own work this prompted

**1. I was about to ship an inverted heuristic.** R1 demotes `debug_assert`s that
guard `saturating_*` arithmetic, treating it as benign — correct as general Rust
advice. Their checklist theme #11 says the opposite:

> **`saturating_sub`/`saturating_*` hiding errors** — saturating math silently
> returns 0 on underflow instead of failing. **This has led to critical exploits
> where insufficient balances were silently accepted.** Default to `checked_*`.

For this codebase, `saturating_*` is the bug pattern, not a safety net. Their
post-mortem lesson #1 is *"Never use `saturating_sub` by default."*

**2. "Saturating arithmetic is bad" is too coarse to be a detector.** Two residual
`saturating_sub` calls in `pallets/currencies/src/lib.rs` (`:657`, `:710`) are
**correct**:

```rust
let remaining = T::MultiCurrency::unreserve_named(id, currency_id, who, value);
let unreserved = value.saturating_sub(remaining);
```

`unreserve_named` returns the amount it could *not* move, so `remaining <= value`
by construction and the subtraction cannot underflow. Both operands come from one
operation — structurally unlike the aToken case, where one operand was a stored
balance and the other a caller-supplied amount.

That distinction is now **R5** in `cli/cs_rust.py`: `saturating_*` between a
balance-named operand and a caller-supplied amount. It catches the aToken shape
and stays silent on the `value - remaining` idiom.

## Result of running R5 across the codebase

**1 hit in 260,665 lines**, and it is fail-safe by direction:

```rust
issuance_increase_in_period.saturating_add(amount) <= context.limit
```

On overflow `saturating_add` yields `u128::MAX`, and `MAX <= limit` is false, so
the circuit breaker **blocks** the mint. The sibling `saturating_sub` correctly
grants more headroom when issuance fell during the period. Not a finding.

So the documented $500k pattern is fixed, and nothing resembling it remains.

## Standing position

Five detectors — R1 `debug_assert` as sole enforcement, R2 raw-balance share price,
R3 missing origin gate, R4 discarded `Result` on value movement, R5 saturating
math on supplied amounts — across **718 files / 260,665 lines** of HydraDX-node:
**zero actionable findings.**

That is a well-evidenced negative, and the two leads it did surface (both R1
revenue-accounting, both fail-safe R5) were closed by reading rather than by
pattern.

The next move is not more scanning. It is **the checklist itself** — 14 recurring
themes, each an invitation. The highest-value unworked ones given what has been
covered:

- **#1 direct transfers bypass hooks** — money reaching a pool account outside a
  pallet extrinsic skips oracle, circuit-breaker and TVL accounting
- **#4 slippage gaps** — `remove_liquidity`, `add_liquidity`,
  `withdraw_protocol_liquidity` (omnipool's `sell` *does* have `min_buy_amount`;
  these three are named in the checklist)
- **#14 confused deputy** — user-supplied resource selector not cross-validated
  against the stored association; this is the XYK liquidity-mining $200k pattern
  and the same shape may survive elsewhere

Each is a targeted read of named functions, which is where reading beats
regex. That is also why the Dwellir endpoint in referendum #419 would matter
more than any further static work: it would let `cs_substrate.py` answer whether
a candidate is live, which is the evidence that killed three separate findings
this session.