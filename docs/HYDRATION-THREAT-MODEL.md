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
---

## Worked the checklist: three themes, three closures

Each theme from Hydration's own auditor checklist, read rather than regexed.

### #14 Confused deputy — defended, at a layer I initially missed

Started from the fixed instance to learn the signature. `redeposit_shares`
(`pallets/xyk-liquidity-mining/src/lib.rs:873`) has the cross-validation:

```rust
let (shares_amount, deposit_amm_pool_id) = ...redeposit_lp_shares(...);
ensure!(amm_pool_id == deposit_amm_pool_id, Error::<T>::InvalidAssetPair);
```

`withdraw_shares` (`:950`) does **not** — it derives `amm_pool_id` from the
user-supplied `asset_pair` and passes it straight into `withdraw_lp_shares` with
no local check. That looked like the $200k bug, unfixed, still reachable.

**It is not.** The check lives one layer down in the shared handler:

```rust
// pallets/liquidity-mining/src/lib.rs:1329
ensure!(amm_pool_id == deposit.amm_pool_id, Error::<T, I>::AmmPoolIdMismatch);
```

Call chain verified: XYK extrinsic → trait `withdraw_lp_shares` (`:1986`) →
`Self::withdraw_lp_shares` (`:2004`) → the `Deposit::try_mutate_exists` body at
`:1315` containing the check. Because it sits in the shared handler, it protects
both `xyk-liquidity-mining` and `omnipool-liquidity-mining`.

**This was my near-miss of the session.** Reporting `withdraw_shares` as an
unfixed $200k confused-deputy would have been a duplicate of a report Hydration
itself filed. The distinction that saved it: grepping for the *fix* tells you
where they put the check in one file, but the check may be an invariant of a
shared layer. Always trace the call chain before calling a layer unpatched.

### #4 Slippage gaps — the named gaps are opt-in, not missing

| Function | Bound |
|---|---|
| `add_liquidity_with_limit(asset, amount, min_shares_limit)` | min ✓ |
| `remove_liquidity_with_limit(position_id, amount, min_limit)` | min ✓ |
| `add_liquidity(origin, asset, amount)` | none — opt-in variant |
| `remove_liquidity(position_id, amount)` | none — opt-in variant |
| `withdraw_protocol_liquidity(asset_id, amount, price, dest)` | `AuthorityOrigin` |

The checklist says to *check* `remove_liquidity`, `add_liquidity` and
`withdraw_protocol_liquidity`. Checked: the first two are the deliberate
no-limit convenience variants with safe siblings — the same design as Gamma's
`deposit`/`depositWithLimit`, and a user opting out of protection is not a bug.

`withdraw_protocol_liquidity` is gated by `T::AuthorityOrigin` — governance
withdrawing the protocol's own liquidity does not need MEV protection from
itself. Its `price: (Balance, Balance)` is **not** a limit at all: it rebuilds a
`Position` whose real fields were lost when a position was sacrificed, per the
dev note. No accepted-but-ignored limit parameter.

### #1 Direct transfers bypass hooks — none found

Zero direct `Currency::transfer` calls into `protocol_account` / pool accounts in
`pallets/omnipool`. All three hooks (`on_liquidity_changed`, `on_trade`,
`on_trade_fee`) are documented and invoked on the extrinsic paths. The
`currencies` pallet's transfers to `ReserveAccount` are the reserve mechanism
itself, and the code states the invariant explicitly: *"The total of all receipts
for an asset must stay equal to the reserve account's erc20 balance."*

## Standing position

No finding from any of the three. The value was the method rather than the
outcome: each theme was a named, high-prioritised shape from the target's own
list, and each closed on a specific reason — a shared-layer invariant, a
deliberate opt-in, and a privileged caller. One of them nearly produced a
duplicate report.

Three themes remain genuinely unworked in the checklist: #2 `asset_in == asset_out`
in paths other than Omnipool's `sell`, #3 division-by-zero on empty pools, and
#5 oracle-hook coverage for every reserve-changing operation. Those are the next
reads, and #5 is the largest — it is the theme the $25k post-mortem actually
exploited.

---

## Worked #5 (oracle hooks) and chased a slippage lead

### #5 Oracle hook coverage — clean

Mapped every state-mutating function in `omnipool` and `stableswap` against hook
invocation. **Zero missing hooks.** `on_liquidity_changed` is fired inside
`do_add_liquidity` (`:1628`, "All done and updated. let's call the
on_liquidity_changed hook"), and `on_trade` via `call_on_trade_hook` on both trade
paths (`:793`, `:899`). `add_assets_liquidity` looked like an omission in a
first pass — it is a 10-line wrapper that delegates to `do_add_liquidity`, so the
hook is reached. No stale-oracle path found in either pool.

### The slippage lead — real gap, but a known class

Chasing `add_assets_liquidity`'s missing local hook surfaced a genuine structural
gap one layer down.

`impl StableswapLiquidityMutation for Pallet<T>` (`stableswap/src/lib.rs:2155`):

```rust
fn add_liquidity(who, pool_id, assets) -> Result<Balance, DispatchError> {
    Self::do_add_liquidity(&who, pool_id, &assets, Balance::zero())
}
```

The trait method has **no `min_shares` parameter at all** and hardcodes zero. The
asymmetry inside the same impl is the tell — `remove_liquidity` and
`remove_liquidity_one_asset` both take and forward their minimums; only `add`
discards protection.

The sole production consumer is `omnipool-liquidity-mining`, whose extrinsic
`add_liquidity_stableswap_omnipool_and_join_farms` (call_index 16) does:

```rust
let stablepool_shares = T::Stableswap::add_liquidity(who, stable_pool_id, stable_asset_amounts.to_vec())?;
let min_shares_limit = min_shares_limit.unwrap_or(Balance::MIN);
let position_id = OmnipoolPallet::<T>::do_add_liquidity(origin, stable_pool_id, stablepool_shares, min_shares_limit)?;
```

So the **stableswap leg executes irreversibly with zero slippage protection before
the caller's limit is even evaluated**, and that limit applies to the Omnipool leg
only. The function's own docstring concedes it: *"Applies to Omnipool step only.
None defaults to no protection."* A user has no way to protect the stableswap leg
through this entry point.

**It is not novel.** Hydration's own catalogue lists the class under theme #4:

> **No slippage check in `remove_liquidity` (Medium)** — *Source: Code4rena M-03,
> RV Stableswap A6, OAK #5* — "Frontrunners can sandwich the transaction for ~1-2%
> extraction. **Also applies to `add_liquidity` (no `min_shares_out`).**"

Already reported three times over, with impact quantified at 1-2%. The direct
extrinsic path was evidently fixed — `add_assets_liquidity` and
`add_liquidity_with_limit` both take a real `min_shares`/`min_shares_limit`. What
survives is the trait path, an instance of the documented class.

The 1-2% figure is also consistent with first principles: adding liquidity to a
*stable* pool mints shares near-proportional to the invariant, so the mint is far
less sandwichable than a swap, and moving the pool costs the attacker. I did not
demonstrate extraction, and on the available evidence would not claim it.

**Verdict: not submittable.** A documented, thrice-reported class, with the
residual instance being a specific path the catalogue already names.

---

## Worked #2 (same-asset trades) and #3 (empty-pool division) — both clean

### #2 `asset_in == asset_out` — protected at the creation layer, not the trade layer

Their checklist rates this the highest-priority item: *"Always validate that
trade/swap pair assets are distinct. **This has led to critical pool drains.**"*

Audited every trade entry point across the DEX pallets:

| Pallet | sell | buy | same-asset guard |
|---|---|---|---|
| omnipool | ✓ | ✓ | yes |
| stableswap | ✓ | ✓ | yes |
| route-executor | ✓ | ✓ | yes |
| **xyk** | ✓ | ✓ | **none on the trade path** |
| **lbp** | ✓ | ✓ | **none on the trade path** |

XYK and LBP carry no same-asset check in `sell`/`buy`. The only guard in either
pallet is at **pool creation** — `xyk:325` and `lbp:448`, both
`ensure!(asset_a != asset_b, CannotCreatePoolWithSameAssets)`.

That is sufficient, and worth stating precisely because it is not obvious from the
trade code. With `asset_in == asset_out == X`:

- XYK `validate_sell` resolves the pool via `Self::exists(assets)` (`xyk:786`) →
  no X/X pool can exist → `TokenPoolNotFound`
- LBP resolves via `PoolData::try_get(&pool_id)` (`lbp:810`) → `PoolNotFound`

So the same-asset trade is unreachable. The invariant is supplied one layer away
from where their checklist expects to see it. Defence-in-depth would put a check
on the trade path too, but a redundant check is not a bounty finding, and calling
this a critical pool drain would be wrong.

**Verdict: no finding.** The class is real, and it has burned them before — but
these two pallets are held by a sound creation-layer invariant.

### #3 Division by zero on emptied pools — minimum-reserve invariants present

XYK has `MinPoolLiquidity` as a `Config` type, enforced at pool creation
(`xyk:321`) **and maintained across withdrawals** (`xyk:659-661`):

> "Account's liquidity left should be either 0 or at least MinPoolLiquidity"

so a withdrawal can never strand the pool with a dust remainder below the floor.

Omnipool has no `MinPoolLiquidity` config but requires a floor at `add_token`
(`omnipool:510-512`): `ensure!(ed > 0 && amount >= ed.saturating_mul(20),
MissingBalance)` — a token cannot enter the pool with less than 20× existential
deposit. On top of that, 53 `checked_div` / `DivisionByZero` / `ArithmeticError`
guards in the pallet, with the `checked_div(...).ok_or(...)` idiom used
consistently on reserve ratios.

**Verdict: no finding.** Both pools hold a floor and guard division explicitly.
The catalogue's adjacent item — "LP exit blocked by MinPoolLiquidity (Major)" — is
the other side of that same trade-off, and is a known characteristic rather than a
new finding.

## Standing position after six checklist themes

| # | Theme | Result |
|---|---|---|
| 1 | Direct transfers bypass hooks | clean — no unhooked path into pool accounts |
| 2 | `asset_in == asset_out` | clean — invariant at pool creation, not trade path |
| 3 | Division by zero on empty pools | clean — minimum-reserve floors + 53 division guards |
| 4 | Slippage gaps | opt-in variants + privileged protocol path; trait path is a known class |
| 5 | Oracle hook coverage | clean — `on_liquidity_changed` / `on_trade` on every mutator |
| 14 | Confused deputy | defended in the shared handler, not the wrapper |

Six of fourteen worked, all closed with a specific reason. Four required reading
code rather than pattern-matching, and **two of the four first looked like
reportable findings** — `withdraw_shares` (a duplicate of Hydration's own $200k
report) and the `StableswapLiquidityMutation` zero-`min_shares` path (a
triply-reported class). Both were closed only by tracing to the layer that actually
carries the invariant, and in the second case by reading the target's own
catalogue.

Eight themes remain: #6 amplification rate-limiting, #7 amplification sandwich,
#8 existential-deposit awareness, #9 EVM/Substrate boundary, #10 privileged-role
impact, #11 `saturating_*` (covered by R5 — clean), #12 multi-block oracle attacks
via transaction ordering, #13 scope creep in shared layers.

Of those, **#9 (EVM/Substrate boundary)** and **#12 (multi-block oracle attacks)**
are the two with payout precedent: #12 *is* the $25k post-mortem, and #9 covers
`pallet-evm-accounts`, `pallet-contracts`, and the ERC20 mapping that a 2024
Pashov audit already found a High in.

---

## Worked #9 (EVM/Substrate boundary) — no finding

### Address-space truncation — the strongest candidate, and already theirs

`pallets/evm-accounts` uses a two-namespace design:

- **truncated**: `b"ETH\0"` + 20-byte EVM address + 8 zero bytes
- **bound**: 20-byte EVM address + 12-byte `AccountExtension` suffix

with `evm_address()` branching on `_is_evm_account`, which requires **two**
conditions — `account_id[0..4] == b"ETH\0" && account_id[24..32] == [0u8; 8]`.
The second condition is the point: a bound account would have to both begin
`0x45544800` *and* have 8 trailing zero bytes, and the extension is not
user-supplied. The namespaces cannot collide. The same rule is replicated in
`runtime/hydradx/src/evm/synthetic_logs.rs:286`.

### ERC20 synthetic-address namespace — real collision, already documented

`HydraErc20Mapping::encode_evm_address` builds `0x00…00 01 <asset_id BE>` with the
marker at **byte 15**, and `is_asset_address` matches the first 16 bytes against
the same pattern. I mis-counted the marker position by eye first and was
disproved by executing the round trip — `0→0`, `1→1`, `0x1234→0x1234`,
`0xDEADBEEF→0xDEADBEEF` all exact. The 20-byte-into-`u32` loop looks wrong but is
correct: `<<8` truncates, leaving exactly `bytes[16..19]`.

**But a correct round trip is not an exclusive namespace.** An EVM address is
user-chosen, and a user can pick one matching the synthetic pattern — e.g.
`0x00000000000000000000000000000001deadbeef` — which `is_asset_address` accepts
and decodes to asset `0xDEADBEEF`. Since `address_to_asset` tries
`decode_evm_address` **first**, a colliding user address shadows the registry
lookup.

`address_to_asset` is consumed in exactly the sensitive places:
`ice/amm-simulator/uniswap_v3.rs:259-260` (resolves pool tokens),
`runtime/hydradx/src/lib.rs:1197-1198` (resolves aToken/reserve), and
`evm/aave_trade_executor.rs:167,174` — the AAVE path, where the $500k aToken
Critical lived.

**Not a finding.** Hydration's own catalogue lists it under theme #9:

> **EVM/Substrate address mapping truncation (Informational)** — "Converting
> between 32-byte Substrate and 20-byte EVM addresses truncates entropy,
> **theoretically enabling collisions and fund loss**."

And the audit table records `2024-10 | Pashov | ERC20 Mapping | 1 high + 3 medium +
5 low`. The class is identified, the component is audited, and the project rates
the residual collision Informational. Reporting it would be re-reporting a
documented, accepted issue.

### Other theme #9 items already listed

`ERC20 return value not verified (Medium)` — `handle_result()` doesn't verify
ERC20 return values — and the EVM migration weight blowup are both catalogued,
with sources. No new ground.

## Session close

Seven of fourteen themes worked: #1, #2, #3, #4, #5, #9, #14. All closed with a
specific reason. Five detectors across 718 files / 260,665 lines: zero actionable
findings. **No novel finding on a $222,222-ceiling programme that has paid
$500k and $25k on two of the exact classes hunted here.**

The dominant failure mode was never missing a bug — it was **tending toward
filing a duplicate**. Concretely:

| Candidate | What it actually was |
|---|---|
| `withdraw_shares` lacks cross-validation | defended in the shared handler — duplicate of their own $200k report |
| `StableswapLiquidityMutation` zero `min_shares` | a class reported 3× over (Code4rena M-03, RV A6, OAK #5) |
| ERC20 synthetic-address collision | catalogued as Informational; component audited by Pashov |
| `calculate_target_fee` `saturating_div` | fail-safe by saturation direction |
| `can_mint` `saturating_add` | saturation *blocks* the mint |
| same-asset trades in xyk/lbp | invariant held at pool creation, not the trade path |

Six candidates, all closed by tracing to the layer that actually carries the
invariant, or by reading the target's own catalogue. Four of them would have been
filed as findings on the strength of a single-file read.

That is the transferable lesson, and it is not specific to this target: **on a
heavily-audited programme, the highest-value step is not another pattern but
finding where the invariant actually lives, and whether the maintainers have
already documented it.**
