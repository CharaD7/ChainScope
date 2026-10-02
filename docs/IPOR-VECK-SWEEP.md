# IPOR — 21-class Critical sweep, both repos

`python3 -m cli veck scan <dir>` across both IPOR codebases, 2026-10-02.

```
ipor/protocol/contracts    189 .sol files
ipor/power-tokens/contracts 45 .sol files
```

## Full class counts

| Class | protocol | power-tokens |
|---|---|---|
| 1  Uninitialized proxies | 11 | 8 |
| 2  Read-only reentrancy | 5 | — |
| 3  Oracle manipulation | — | 11 |
| 5  Storage collisions | 26 | 4 |
| 7  Access control on admin fns | 63 | 32 |
| 9  Incorrect token handling | 29 | 7 |
| 12 delegatecall to untrusted | 1 | 1 |
| 18 Swap slippage / MEV | 477 | — |
| others | 0 | 0 |

Class 18's 477 is the shape of an AMM, not a finding. The two strong-only hits
were the interesting ones, and both are false positives on deployed code.

## Strong hits, both disproven

**Class 1 — `initialize(...) external initializer`** on `IporProtocolRouterAbstract.sol:24`
and `PowerTokenRouter.sol:46`.

Every other class-1 hit is a `_disableInitializers()` call in a constructor — that
is the mitigation, not the bug. The two real candidates were checked against
mainnet, not just read:

| Contract | Test | Result |
|---|---|---|
| PowerToken proxy `0xD72915B9…5409F` | `eth_call initialize()` | reverts `Initializable: contract is already initialized` |
| IporProtocolRouter `0x16d10400…26fd` | owner at slot `0xF4240` | `0xd92e9f039e4189c342b4067cc61f5d063960d248` (non-zero) |

`StorageLib._getStorageSlot` is `uint256(storageId) + 1_000_000`, so `Owner` (enum 0)
is slot `0xF4240`. Both proxies are initialised. **Disproven.**

## Class 12 — `delegatecall` in both routers

`SpreadRouter.sol:144` and `PowerTokenRouter.sol:164`. Both `_delegate` into
`getRouterImplementation(msg.sig)`, an if/else ladder over **four `immutable`
addresses** (`stakeService`, `flowsService`, `liquidityMiningLens`,
`powerTokenLens`) that ends in `revert(Errors.ROUTER_INVALID_SIGNATURE)`.

Immutables are fixed at construction, and an unrecognised selector reverts rather
than falling through. The delegatecall target is not user-controlled.
**Disproven.**

## Where the remaining signal is

Ranked by how much money is reachable, not by hit count.

1. **`DemandSpreadLibs` — what bounds `demandSpread`.**
   `OfferedRateCalculationLibs.calculatePayFixedOfferedRate` applies the
   `payFixedMinCap` to the *base* rate and then adds `demandSpread` on top:

   ```solidity
   if (baseOfferedRate > payFixedMinCap) offeredRate = baseOfferedRate + demandSpread;
   else                                   offeredRate = payFixedMinCap + demandSpread;
   ```

   So the cap does **not** bound the final offered rate. Whether that matters
   depends entirely on the demand curve being bounded, and that curve has not been
   read. This is the highest-Critical-potential lead left in the AMM.

2. **`CalculateWeightedLpTokenBalance{Ethereum,Arbitrum}` (class 3, 11 hits).**
   Weighting LP-token balances by a Chainlink `latestRoundData()` read. Class 3 is
   usually a false positive when the feed is a real oracle, but the interesting
   question is not spot-manipulability — it is whether a stale or
   partially-populated round (`answeredInRound`, `updatedAt`) is checked before
   the answer is used.

3. **`AmmTreasuryBaseV2` (class 2/5/9).** Reads `IERC4626(ammAssetManagement)
   .balanceOf(address(this))` and raw `IERC20.balanceOf` into signed `int256`
   arithmetic. The ERC4626 vault's own share price feeding treasury accounting is
   the same donation-sensitivity family as PowerToken — and the sDAI/PowerToken
   work already gives the harness for it.

4. **Class 9 (29 protocol hits) — fee-on-transfer assumption.** IPOR pulls DAI,
   USDC, USDT. USDC/USDT are not fee-on-transfer today, but the accounting assumes
   an exact pull. Whether the AMM checks received-vs-requested on open determines
   if a fee token would silently desync the treasury.

## Honest status

I have not found the Critical. The two scanner strong-hits are false positives and
I proved both on-chain. The PowerToken exchange rate is real but unprofitable. The
rate math is clamped on both sides. What remains is the demand-spread bound, the
oracle freshness checks, and the ERC4626 treasury interaction — all plausible,
none yet demonstrated.

IPOR's Critical tier pays a **flat $1,000**, so none of this is worth escalating
without a demonstration. The lead worth pursuing is #1, because an unbounded
demand spread on a rate that is added after its own cap is the kind of thing that
turns into a reportable number rather than a story.