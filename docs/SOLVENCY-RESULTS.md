# IPOR — solvency accounting, tested

The gap in this project was reading without testing. These are the first fuzz
invariants over `AmmStorage`'s accounting — the surface behind the `Protocol
insolvency` High tier — driven through the protocol's own `AmmStorage` harness.

```bash
cd protocol && forge test --match-contract SolvencyAccountingTest -vv
# 5 passed, 0 failed   (768 fuzz runs)
```

## Invariants that hold

| Test | Runs | Property |
|---|---|---|
| `testFuzz_roundTrip_restoresCounters` | 256 | A PayFixed open/close round trip returns every collateral counter to its starting value, for any collateral, notional and liquidation deposit |
| `testFuzz_roundTrip_receiveFixedLeg` | 256 | Same for the ReceiveFixed leg |
| `testFuzz_manyRoundTrips_conserve` | 256 | N opens then N closes still nets to zero |
| `test_doubleClose_isRejected` | 1 | A swap cannot be closed twice |

## Caller-supplied struct: tested, not assumed

`updateStorageWhenCloseSwapPayFixedInternal` takes a `Swap` **from the caller**, and
`_updateSwapsWhenClosePayFixed` reads `swap.buyer`, `swap.idsIndex` and `swap.id`
from it. `_updateBalancesWhenCloseSwapPayFixed` then uses that struct's
`collateral` and `wadLiquidationDepositAmount`. That is a trust assumption
worth probing, because the solvency-critical fields differ in how they are
handled:

| Caller lies about | Result |
|---|---|
| `collateral` inflated 500x | **reverts** — arithmetic underflow |
| `buyer` forged to `0xDEAD` | **reverts** — arithmetic underflow |
| `liquidationDepositAmount` doubled | **no effect** — sourced from storage, not the struct |

So the solvency-critical fields are defensively validated by the arithmetic, and
the deposit field is simply not taken from the caller. No finding — but the
asymmetry is now pinned by tests rather than inferred from reading.

## The liquidation-deposit accounting

Open credits `liquidationDepositAmount * 1e12`; close debits
`wadLiquidationDepositAmount`, which is stored as
`liquidationDepositAmount * 1e12` (`AmmStorageBaseV1:136`). They agree, and the
fuzz round trips confirm the counter returns to zero.

Note the datatype: `liquidationDepositAmount` is stored as **uint32**
(`AmmStorageBaseV1:439`), so it is a small config value (e.g. 25), not an
18-decimal amount. Passing `1e18` reverts with `SafeCast: value doesn't fit in 32 bits`.

## What is NOT covered

These exercise `AmmStorage` accounting in isolation. Untested and still open:

- the floating-pool share maths on `Market` (`previewBorrow`/`previewRepay`/`previewRefund`
  round-trip) — needs the full oracle/auditor/treasury stack deployed
- the oracle rate model (`spread`) and sanity checks
- `PowerToken`'s exchange rate, which is derived from a raw `balanceOf` and is
  therefore donation-sensitive in principle
- asset management and rebalance

## Verdict

**No insolvency or theft finding in the tested surface.** The accounting holds
under fuzzing, and the one trust assumption in the design is defensively
handled.

At IPOR's real payout — Critical **flat $1,000** — this is not a place to spend
more time. The gate reports it as blocked anyway: the program is alive and
free-to-file, but three gates remain unresolved.
