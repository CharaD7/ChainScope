# mETH — `Staking.unstakeRequestWithPermit` permit front-running griefing

**Status:** confirmed by execution. PoC is a Foundry test; control and attack both pass.
**Program:** mETH / Instascope (Immunefi), **CRITICAL-only** (Medium pays $5,000)
**Severity:** Medium
**Class:** permit/signature front-running griefing — the same class as Lido DAO issue #803

## Summary

`Staking.unstakeRequestWithPermit` accepts an ERC20-2612 permit signature as
calldata and passes it straight to `safePermit`, with no check for an existing
allowance:

```solidity
// contracts/src/Staking.sol:362
function unstakeRequestWithPermit(
    uint128 methAmount,
    uint128 minETHAmount,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external returns (uint256) {
    SafeERC20Upgradeable.safePermit(mETH, msg.sender, address(this), methAmount, deadline, v, r, s);
    return _unstakeRequest(methAmount, minETHAmount);
}
```

`(v, r, s)` are public calldata on a pending transaction. Anyone reading the
mempool can submit that same permit first, consuming the victim's nonce. The
victim's transaction then reverts with `ERC20Permit: invalid signature` and their
withdrawal request never reaches the queue.

## Why this is a known-valid class

Lido DAO **issue #803** — "Potential withdrawal request griefing vector via
`permit` front-running" — is the same defect on `WithdrawalQueue`. It was reported
through Immunefi, **rated MEDIUM, and the reporter was paid**. It remains **open**
with the label `next upgrade`, so Lido's own fix was still pending.

Lido's proposed fix is precisely the check mETH lacks:

```solidity
if (STETH.allowance(msg.sender, address(this)) < _permit.value) {
    STETH.permit(msg.sender, address(this), _permit.value, _permit.deadline, _permit.v, _permit.r, _permit.s);
}
```

mETH is a different program on a different chain, so Lido's disclosure does not
disclose mETH. The defect is independently present in mETH's source.

## PoC

`test/PermitFrontRunning.t.sol` (in the mETH contract tree, reusing their own
`StakingTest` harness):

```solidity
[PASS] testPermitUnstakeSucceedsWhenNotFrontRun   // control: works normally
[PASS] testPermitUnstakeGriefedByFrontRunner      // attack: nonce consumed, victim reverts
```

The attack test asserts `mETH.nonces(victim)` increased after the attacker's
call, then that the victim's still-pending call reverts.

## In scope

`Staking` is listed in mETH's Immunefi scope:

| Contract | Address | Chain |
|---|---|---|
| Staking | `0xe3cBd06D7dadB3F4e6557bAb7EdD924CD1489E8f` | 1 |

## Impact

mETH's scope defines Medium as *"Griefing (e.g. no profit motive for an attacker,
but damage to the users or the protocol)"* — which is this exactly. There is no
fund loss, so it is not Critical or High. The user must re-sign and resubmit; the
withdrawal is not lost, but it can be delayed indefinitely by a cheap mempool
watcher. Because `unstakeRequest` (non-permit) exists and the allowance is set by
the first attempt, practical mitigation is to approve first and use the plain
path — which is why Lido rated it Medium rather than High.

## Coverage gap worth flagging separately

The function is tested, but **only on the happy path**
(`test/Staking.t.sol:886`). The front-running case has no coverage. That is how
the issue survived.

## Suggested fix

Lido's allowance pre-check, or simply documenting `approve` + `unstakeRequest` as
the recommended path and removing the permit variant.

## Reproducing

```bash
cd contracts && forge test --match-contract PermitFrontRunning -vv
```

Requires the mETH contract tree (`mantle-lsp/contracts`). Note that
`test/liquidityBuffer/LiquidityBufferWithdrawRole.t.sol` fails in `setUp()` on a
clean checkout — pre-existing, unrelated to this PoC, but it means the repo's own
test for the withdraw-role change does not currently run.
