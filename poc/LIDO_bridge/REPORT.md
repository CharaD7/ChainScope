# Lido `L1OutboundDataParser.from` — tested

## Result

`L1OutboundDataParser.decode` branches on `msg.sender`:

```solidity
if (msg.sender != router_) {
    return (msg.sender, _parseSubmissionCostData(data_));      // safe
}
(address from, bytes memory extraData) = abi.decode(data_, (address, bytes));
return (from, _parseSubmissionCostData(extraData));            // calldata decides
```

Six tests, all passing, executed against the real library (solc 0.8.10, matching the
repo's exact pragma):

| test | establishes |
|---|---|
| `test_directCaller_isAlwaysDebited` | **direct path binds `from = msg.sender`** — calldata cannot redirect it. The safety property holds. |
| `test_directPath_rejectsRouterFormat` | the direct path rejects the router encoding outright rather than silently honouring it |
| `test_asRouter_fromComesFromCalldata` | **as router, `from` is whatever calldata says** |
| `test_asRouter_acceptsArbitraryAddress` | **any arbitrary address is accepted — not a whitelist** |
| `test_innerExtraDataMustBeEmpty` | the inner `extraData` emptiness guard holds |
| `test_malformedInnerReverts` | malformed inner encoding reverts rather than defaulting to zero cost |

**Settled by execution:** the library/gateway imposes **no constraint of its own** on
`from` when the caller is the router, and will accept an arbitrary address. The only
remaining protection on the gateway's `safeTransferFrom(from, ...)` is the ERC20
allowance.

## Still unclosed

Whether Arbitrum's canonical `L1GatewayRouter` forwards user-controlled bytes into
that slot. That contract is not in `lido-l2`, three plausible paths 404'd, the
GitHub tree API returns 401, and Lido publishes zero in-scope addresses so the
deployed `router` value cannot be read on-chain either.

A Critical requires BOTH: a router that forwards attacker-chosen `data_`, AND a user
with a live allowance on that token. The second is realistic (anyone who has bridged
has approved the gateway). The first is not established.

## Two harness traps worth recording

Both produced "confirmed" results that were wrong, and both are the same class of
error as this session's other measurement failures:

1. **`address(this)` as the router silently took the router branch.** The parser
   branches on `msg.sender` inside the library, which is whoever calls `decodeAs` — the
   test contract. Passing `address(this)` as `router_` made `msg.sender == router_`, so
   the two "direct path" tests were actually exercising the router path. Fixed by
   passing a distinct `SOME_OTHER_ROUTER`.
2. **forge-std is unusable here.** `lido-l2` pins `pragma 0.8.10` exactly and
   forge-std requires >=0.8.13, so they cannot share a compilation unit. The tests use
   hand-rolled assertions and a manually declared `Vm` interface instead.

Also worth noting: `vm.store` into `BridgingManager`'s proxy slot (needed to flip
`whenDepositsEnabled` on the full gateway) silently did nothing in this setup. Testing
the library directly avoided it, which is also the more honest test — the proxy slot is
deployment wiring, not the question being asked.
