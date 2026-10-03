# Detector validation harness

Every wrong number this session produced came from the same place: **a detector that
returned an answer I could not distinguish from a correct one.** The list is long enough
to be worth an argument for machinery rather than vigilance:

| wrong number | why it looked fine |
|---|---|
| 274 "beacon proxies" | `classify` set the label whenever the impl slot was empty, so every direct contract matched — no error, plausible output |
| fabricated selectors | `initialized()` recorded as `0xf7a05767` instead of `0x158ef93e`; probes "reverted", which read as evidence |
| `_initialized = 0` on both implementations | read implementation storage, where it is always empty — would have been a fabricated Critical |
| 386 / 638 strong-hit class counts | classes keyed on bare identifiers, matching vocabulary not risk |
| GMX coverage "done" | 20 lines of 3,586 |

None of these raised. All of them were believed.

## What the harness does

`tests/test_detector_validation.py` gives each detector fixtures where **the truth is
known**, and fails the build when the detector disagrees. The point is not coverage — it
is that a wrong number now breaks CI instead of depending on me catching it.

The RPC layer is mocked, deliberately: what broke was slot interpretation and model
classification, not connectivity, and mocking makes those cases exact and fast.

Eleven fixtures, built around the specific failures:

**Ground truth on proxy shape**
- a direct contract (both slots empty) must not be called a proxy — the exact case the
  beacon bug swallowed
- a beacon proxy (beacon set, impl empty) must resolve through to its implementation
- an implementation proxy (impl set, beacon empty) must not be called a beacon

**Known positive and negative on the Critical class**
- `initialized() == 0` must surface as uninitialised
- `initialized() == 1` must not be flagged
- a **reverting** read must never be silently reported as a value

**Probe honesty**
- a function that returns data must be detected as existing, at high confidence
- a selector that behaves *identically to a random one* must be reported
  **indistinguishable**, not as proven absent — this is the distinction the whole
  deployment axis turned on

**Regression pins**
- the four resolved selectors, so reintroducing a hand-written literal fails here
- `cs_deploy._rpc` and `cs_init._rpc` have **incompatible signatures** (url-first vs
  url-third). Assuming they were interchangeable was its own small mistake while
  writing this.

## What it does not do

These fixtures pin the *logic* of two detectors on synthetic data. They do not
validate the sweep against a live chain, and they cannot catch a detector that is
correct on fixtures and wrong against real bytecode. Extending them to the other
detectors — R1–R5, M1/M3, the Veck classes — is the obvious next step and is mechanical.

The honest summary: this does not make me less likely to be wrong. It converts the
specific failure mode that produced six wrong numbers this session — a plausible
number with nothing behind it — into a red build.
