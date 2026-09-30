# Platform coverage — TODO backlog

Target platforms still missing or partial. Ordered by how much of the existing
stack each one reuses.

Shared shape every platform module should implement, so they stay comparable:

| Surface | Commands | Notes |
| --- | --- | --- |
| catalog | `list`, `keizo` | rank by ceiling, rep gate, report count, scope type, fee |
| evidence | `meta` | one program: ceiling, dates, published audits + links |
| scope | `scope` | in-scope addresses and code repos |
| pipeline | `triage` | scope -> fetch deployed sources -> graph -> hotspots |

Shared obligations — learned the hard way on Immunefi/HackenProof:

- **Never treat an `audits`/`audit` field as coverage evidence.** Immunefi
  reports `0` for GMX, Chainlink, Arbitrum, Wormhole; every HackenProof SC
  program returns `audit: false`. If a platform flag is not demonstrably
  discriminating, treat absence as `unknown`, never as "unaudited".
- **Authoritative ceiling.** Prefer the program's own max-bounty field; watch
  for stale `legacy`/mirrored arrays that overstate it.
- **Scope filters only against the asset table**, never the whole page.
- Cache rows are shape-sensitive: version the cache so a changed row shape
  invalidates it rather than silently degrading derived signals.

---

## TODO

### 1. Sherlock — **partial, finish it**
Status: `cli/cs_sherlock.py` exists but is **uncommitted** and implements only
`keizo` and `list`. Missing `meta`, `scope`, `triage`.
Also has leftovers to clean up or gitignore: `sherlock.html`, `add_programs.py`.
Note: Sherlock is contest-based, so the ranking signal is *contest status* and
*prize pool*, not bug-bounty ceiling.

### 2. Intigriti — **partial, extend it**
Status: `cs_intigriti` has `keizo` and `list`. Missing `meta`, `scope`, `triage`.
Intigriti is where a lot of the larger protocols list, so this is high value.

### 3. Bugcrowd — **absent, add it**
Status: not implemented. Directly relevant: an entire multi-round engagement ran
on Wyze and eToro (both Bugcrowd) with **no catalog tooling available**.
Known shape to verify: `https://bugcrowd.com/programs.json`, and per-program
HTML at `/programs/<slug>` (the pattern already exercised against
`api.crawler` during earlier sessions).

### 4. CertiK — **absent, add it**
Status: not implemented. CertiK runs its own bounty program and also appears as
an *auditor* reference inside other platforms' pages, so a firm-name detector
here is reusable by the audit-evidence logic in `cs_screen`.

### 5. YesWeHack — **absent, add it**
Status: not implemented. Smaller ecosystem; treat as low priority, same shape as
Intigriti.

---

## Not doing

- **Auto-submitting to any platform.** Out of scope by design; every platform's
  terms require the human researcher to file, and several (Wyze, Celer) require
  KYC or a pay-to-submit fee.
- **Treating any ranking as a verdict.** `cs_screen` deliberately reports
  `audit_status: unknown` for every row for this reason.
