#!/usr/bin/env python3
"""Rank Immunefi bug-bounty programs by freshness, payout, and audit load.

This is the Immunefi counterpart to `cli/cs_hacken.py`. Immunefi has no
public JSON API, so the catalog and per-program metadata are recovered from the
React Server Component payload embedded in each program page.

    python -m cli immune list --min-bounty 100000 --top 20
    python -m cli immune list --fresh-scope --json
    python -m cli immune keizo --top 15
    python -m cli immune scope aera
    python -m cli immune triage aera --max-fetch 12

Immunefi differs from HackenProof in ways that shape the filters:
  * no reputation gate and no public report count, so those filters do not
    exist here (`keizo` re-weights the available signals accordingly);
  * `primacy` is `primacy_of_rules` (unlisted assets ineligible) or
    `primacy_of_impact` (broader), which materially changes what is worth
    hunting -- both are exposed;
  * every program publishes an `audits[]` array, which is the dedup surface
    most likely to make a finding ineligible. It is surfaced per program.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import html as _html
import json
import math
import re
import time
import typing
import urllib.error
import urllib.request

import typer

app = typer.Typer()

_INDEX = "https://immunefi.com/bug-bounty/"
_PAGE = "https://immunefi.com/bug-bounty/{slug}/information/"
_CACHE = Path(_PARENT) / ".chainsource" / "immune_programs.json"
_TTL = 24 * 3600
_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
_RETRY = 4


def _get(url: str, timeout: int = 45) -> str:
    """GET with bounded retries.

    Immunefi serves its pages chunked and dropped the connection mid-read more
    than once while building this module, so both transport errors and
    mid-body read failures (`IncompleteRead`) are retried before giving up.
    """
    import http.client

    last: Exception | None = None
    for attempt in range(_RETRY):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "text/html"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "ignore")
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            OSError,
        ) as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"failed to fetch {url}: {last}")


def _unescape(raw: str) -> str:
    """Turn the RSC payload's escaped JSON back into ordinary JSON text."""
    # RSC embeds JSON as a JS string literal: \" -> ", \\ -> \", \n -> newline
    out = raw.replace('\\\\"', '"').replace('\\\\\\"', '"')
    out = out.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t")
    out = out.replace("\\\\", "\\")
    return out


def _scalars(seg: str, key: str) -> typing.Any:
    """Pull one JSON scalar (string/number/bool/null) for `key` out of `seg`.

    Whole-blob ``json.loads`` is unreliable on RSC payloads: asset descriptions
    carry raw tabs and invalid escapes that make strict JSON fail. Every field
    we need is a simple scalar, so field extraction is both simpler and more
    robust than parsing the object.
    """
    m = re.search(r'"{key}":\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)'.format(key=re.escape(key)), seg)
    if not m:
        return None
    tok = m.group(1)
    if tok.startswith('"'):
        return tok[1:-1]
    if tok == "true":
        return True
    if tok == "false":
        return False
    if tok == "null":
        return None
    try:
        return int(tok) if re.fullmatch(r"-?\d+", tok) else float(tok)
    except ValueError:
        return None


_SCALARS = (
    "slug", "project", "maxBounty", "launchDate", "updatedDate", "kyc",
    "networkType", "proofOfConceptType", "primacy", "pausedAt", "endDate",
    "attackTimeInterval", "reductionPercentage", "kycLevel", "contentfulId",
)


def _audits(seg: str) -> list[dict[str, typing.Any]]:
    """Extract the published `audits[]` array (the dedup surface)."""
    out: list[dict[str, typing.Any]] = []
    for m in re.finditer(
        r'\{[^{}]*?"auditor":\s*("(?:[^"\\]|\\.)*"|null).*?\}', seg
    ):
        blob = m.group(0)
        out.append({
            "auditor": _scalars(blob, "auditor"),
            "date": _scalars(blob, "date"),
            "url": _scalars(blob, "url"),
        })
    return out


def _program_block(raw: str, slug: str) -> dict[str, typing.Any] | None:
    """Pull the `bounty` object out of a program page's RSC payload.

    The payload is an escaped JS string literal in which every JSON quote
    appears as `\\"`, so we unescape first, then read the scalars we need out of
    the `bounty` object. Strict ``json.loads`` on the whole object is not used:
    asset-description prose in the same object contains raw tabs and invalid
    escapes that break strict parsing while the numeric fields remain valid.
    """
    text = _unescape(raw)
    idx = text.find('"bounty":{')
    if idx < 0:
        return None
    start = text.index("{", idx)
    depth = 0
    in_str = False
    esc = False
    end = len(text)
    for i in range(start, min(start + 400_000, len(text))):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    seg = text[start:end]
    if '"slug"' not in seg:
        return None
    obj: dict[str, typing.Any] = {k: _scalars(seg, k) for k in _SCALARS}
    obj["_seg"] = seg
    obj["audits"] = _audits(seg)
    # knownIssues is an array; count its top-level entries.
    ki = seg.find('"knownIssues":')
    obj["knownIssues"] = 0
    if ki >= 0:
        rest = seg[ki + len('"knownIssues":') :]
        if rest.lstrip().startswith("["):
            inner = rest[rest.index("[") + 1 :]
            depth = 1
            count = 0
            for ch in inner:
                if ch == "{":
                    depth += 1
                    if depth == 2:
                        count += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 1:
                        break
            obj["knownIssues"] = count
    return obj


def _catalog() -> list[str]:
    raw = _get(_INDEX, timeout=60)
    slugs = set(re.findall(r"/bug-bounty/([a-z0-9][a-z0-9_-]{2,60})/", raw))
    slugs -= {
        "list", "information", "scope", "resources", "submit-bug",
        "bug-bounty", "help", "learn", "sign-up", "sign-in",
    }
    return sorted(slugs)


def _program(slug: str) -> dict[str, typing.Any] | None:
    try:
        raw = _get(_PAGE.format(slug=slug))
    except RuntimeError:
        return None
    obj = _program_block(raw, slug)
    if obj is None:
        return None
    obj["_slug"] = slug
    return obj


def _load(refresh: bool = False) -> list[dict[str, typing.Any]]:
    """Return cached program metadata, fetching only what is missing."""
    cached: dict[str, dict[str, typing.Any]] = {}
    fresh_enough = False
    if _CACHE.exists():
        try:
            payload = json.loads(_CACHE.read_text())
            cached = {p["_slug"]: p for p in payload.get("programs", []) if "_slug" in p}
            fresh_enough = (time.time() - _CACHE.stat().st_mtime) < _TTL
        except (json.JSONDecodeError, OSError):
            cached = {}
    if not refresh and fresh_enough and cached:
        return list(cached.values())

    slugs = _catalog()
    if refresh and cached:
        slugs = sorted(set(slugs) | set(cached))
    out: list[dict[str, typing.Any]] = []
    missing = [s for s in slugs if refresh or s not in cached]
    for slug in slugs:
        if slug in missing:
            prog = _program(slug)
            if prog:
                out.append(prog)
        else:
            out.append(cached[slug])
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    _CACHE.write_text(json.dumps({"fetched_at": int(time.time()), "programs": out}))
    return out


def _iso_epoch(value: typing.Any) -> float:
    """Parse an ISO-8601 timestamp (Immunefi's format) into epoch seconds.

    The RSC payload carries `updatedDate`/`launchDate` as strings such as
    "2026-09-09T13:05:59.009Z", NOT epoch millis. Parsing them as a float threw
    and silently defaulted `updated` to 0, which zeroed the freshness signal for
    every program and made the whole keizo ranking meaningless. Handles both
    formats so a future payload change degrades rather than breaks.
    """
    if value is None or value == "":
        return 0.0
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v
    text = str(value).strip()
    try:
        return float(text) / (1000.0 if float(text) > 1e11 else 1.0)
    except (TypeError, ValueError):
        pass
    from datetime import datetime, timezone

    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(
            tzinfo=datetime.fromisoformat(text.replace("Z", "+00:00")).tzinfo or timezone.utc
        ).timestamp()
    except (TypeError, ValueError):
        return 0.0


# Payout formats seen in the wild:
#   "Up to USD $2,000,000"        (celer)
#   "USD $50,000 - USD $250,000"   (lombard-finance, range with dash)
#   "USD $15,000 to USD $30,000"  (lombard-finance legacy list, range with "to")
#   "USD $100,000"                 (single)
# The ceiling for ranking is the UPPER bound of whichever applies.
_TIER_RE = (
    r'"level"\s*:\s*"(Critical|High|Medium|Low|Informational)"\s*,\s*"payout"\s*:\s*'
    r'"(?:Up to )?USD \$([\d,]+)(?:\s*(?:to|-)\s*(?:USD \$)?([\d,]+))?"'
)


def _tiers(seg: str) -> dict[str, dict[str, typing.Any]]:
    """Parse the per-severity reward table.

    Two bugs this fixes:
      1. `maxBounty` is not the ceiling. Celer reported 200,000 while its Critical
         tier is 2,000,000 - a 10x understatement that mis-ranked targets.
      2. Payouts may be RANGES ("USD $50,000 - USD $250,000"). The first capture
         group is the floor, so taking it as the ceiling under-reports by 5x.
    """
    found: dict[str, dict[str, typing.Any]] = {}
    for m in re.finditer(_TIER_RE, seg):
        level = m.group(1)
        lo = float(m.group(2).replace(",", ""))
        hi = float((m.group(3) or m.group(2)).replace(",", ""))
        # legacy_*_rewards is listed FIRST and is stale; the current list comes
        # later, so last-wins is correct here (inverse of the naive assumption).
        found[level] = {"floor": lo, "payout": hi, "primacy": None}
    for m in re.finditer(
        r'"primacy"\s*:\s*"(primacy_of_impact|primacy_of_rules)"\s*,\s*"severity"\s*:\s*"(Critical|High|Medium|Low)"',
        seg,
    ):
        prim, sev = m.group(1), m.group(2).title()
        if sev in found:
            found[sev]["primacy"] = prim
    return found


def _known_issues_count(value: typing.Any) -> int:
    """knownIssues arrives as an int in some payloads and a JSON array in others
    (e.g. "[]" or []). Never let a representation difference crash the ranking."""
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return len(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
        if text.startswith("["):
            inner = text.strip("[]").strip()
            return 0 if not inner else inner.count("{")
    return 0


def _row(p: dict[str, typing.Any]) -> dict[str, typing.Any]:
    seg = p.get("_seg") or ""
    audits = p.get("audits") or []
    updated = _iso_epoch(p.get("updatedDate"))
    tiers = _tiers(seg) if seg else {}
    critical = tiers.get("Critical", {})
    high = tiers.get("High", {})
    # maxBounty is the AUTHORITATIVE ceiling. The payload also carries stale
    # `legacy` / `smartcontract_rewards` / `web_rewards` arrays whose values
    # disagree with the live program page (Celer: maxBounty=200,000 but
    # smartcontract_rewards claims 2,000,000). Prefer maxBounty; report tier
    # values as cross-checks only, never as a ceiling.
    ceiling = float(p.get("maxBounty") or 0)
    claimed = critical.get("payout")
    if claimed and claimed > ceiling * 4:
        # implausible vs the authoritative field - treat as stale, do not use
        claimed = None
    return {
        "slug": p.get("_slug") or p.get("slug"),
        "project": p.get("project"),
        "url": f"https://immunefi.com/bug-bounty/{p.get('_slug') or p.get('slug')}/information/",
        "max_bounty": ceiling,
        "tiers": tiers,
        "critical_payout": critical.get("payout"),
        "critical_payout_stale": bool(claimed is None and critical.get("payout")),
        "high_payout": high.get("payout"),
        "updated": updated,
        "updated_date": (p.get("updatedDate") or "")[:10],
        "launch_date": (p.get("launchDate") or "")[:10],
        "kyc": bool(p.get("kyc")),
        "poc": (p.get("proofOfConceptType") or "").lower() in ("required", "true", "yes"),
        # Immunefi supports PER-TIER primacy. The program default is `primacy`, and
        # a tier may override it. Surface both instead of collapsing to one value.
        "primacy_default": p.get("primacy"),
        "primacy_critical": critical.get("primacy") or p.get("primacy"),
        "network": p.get("networkType"),
        "audits": len(audits),
        "audit_refs": [{"auditor": a.get("auditor"), "date": a.get("date"), "url": a.get("url")} for a in audits],
        "known_issues": _known_issues_count(p.get("knownIssues")),
    }


# Explorer host -> Sourcify chain spec, so deploy_source can resolve it.
_HOST_CHAINS = {
    "etherscan.io": "1",
    "basescan.org": "8453",
    "arbiscan.io": "42161",
    "optimistic.etherscan.io": "10",
    "bscscan.com": "56",
    "polygonscan.com": "137",
    "snowtrace.io": "43114",
    "ftmscan.com": "250",
    "lineascan.build": "59144",
    "scrollscan.com": "534352",
    "explorer.zkevm.cronos.org": "388",
    "zkevm.cronos.org": "388",
    "cronoscan.com": "25",
    "explorer.morphl2.io": "2818",
    "hyperevmscan.io": "999",
}

_SKIP_HOSTS = {
    "app.originprotocol.com", "lombard.finance", "immunefi.com",
    "github.com", "discord.com", "twitter.com", "x.com", "docs.immunefi.foundation",
    "immunefi.foundation", "immunefisecurity.com", "t.me", "telegram.me",
    "blog.immunefi.com", "immunefi.com/bug-bounty",
}


def _scope(slug: str, timeout: int = 45) -> dict[str, typing.Any]:
    """Scrape a program page for in-scope contract addresses and code repos.

    Returns {"addresses": [{"chain", "address", "host"}], "repos": [...]}.
    Explorer host is preserved as the Sourcify chain spec for deploy_source.
    """
    raw = _get(_PAGE.format(slug=slug), timeout=timeout)
    addresses: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for host, addr in re.findall(
        r"https?://([A-Za-z0-9.-]+)/[^\"'\s]*?(?:address|token|account)/(0x[0-9a-fA-F]{40})",
        _unescape(raw),
    ):
        host_l = host.lower()
        if host_l in _SKIP_HOSTS:
            continue
        key = (host_l, addr.lower())
        if key in seen:
            continue
        seen.add(key)
        chain = _HOST_CHAINS.get(host_l, host_l)
        addresses.append({"chain": chain, "address": addr, "host": host_l})
    # de-duplicate by address across hosts (same contract, multiple explorers)
    by_addr: dict[str, dict[str, str]] = {}
    for a in addresses:
        by_addr.setdefault(a["address"].lower(), a)
    repos = sorted(
        set(re.findall(r"https?://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+", raw))
    )
    return {"addresses": list(by_addr.values()), "repos": repos}


@app.command(name="list")
def list_programs(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    only_impact: bool = typer.Option(False, "--only-impact", help="Only programs using Primacy of Impact"),
    no_audits: bool = typer.Option(False, "--no-audits", help="Exclude programs with published audits"),
    fresh_scope: bool = typer.Option(False, "--fresh-scope", help="Only programs updated in the last N days"),
    fresh_days: int = typer.Option(30, "--fresh-days", help="Window for --fresh-scope"),
    sort: str = typer.Option("bounty", "--sort", help="Sort by: bounty|updated|audits"),
    top: int = typer.Option(20, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List Immunefi programs matching the filters."""
    programs = _load(refresh)
    now = time.time()
    rows = [_row(p) for p in programs]
    rows = [r for r in rows if r["max_bounty"] >= min_bounty]
    if only_impact:
        rows = [r for r in rows if r["primacy_critical"] == "primacy_of_impact"]
    if no_audits:
        rows = [r for r in rows if not r["audits"]]
    if fresh_scope:
        cutoff = now - fresh_days * 86400
        rows = [r for r in rows if r["updated"] and r["updated"] >= cutoff]
    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
    keyf = {
        "bounty": lambda r: r["max_bounty"],
        "updated": lambda r: r["updated"],
        "audits": lambda r: r["audits"],
    }[sort]
    rows.sort(key=keyf, reverse=True)
    rows = rows[: int(top)]
    typer.echo(f"{len(rows)} program(s) match (max>={min_bounty:g}):")
    for r in rows:
        flags = []
        if r["primacy_critical"] == "primacy_of_impact":
            flags.append("IMPACT")
        if r["poc"]:
            flags.append("POC")
        if r["kyc"]:
            flags.append("KYC")
        tag = ("[" + ",".join(flags) + "] ") if flags else ""
        typer.echo(
            f"  ${r['max_bounty']:>10,.0f}  audits={r['audits']:<3d} upd={r['updated_date']:<10} "
            f"{tag}{r['project'] or r['slug']}  {r['url']}"
        )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


def _keizo(p: dict[str, typing.Any], now: float) -> dict[str, typing.Any]:
    """Rank by signals Immunefi actually exposes.

    HackenProof's variant used thin_hunt (report count) and open_gate (rep
    requirement); neither exists on Immunefi, so the weight moves to signals
    that do: recency of scope change, payout, audit load (higher = more
    dedup pressure), Primacy of Impact (broader scope), and PoC friction.
    """
    row = _row(p)
    fresh = 0.0
    if row["updated"]:
        age_days = max(0.0, (now - row["updated"]) / 86400.0)
        fresh = max(0.0, 1.0 - age_days / 365.0)
    payout = min(1.0, math.log10(1.0 + row["max_bounty"]) / 6.0)
    # More audits => more of the surface is documented => less likely novel.
    dedup_load = min(1.0, row["audits"] / 6.0)
    impact = 1.0 if row["primacy_critical"] == "primacy_of_impact" else 0.0
    poc = 1.0 if row["poc"] else 0.0
    score = round(
        0.30 * fresh + 0.25 * payout + 0.20 * (1.0 - dedup_load) + 0.15 * impact + 0.10 * poc,
        3,
    )
    row["keizo"] = score
    row["signals"] = {
        "fresh": round(fresh, 3),
        "payout": round(payout, 3),
        "unmined": round(1.0 - dedup_load, 3),
        "primacy_impact": impact,
        "poc_required": poc,
    }
    return row


@app.command(name="keizo")
def keizo_rank(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    only_impact: bool = typer.Option(False, "--only-impact", help="Only Primacy of Impact programs"),
    no_audits: bool = typer.Option(False, "--no-audits", help="Exclude programs with published audits"),
    top: int = typer.Option(15, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Rank Immunefi programs: fresh scope + payout + low dedup load + broad scope."""
    programs = _load(refresh)
    now = time.time()
    rows = [_keizo(p, now) for p in programs]
    rows = [r for r in rows if r["max_bounty"] >= min_bounty]
    if only_impact:
        rows = [r for r in rows if r["primacy_critical"] == "primacy_of_impact"]
    if no_audits:
        rows = [r for r in rows if not r["audits"]]
    rows.sort(key=lambda r: r["keizo"], reverse=True)
    rows = rows[: int(top)]
    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
    typer.echo(f"Keizo ranking (max>={min_bounty:g}):")
    for r in rows:
        s = r["signals"]
        typer.echo(
            f"  keizo={r['keizo']:.3f}  ${r['max_bounty']:>10,.0f}  audits={r['audits']:<3d} "
            f"upd={r['updated_date']:<10} {r['project'] or r['slug']}"
        )
        typer.echo(
            f"      fresh={s['fresh']:.2f} payout={s['payout']:.2f} unmined={s['unmined']:.2f} "
            f"impact={s['primacy_impact']:.0f} poc={s['poc_required']:.0f}  {r['url']}"
        )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


@app.command(name="scope")
def show_scope(
    slug: str = typer.Argument(..., help="Immunefi program slug (e.g. 'aera')"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show in-scope contract addresses and code repos for a program."""
    try:
        scope = _scope(slug)
    except RuntimeError as exc:
        typer.echo(f"scope fetch failed: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(f"{slug}: {len(scope['addresses'])} in-scope address(es), {len(scope['repos'])} repo(s)")
    for a in scope["addresses"]:
        typer.echo(f"  {a['chain']:>28}:{a['address']}   ({a['host']})")
    for r in scope["repos"]:
        typer.echo(f"  repo: {r}")
    if json_output:
        typer.echo(json.dumps(scope, indent=2))


@app.command(name="meta")
def show_meta(
    slug: str = typer.Argument(..., help="Immunefi program slug (e.g. 'aera')"),
):
    """Show one program's metadata, including its published audits (the dedup surface)."""
    prog = _program(slug)
    if prog is None:
        typer.echo(f"could not load program: {slug}", err=True)
        raise typer.Exit(1)
    row = _row(prog)
    typer.echo(f"{row['project'] or slug}  ({slug})")
    typer.echo(f"  max bounty    : ${row['max_bounty']:,.0f}")
    typer.echo(f"  launched      : {row['launch_date']}")
    typer.echo(f"  last updated  : {row['updated_date']}")
    typer.echo(f"  network       : {row['network']}")
    typer.echo(f"  primacy       : {row['primacy']}")
    typer.echo(f"  PoC required  : {row['poc']}")
    typer.echo(f"  KYC required  : {row['kyc']}")
    typer.echo(f"  known issues  : {row['known_issues']}")
    typer.echo(f"  audits ({row['audits']}) — findings here are likely ineligible:")
    for a in row["audit_refs"]:
        typer.echo(f"    {a['auditor']}  {a['date']}  {a['url']}")


@app.command(name="triage")
def triage(
    slug: str = typer.Argument(..., help="Immunefi program slug (e.g. 'aera')"),
    max_fetch: int = typer.Option(12, "--max-fetch", help="Max in-scope addresses to fetch+index"),
    timeout: int = typer.Option(200, "--timeout", help="Graph build timeout seconds"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Automated pipeline: scrape scope -> fetch sources -> build graph -> surface.

    Stops at hotspot ranking. Verdict + PoC stay manual.
    """
    from core import deploy_source

    try:
        scope = _scope(slug)
    except RuntimeError as exc:
        typer.echo(f"scope fetch failed: {exc}", err=True)
        raise typer.Exit(1)
    addrs = scope["addresses"][: int(max_fetch)]
    typer.echo(f"{slug}: {len(scope['addresses'])} in-scope address(es), {len(scope['repos'])} repo(s); fetching {len(addrs)}.")
    for r in scope["repos"][:10]:
        typer.echo(f"  repo: {r}")

    out = f".chainsource/immune-{slug}"
    specs = [f"{a['chain']}:{a['address']}" for a in addrs]
    results = deploy_source.fetch_many(specs, base_out=out) if specs else []
    ok = [r for r in results if "error" not in r]
    bad = [r for r in results if "error" in r]
    for r in ok:
        typer.echo(f"  [ok] {r['chain']}:{r['address']} files={r['files']}")
    for r in bad:
        typer.echo(f"  [err] {r.get('spec')}: {r['error']}", err=True)
    if not ok:
        typer.echo("No sources fetched; triage stops here.", err=True)
        raise typer.Exit(1)

    import mcp_server

    db = f"immune-{slug}.db"
    try:
        data = json.loads(mcp_server.cs_build(
            repo_path=out, db=db, lang="solidity",
            include_research=False, timeout_seconds=int(timeout), max_failure_examples=5,
        ))
        typer.echo(
            f"graph: {data['nodes']} nodes, {data['edges']} edges, "
            f"{data['files_indexed']}/{data['files_considered']} files"
        )
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"graph build failed: {exc}", err=True)
        raise typer.Exit(1)

    import subprocess

    subprocess.run(
        [sys.executable, "-m", "cli", "surface", "surface", db, "--top", "25", "--json"],
        check=False, capture_output=True,
    )
    hotspots: list[dict[str, typing.Any]] = []
    try:
        surf = json.loads(Path(f"{Path(db).stem}_surface/hotspots.json").read_text())
        items = surf if isinstance(surf, list) else surf.get("hotspots", surf.get("items", []))
        hotspots = items[:25] if isinstance(items, list) else []
    except Exception:  # noqa: BLE001
        pass
    typer.echo(f"top hotspots ({db}):")
    for h in hotspots[:15]:
        typer.echo(
            f"  {h.get('function', '?')} {h.get('file', '?')}:{h.get('line', '?')} "
            f"score={h.get('score', '?')} [{','.join(h.get('reasons', [])[:4])}]"
        )
    typer.echo(
        "Next: read flagged functions, adjudicate vs program rules and the audit list, "
        "build fork PoC for survivors."
    )
    if json_output:
        typer.echo(json.dumps({"scope": scope, "fetched": len(ok), "errors": len(bad), "hotspots": hotspots}, indent=2))


if __name__ == "__main__":
    app()
