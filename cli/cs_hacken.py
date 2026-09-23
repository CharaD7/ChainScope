#!/usr/bin/env python3
"""Rank HackenProof bug-bounty programs by reputation gate, payout, and report count.

This is the target-selection engine for HackenProof hunting. It pulls the full
program list from the HackenProof dashboard API (423 programs, paginated),
caches it locally, and lets you filter/sort:

    python -m cli hacken list --max-rep 80 --min-bounty 20000 --sort submissions
    python -m cli hacken list --max-rep 80 --min-bounty 20000 --only-sc --json
    python -m cli hacken list --refresh  # force re-fetch (cache TTL is 24h)
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json
import time
import typing
import urllib.request

import typer

app = typer.Typer()

_API = "https://dashboard.hackenproof.com/api/v1/programs?page={page}"
_CACHE = Path(_PARENT) / ".chainsource" / "hacken_programs.json"
_TTL = 24 * 3600


def _fetch_all() -> list[dict[str, typing.Any]]:
    programs: list[dict[str, typing.Any]] = []
    page: int | None = 1
    while page:
        req = urllib.request.Request(
            _API.format(page=page),
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
        programs.extend(data["programs"])
        page = data["next_page"]
    return programs


def _load(refresh: bool = False) -> list[dict[str, typing.Any]]:
    if not refresh and _CACHE.exists() and time.time() - _CACHE.stat().st_mtime < _TTL:
        cached = json.loads(_CACHE.read_text())
        if isinstance(cached, dict):
            return cached["programs"]
        return cached
    programs = _fetch_all()
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"fetched_at": int(time.time()), "programs": programs}
    _CACHE.write_text(json.dumps(payload))
    return programs


def _row(p: dict[str, typing.Any]) -> dict[str, typing.Any]:
    labels = p.get("labels") or {}
    return {
        "title": p["title"],
        "url": f"https://hackenproof.com/programs/{p['slug']}",
        "rep": p["min_reputation_points"],
        "max_bounty": float(p["max_bounty"] or 0),
        "reports": p["submitted_reports"],
        "audit": p["audit_program"],
        "sc": "smart contract" in (labels.get("types") or []),
        "kyc": p["kyc_required"],
        "poc": p["poc_required"],
        "fee": p["submission_cost"],
    }


@app.command(name="list")
def list_programs(
    max_rep: int = typer.Option(80, "--max-rep", help="Max reputation requirement (null = no gate, always included)"),
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    only_sc: bool = typer.Option(False, "--only-sc", help="Only smart-contract scope programs"),
    no_audits: bool = typer.Option(True, "--no-audits/--with-audits", help="Exclude audit contests"),
    sort: str = typer.Option("submissions", "--sort", help="Sort by: submissions|bounty|rep"),
    top: int = typer.Option(20, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    programs = _load(refresh)
    rows = [
        _row(p)
        for p in programs
        if (p["status"] or {}).get("name") == "Active"
        and (p["min_reputation_points"] is None or p["min_reputation_points"] <= max_rep)
        and float(p["max_bounty"] or 0) >= min_bounty
        and (not no_audits or not p["audit_program"])
    ]
    if only_sc:
        rows = [r for r in rows if r["sc"]]
    key = {"submissions": lambda r: r["reports"], "bounty": lambda r: r["max_bounty"], "rep": lambda r: (r["rep"] is None, r["rep"] or 0)}[sort]
    rows.sort(key=key, reverse=(sort == "bounty"))
    rows = rows[: int(top)]

    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
    typer.echo(f"{len(rows)} program(s) match (rep<={max_rep}, max>={min_bounty:g}):")
    for r in rows:
        typer.echo(
            f"  reports={r['reports']:5d}  rep={str(r['rep']):>4s}  up to ${r['max_bounty']:>10,.0f}  "
            f"{'[SC] ' if r['sc'] else ''}{r['title']}  {r['url']}"
        )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


def _keizo_score(p: dict[str, typing.Any], now: float) -> dict[str, typing.Any]:
    """Keizo-style program score from catalog signals.

    Methodology (cf. README `cs_target`): prefer fresh, thin-hunted,
    self-written smart-contract targets with reachable money paths.
    Catalog-level proxies used here (contract-level permissionless-path
    scoring still needs per-program fetch + triage):
      - thin_hunt: fewer submitted reports => less picked-over (0..1)
      - fresh: recently updated program => newer scope/assets (0..1)
      - payout: log-scaled max bounty (0..1)
      - open_gate: no reputation requirement => less competition (0/1)
      - sc: smart-contract scope (0/1)
    """
    import datetime
    import math

    reports = p["submitted_reports"] or 0
    thin_hunt = 1.0 / (1.0 + reports / 100.0)
    try:
        updated = datetime.datetime.strptime(p["updated_at"], "%d %b %Y").timestamp()
        fresh = max(0.0, 1.0 - (now - updated) / (365 * 86400))
    except (ValueError, TypeError):
        fresh = 0.0
    payout = min(1.0, math.log10(1.0 + float(p["max_bounty"] or 0)) / 6.0)
    open_gate = 1.0 if p["min_reputation_points"] is None else 0.0
    labels = p.get("labels") or {}
    sc = 1.0 if "smart contract" in (labels.get("types") or []) else 0.0
    score = round(0.35 * thin_hunt + 0.25 * fresh + 0.20 * payout + 0.10 * open_gate + 0.10 * sc, 3)
    row = _row(p)
    row["keizo"] = score
    row["signals"] = {
        "thin_hunt": round(thin_hunt, 3),
        "fresh": round(fresh, 3),
        "payout": round(payout, 3),
        "open_gate": open_gate,
        "sc": sc,
    }
    return row


@app.command(name="keizo")
def keizo_rank(
    max_rep: int = typer.Option(80, "--max-rep", help="Max reputation requirement (null = no gate, always included)"),
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    only_sc: bool = typer.Option(False, "--only-sc", help="Only smart-contract scope programs"),
    no_audits: bool = typer.Option(True, "--no-audits/--with-audits", help="Exclude audit contests"),
    top: int = typer.Option(15, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Rank HackenProof programs Keizo-style: thin-hunted + fresh + payout + open gate + SC."""
    programs = _load(refresh)
    now = time.time()
    rows = [
        _keizo_score(p, now)
        for p in programs
        if (p["status"] or {}).get("name") == "Active"
        and (p["min_reputation_points"] is None or p["min_reputation_points"] <= max_rep)
        and float(p["max_bounty"] or 0) >= min_bounty
        and (not no_audits or not p["audit_program"])
    ]
    if only_sc:
        rows = [r for r in rows if r["sc"]]
    rows.sort(key=lambda r: r["keizo"], reverse=True)
    rows = rows[: int(top)]

    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
    typer.echo(f"Keizo ranking (rep<={max_rep}, max>={min_bounty:g}):")
    for r in rows:
        s = r["signals"]
        typer.echo(
            f"  keizo={r['keizo']:.3f}  reports={r['reports']:5d}  rep={str(r['rep']):>4s}  "
            f"up to ${r['max_bounty']:>10,.0f}  {'[SC] ' if r['sc'] else ''}{r['title']}"
        )
        typer.echo(
            f"      thin={s['thin_hunt']:.2f} fresh={s['fresh']:.2f} payout={s['payout']:.2f} "
            f"open_gate={s['open_gate']:.0f} sc={s['sc']:.0f}  {r['url']}"
        )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


_EXPLORER_CHAINS = (
    "etherscan.io",
    "basescan.org",
    "arbiscan.io",
    "optimism.",
    "cronoscan.com",
    "explorer.cronos.org",
    "zkevm.cronos.org",
    "polygonscan.com",
    "bscscan.com",
    "snowtrace.io",
    "ftmscan.com",
)

_HOST_CHAINS = {
    "explorer.cronos.com": "25",
    "cronoscan.com": "25",
    "cronos.org": "25",
    "explorer.zkevm.cronos.org": "388",
}


def _hacken_scope(program_url: str, timeout: int = 30) -> dict[str, typing.Any]:
    """Scrape a HackenProof program page for in-scope contract addresses + repos.

    Returns {"addresses": [{"chain": explorer_host, "address": 0x..}], "repos": [github urls]}.
    Explorer host is kept as the Sourcify chain spec (deploy_source resolves it).
    """
    import re

    req = urllib.request.Request(program_url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", "ignore")
    addresses: list[dict[str, str]] = []
    seen: set[str] = set()
    for m in re.finditer(r"https?://([^/\"' ]+)/[^\"' ]*?(?:address|token)/(0x[0-9a-fA-F]{40})", raw):
        host, addr = m.group(1), m.group(2)
        key = addr.lower()
        if key in seen:
            continue
        seen.add(key)
        chain = _HOST_CHAINS.get(host, host)
        addresses.append({"chain": chain, "address": addr})
    repos = sorted(set(re.findall(r"https?://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+", raw)))
    return {"addresses": addresses, "repos": repos}


@app.command(name="triage")
def triage(
    slug: str = typer.Argument(..., help="HackenProof program slug (e.g. 'cronos-smart-contracts')"),
    max_fetch: int = typer.Option(12, "--max-fetch", help="Max deployed addresses to fetch+index"),
    timeout: int = typer.Option(200, "--timeout", help="Graph build timeout seconds"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Automate the manual pipeline: scrape scope -> fetch sources -> build graph -> surface.

    Stops at hotspot ranking + rule-hint pre-filter. Verdict + PoC stay manual.
    """
    from core import deploy_source

    program_url = f"https://hackenproof.com/programs/{slug}"
    scope = _hacken_scope(program_url)
    addrs = scope["addresses"][: int(max_fetch)]
    typer.echo(f"{slug}: {len(scope['addresses'])} in-scope addresses, {len(scope['repos'])} repos; fetching {len(addrs)}.")
    for r in scope["repos"][:10]:
        typer.echo(f"  repo: {r}")

    out = f".chainsource/hacken-{slug}"
    specs = [f"{a['chain']}:{a['address']}" for a in addrs]
    results = deploy_source.fetch_many(specs, base_out=out) if specs else []
    ok = [r for r in results if "error" not in r]
    bad = [r for r in results if "error" in r]
    for r in ok:
        typer.echo(f"  [ok] {r['chain']}:{r['address']} files={r['files']}")
    for r in bad:
        typer.echo(f"  [err] {r['spec']}: {r['error']}", err=True)
    if not ok:
        typer.echo("No sources fetched; triage stops here.", err=True)
        raise typer.Exit(1)

    import mcp_server

    db = f"hacken-{slug}.db"
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
    typer.echo("Next: read flagged functions, adjudicate vs program rules, build fork PoC for survivors.")
    if json_output:
        typer.echo(json.dumps({"scope": scope, "fetched": len(ok), "errors": len(bad), "hotspots": hotspots}, indent=2))


if __name__ == "__main__":
    app()
