#!/usr/bin/env python3
"""Cantina bug bounty platform module.

Cantina exposes a public API at https://api.cantina.xyz/api/v0/opportunities
that lists all bug bounty programs with their scope, payouts, and status.

Usage:
    python -m cli cantina list --min-bounty 20000 --top 20
    python -m cli cantina triage f9df94db-c7b1-434b-bb06-d1360abdd1be --max-fetch 10
"""

from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import json
import math
import os
import re
import time
import typing
import urllib.error
import urllib.request

import typer

app = typer.Typer()

_API_BASE = "https://api.cantina.xyz/api/v0"
_OPPORTUNITIES = f"{_API_BASE}/opportunities"
_CACHE = Path(_PARENT) / ".chainsource" / "cantina_programs.json"
_TTL = 24 * 3600
_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
_RETRY = 4


def _get(url: str, timeout: int = 45) -> str:
    """GET request with retries and proper headers."""
    last: Exception | None = None
    for attempt in range(_RETRY):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": _UA, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "ignore")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"failed to fetch {url}: {last}")


def _money(text: typing.Any) -> float:
    """Parse a dollar amount string into a float."""
    if text is None:
        return 0.0
    if isinstance(text, (int, float)):
        return float(text)
    s = str(text).replace(",", "").replace("$", "")
    nums = re.findall(r"\d+(?:\.\d+)?", s)
    return float(nums[-1]) if nums else 0.0


def _get_org_repos(org_name: str) -> list[str]:
    """Fetch all public repos from a GitHub org."""
    repos = []
    page = 1
    while True:
        url = f"https://api.github.com/orgs/{org_name}/repos?per_page=100&page={page}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))
        except Exception:
            break
        if not data:
            break
        for r in data:
            repos.append(f"https://github.com/{r['full_name']}")
        page += 1
    return repos


def _row(e: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """Normalize a Cantina program record into a common row dict."""
    company = e.get("company") or {}
    slug = e.get("id") or ""
    return {
        "slug": slug,
        "project": e.get("name") or slug,
        "tagline": e.get("tagline"),
        "url": e.get("url") or f"https://cantina.xyz/code/{slug}",
        "brief_url": e.get("url") or f"https://cantina.xyz/code/{slug}",
        "max_bounty": float(e.get("totalRewardPot") or 0.0),
        "min_bounty": _money(e.get("submissionFee") or 0),
        "scope_rank": None,
        "access": e.get("status"),
        "industry": "web3",
        "reward_summary": f"{e.get('currencyCode','USDC')} up to ${_money(e.get('totalRewardPot')):,.0f}",
        "rep_req": None,
        "fee": _money(e.get("submissionFee") or 0),
        "reports": None,
        "audit_status": "unknown",
        "poc": None,
        "company": company.get("name"),
        "github": company.get("github"),
        "website": company.get("website"),
        "twitter": company.get("twitter"),
    }


def _load(refresh: bool = False) -> list[dict[str, typing.Any]]:
    """Load Cantina program catalog from API."""
    cached: list[dict[str, typing.Any]] = []
    fresh = False
    if _CACHE.exists():
        try:
            payload = json.loads(_CACHE.read_text())
            cached = payload.get("programs", [])
            fresh = (time.time() - _CACHE.stat().st_mtime) < _TTL
        except (json.JSONDecodeError, OSError):
            cached = []
    if not refresh and fresh and cached:
        return cached

    raw = _get(_OPPORTUNITIES, timeout=60)
    data = json.loads(raw)
    items = data.get("items", [])

    out: list[dict[str, typing.Any]] = []
    for item in items:
        try:
            prog = _row(item)
            out.append(prog)
        except Exception as exc:
            typer.echo(f"  [err] {item.get('id', '?')}: {exc}", err=True)

    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    _CACHE.write_text(
        json.dumps({"fetched_at": int(time.time()), "programs": out}, indent=2)
    )
    return out


@app.command(name="list")
def list_programs(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    top: int = typer.Option(20, "--top", help="How many to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List public Cantina programs."""
    rows = [p for p in _load(refresh) if p["max_bounty"] >= min_bounty]
    rows.sort(key=lambda p: p["max_bounty"], reverse=True)
    rows = rows[: int(top)]
    if not rows:
        typer.echo("No programs matched.", err=True)
        raise typer.Exit(1)
    if not json_output:
        typer.echo(f"{len(rows)} Cantina program(s):")
        for p in rows:
            fee = f" fee=\${p['fee']:,.0f}" if p["fee"] else " free"
            typer.echo(
                f"  ${p['max_bounty']:>10,.0f}  {fee:<15} {str(p['project'] or '')[:44]}"
            )
            typer.echo(f"    {p['url']}")
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


@app.command(name="meta")
def show_meta(
    slug: str = typer.Argument(..., help="Program slug/id, e.g. 'f9df94db-c7b1-434b-bb06-d1360abdd1be'"),
):
    """One program: bounty, scope repos, and metadata."""
    hit = next((p for p in _load() if p["slug"] == slug), None)
    if hit is None:
        typer.echo(f"not in public catalog: {slug}", err=True)
        raise typer.Exit(1)
    typer.echo(f"{hit['project']} ({slug})")
    typer.echo(f"  max bounty : ${hit['max_bounty']:,.0f}")
    typer.echo(f"  industry     : {hit['industry']}")
    typer.echo(f"  fee          : ${hit['fee']:,.0f}")
    typer.echo(f"  url          : {hit['url']}")
    typer.echo(f"  company      : {hit['company']}")
    typer.echo(f"  github       : {hit['github']}")
    typer.echo(f"  website      : {hit['website']}")


@app.command(name="scope")
def show_scope(
    slug: str = typer.Argument(..., help="Program slug/id"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show in-scope repos from the Cantina program page."""
    # Cantina lists repos in the program page metadata
    hit = next((p for p in _load() if p["slug"] == slug), None)
    if hit is None:
        typer.echo(f"not in public catalog: {slug}", err=True)
        raise typer.Exit(1)
    repos = []
    if hit.get("github"):
        repos.append(f"https://github.com/{hit['github']}")
    typer.echo(f"{slug}: {len(scope['repos'])} repo(s)")
    for r in repos:
        typer.echo(f"  repo: {r}")
    if json_output:
        typer.echo(
            json.dumps(
                {"slug": slug, "addresses": [], "repos": repos}, indent=2
            )
        )


@app.command(name="triage")
def triage(
    slug: str = typer.Argument(..., help="Program slug/id"),
    max_fetch: int = typer.Option(10, "--max-fetch", help="Max repos to clone+analyze"),
    timeout: int = typer.Option(300, "--timeout", help="Graph build timeout seconds"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Automated pipeline: clone repos -> build graph -> surface hotspots."""
    import subprocess
    from core import deploy_source

    hit = next((p for p in _load() if p["slug"] == slug), None)
    if hit is None:
        typer.echo(f"not in public catalog: {slug}", err=True)
        raise typer.Exit(1)

    # Build list of repos to analyze
    repos = []
    if hit.get("github"):
        github = hit["github"]
        if "/" in github:
            # Full repo path like "Uniswap/v3-core"
            repos.append(f"https://github.com/{github}")
        else:
            # Org name like "base" - fetch all repos from that org
            org_repos = _get_org_repos(github)
            repos.extend(org_repos)

    if not repos:
        typer.echo("No repos found; triage stops here.", err=True)
        raise typer.Exit(1)

    typer.echo(f"{slug}: {len(repos)} repo(s); cloning {min(len(repos), max_fetch)}.")

    out = f".chainsource/hacken-{slug}"
    import os
    os.makedirs(out, exist_ok=True)

    cloned_repos = []
    for repo_url in repos[: int(max_fetch)]:
        repo_name = repo_url.rstrip("/").split("/")[-1]
        repo_path = os.path.join(out, "repos", repo_name)
        if not os.path.exists(repo_path):
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", repo_url, repo_path],
                    check=True, capture_output=True, timeout=120,
                )
                typer.echo(f"  [cloned] {repo_url}")
            except subprocess.CalledProcessError as exc:
                typer.echo(f"  [err] clone failed for {repo_url}: {exc}", err=True)
                continue
            except subprocess.TimeoutExpired:
                typer.echo(f"  [err] clone timeout for {repo_url}", err=True)
                continue
        cloned_repos.append(repo_path)

    if not cloned_repos:
        typer.echo("No repos cloned; triage stops here.", err=True)
        raise typer.Exit(1)

    import mcp_server

    # Clone repos into a combined build directory
    import shutil as _shutil
    build_dir = os.path.join(out, "all_sources")
    os.makedirs(build_dir, exist_ok=True)

    def _copy_tree(src: str, dst_root: str):
        for root, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d != ".git"]
            for f in files:
                sf = os.path.join(root, f)
                rel = os.path.relpath(sf, src)
                df = os.path.join(dst_root, rel)
                os.makedirs(os.path.dirname(df), exist_ok=True)
                _shutil.copy2(sf, df)

    for rp in cloned_repos:
        _copy_tree(rp, build_dir)

    db = f"cantina-{slug}.db"
    try:
        data = json.loads(mcp_server.cs_build(
            repo_path=build_dir, db=db, lang="solidity",
            include_research=False, timeout_seconds=int(timeout), max_failure_examples=5,
        ))
        typer.echo(
            f"graph: {data['nodes']} nodes, {data['edges']} edges, "
            f"{data['files_indexed']}/{data['files_considered']} files"
        )
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"graph build failed: {exc}", err=True)
        raise typer.Exit(1)

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
        "Next: read flagged functions, adjudicate vs program rules, build fork PoC for survivors."
    )
    if json_output:
        typer.echo(
            json.dumps(
                {"scope": {"repos": cloned_repos}, "cloned_repos": len(cloned_repos), "hotspots": hotspots},
                indent=2,
            )
        )


if __name__ == "__main__":
    app()
