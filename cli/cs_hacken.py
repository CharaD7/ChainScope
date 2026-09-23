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


if __name__ == "__main__":
    app()
