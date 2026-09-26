#!/usr/bin/env python3
"""Rank Intigriti bug bounty programs by scope, payout, and hunt intensity.

Usage:
    python -m cli intigriti list --sort bounty
    python -m cli intigriti list --refresh
    python -m cli intigriti list --json
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
import math

import typer

app = typer.Typer()

_CACHE = Path(_PARENT) / ".chainsource" / "intigriti_programs.json"
_TTL = 24 * 3600
_API = "https://app.intigriti.com/api/core/public/programs"


def _fetch_all() -> list[dict[str, typing.Any]]:
    req = urllib.request.Request(
        _API,
        headers={"User-Agent": "Mozilla/5.0 (ChainScope)", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    return data


def _load(refresh: bool = False) -> list[dict[str, typing.Any]]:
    if not refresh and _CACHE.exists() and time.time() - _CACHE.stat().st_mtime < _TTL:
        cached = json.loads(_CACHE.read_text())
        if isinstance(cached, dict):
            return cached.get("programs", [])
        return cached
    programs = _fetch_all()
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"fetched_at": int(time.time()), "programs": programs}
    _CACHE.write_text(json.dumps(payload))
    return programs


def _row(p: dict[str, typing.Any]) -> dict[str, typing.Any]:
    max_bounty = 0.0
    if p.get("maxBounty"):
        val = p["maxBounty"].get("value", 0.0)
        # simplistic conversion (assuming EUR is mostly ~1.05 USD for ranking)
        curr = p["maxBounty"].get("currency", "EUR")
        if curr == "EUR":
            max_bounty = val * 1.05
        elif curr == "GBP":
            max_bounty = val * 1.25
        else:
            max_bounty = val
            
    reports = 0

    return {
        "title": p.get("name", "Unknown"),
        "url": f"https://app.intigriti.com/programs/{p.get('companyHandle', '')}/{p.get('handle', '')}",
        "slug": p.get("handle", ""),
        "rep": None,
        "max_bounty": max_bounty,
        "reports": reports,
        "status": "Active" if p.get("status") in (3, 4) else "Paused", # status 3=Published
        "type": p.get("industry", ""),
        "platform": "Intigriti",
        "sc": False,
        "raw": p,
    }


@app.command(name="list")
def list_programs(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    sort: str = typer.Option("bounty", "--sort", help="Sort by: bounty|type"),
    top: int = typer.Option(20, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    programs = _load(refresh)
    rows = [
        _row(p)
        for p in programs
        if str(p.get("status", "")) in ("3", "4", "3.0") or p.get("status") in (3, 4)
    ]
    rows = [r for r in rows if r["max_bounty"] >= min_bounty]
    
    if sort == "type":
        key = lambda r: r["type"]
    else:
        key = lambda r: r["max_bounty"]

    rows.sort(key=key, reverse=(sort == "bounty"))
    rows = rows[: int(top)]

    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
        
    typer.echo(f"{len(rows)} Intigriti program(s) match (max>={min_bounty:g}):")
    for r in rows:
        typer.echo(
            f"  up to ${r['max_bounty']:>10,.0f}  {r['type']:>12s}  "
            f"{r['title']}  {r['url']}"
        )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


@app.command(name="keizo")
def keizo_rank(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    sort: str = typer.Option("keizo", "--sort", help="Sort by: keizo|bounty"),
    top: int = typer.Option(10, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    programs = _load(refresh)
    now = time.time()
    rows = []
    for p in programs:
        if p.get("status") not in (3, 4):
            continue
            
        row = _row(p)
        if row["max_bounty"] < min_bounty:
            continue
            
        payout = min(1.0, math.log10(1.0 + row["max_bounty"]) / 6.0)
        open_gate = 1.0
        
        updated_at = p.get("lastUpdatedAt") or p.get("createdAt") or now
        age_days = (now - updated_at) / (24 * 3600)
        fresh = max(0.0, 1.0 - (age_days / 365.0))
        
        score = round(0.35 * fresh + 0.35 * payout + 0.30 * open_gate, 3)
        row["keizo"] = score
        row["signals"] = {"fresh": round(fresh, 3), "payout": round(payout, 3), "open_gate": open_gate}
        rows.append(row)

    rows.sort(key=lambda r: r["keizo"] if sort == "keizo" else r["max_bounty"], reverse=True)
    rows = rows[: int(top)]

    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
        
    typer.echo(f"Keizo ranking (Intigriti, max>={min_bounty:g}):")
    for r in rows:
        s = r["signals"]
        typer.echo(
            f"  keizo={r['keizo']:.3f}  up to ${r['max_bounty']:>10,.0f}  "
            f"{r['type']:>12s}  {r['title']}"
        )
        typer.echo(f"      fresh={s['fresh']:.2f} payout={s['payout']:.2f} open_gate={s['open_gate']:.0f}")
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


if __name__ == "__main__":
    app()
