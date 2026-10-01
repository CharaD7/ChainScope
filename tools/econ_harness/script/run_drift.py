"""Run the rounding-drift attack across a list of real vaults on forks.

Unlike the fixture binding there is nothing to compare against: a live vault's
conversion functions cannot be faithfully reimplemented in Python without reading
its source, so the fork result is the answer. What this reports per vault is
whether the attack could run at all - a vault with a withdrawal cap or a minimum
deposit cannot be cycled, and that is reported as unprobeable rather than
cleared.

Usage:
    python3 run_drift.py --vaults 0xA 0xB [--asset 0xTOKEN] [--cycles 20]
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
REPO = HARNESS.parent.parent
sys.path.insert(0, str(REPO))

from core.cs_rpc import load_dotenv, rpc_for  # noqa: E402

FOUNDRY = Path.home() / ".foundry/bin"
DEFAULT_RPC = "https://ethereum.publicnode.com"
_LOG = re.compile(r"DRIFT_(\S+)\s+(\S+)\s*:\s*(-?\d+)")


def _env() -> dict[str, str]:
    return {**os.environ, "PATH": f"{FOUNDRY}:{os.environ.get('PATH', '')}"}


def latest_block() -> int:
    out = subprocess.run(["cast", "block-number", "--rpc-url", os.environ.get("ALCHEMY_MAINNET", DEFAULT_RPC)],
                         capture_output=True, text=True, timeout=120, env=_env())
    try:
        return int(out.stdout.strip())
    except ValueError:
        return 0


def run(vault: str, asset: str, block: int, cycles: int, test: str) -> tuple[dict, str]:
    env = _env()
    env.update({"TARGET_VAULT": vault, "FORK_BLOCK": str(block),
                "RPC_URL": os.environ.get("ALCHEMY_MAINNET", DEFAULT_RPC),
                "CYCLES": str(cycles)})
    if asset:
        env["TARGET_ASSET"] = asset
    combined = ""
    parsed: dict[str, int] = {}
    # one retry: the authenticated endpoint intermittently times out mid-sweep and
    # an empty result reads as "no drift" when it means "never ran"
    for attempt in range(2):
        p = subprocess.run(["forge", "test", "--match-contract", "RoundingDriftTest",
                            "--match-test", test, "-vv"],
                           cwd=HARNESS, capture_output=True, text=True, timeout=1800, env=env)
        combined = p.stdout + p.stderr
        parsed = dict((f, int(v)) for _t, f, v in _LOG.findall(combined))
        if parsed:
            break
    return parsed, combined


def verdict(d: dict) -> tuple[str, str]:
    if not d:
        return "RPC-FAILED", "no output from two attempts; this is an endpoint failure, not a result"
    done = d.get("cycles_done", 0)
    net = d.get("net", 0)
    stopped = d.get("stopped", 0)
    if done == 0:
        return "UNPROBEABLE", "vault blocked the first cycle (cap, minimum deposit, or no redeem)"
    if net < 0:
        return "DRIFT FOUND", f"depositor lost {-net:,} over {done} cycles"
    return "NO DRIFT", f"depositor net +{net:,} over {done} cycles (vault_delta {d.get('vault_delta',0):,})"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vaults", nargs="+", required=True)
    ap.add_argument("--asset", default="")
    ap.add_argument("--cycles", type=int, default=20)
    ap.add_argument("--block", type=int, default=0)
    args = ap.parse_args()

    load_dotenv()
    block = args.block or latest_block()
    print(f"fork block: {block}   cycles: {args.cycles}")
    print(f"{'vault':<44}{'cycles':>7}{'net':>22}  verdict")
    print("-" * 100)

    summary: dict[str, str] = {}
    for v in args.vaults:
        for test, label in (("test_drift_large", "large"), ("test_drift_small", "small")):
            d, _ = run(v, args.asset, block, args.cycles, test)
            if not d and label == "small":
                break
            verdict_s, note = verdict(d)
            print(f"{v + ' [' + label + ']':<44}{d.get('cycles_done', 0):>7}"
                  f"{d.get('net', 0):>22,}  {verdict_s} - {note}")
            if verdict_s == "DRIFT FOUND":
                summary[v] = verdict_s
    print()
    print(f"{len(summary)} vault(s) with depositor loss across cycles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
