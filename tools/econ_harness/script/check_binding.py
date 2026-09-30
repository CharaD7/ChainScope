"""Prove `core/cs_econ.py` agrees with the EVM, then fail loudly if it stops doing so.

The Python models are exact only for the maths they are given. Nothing in them
establishes that those maths are the maths a real vault actually runs. This closes
that gap against ground truth we control: `NaiveVault` (known vulnerable) and
`OffsetVault` (known safe) in the same Foundry project, which execute the same
attack sequence the model prices.

Run `forge test -vv` first, or let this invoke it. Every field is compared, and a
mismatch is fatal - a model that has drifted from EVM execution will report a
confident wrong number for a real vault, which is the failure mode this whole
module exists to prevent.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
REPO = HARNESS.parent.parent          # ChainScope
sys.path.insert(0, str(REPO))

from core.cs_econ import (  # noqa: E402
    erc4626_naive,
    erc4626_virtual,
    donation_attack,
)
from core.cs_econ import (  # noqa: E402
    _assets_naive as _assets_naive,
    _assets_virtual as _assets_virtual,
)

W = 10 ** 18

# label -> (shares model, assets model, seed, donation, victim_deposit)
CASES = {
    "naive_tiny":  (erc4626_naive, _assets_naive, 1, 100 * W, W),
    "naive_equal": (erc4626_naive, _assets_naive, W, 100 * W, W),
    "offset_tiny": (erc4626_virtual, _assets_virtual, 1, 100 * W, W),
}

FIELDS = ("victim_shares", "attacker_out", "profit", "victim_loss")

# the harness emits `profit`; the model's key is `attacker_profit`
MODEL_KEY = {
    "victim_shares": "victim_shares",
    "attacker_out": "attacker_out",
    "profit": "attacker_profit",
    "victim_loss": "victim_loss",
}

_LINE = re.compile(r"MODEL\s+(\S+)\s+(\S+)\s*:\s*(-?\d+)")


def run_forge() -> str:
    proc = subprocess.run(
        ["forge", "test", "-vv"],
        cwd=HARNESS, capture_output=True, text=True, timeout=900,
        env={**__import__("os").environ, "PATH": f"{Path.home()}/.foundry/bin:"
              + __import__("os").environ.get("PATH", "")},
    )
    if "Suite result: ok" not in proc.stdout:
        print(proc.stdout[-3000:], file=sys.stderr)
        raise SystemExit("forge tests did not pass; fix the harness before trusting the model")
    return proc.stdout


def main() -> int:
    observed = {label: {} for label in CASES}
    for label, field, value in _LINE.findall(run_forge()):
        if label in observed and field in FIELDS:
            observed[label][field] = int(value)

    failures: list[str] = []
    print(f"{'case':<14}{'field':<16}{'evm':>24}{'model':>24}  result")
    print("-" * 80)

    for label, (model, red_model, seed, donation, victim) in CASES.items():
        got = observed.get(label, {})
        if not got:
            failures.append(f"{label}: no EVM numbers captured from forge output")
            continue
        predicted = donation_attack(model, convert_to_assets=red_model, attacker_deposit=seed,
                                    donation=donation, victim_deposit=victim)
        for field in FIELDS:
            model_value = predicted[MODEL_KEY[field]]
            evm_value = got.get(field)
            if evm_value is None:
                failures.append(f"{label}.{field}: missing from forge output")
                continue
            ok = evm_value == model_value
            print(f"{label:<13}{field:<15}{evm_value:>22,}{model_value:>22,}  {'ok' if ok else 'MISMATCH'}")
            if not ok:
                failures.append(f"{label}.{field}: evm={evm_value} model={model_value}")

    print()
    if failures:
        print(f"{len(failures)} mismatch(es) between core/cs_econ.py and EVM execution:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("core/cs_econ.py matches EVM execution on every field of every case.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())