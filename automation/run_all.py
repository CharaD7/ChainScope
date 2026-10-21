#!/usr/bin/env python3
"""Master driver to run ChainScope automation for all supported platforms.

Usage examples:
    python automation/run_all.py --platform all
    python automation/run_all.py --platform immunefi --chain goerli
    python automation/run_all.py --platform hacken --out my_report.md
"""

import argparse
from pathlib import Path
from importlib import import_module
from datetime import datetime

# Mapping from platform name to the corresponding module (relative to this package)
_PLATFORM_MODULES = {
    "immunefi": "automation.automate_immune",
    "hacken": "automation.automate_hacken",
    "cantina": "automation.automate_cantina",
    "bugcrowd": "automation.automate_bugcrowd",
    "sherlock": "automation.automate_sherlock",
    "intigriti": "automation.automate_intigriti",
    "google": "automation.automate_google",
}

def main() -> None:
    parser = argparse.ArgumentParser(description="Run ChainScope automation across platforms.")
    parser.add_argument(
        "--platform",
        default="all",
        help="Platform to run (all, immunefi, hacken, cantina, bugcrowd, sherlock, intigriti, google)",
    )
    parser.add_argument("--chain", default="mainnet", help="Chain identifier passed to each wrapper")
    parser.add_argument("--out-dir", type=Path, default=None, help="Directory to place generated reports (default: automation folder)")
    args = parser.parse_args()

    selected = args.platform.lower()
    if selected != "all" and selected not in _PLATFORM_MODULES:
        raise SystemExit(f"Unknown platform: {selected}")

    platforms = [_PLATFORM_MODULES[selected]] if selected != "all" else list(_PLATFORM_MODULES.values())

    for mod_path in platforms:
        mod = import_module(mod_path)
        # Build a temporary args list for the wrapper's main()
        wrapper_args = ["--chain", args.chain]
        if args.out_dir:
            # Compute a platform‑specific filename inside the out dir
            platform_name = mod_path.split(".")[-1].replace("automate_", "")
            out_path = args.out_dir / f"{platform_name}_report_{args.chain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
            wrapper_args.extend(["--out", str(out_path)])
        # Simulate command‑line arguments for the module
        import sys
        old_argv = sys.argv
        sys.argv = [mod_path] + wrapper_args
        try:
            mod.main()
        finally:
            sys.argv = old_argv

if __name__ == "__main__":
    main()
