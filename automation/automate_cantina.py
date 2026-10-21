#!/usr/bin/env python3
"""Automation script for ChainScope Cantina analysis.

Features:
- Accepts a `--chain` argument to select the blockchain network.
- Runs the ChainScope CLI tools `cs_veck`, `cs_sweep`, and `cs_audit` sequentially.
- After the sweep step, detects raw `ecrecover` hits in the output and records them.
- Generates a comprehensive Markdown report with timestamps, command logs, and any ecrecover findings.
- Designed to live under the `automation/` directory of the ChainScope repository without modifying existing source files.
"""

import argparse
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str], cwd: Path | None = None) -> str:
    """Run a command and return its stdout (stderr is merged).
    Raises subprocess.CalledProcessError on failure.
    """
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )
    return result.stdout

def write_report(report_path: Path, sections: dict[str, str]):
    """Write a markdown report from a mapping of headings to content."""
    with report_path.open("w", encoding="utf-8") as f:
        f.write(f"# ChainScope Cantina Automation Report\n\n")
        f.write(f"Generated: {datetime.utcnow().isoformat()}Z\n\n")
        for heading, body in sections.items():
            f.write(f"## {heading}\n\n")
            f.write(body)
            f.write("\n\n")

# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Run ChainScope automation for Cantina programs.")
    parser.add_argument(
        "--chain",
        default="mainnet",
        help="Blockchain network identifier (e.g., mainnet, goerli, arbitrum).",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]  # ChainScope repo root
    automation_dir = Path(__file__).resolve().parent
    report_path = automation_dir / f"cantina_report_{args.chain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"

    sections = {}
    sections["Configuration"] = f"- Chain: `{args.chain}`\n- Repository root: `{repo_root}`"

    # 1. Build graph (if needed – placeholder command)
    try:
        sections["Graph Construction"] = "Running graph construction..."
        graph_cmd = ["python", "-m", "chain_scope_cli.build_graph", "--chain", args.chain]
        graph_output = run_cmd(graph_cmd, cwd=repo_root)
        sections["Graph Construction"] = f"```
{graph_output}
```"
    except Exception as e:
        sections["Graph Construction"] = f"**Error:** {e}"
        write_report(report_path, sections)
        sys.exit(1)

    # 2. Run cs_veck
    try:
        sections["cs_veck"] = "Executing `cs_veck`..."
        veck_cmd = ["cs_veck", "--chain", args.chain]
        veck_output = run_cmd(veck_cmd, cwd=repo_root)
        sections["cs_veck"] = f"```
{veck_output}
```"
    except Exception as e:
        sections["cs_veck"] = f"**Error:** {e}"
        write_report(report_path, sections)
        sys.exit(1)

    # 3. Run cs_sweep and capture output for ecrecover detection
    ecrecover_hits = []
    try:
        sections["cs_sweep"] = "Executing `cs_sweep`..."
        sweep_cmd = ["cs_sweep", "--chain", args.chain]
        sweep_output = run_cmd(sweep_cmd, cwd=repo_root)
        sections["cs_sweep"] = f"```
{sweep_output}
```"
        # Detect raw ecrecover hits (simple heuristic)
        for line in sweep_output.splitlines():
            if "ecrecover" in line.lower():
                ecrecover_hits.append(line.strip())
    except Exception as e:
        sections["cs_sweep"] = f"**Error:** {e}"
        write_report(report_path, sections)
        sys.exit(1)

    # 4. Run cs_audit
    try:
        sections["cs_audit"] = "Executing `cs_audit`..."
        audit_cmd = ["cs_audit", "--chain", args.chain]
        audit_output = run_cmd(audit_cmd, cwd=repo_root)
        sections["cs_audit"] = f"```
{audit_output}
```"
    except Exception as e:
        sections["cs_audit"] = f"**Error:** {e}"
        write_report(report_path, sections)
        sys.exit(1)

    # 5. Summarize ecrecover findings
    if ecrecover_hits:
        hits_md = "\n".join([f"- `{hit}`" for hit in ecrecover_hits])
        sections["ecrecover Findings"] = f"The sweep output contained raw `ecrecover` calls:\n\n{hits_md}"
    else:
        sections["ecrecover Findings"] = "No raw `ecrecover` calls detected in sweep output."

    # Write the final report
    write_report(report_path, sections)
    print(f"Report written to {report_path}")

if __name__ == "__main__":
    main()
