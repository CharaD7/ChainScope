#!/usr/bin/env python3
"""Common utilities shared by platform‑specific automation scripts.

This module abstracts the repetitive parts of the Cantina automation workflow:
* Running a subprocess and capturing its output
* Writing a markdown report
* Detecting raw `ecrecover` calls in sweep output

Each platform script imports :func:`run_pipeline` and supplies:
* ``repo_root`` – the directory that contains the fetched source code for the program.
* ``chain`` – blockchain/network identifier (default ``mainnet``).
* ``report_path`` – where the generated markdown file should be written.
"""

import subprocess
from datetime import datetime
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Low‑level helpers
# ---------------------------------------------------------------------------

def run_cmd(cmd: List[str], cwd: Path | None = None) -> str:
    """Execute *cmd* and return its combined stdout/stderr.

    Raises ``subprocess.CalledProcessError`` on non‑zero exit status.
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

def write_report(report_path: Path, sections: dict[str, str]) -> None:
    """Create a markdown report from *sections*.

    ``sections`` maps a heading (without the ``##``) to the body text.
    """
    with report_path.open("w", encoding="utf-8") as f:
        f.write("# ChainScope Automation Report\n\n")
        f.write(f"Generated: {datetime.utcnow().isoformat()}Z\n\n")
        for heading, body in sections.items():
            f.write(f"## {heading}\n\n")
            f.write(body)
            f.write("\n\n")

def detect_ecrecover(sweep_output: str) -> List[str]:
    """Return a list of lines from *sweep_output* that mention ``ecrecover``.
    Simple case‑insensitive substring search is sufficient for the current use‑case.
    """
    hits = []
    for line in sweep_output.splitlines():
        if "ecrecover" in line.lower():
            hits.append(line.strip())
    return hits

# ---------------------------------------------------------------------------
# High‑level pipeline
# ---------------------------------------------------------------------------

def run_pipeline(repo_root: Path, chain: str, report_path: Path) -> None:
    """Execute the full ChainScope analysis pipeline and write a markdown report.

    Steps performed:
    1. (Optional) graph construction – placeholder for future use.
    2. ``cs_veck``
    3. ``cs_sweep`` (captured for ecrecover detection)
    4. ``cs_audit``
    5. Assemble the markdown report.
    """
    sections: dict[str, str] = {}
    sections["Configuration"] = f"- Chain: `{chain}`\n- Repository root: `{repo_root}`"

    # 1. Graph construction – ChainScope historically provides a CLI tool, but it is optional.
    try:
        graph_cmd = ["python", "-m", "chain_scope_cli.build_graph", "--chain", chain]
        graph_out = run_cmd(graph_cmd, cwd=repo_root)
        sections["Graph Construction"] = f"```
{graph_out}
```"
    except Exception as e:
        sections["Graph Construction"] = f"**Error:** {e}"
        write_report(report_path, sections)
        raise

    # 2. cs_veck
    try:
        veck_cmd = ["cs_veck", "--chain", chain]
        veck_out = run_cmd(veck_cmd, cwd=repo_root)
        sections["cs_veck"] = f"```
{veck_out}
```"
    except Exception as e:
        sections["cs_veck"] = f"**Error:** {e}"
        write_report(report_path, sections)
        raise

    # 3. cs_sweep – capture output for ecrecover detection
    try:
        sweep_cmd = ["cs_sweep", "--chain", chain]
        sweep_out = run_cmd(sweep_cmd, cwd=repo_root)
        sections["cs_sweep"] = f"```
{sweep_out}
```"
        ecrecover_hits = detect_ecrecover(sweep_out)
    except Exception as e:
        sections["cs_sweep"] = f"**Error:** {e}"
        write_report(report_path, sections)
        raise

    # 4. cs_audit
    try:
        audit_cmd = ["cs_audit", "--chain", chain]
        audit_out = run_cmd(audit_cmd, cwd=repo_root)
        sections["cs_audit"] = f"```
{audit_out}
```"
    except Exception as e:
        sections["cs_audit"] = f"**Error:** {e}"
        write_report(report_path, sections)
        raise

    # 5. ecrecover summary
    if ecrecover_hits:
        hits_md = "\n".join([f"- `{hit}`" for hit in ecrecover_hits])
        sections["ecrecover Findings"] = f"The sweep output contained raw `ecrecover` calls:\n\n{hits_md}"
    else:
        sections["ecrecover Findings"] = "No raw `ecrecover` calls detected in sweep output."

    # Write final report
    write_report(report_path, sections)

# ---------------------------------------------------------------------------
# Convenience entry‑point for direct execution (debugging)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run the generic ChainScope pipeline on a given repo.")
    parser.add_argument("repo_root", type=Path, help="Path to the program source directory")
    parser.add_argument("--chain", default="mainnet", help="Chain identifier")
    parser.add_argument("--out", type=Path, default=None, help="Optional custom report path")
    args = parser.parse_args()
    out_path = args.out or (Path(args.repo_root) / f"report_{args.chain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md")
    run_pipeline(Path(args.repo_root), args.chain, out_path)
    print(f"Report written to {out_path}")
