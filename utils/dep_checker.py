"""
AGENT ANONMUSK — Dependency Checker
==================================
Verifies all external tools are installed and reports status.
"""

from __future__ import annotations

import shutil
import logging
from typing import Optional

from rich.console import Console
from rich.table import Table

logger = logging.getLogger("anonmusk_agent.deps")
console = Console()


# ── Required & Optional Tools ────────────────────────────────

TOOLS = {
    # (tool_name, install_hint, required)
    "subfinder": ("go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", False),
    "amass": ("go install -v github.com/owasp-amass/amass/v4/...@master", False),
    "assetfinder": ("go install -v github.com/tomnomnom/assetfinder@latest", False),
    "httpx": ("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", False),
    "nuclei": ("go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", False),
    "waybackurls": ("go install -v github.com/tomnomnom/waybackurls@latest", False),
    "gau": ("go install -v github.com/lc/gau/v2/cmd/gau@latest", False),
    "katana": ("go install -v github.com/projectdiscovery/katana/cmd/katana@latest", False),
    "python": ("https://python.org/downloads/", True),
    "go": ("https://go.dev/dl/", False),
}


def check_tool(name: str) -> bool:
    """Check if a tool is available on PATH or local ./tools directory."""
    if shutil.which(name):
        return True
    
    # Check local tools directory (Windows)
    import sys
    from pathlib import Path
    ext = ".exe" if sys.platform == "win32" else ""
    local_path = Path("./tools") / f"{name}{ext}"
    return local_path.exists()


def check_all_dependencies(verbose: bool = True) -> dict[str, bool]:
    """
    Check all tool dependencies and display status.

    Returns:
        dict of tool_name → is_available
    """
    results = {}

    if verbose:
        table = Table(
            title="🔧 Dependency Check",
            border_style="dim",
            show_header=True,
        )
        table.add_column("Tool", style="cyan", width=15)
        table.add_column("Status", width=12)
        table.add_column("Install Command", style="dim")

    for tool_name, (install_hint, required) in TOOLS.items():
        available = check_tool(tool_name)
        results[tool_name] = available

        if verbose:
            if available:
                status = "[bold green]✓ Found[/]"
            elif required:
                status = "[bold red]✗ MISSING[/]"
            else:
                status = "[yellow]○ Optional[/]"

            table.add_row(tool_name, status, install_hint)

    if verbose:
        console.print(table)

        missing_required = [
            name for name, (_, req) in TOOLS.items()
            if req and not results.get(name, False)
        ]
        if missing_required:
            console.print(
                f"\n[bold red]⚠ Required tools missing:[/] "
                f"{', '.join(missing_required)}"
            )

        available_count = sum(1 for v in results.values() if v)
        console.print(
            f"\n[dim]{available_count}/{len(TOOLS)} tools available[/]"
        )

    return results


def get_tool_path(name: str, config: Optional[dict] = None) -> str:
    """Get the path for a tool, checking config overrides first."""
    if config:
        tools_config = config.get("tools", {})
        if name in tools_config:
            custom = tools_config[name]
            if shutil.which(custom):
                return custom
    return name
