"""
AGENT ANONMUSK — Structured Logger
=================================
Rich console + JSON file logging for scan events, LLM decisions, and findings.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# ── Severity Colors ──────────────────────────────────────────
SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold cyan",
    "info": "bold dim",
}

PHASE_ICONS = {
    "init": "🔧",
    "recon": "👁️",
    "analysis": "🧠",
    "attack": "🤚",
    "validate": "✅",
    "report": "📊",
    "done": "🏁",
    "error": "❌",
}


def setup_logger(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Configure the Agent AnonMusk logger with Rich console and optional file output."""

    logger = logging.getLogger("anonmusk")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    logger.handlers.clear()

    # Rich console handler
    rich_handler = RichHandler(
        console=console,
        show_path=False,
        show_time=True,
        rich_tracebacks=True,
        markup=True,
    )
    rich_handler.setLevel(logging.DEBUG)
    logger.addHandler(rich_handler)

    # File handler (JSON lines)
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(path), encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)

    return logger


class JSONFormatter(logging.Formatter):
    """Formats log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "data"):
            log_entry["data"] = record.data
        return json.dumps(log_entry)


# ── Display Helpers ──────────────────────────────────────────

def print_banner():
    """Print the Agent AnonMusk startup banner."""
    banner = Text()
    banner.append("    ▄▀█ ", style="bold red")
    banner.append("A G E N T   A N O N M U S K\n", style="bold white")
    banner.append("    █▀█ ", style="bold red")
    banner.append("nonMusk Bug Bounty Agent\n", style="dim")
    banner.append("    ─── ", style="dim red")
    banner.append("v1.0.0 │ Recon → Reason → Act", style="dim")

    console.print(Panel(
        banner,
        border_style="red",
        padding=(1, 2),
        title="[bold red]⚡ AGENT ANONMUSK ⚡[/]",
        subtitle="[dim]github.com/royal/anonmusk_agent[/]",
    ))


def print_phase(phase: str, message: str):
    """Print a phase transition."""
    icon = PHASE_ICONS.get(phase, "▸")
    console.print(f"\n{icon} [bold magenta]{phase.upper()}[/] │ {message}")


def print_finding(title: str, severity: str, cvss: float, url: str = ""):
    """Print a finding highlight."""
    style = SEVERITY_STYLES.get(severity, "bold")
    console.print(Panel(
        f"[{style}]{severity.upper()}[/] │ CVSS {cvss:.1f}\n"
        f"[bold]{title}[/]\n"
        f"[dim]{url}[/]",
        border_style="red" if severity in ("critical", "high") else "yellow",
        title="[bold]🔓 FINDING[/]",
    ))


def print_stats(stats: dict[str, Any]):
    """Print scan statistics table."""
    table = Table(title="Scan Statistics", border_style="dim")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Subdomains", str(stats.get("subdomains", 0)))
    table.add_row("Live Hosts", str(stats.get("live_hosts", 0)))
    table.add_row("Endpoints", str(stats.get("endpoints", 0)))
    table.add_row("Findings", str(stats.get("findings", 0)))

    severity = stats.get("severity", {})
    for sev, count in severity.items():
        style = SEVERITY_STYLES.get(sev, "")
        table.add_row(f"  ↳ {sev}", f"[{style}]{count}[/]")

    console.print(table)
