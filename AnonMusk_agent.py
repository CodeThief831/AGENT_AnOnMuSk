#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  ⚡ AGENT ANONMUSK — Autonomous Bug Bounty Agent               ║
║  Recon → Reason → Act                                       ║
║                                                              ║
║  ⚠  For authorized security testing only.                   ║
╚══════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv

load_dotenv()


def main():
    """CLI entry point for Agent AnonMusk."""
    parser = argparse.ArgumentParser(
        prog="anonmusk_agent",
        description="⚡ Agent AnonMusk — Autonomous Bug Bounty Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  anonmusk_agent scan -t example.com
  anonmusk_agent scan -t example.com --scope scope.txt --verbose
  anonmusk_agent recon -t example.com --full
  anonmusk_agent deps install
  anonmusk_agent replay output/poc_scripts/sqli_abc123.py
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan ─────────────────────────────────────────────
    scan_parser = subparsers.add_parser(
        "scan", help="Run a full autonomous scan"
    )
    scan_parser.add_argument(
        "-t", "--target", required=True, help="Target domain"
    )
    scan_parser.add_argument(
        "--scope", help="Path to scope file (default: auto-scope to target)"
    )
    scan_parser.add_argument(
        "--config", default="config.yaml", help="Config file path"
    )
    scan_parser.add_argument(
        "-o", "--output", default="./output", help="Output directory"
    )
    scan_parser.add_argument(
        "--llm-provider", default=os.getenv("LLM_PROVIDER", "openai"),
        choices=["openai", "anthropic"],
        help="LLM provider",
    )
    scan_parser.add_argument(
        "--llm-model", default=os.getenv("LLM_MODEL", "gpt-4o"),
        help="LLM model name",
    )
    scan_parser.add_argument(
        "--api-key", default="",
        help="LLM API key (or set via OPENAI_API_KEY / ANTHROPIC_API_KEY env)",
    )
    scan_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )

    # ── recon ────────────────────────────────────────────
    recon_parser = subparsers.add_parser(
        "recon", help="Run reconnaissance only"
    )
    recon_parser.add_argument(
        "-t", "--target", required=True, help="Target domain"
    )
    recon_parser.add_argument(
        "--scope", help="Path to scope file"
    )
    recon_parser.add_argument(
        "-o", "--output", default="./output", help="Output directory"
    )
    recon_parser.add_argument(
        "--full", action="store_true", help="Run full-fledged reconnaissance (mimics ReconFTW)"
    )
    recon_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )

    # ── deps ─────────────────────────────────────────────
    deps_parser = subparsers.add_parser(
        "deps", help="Check or install external tool dependencies"
    )
    deps_parser.add_argument(
        "action", nargs="?", choices=["check", "install"], default="check",
        help="Action to perform (default: check)"
    )

    # ── replay ───────────────────────────────────────────
    replay_parser = subparsers.add_parser(
        "replay", help="Replay a PoC script"
    )
    replay_parser.add_argument(
        "script", help="Path to PoC script"
    )
    replay_parser.add_argument(
        "--proxy", "-p", help="Proxy URL (e.g., http://127.0.0.1:8080)",
    )

    # ── report ───────────────────────────────────────────
    report_parser = subparsers.add_parser(
        "report", help="Generate report from saved scan data"
    )
    report_parser.add_argument(
        "scan_file", help="Path to scan JSON file"
    )
    report_parser.add_argument(
        "-o", "--output", default="./output", help="Output directory"
    )

    # Parse args
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Dispatch
    if args.command == "scan":
        _run_scan(args)
    elif args.command == "recon":
        _run_recon(args)
    elif args.command == "deps":
        _run_deps(args)
    elif args.command == "replay":
        _run_replay(args)
    elif args.command == "report":
        _run_report(args)


def _run_scan(args):
    """Execute a full autonomous scan."""
    from core.orchestrator import Orchestrator

    orch = Orchestrator(
        target=args.target,
        scope_file=args.scope,
        config_path=args.config,
        output_dir=args.output,
        llm_provider=args.llm_provider,
        llm_model=args.llm_model,
        api_key=args.api_key,
        verbose=args.verbose,
        full_recon=getattr(args, "full", False),
    )

    asyncio.run(orch.run())


def _run_recon(args):
    """Run reconnaissance only (no attacks)."""
    from core.orchestrator import Orchestrator
    from core.logger import print_banner, print_stats

    async def recon_only():
        orch = Orchestrator(
            target=args.target,
            scope_file=args.scope,
            output_dir=args.output,
            verbose=args.verbose,
            full_recon=args.full,
        )
        print_banner()

        from core.orchestrator import ScanState
        orch._transition(ScanState.RECON, "Starting reconnaissance...")
        await orch._run_recon()

        print_stats(orch.ctx.stats)
        save_path = orch.ctx.save(args.output)
        print(f"\nScan data saved: {save_path}")

    asyncio.run(recon_only())


def _run_deps(args):
    """Check or install external tool dependencies."""
    from utils.dep_checker import check_all_dependencies
    
    if args.action == "install":
        from utils.install_tools import install_all_tools
        install_all_tools()
        # Re-check after install
        print("\n[bold cyan]Verifying installation...[/]")
        check_all_dependencies(verbose=True)
    else:
        check_all_dependencies(verbose=True)


def _run_replay(args):
    """Replay a PoC script."""
    from burp_mimic.replay import ReplayEngine

    async def replay():
        engine = ReplayEngine()
        result = await engine.replay(
            args.script,
            proxy=getattr(args, "proxy", None),
        )

        if result["success"]:
            print(f"✅ Replay successful\n\n{result['output']}")
        else:
            print(f"❌ Replay failed\n\n{result['error']}")

    asyncio.run(replay())


def _run_report(args):
    """Generate report from saved scan data."""
    from core.context import ScanContext
    from reporting.report_generator import ReportGenerator

    ctx = ScanContext.load(args.scan_file)
    gen = ReportGenerator(output_dir=args.output)
    report = gen.generate(ctx)
    json_path = gen.export_json(ctx)

    print(f"📄 Report: {report}")
    print(f"📋 JSON:   {json_path}")


if __name__ == "__main__":
    main()
