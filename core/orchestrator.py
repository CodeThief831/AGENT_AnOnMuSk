"""
AGENT ANONMUSK — Orchestrator (State Machine)
============================================
The master controller that drives the Recon → Reason → Act loop.
"""

from __future__ import annotations

import asyncio
import logging
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml
from rich.console import Console

from core.context import ScanContext
from core.logger import print_banner, print_phase, print_stats, print_finding, setup_logger
from core.scope import ScopeValidator
from core.task_queue import AsyncTaskQueue

console = Console()
logger = logging.getLogger("anonmusk_agent.orchestrator")


class ScanState(str, Enum):
    INIT = "init"
    RECON = "recon"
    ANALYSIS = "analysis"
    ATTACK = "attack"
    VALIDATE = "validate"
    REPORT = "report"
    DONE = "done"
    ERROR = "error"


class Orchestrator:
    """
    The AGENT ANONMUSK state machine.

    Flow:
        INIT → RECON → ANALYSIS → ATTACK → VALIDATE → REPORT → DONE
                 ↑        ↓          ↑         ↓
                 └── (Brain decides) ─┘── (loop) ─┘

    Usage:
        orch = Orchestrator(target="example.com", scope_file="scope.txt")
        await orch.run()
    """

    def __init__(
        self,
        target: str,
        scope_file: Optional[str] = None,
        config_path: str = "config.yaml",
        output_dir: str = "./output",
        llm_provider: str = "openai",
        llm_model: str = "gpt-4o",
        api_key: str = "",
        verbose: bool = False,
        full_recon: bool = False,
    ):
        self.state = ScanState.INIT
        self.target = target
        self.output_dir = output_dir
        self.verbose = verbose
        self.full_recon = full_recon

        # Load configuration
        self.config = self._load_config(config_path)

        # Initialize scope validator
        if scope_file:
            self.scope = ScopeValidator.from_file(scope_file)
        else:
            self.scope = ScopeValidator.from_target(target)

        # Initialize scan context
        self.ctx = ScanContext(
            target=target,
            scope_domains=self.scope.include_patterns,
            scope_excludes=self.scope.exclude_patterns,
        )

        # LLM config
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.api_key = api_key

        # Task queue
        self.queue = AsyncTaskQueue(
            max_concurrent=self.config.get("general", {}).get(
                "max_concurrent_tasks", 10
            )
        )

        # Module references (lazy-loaded)
        self._recon_modules: dict[str, Any] = {}
        self._attack_modules: dict[str, Any] = {}
        self._brain = None
        self._reporter = None
        self._mimic = None

        # Logger
        log_level = "DEBUG" if verbose else self.config.get(
            "general", {}
        ).get("log_level", "INFO")
        log_file = str(Path(output_dir) / "anonmusk_agent.log")
        setup_logger(log_level=log_level, log_file=log_file)

    @staticmethod
    def _load_config(config_path: str) -> dict:
        """Load YAML configuration, return defaults if file missing."""
        path = Path(config_path)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        logger.warning("Config file not found: %s — using defaults", config_path)
        return {}

    def _transition(self, new_state: ScanState, message: str = ""):
        """Transition to a new state."""
        old = self.state
        self.state = new_state
        self.ctx.current_phase = new_state.value
        msg = message or f"{old.value} → {new_state.value}"
        print_phase(new_state.value, msg)
        self.ctx.add_event(
            event_type="state_transition",
            module="orchestrator",
            message=msg,
            data={"from": old.value, "to": new_state.value},
        )

    async def run(self):
        """Execute the full scan pipeline."""
        print_banner()
        console.print(
            f"\n[bold cyan]Target:[/] {self.target}"
            f"\n[bold cyan]Scope:[/] {self.scope}"
            f"\n[bold cyan]Output:[/] {self.output_dir}\n"
        )

        try:
            # Validate scope
            self.scope.validate_or_raise(self.target)

            # ── Phase 1: RECON ──
            self._transition(ScanState.RECON, "Starting reconnaissance...")
            await self._run_recon()

            # ── Phase 2: ANALYSIS ──
            self._transition(ScanState.ANALYSIS, "LLM analyzing recon data...")
            await self._run_analysis()

            # ── Phase 3: ATTACK ──
            self._transition(ScanState.ATTACK, "Executing attack vectors...")
            await self._run_attacks()

            # ── Phase 4: VALIDATE ──
            self._transition(ScanState.VALIDATE, "Validating findings...")
            await self._run_validation()

            # ── Phase 5: REPORT ──
            self._transition(ScanState.REPORT, "Generating reports...")
            await self._run_report()

            # ── DONE ──
            self._transition(ScanState.DONE, "Scan complete!")
            print_stats(self.ctx.stats)

        except ValueError as e:
            self._transition(ScanState.ERROR, str(e))
            logger.error("Scope violation: %s", e)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]⚠ Scan interrupted by user[/]")
            self.state = ScanState.ERROR
        except Exception as e:
            self._transition(ScanState.ERROR, f"Fatal: {e}")
            logger.exception("Unhandled error in orchestrator")
        finally:
            # Always save context
            save_path = self.ctx.save(self.output_dir)
            console.print(f"\n[dim]Scan data saved: {save_path}[/]")

    # ── Phase Implementations ────────────────────────────────

    async def _run_recon(self):
        """Execute all reconnaissance modules."""
        from modules.recon.subdomain import SubdomainEnumerator
        from modules.recon.live_check import LiveChecker
        from modules.recon.endpoint_enum import EndpointEnumerator
        from modules.recon.js_analyzer import JSAnalyzer
        from modules.recon.tech_fingerprint import TechFingerprinter

        # Subdomain enumeration
        sub_enum = SubdomainEnumerator(self.ctx, self.scope, self.config)
        await sub_enum.run()

        # Live host checking
        live_check = LiveChecker(self.ctx, self.scope, self.config)
        await live_check.run()

        # Endpoint enumeration
        ep_enum = EndpointEnumerator(self.ctx, self.scope, self.config)
        await ep_enum.run()

        # JS Analysis
        js_analyzer = JSAnalyzer(self.ctx, self.scope, self.config)
        await js_analyzer.run()

        # Tech fingerprinting
        fingerprinter = TechFingerprinter(self.ctx, self.scope, self.config)
        await fingerprinter.run()

        # Run Full RECON if requested
        if self.full_recon:
            from modules.recon.full_recon import FullReconRunner
            full_recon = FullReconRunner(self.ctx, self.scope, self.config)
            await full_recon.run()

        logger.info(
            "Recon complete — %d subdomains, %d live, %d endpoints",
            len(self.ctx.subdomains),
            len(self.ctx.live_hosts),
            len(self.ctx.endpoints),
        )

    async def _run_analysis(self):
        """LLM analyzes recon data and decides attack vectors."""
        from brain.reasoning import ReasoningEngine

        self._brain = ReasoningEngine(
            provider=self.llm_provider,
            model=self.llm_model,
            api_key=self.api_key,
            config=self.config,
        )

        attack_plan = await self._brain.analyze_recon(self.ctx)
        self.ctx.attack_queue = attack_plan
        self.ctx.add_event(
            event_type="analysis",
            module="brain",
            message=f"LLM proposed {len(attack_plan)} attack vectors",
            data={"attack_plan": attack_plan},
        )

    async def _run_attacks(self):
        """Execute LLM-directed attack vectors."""
        from modules.auth.username_enum import UsernameEnumerator
        from modules.auth.session_audit import SessionAuditor
        from modules.auth.session_fixation import SessionFixationTester
        from modules.injection.bola_idor import BOLADetector
        from modules.injection.xss_engine import XSSEngine
        from modules.injection.sqli_engine import SQLiEngine
        from modules.injection.command_injection import CommandInjectionEngine
        from modules.api.rate_limiter import RateLimitTester
        from modules.api.bola_logic import APIBOLALogic
        from modules.nuclei.runner import NucleiRunner

        # Module registry
        modules = {
            "username_enum": UsernameEnumerator,
            "session_audit": SessionAuditor,
            "session_fixation": SessionFixationTester,
            "bola_idor": BOLADetector,
            "xss": XSSEngine,
            "sqli": SQLiEngine,
            "command_injection": CommandInjectionEngine,
            "rate_limit": RateLimitTester,
            "api_bola": APIBOLALogic,
            "nuclei": NucleiRunner,
        }

        for attack in self.ctx.attack_queue:
            module_name = attack.get("module", "")
            module_class = modules.get(module_name)

            if not module_class:
                logger.warning("Unknown attack module: %s", module_name)
                continue

            try:
                instance = module_class(self.ctx, self.scope, self.config)
                instance.set_attack_params(attack.get("params", {}))
                await instance.run()
            except Exception as e:
                logger.error("Module %s failed: %s", module_name, e)
                self.ctx.add_event(
                    event_type="error",
                    module=module_name,
                    message=str(e),
                )

        # Always run Nuclei as a baseline
        nuclei_cfg = self.config.get("nuclei", {})
        if nuclei_cfg.get("enabled", True):
            try:
                nuclei = NucleiRunner(self.ctx, self.scope, self.config)
                await nuclei.run()
            except Exception as e:
                logger.error("Nuclei scan failed: %s", e)

    async def _run_validation(self):
        """Validate findings — generate PoC scripts and re-verify."""
        from burp_mimic.generator import BurpMimicGenerator

        self._mimic = BurpMimicGenerator(
            output_dir=str(Path(self.output_dir) / "poc_scripts"),
        )

        for finding in self.ctx.findings:
            if finding.evidence:
                script_path = self._mimic.generate(finding)
                finding.poc_script_path = script_path
                logger.info("PoC generated: %s", script_path)

                # Print finding
                print_finding(
                    finding.title,
                    finding.severity.value,
                    finding.cvss_score,
                    finding.target_url,
                )

    async def _run_report(self):
        """Generate final reports."""
        from reporting.report_generator import ReportGenerator

        self._reporter = ReportGenerator(
            output_dir=self.output_dir,
            config=self.config,
        )

        report_path = self._reporter.generate(self.ctx)
        logger.info("Report generated: %s", report_path)

        # JSON export
        json_path = self._reporter.export_json(self.ctx)
        logger.info("JSON export: %s", json_path)

        console.print(f"\n[bold green]📄 Report:[/] {report_path}")
        console.print(f"[bold green]📋 JSON:[/]   {json_path}")
