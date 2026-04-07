"""
Agent AnonMusk — Full Recon Module
==================================
Comprehensive reconnaissance flow incorporating ReconFTW (via WSL) or an
enhanced native multi-tool sequence.
"""

import asyncio
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Optional

from modules.base import BaseModule
from core.context import ScanContext
from core.scope import ScopeValidator

logger = logging.getLogger("anonmusk_agent.recon.full")

class FullReconRunner(BaseModule):
    """
    Implements 'Full Fledged RECON' by wrapping ReconFTW or orchestrating
    a deep multi-tool sequence.
    """

    def __init__(self, ctx: ScanContext, scope: ScopeValidator, config: dict):
        super().__init__(ctx, scope, config)
        # Sanitize target for Windows directory compatibility
        safe_target = ctx.target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_").strip("_")
        self.recon_dir = Path("output") / safe_target / "recon"
        self.recon_dir.mkdir(parents=True, exist_ok=True)

    async def run(self):
        """Execute the full reconnaissance flow."""
        logger.info("Starting Full Fledged RECON for %s", self.ctx.target)

        # 1. Try ReconFTW via WSL
        if await self._try_reconftw_wsl():
            return

        # 2. Fallback: Enhanced Native Recon
        await self._run_enhanced_native_recon()

    async def _try_reconftw_wsl(self) -> bool:
        """Attempt to run ReconFTW via Windows Subsystem for Linux (WSL)."""
        if shutil.which("wsl") is None:
            return False

        # Check if reconftw is installed in WSL
        try:
            check_cmd = ["wsl", "bash", "-c", "command -v reconftw.sh"]
            proc = await asyncio.create_subprocess_exec(
                *check_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                logger.debug("ReconFTW not found in WSL path.")
                return False

            logger.info("ReconFTW detected in WSL! Running full scan...")
            
            # Run reconftw
            # -d: domain, -r: recon, -v: verbose
            run_cmd = ["wsl", "bash", "-c", f"reconftw.sh -d {self.ctx.target} -r"]
            proc = await asyncio.create_subprocess_exec(
                *run_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            
            # We don't wait for completion here if it's too long, but for 'recon' command we should
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                logger.info("ReconFTW scan complete via WSL.")
                # Logic to parse ReconFTW results would go here
                return True
            else:
                logger.warning("ReconFTW failed: %s", stderr.decode())
                return False

        except Exception as e:
            logger.error("Error calling WSL/ReconFTW: %s", e)
            return False

    async def _run_enhanced_native_recon(self):
        """
        Fallback: Run a thorough sequence of native tools with parallel execution where possible.
        """
        logger.info("Running parallelized Enhanced Native Recon...")

        # 1. Parallel Subdomain Discovery
        # subfinder (recursive) + amass (passive)
        subfinder_task = self._run_tool(
            "subfinder",
            ["-d", self.ctx.target, "-all", "-recursive", "-silent"],
            self._parse_subdomains
        )
        amass_task = self._run_tool(
            "amass",
            ["enum", "-passive", "-d", self.ctx.target],
            self._parse_subdomains
        )
        
        await asyncio.gather(subfinder_task, amass_task, return_exceptions=True)

        # 3. Active Probing with httpx (screenshots, tech, status)
        if self.ctx.subdomains:
            # Save subdomains to a temp file
            temp_file = Path("temp_subs.txt")
            temp_file.write_text("\n".join(self.ctx.subdomains))
            
            await self._run_tool(
                "httpx",
                ["-l", "temp_subs.txt", "-sc", "-td", "-ip", "-title", "-silent"],
                self._parse_httpx_results
            )
            
            if temp_file.exists():
                temp_file.unlink()

        # 4. Deep Parameter / Link Discovery
        await self._run_tool(
            "katana",
            ["-u", self.ctx.target, "-d", "5", "-silent"],
            self._parse_endpoints
        )

        logger.info("Enhanced Native Recon complete.")

    async def _run_tool(self, name: str, args: list[str], parser_callback):
        """Helper to run a tool and parse output."""
        try:
            cmd = [name] + args
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                output = stdout.decode().splitlines()
                parser_callback(output)
            else:
                logger.debug("%s failed with code %d: %s", name, proc.returncode, stderr.decode())
        except Exception as e:
            logger.error("Error running %s: %s", name, e)

    def _parse_subdomains(self, lines: list[str]):
        """Callback to parse subdomain discoveries."""
        for line in lines:
            if self.scope.is_in_scope(line):
                self.ctx.add_subdomain(line.strip())

    def _parse_httpx_results(self, lines: list[str]):
        """Callback to parse httpx output (assumes default/silent output format)."""
        # Note: httpx --silent -sc -td output is typically: [url] [status] [tech]
        for line in lines:
            line = line.strip()
            if line:
                # Add to live hosts
                url = line.split()[0]
                self.ctx.add_live_host(url)

    def _parse_endpoints(self, lines: list[str]):
        """Callback to parse link discoveries."""
        for line in lines:
            line = line.strip()
            if line and self.scope.is_in_scope(line):
                self.ctx.add_endpoint(line)
