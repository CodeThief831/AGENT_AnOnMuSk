"""
AGENT ANONMUSK — Subdomain Enumerator
=====================================
Wraps subfinder, amass, and assetfinder for comprehensive subdomain discovery.
"""

from __future__ import annotations

import asyncio
import logging

from modules.base import BaseModule
from utils.tool_wrapper import ToolWrapper

logger = logging.getLogger("anonmusk_agent.recon.subdomain")


class SubdomainEnumerator(BaseModule):
    """
    Discovers subdomains using multiple tools and deduplicates results.

    Tools used:
        - subfinder (fast, passive)
        - amass (thorough, slow)
        - assetfinder (quick, broad)
    """

    MODULE_NAME = "subdomain_enum"

    async def run(self) -> None:
        self._log_start("Enumerating subdomains...")

        target = self.ctx.target
        all_subdomains: set[str] = set()
        tools_config = self.config.get("recon", {}).get(
            "subdomain_tools", ["subfinder", "amass", "assetfinder"]
        )
        tool_paths = self.config.get("tools", {})
        
        # Concurrency management
        semaphore = asyncio.Semaphore(3)

        async def run_one(tool_name: str, args: list[str], timeout: int, max_lines: int) -> list[str]:
            async with semaphore:
                tool = ToolWrapper(tool_name, tool_paths.get(tool_name))
                if tool.is_available:
                    logger.info("Running %s on %s", tool_name, target)
                    return await tool.run_lines(
                        args,
                        timeout=timeout,
                        max_lines=max_lines,
                    )
                else:
                    logger.warning("%s not available — skipping", tool_name)
                    return []

        # Define tasks
        tasks = []
        if "subfinder" in tools_config:
            tasks.append(run_one("subfinder", ["-d", target, "-silent"], 300, 5000))
        if "amass" in tools_config:
            tasks.append(run_one("amass", ["enum", "-passive", "-d", target], 600, 5000))
        if "assetfinder" in tools_config:
            tasks.append(run_one("assetfinder", ["--subs-only", target], 300, 5000))

        # Run everything in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Parse results
        for idx, res in enumerate(results):
            if isinstance(res, list):
                all_subdomains.update(res)
            elif isinstance(res, Exception):
                logger.error("A discovery tool failed: %s", res)

        # ── Deduplicate & filter by scope ────────────────
        in_scope = sorted({
            sub.lower().strip()
            for sub in all_subdomains
            if sub.strip() and self.scope.is_in_scope(sub.strip())
        })

        self.ctx.subdomains = in_scope
        self._log_complete(
            f"Found {len(in_scope)} unique in-scope subdomains "
            f"(from {len(all_subdomains)} total)",
            data={"total_raw": len(all_subdomains), "in_scope": len(in_scope)},
        )
