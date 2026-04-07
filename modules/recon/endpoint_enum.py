"""
AGENT ANONMUSK — Endpoint Enumerator
====================================
Discovers endpoints from waybackurls, gau, katana, and identifies interesting patterns.
"""

from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urlparse, parse_qs

from core.context import Endpoint
from modules.base import BaseModule
from utils.tool_wrapper import ToolWrapper

logger = logging.getLogger("anonmusk_agent.recon.endpoint")

# Patterns that indicate interesting/exploitable parameters
INTERESTING_PARAMS = re.compile(
    r"(?:id|user_?id|account_?id|org_?id|file|path|url|redirect|next|return|"
    r"callback|cmd|exec|query|search|page|template|include|load|read|fetch|"
    r"action|type|name|email|token|key|secret|password|admin|debug)",
    re.IGNORECASE,
)


class EndpointEnumerator(BaseModule):
    """
    Enumerates endpoints from historical sources and live crawling.

    Tools: waybackurls, gau, katana
    """

    MODULE_NAME = "endpoint_enum"

    async def run(self) -> None:
        self._log_start("Enumerating endpoints...")

        target = self.ctx.target
        all_urls: set[str] = set()
        tool_paths = self.config.get("tools", {})
        endpoint_tools = self.config.get("recon", {}).get(
            "endpoint_tools", ["waybackurls", "gau", "katana"]
        )
        
        # Concurrency management
        semaphore = asyncio.Semaphore(3)

        async def run_one(tool_name: str, args: list[str], input_data: str = None, timeout: int = 600, max_lines: int = None) -> list[str]:
            async with semaphore:
                tool = ToolWrapper(tool_name, tool_paths.get(tool_name))
                if tool.is_available:
                    logger.info("Running %s on %s", tool_name, target if not input_data else "live hosts")
                    return await tool.run_lines(
                        args,
                        input_data=input_data,
                        timeout=timeout,
                        max_lines=max_lines,
                    )
                return []

        # 1. Start historical discovery in parallel
        hist_tasks = []
        if "waybackurls" in endpoint_tools:
            hist_tasks.append(run_one("waybackurls", [], input_data=target, max_lines=10000))
        if "gau" in endpoint_tools:
            hist_tasks.append(run_one("gau", [target, "--subs"], max_lines=10000))
            
        hist_results = await asyncio.gather(*hist_tasks, return_exceptions=True)
        for res in hist_results:
            if isinstance(res, list):
                all_urls.update(res)

        # 2. Run katana in parallel across live hosts
        if "katana" in endpoint_tools and self.ctx.live_hosts:
            logger.info("Running parallel katana crawler...")
            katana_tasks = []
            for host in self.ctx.live_hosts[:5]:  # top 5 hosts
                katana_tasks.append(run_one("katana", ["-u", host, "-silent", "-d", "3"]))
            
            katana_results = await asyncio.gather(*katana_tasks, return_exceptions=True)
            for res in katana_results:
                if isinstance(res, list):
                    all_urls.update(res)

        # ── Parse & classify ─────────────────────────────
        endpoints: list[Endpoint] = []
        seen: set[str] = set()

        for url in all_urls:
            url = url.strip()
            if not url or url in seen:
                continue
            if not self.scope.is_in_scope(url):
                continue

            seen.add(url)

            # Extract params
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())

            # Check if any param is interesting
            interesting = any(
                INTERESTING_PARAMS.search(p) for p in params
            )

            endpoints.append(Endpoint(
                url=url,
                method="GET",
                params=params,
                source="endpoint_enum",
                interesting=interesting,
            ))

        # Sort: interesting endpoints first
        endpoints.sort(key=lambda e: (not e.interesting, e.url))
        self.ctx.endpoints = endpoints

        interesting_count = sum(1 for e in endpoints if e.interesting)
        self._log_complete(
            f"Found {len(endpoints)} endpoints ({interesting_count} interesting)",
            data={
                "total": len(endpoints),
                "interesting": interesting_count,
                "sources": len(all_urls),
            },
        )
