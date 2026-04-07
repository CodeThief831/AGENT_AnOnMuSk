"""
AGENT ANONMUSK — PoC Replay Engine
==================================
Re-executes generated PoC scripts to verify findings are still reproducible.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

logger = logging.getLogger("AGENT ANONMUSK.burp_mimic.replay")


class ReplayEngine:
    """
    Replays PoC scripts to verify finding reproducibility.

    Usage:
        engine = ReplayEngine()
        result = await engine.replay("output/poc_scripts/sqli_abc123.py")
    """

    async def replay(
        self,
        script_path: str,
        proxy: str | None = None,
        timeout: int = 60,
    ) -> dict:
        """
        Execute a PoC script and capture its output.

        Args:
            script_path: Path to the PoC Python script
            proxy: Optional proxy URL (e.g., http://127.0.0.1:8080)
            timeout: Max execution time in seconds

        Returns:
            {"success": bool, "output": str, "error": str}
        """
        path = Path(script_path)
        if not path.exists():
            return {"success": False, "output": "", "error": f"Script not found: {script_path}"}

        cmd = ["python", str(path)]
        if proxy:
            cmd.extend(["--proxy", proxy])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )

            output = stdout.decode("utf-8", errors="replace")
            errors = stderr.decode("utf-8", errors="replace")

            success = process.returncode == 0

            logger.info(
                "Replay %s: %s",
                script_path,
                "SUCCESS" if success else "FAILED",
            )

            return {
                "success": success,
                "output": output,
                "error": errors,
                "return_code": process.returncode,
            }

        except asyncio.TimeoutError:
            logger.warning("Replay timed out: %s", script_path)
            return {
                "success": False,
                "output": "",
                "error": f"Script timed out after {timeout}s",
            }

        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
            }

    async def replay_all(
        self,
        poc_dir: str,
        proxy: str | None = None,
    ) -> list[dict]:
        """Replay all PoC scripts in a directory."""
        results = []
        poc_path = Path(poc_dir)

        if not poc_path.exists():
            return results

        scripts = sorted(poc_path.glob("*.py"))
        logger.info("Replaying %d PoC scripts from %s", len(scripts), poc_dir)

        for script in scripts:
            result = await self.replay(str(script), proxy=proxy)
            result["script"] = str(script)
            results.append(result)

        successes = sum(1 for r in results if r["success"])
        logger.info("Replay complete: %d/%d passed", successes, len(results))

        return results
