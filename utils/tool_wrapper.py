"""
AGENT ANONMUSK — External Tool Wrapper
=====================================
Cross-platform subprocess wrapper for CLI security tools.
Gracefully degrades when tools are not installed.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import sys
from typing import Optional

logger = logging.getLogger("anonmusk_agent.tools")

IS_WINDOWS = sys.platform == "win32"


class ToolNotFoundError(Exception):
    """Raised when a required external tool is not installed."""
    pass


class ToolWrapper:
    """
    Generic wrapper for external CLI tools (amass, subfinder, nuclei, etc.)

    Features:
    - Cross-platform (Windows cmd / Linux sh)
    - Graceful degradation if tool missing
    - Timeout management
    - Async execution
    """

    def __init__(self, tool_name: str, custom_path: Optional[str] = None):
        self.tool_name = tool_name
        self.tool_path = custom_path or tool_name
        self._available: Optional[bool] = None

    @property
    def is_available(self) -> bool:
        """Check if the tool is installed (PATH or local ./tools directory)."""
        if self._available is None:
            # Check PATH first
            path_found = shutil.which(self.tool_path)
            if path_found:
                self._available = True
                return True
            
            # Check local ./tools directory (Windows)
            local_ext = ".exe" if IS_WINDOWS else ""
            local_path = Path("./tools") / f"{self.tool_path}{local_ext}"
            if local_path.exists():
                self.tool_path = str(local_path.absolute())
                self._available = True
                return True
                
            self._available = False
        return self._available

    def require(self):
        """Raise if tool is not available."""
        if not self.is_available:
            raise ToolNotFoundError(
                f"'{self.tool_name}' is not installed or not on PATH.\n"
                f"Install it and try again."
            )

    async def run(
        self,
        args: list[str],
        input_data: Optional[str] = None,
        timeout: int = 300,
        check: bool = False,
        max_lines: Optional[int] = None,
    ) -> str:
        """
        Run the tool asynchronously and return stdout.
        
        Uses a streaming read loop to support limits and robust cancellation.
        """
        if not self.is_available:
            logger.warning(
                "Tool '%s' not available — returning empty result", self.tool_name
            )
            return ""

        cmd = [self.tool_path] + args
        logger.debug("Running: %s", " ".join(cmd))

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            if input_data:
                process.stdin.write(input_data.encode())
                await process.stdin.drain()
                process.stdin.close()

            lines = []
            line_count = 0
            
            # Use wait_for on the entire reading loop
            async def read_loop():
                nonlocal line_count
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    lines.append(line.decode("utf-8", errors="replace").strip())
                    line_count += 1
                    if max_lines and line_count >= max_lines:
                        logger.info("Tool '%s' reached result limit (%d)", self.tool_name, max_lines)
                        break
                return "\n".join(lines)

            output = await asyncio.wait_for(read_loop(), timeout=timeout)
            
            # Wait for process to exit normally
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()

            if check and process.returncode != 0:
                stderr = (await process.stderr.read()).decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    f"{self.tool_name} exited with code {process.returncode}: {stderr}"
                )

            return output

        except (asyncio.TimeoutError, asyncio.CancelledError) as e:
            msg = "timed out" if isinstance(e, asyncio.TimeoutError) else "was cancelled"
            logger.warning("Tool '%s' %s after %ds", self.tool_name, msg, timeout)
            if process:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
            return "\n".join(lines) if "lines" in locals() else ""

        except Exception as e:
            logger.error("Error executing %s: %s", self.tool_name, e)
            if process:
                try:
                    process.kill()
                except Exception:
                    pass
            return ""

    async def run_lines(
        self,
        args: list[str],
        input_data: Optional[str] = None,
        timeout: int = 300,
        max_lines: Optional[int] = None,
    ) -> list[str]:
        """Run tool and return output as list of non-empty lines."""
        output = await self.run(
            args, 
            input_data=input_data, 
            timeout=timeout, 
            max_lines=max_lines
        )
        if not output:
            return []
        return [line.strip() for line in output.splitlines() if line.strip()]

    async def run_with_pipe(
        self,
        args: list[str],
        pipe_input: list[str],
        timeout: int = 300,
    ) -> list[str]:
        """Run tool with piped input (e.g., list of domains to stdin)."""
        input_data = "\n".join(pipe_input)
        return await self.run_lines(args, input_data=input_data, timeout=timeout)
