"""
AGENT ANONMUSK — Base Module
===========================
Abstract base class for all scan modules.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from core.context import ScanContext
from core.scope import ScopeValidator


class BaseModule(ABC):
    """
    Base class for all AGENT ANONMUSK modules.

    Subclasses must implement:
        async run() -> None
    """

    MODULE_NAME: str = "base"

    def __init__(
        self,
        ctx: ScanContext,
        scope: ScopeValidator,
        config: dict,
    ):
        self.ctx = ctx
        self.scope = scope
        self.config = config
        self._attack_params: dict[str, Any] = {}
        self.logger = logging.getLogger(f"anonmusk_agent.{self.MODULE_NAME}")

    def set_attack_params(self, params: dict[str, Any]):
        """Set parameters from LLM-directed attack plan."""
        self._attack_params = params

    @abstractmethod
    async def run(self) -> None:
        """Execute the module's primary function."""
        ...

    def _log_start(self, message: Optional[str] = None):
        """Log module start."""
        msg = message or f"Starting {self.MODULE_NAME}"
        self.logger.info(msg)
        self.ctx.add_event(
            event_type="module_start",
            module=self.MODULE_NAME,
            message=msg,
        )

    def _log_complete(self, message: Optional[str] = None, data: Optional[dict] = None):
        """Log module completion."""
        msg = message or f"Completed {self.MODULE_NAME}"
        self.logger.info(msg)
        self.ctx.add_event(
            event_type="module_complete",
            module=self.MODULE_NAME,
            message=msg,
            data=data,
        )

    def _log_error(self, error: str):
        """Log module error."""
        self.logger.error(error)
        self.ctx.add_event(
            event_type="error",
            module=self.MODULE_NAME,
            message=error,
        )
