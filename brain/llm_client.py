"""
AGENT ANONMUSK — LLM Client
===========================
Unified interface for OpenAI and Anthropic APIs with retry logic,
structured output parsing, and cost tracking.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional

logger = logging.getLogger("AGENT ANONMUSK.brain.llm")


class LLMClient:
    """
    Unified LLM client supporting OpenAI and Anthropic.

    Usage:
        client = LLMClient(provider="openai", model="gpt-4o", api_key="...")
        response = await client.chat(
            system="You are a security researcher.",
            user="Analyze these endpoints for vulnerabilities.",
        )
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        api_key: str = "",
        temperature: float = 0.2,
        max_tokens: int = 4096,
        retry_attempts: int = 3,
        retry_delay: float = 2.0,
    ):
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key or self._get_api_key()
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay

        # Token usage tracking
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_requests = 0
        self.total_cost = 0.0

        self._client = None

    def _get_api_key(self) -> str:
        """Get API key from environment."""
        if self.provider == "openai":
            return os.getenv("OPENAI_API_KEY", "")
        elif self.provider == "anthropic":
            return os.getenv("ANTHROPIC_API_KEY", "")
        return ""

    async def _ensure_client(self):
        """Lazy-initialize the provider client."""
        if self._client is not None:
            return

        if self.provider == "openai":
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=self.api_key)
        elif self.provider == "anthropic":
            import anthropic
            self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
        else:
            raise ValueError(f"Unknown LLM provider: {self.provider}")

    async def chat(
        self,
        system: str,
        user: str,
        json_mode: bool = False,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Send a chat message and return the response text.

        Args:
            system: System prompt
            user: User message
            json_mode: Request JSON output format
            temperature: Override default temperature

        Returns:
            Response text from the LLM
        """
        await self._ensure_client()
        temp = temperature if temperature is not None else self.temperature

        for attempt in range(self.retry_attempts):
            try:
                if self.provider == "openai":
                    return await self._chat_openai(system, user, temp, json_mode)
                elif self.provider == "anthropic":
                    return await self._chat_anthropic(system, user, temp, json_mode)
            except Exception as e:
                logger.warning(
                    "LLM request failed (attempt %d/%d): %s",
                    attempt + 1, self.retry_attempts, e,
                )
                if attempt < self.retry_attempts - 1:
                    delay = self.retry_delay * (2 ** attempt)
                    logger.debug("Retrying in %.1fs...", delay)
                    import asyncio
                    await asyncio.sleep(delay)
                else:
                    logger.error("LLM request failed after %d attempts", self.retry_attempts)
                    raise

        return ""

    async def chat_json(
        self,
        system: str,
        user: str,
        temperature: Optional[float] = None,
    ) -> dict[str, Any]:
        """Send a chat message and parse the response as JSON."""
        response = await self.chat(
            system=system,
            user=user,
            json_mode=True,
            temperature=temperature,
        )

        # Try to extract JSON from the response
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to find JSON block in response
            json_match = _extract_json(response)
            if json_match:
                return json.loads(json_match)
            logger.warning("Failed to parse LLM response as JSON")
            return {"raw_response": response}

    async def _chat_openai(
        self, system: str, user: str, temperature: float, json_mode: bool
    ) -> str:
        """OpenAI API call."""
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": self.max_tokens,
        }

        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = await self._client.chat.completions.create(**kwargs)

        # Track usage
        usage = response.usage
        if usage:
            self.total_input_tokens += usage.prompt_tokens
            self.total_output_tokens += usage.completion_tokens
            self.total_requests += 1
            self._estimate_cost(usage.prompt_tokens, usage.completion_tokens)

        return response.choices[0].message.content or ""

    async def _chat_anthropic(
        self, system: str, user: str, temperature: float, json_mode: bool
    ) -> str:
        """Anthropic API call."""
        user_content = user
        if json_mode:
            user_content += "\n\nRespond with valid JSON only."

        response = await self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=temperature,
            system=system,
            messages=[{"role": "user", "content": user_content}],
        )

        # Track usage
        usage = response.usage
        if usage:
            self.total_input_tokens += usage.input_tokens
            self.total_output_tokens += usage.output_tokens
            self.total_requests += 1
            self._estimate_cost(usage.input_tokens, usage.output_tokens)

        return response.content[0].text if response.content else ""

    def _estimate_cost(self, input_tokens: int, output_tokens: int):
        """Rough cost estimation based on model."""
        # Approximate pricing per 1M tokens (as of mid-2025)
        pricing = {
            "gpt-4o": (5.0, 15.0),
            "gpt-4o-mini": (0.15, 0.6),
            "gpt-4-turbo": (10.0, 30.0),
            "claude-sonnet-4-20250514": (3.0, 15.0),
            "claude-3-5-sonnet-20241022": (3.0, 15.0),
            "claude-3-haiku-20240307": (0.25, 1.25),
        }

        rate = pricing.get(self.model, (5.0, 15.0))
        cost = (input_tokens * rate[0] + output_tokens * rate[1]) / 1_000_000
        self.total_cost += cost

    @property
    def usage_summary(self) -> dict[str, Any]:
        """Get token usage summary."""
        return {
            "provider": self.provider,
            "model": self.model,
            "total_requests": self.total_requests,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "estimated_cost_usd": round(self.total_cost, 4),
        }


def _extract_json(text: str) -> Optional[str]:
    """Try to extract a JSON object or array from text."""
    # Look for ```json blocks
    import re
    json_block = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
    if json_block:
        return json_block.group(1).strip()

    # Look for raw { ... } or [ ... ]
    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start = text.find(start_char)
        if start == -1:
            continue
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == start_char:
                depth += 1
            elif ch == end_char:
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
    return None
