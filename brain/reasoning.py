"""
AGENT ANONMUSK — Reasoning Engine
=================================
The "Brain" — analyzes scan data and decides attack vectors using LLM reasoning.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from brain.llm_client import LLMClient
from core.context import ScanContext

logger = logging.getLogger("AGENT ANONMUSK.brain.reasoning")

# ── Prompt Directory ─────────────────────────────────────────
PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load_prompt(name: str) -> str:
    """Load a prompt template from the prompts directory."""
    path = PROMPTS_DIR / f"{name}.md"
    if path.exists():
        return path.read_text(encoding="utf-8")
    logger.warning("Prompt template not found: %s", name)
    return ""


class ReasoningEngine:
    """
    LLM-driven reasoning engine that analyzes recon data
    and decides the next logical attack vectors.

    Responsibilities:
    1. ANALYZE_RECON — Summarize findings, identify high-value targets
    2. SELECT_ATTACK — Choose attack modules and parameters
    3. EVALUATE_RESPONSE — Determine if a response indicates a vulnerability
    4. GENERATE_PAYLOAD — Craft context-aware payloads (WAF-evasion)
    5. VALIDATE_FINDING — Confirm true positives vs false positives
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        api_key: str = "",
        config: Optional[dict] = None,
    ):
        llm_config = (config or {}).get("llm", {})

        self.client = LLMClient(
            provider=provider or llm_config.get("provider", "openai"),
            model=model or llm_config.get("model", "gpt-4o"),
            api_key=api_key,
            temperature=llm_config.get("temperature", 0.2),
            max_tokens=llm_config.get("max_tokens", 4096),
            retry_attempts=llm_config.get("retry_attempts", 3),
        )

        self.system_prompt = _load_prompt("system") or self._default_system_prompt()

    @staticmethod
    def _default_system_prompt() -> str:
        return """You are AGENT ANONMUSK, an expert security researcher AI assistant.
Your role is to analyze web application scan data and make strategic decisions
about which attack vectors to pursue next.

You operate in a Recon → Reason → Act loop:
1. You receive reconnaissance data (subdomains, endpoints, tech stack)
2. You reason about the most likely vulnerabilities
3. You direct attack modules with specific parameters

Rules:
- Always prioritize high-impact vulnerabilities (BOLA, SQLi, Auth Bypass)
- Consider the tech stack when recommending payloads
- If a WAF is detected, recommend evasion techniques
- Be precise in your attack module selections
- Respond with valid JSON when asked for structured output
"""

    async def analyze_recon(self, ctx: ScanContext) -> list[dict[str, Any]]:
        """
        Analyze recon data and produce an ordered attack plan.

        Returns:
            List of attack directives:
            [
                {
                    "module": "xss",
                    "priority": 1,
                    "params": {"target_urls": [...], "payloads": [...]}
                    "reasoning": "React frontend with reflected params..."
                },
                ...
            ]
        """
        recon_summary = self._build_recon_summary(ctx)
        prompt_template = _load_prompt("attack_selection") or self._default_attack_prompt()

        user_message = prompt_template.replace("{{RECON_DATA}}", recon_summary)

        response = await self.client.chat_json(
            system=self.system_prompt,
            user=user_message,
        )

        # Parse attack plan
        attack_plan = response.get("attack_plan", [])
        if not attack_plan and isinstance(response, dict):
            # Maybe the response IS the plan
            if "module" in response:
                attack_plan = [response]
            elif "attacks" in response:
                attack_plan = response["attacks"]

        # Sort by priority
        attack_plan.sort(key=lambda x: x.get("priority", 99))

        # Log decisions
        ctx.llm_decisions.append({
            "type": "attack_plan",
            "input_summary": {
                "subdomains": len(ctx.subdomains),
                "live_hosts": len(ctx.live_hosts),
                "endpoints": len(ctx.endpoints),
                "tech_stack": ctx.tech_stack.model_dump(),
            },
            "output": attack_plan,
            "model": self.client.model,
        })

        logger.info("LLM proposed %d attack vectors", len(attack_plan))
        return attack_plan

    async def evaluate_response(
        self,
        ctx: ScanContext,
        request_info: dict[str, Any],
        response_info: dict[str, Any],
        attack_type: str,
    ) -> dict[str, Any]:
        """
        Have the LLM evaluate whether an HTTP response indicates a vulnerability.

        Returns:
            {
                "is_vulnerable": bool,
                "confidence": float (0.0 - 1.0),
                "reasoning": str,
                "severity": str,
                "title": str,
            }
        """
        prompt = (
            f"Evaluate this HTTP response for {attack_type} vulnerability.\n\n"
            f"## Request\n"
            f"Method: {request_info.get('method', 'GET')}\n"
            f"URL: {request_info.get('url', '')}\n"
            f"Payload: {request_info.get('payload', '')}\n\n"
            f"## Response\n"
            f"Status: {response_info.get('status', '')}\n"
            f"Headers: {json.dumps(response_info.get('headers', {}), indent=2)}\n"
            f"Body (first 2000 chars):\n{response_info.get('body', '')[:2000]}\n\n"
            f"## Context\n"
            f"Tech Stack: {ctx.tech_stack.model_dump()}\n"
            f"WAF Detected: {ctx.tech_stack.waf or 'None'}\n\n"
            f"Respond with JSON containing: is_vulnerable (bool), confidence (0.0-1.0), "
            f"reasoning (string), severity (critical/high/medium/low/info), title (string)"
        )

        return await self.client.chat_json(
            system=self.system_prompt,
            user=prompt,
        )

    async def generate_payload(
        self,
        ctx: ScanContext,
        attack_type: str,
        context_info: str,
    ) -> list[str]:
        """
        Generate context-aware payloads, considering WAF evasion.

        Returns:
            List of payload strings
        """
        waf = ctx.tech_stack.waf
        prompt = (
            f"Generate {attack_type} payloads for this context:\n"
            f"{context_info}\n\n"
            f"Tech Stack: {ctx.tech_stack.framework or 'Unknown'} / "
            f"{ctx.tech_stack.language or 'Unknown'}\n"
            f"WAF: {waf or 'None detected'}\n\n"
        )

        if waf:
            prompt += (
                f"IMPORTANT: A {waf} WAF is detected. Use evasion techniques:\n"
                f"- Fragmented injection\n"
                f"- Case manipulation\n"
                f"- Hex/Unicode encoding\n"
                f"- Comment insertion\n"
                f"- Double encoding\n\n"
            )

        prompt += (
            "Return a JSON object with key 'payloads' containing a list of "
            "20 payload strings, ordered by likelihood of success."
        )

        response = await self.client.chat_json(
            system=self.system_prompt,
            user=prompt,
        )

        return response.get("payloads", [])

    def _build_recon_summary(self, ctx: ScanContext) -> str:
        """Build a concise recon summary for the LLM."""
        parts = [
            f"# Recon Results for {ctx.target}\n",
            f"## Subdomains ({len(ctx.subdomains)} found)",
        ]

        # Show top 20 subdomains
        for sub in ctx.subdomains[:20]:
            parts.append(f"- {sub}")
        if len(ctx.subdomains) > 20:
            parts.append(f"- ... and {len(ctx.subdomains) - 20} more")

        parts.append(f"\n## Live Hosts ({len(ctx.live_hosts)} found)")
        for host in ctx.live_hosts[:15]:
            parts.append(f"- {host}")

        parts.append(f"\n## Interesting Endpoints")
        interesting = [e for e in ctx.endpoints if e.interesting]
        for ep in interesting[:30]:
            parts.append(f"- {ep.url} (params: {', '.join(ep.params)})")

        parts.append(f"\n## Technology Stack")
        tech = ctx.tech_stack
        parts.append(f"- Server: {tech.server or 'Unknown'}")
        parts.append(f"- Framework: {tech.framework or 'Unknown'}")
        parts.append(f"- Language: {tech.language or 'Unknown'}")
        parts.append(f"- WAF: {tech.waf or 'None detected'}")
        parts.append(f"- Cookies: {', '.join(tech.cookies[:10]) or 'None'}")

        if ctx.js_secrets:
            parts.append(f"\n## JS Secrets Found ({len(ctx.js_secrets)})")
            for secret in ctx.js_secrets[:5]:
                parts.append(f"- [{secret['type']}] in {secret['source']}")

        return "\n".join(parts)

    @staticmethod
    def _default_attack_prompt() -> str:
        return """Based on the reconnaissance data below, create an attack plan.

{{RECON_DATA}}

Analyze the data and produce a JSON attack plan. Consider:
1. **High-value targets**: Endpoints with user_id, account_id, or similar params → test BOLA/IDOR
2. **Input points**: Parameters that accept user input → test XSS, SQLi
3. **Auth endpoints**: Login/register/reset → test username enumeration, session issues
4. **API endpoints**: /api/ routes → test rate limiting, BOLA
5. **Tech-specific**: Framework/language-specific vulnerabilities

Respond with JSON:
{
    "attack_plan": [
        {
            "module": "module_name",
            "priority": 1,
            "params": {
                "target_urls": ["url1", "url2"],
                "parameters": ["param1"],
                "notes": "reason for this test"
            },
            "reasoning": "Why this attack vector"
        }
    ]
}

Available modules: username_enum, session_audit, session_fixation, bola_idor,
xss, sqli, command_injection, rate_limit, api_bola, nuclei
"""
