"""
AGENT ANONMUSK — API BOLA Logic
================================
Maps API object IDs and tests unauthorized enumeration.
"""

from __future__ import annotations

import json
import logging
import re

from core.context import Evidence, Finding, Severity, VulnType
from modules.base import BaseModule
from utils.http_client import HTTPClient

logger = logging.getLogger("AGENT ANONMUSK.api.bola")


class APIBOLALogic(BaseModule):
    """
    API-level Broken Object-Level Authorization testing.

    1. Discover API endpoints that return object IDs
    2. Extract IDs from responses
    3. Try accessing other objects with those IDs
    4. Compare responses to detect unauthorized access
    """

    MODULE_NAME = "api_bola"

    async def run(self) -> None:
        self._log_start("Testing API-level BOLA...")

        target_urls = self._attack_params.get("target_urls", [])
        if not target_urls:
            # Find API endpoints
            target_urls = [
                ep.url for ep in self.ctx.endpoints
                if "/api/" in ep.url.lower() or "/v1/" in ep.url.lower()
                or "/v2/" in ep.url.lower()
            ]

        if not target_urls:
            self._log_complete("No API endpoints found")
            return

        scan_config = self.config.get("scanning", {})
        async with HTTPClient(
            scope=self.scope,
            rate_limit=scan_config.get("rate_limit", 5),
            timeout=scan_config.get("request_timeout", 15),
        ) as client:
            # Step 1: Map object IDs from responses
            id_map = await self._map_object_ids(client, target_urls)

            # Step 2: Test cross-object access
            for url, ids in id_map.items():
                await self._test_cross_access(client, url, ids)

        self._log_complete("API BOLA testing complete")

    async def _map_object_ids(
        self, client: HTTPClient, urls: list[str]
    ) -> dict[str, list[str]]:
        """Extract object IDs from API responses."""
        id_map: dict[str, list[str]] = {}

        for url in urls[:10]:
            try:
                resp, _ = await client.get(url)
                if resp.status_code != 200:
                    continue

                # Try to parse JSON response
                try:
                    data = resp.json()
                    ids = self._extract_ids_from_json(data)
                    if ids:
                        id_map[url] = ids
                        logger.debug("Found %d IDs from %s", len(ids), url)
                except (json.JSONDecodeError, ValueError):
                    pass

            except Exception as e:
                logger.debug("Failed to map IDs from %s: %s", url, e)

        return id_map

    def _extract_ids_from_json(
        self, data, depth: int = 0, max_depth: int = 5
    ) -> list[str]:
        """Recursively extract potential object IDs from JSON data."""
        if depth > max_depth:
            return []

        ids = []
        id_keys = ["id", "user_id", "account_id", "org_id", "project_id",
                    "team_id", "document_id", "order_id", "invoice_id"]

        if isinstance(data, dict):
            for key, value in data.items():
                if key.lower() in id_keys and isinstance(value, (str, int)):
                    ids.append(str(value))
                elif isinstance(value, (dict, list)):
                    ids.extend(self._extract_ids_from_json(value, depth + 1))

        elif isinstance(data, list):
            for item in data[:10]:  # Limit to 10 items
                ids.extend(self._extract_ids_from_json(item, depth + 1))

        return list(set(ids))

    async def _test_cross_access(
        self, client: HTTPClient, base_url: str, ids: list[str]
    ):
        """Test if objects can be accessed with different IDs."""
        if len(ids) < 2:
            return

        # Try to access the URL with each alternative ID
        id_pattern = re.compile(r'/(\d+)(?:/|$|\?)')
        match = id_pattern.search(base_url)

        if not match:
            return

        original_id = match.group(1)

        for test_id in ids:
            if test_id == original_id:
                continue

            test_url = base_url.replace(f"/{original_id}", f"/{test_id}")

            try:
                resp, evidence = await client.get(test_url)

                if resp.status_code == 200 and len(resp.text) > 50:
                    finding = Finding(
                        title=f"API BOLA at {base_url}",
                        vuln_type=VulnType.BOLA,
                        severity=Severity.HIGH,
                        description=(
                            f"API Broken Object-Level Authorization detected. "
                            f"Object ID '{test_id}' accessible without proper "
                            f"authorization checks."
                        ),
                        evidence=[evidence],
                        confidence=0.8,
                        target_url=base_url,
                        parameter="id",
                        payload=test_id,
                        remediation=(
                            "Verify object ownership in every API handler. "
                            "Use middleware that checks if the authenticated "
                            "user is authorized to access the requested resource."
                        ),
                    )
                    self.ctx.add_finding(finding)
                    logger.warning("🔓 API BOLA: %s", test_url)
                    return

            except Exception as e:
                logger.debug("API BOLA test failed: %s", e)
