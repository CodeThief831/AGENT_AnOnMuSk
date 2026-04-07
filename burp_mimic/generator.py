"""
AGENT ANONMUSK — Burp Suite Mimic Script Generator
===================================================
Generates standalone Python PoC scripts that mimic Burp Suite Repeater requests.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, BaseLoader

from core.context import Finding

logger = logging.getLogger("AGENT ANONMUSK.burp_mimic")

# ── Jinja2 Templates ────────────────────────────────────────

REPEATER_TEMPLATE = '''#!/usr/bin/env python3
"""
┌──────────────────────────────────────────────────────────────┐
│  AGENT ANONMUSK — Proof of Concept Script                       │
│  Generated: {{ generated_at }}                               │
│                                                              │
│  Finding: {{ finding.title }}                                │
│  Severity: {{ finding.severity.value | upper }}              │
│  CVSS: {{ finding.cvss_score }}                              │
│                                                              │
│  ⚠  AUTHORIZED TESTING ONLY                                 │
│  This script is for authorized security testing.             │
│  Unauthorized use is illegal and unethical.                  │
└──────────────────────────────────────────────────────────────┘
"""

import sys
import argparse

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Install requests: pip install requests")
    sys.exit(1)


def exploit(proxy=None, verify_ssl=False):
    """Replay the detected vulnerability."""

    url = "{{ evidence.request_url }}"

    headers = {{ headers_json }}

    {% if evidence.request_body %}
    data = """{{ evidence.request_body }}"""
    {% endif %}

    proxies = {"http": proxy, "https": proxy} if proxy else None

    print(f"[*] Target: {url}")
    print(f"[*] Method: {{ evidence.request_method or 'GET' }}")
    {% if finding.payload %}
    print(f"[*] Payload: {{ finding.payload }}")
    {% endif %}
    print()

    try:
        response = requests.{{ (evidence.request_method or 'GET') | lower }}(
            url,
            headers=headers,
            {% if evidence.request_body %}
            data=data,
            {% endif %}
            proxies=proxies,
            verify=verify_ssl,
            timeout=30,
        )

        print(f"[+] Status: {response.status_code}")
        print(f"[+] Length: {len(response.text)}")
        print(f"[+] Time: {response.elapsed.total_seconds():.2f}s")
        print()

        # Response headers
        print("── Response Headers ──")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")
        print()

        # Response body (first 2000 chars)
        print("── Response Body ──")
        print(response.text[:2000])

        {% if finding.vuln_type.value == 'sqli' %}
        # SQLi indicators
        sql_errors = ["sql syntax", "mysql", "postgresql", "oracle", "sqlite"]
        for indicator in sql_errors:
            if indicator in response.text.lower():
                print(f"\\n[!] SQL Error indicator found: '{indicator}'")
        {% endif %}

        {% if finding.vuln_type.value == 'xss' %}
        # XSS reflection check
        payload = "{{ finding.payload }}"
        if payload in response.text:
            print(f"\\n[!] XSS payload reflected in response!")
        {% endif %}

        return response

    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AGENT ANONMUSK PoC — {{ finding.title }}",
    )
    parser.add_argument(
        "--proxy", "-p",
        help="Proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)",
        default=None,
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates",
    )

    args = parser.parse_args()
    exploit(proxy=args.proxy, verify_ssl=args.verify_ssl)
'''

INTRUDER_TEMPLATE = '''#!/usr/bin/env python3
"""
┌──────────────────────────────────────────────────────────────┐
│  AGENT ANONMUSK — Intruder-Style Fuzzing Script                 │
│  Generated: {{ generated_at }}                               │
│                                                              │
│  Target: {{ evidence.request_url }}                          │
│  Parameter: {{ finding.parameter }}                          │
│                                                              │
│  ⚠  AUTHORIZED TESTING ONLY                                 │
└──────────────────────────────────────────────────────────────┘
"""

import sys
import time

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Install requests: pip install requests")
    sys.exit(1)


PAYLOADS = {{ payloads_json }}


def fuzz(proxy=None, delay=0.5):
    """Fuzz the parameter with multiple payloads."""

    url = "{{ evidence.request_url }}"
    param = "{{ finding.parameter }}"

    print(f"[*] Target: {url}")
    print(f"[*] Parameter: {param}")
    print(f"[*] Payloads: {len(PAYLOADS)}")
    print()

    proxies = {"http": proxy, "https": proxy} if proxy else None
    results = []

    for i, payload in enumerate(PAYLOADS, 1):
        try:
            params = {param: payload}
            response = requests.get(
                url,
                params=params,
                proxies=proxies,
                verify=False,
                timeout=30,
            )

            status = response.status_code
            length = len(response.text)
            elapsed = response.elapsed.total_seconds()

            indicator = "🔥" if status == 200 and length > 100 else "  "
            print(
                f"  {indicator} [{i:03d}] Status:{status} "
                f"Length:{length:>6} Time:{elapsed:.2f}s "
                f"Payload: {payload[:50]}"
            )

            results.append({
                "payload": payload,
                "status": status,
                "length": length,
                "time": elapsed,
            })

            time.sleep(delay)

        except Exception as e:
            print(f"  ❌ [{i:03d}] Error: {e}")

    # Summary
    print(f"\\n── Summary ──")
    print(f"Total: {len(results)} requests")
    unique_statuses = set(r["status"] for r in results)
    print(f"Status codes: {unique_statuses}")

    # Flag anomalies
    if results:
        avg_length = sum(r["length"] for r in results) / len(results)
        anomalies = [
            r for r in results
            if abs(r["length"] - avg_length) > avg_length * 0.3
        ]
        if anomalies:
            print(f"\\n[!] {len(anomalies)} anomalous responses detected:")
            for a in anomalies:
                print(f"    Payload: {a['payload'][:60]} → {a['length']} bytes")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", "-p", default=None)
    parser.add_argument("--delay", "-d", type=float, default=0.5)
    args = parser.parse_args()
    fuzz(proxy=args.proxy, delay=args.delay)
'''


class BurpMimicGenerator:
    """
    Generates standalone Python PoC scripts for every finding.

    Each script:
    - Uses only the `requests` library (no custom deps)
    - Captures exact headers, cookies, and body
    - Includes --proxy flag for routing through Burp Suite
    - Is self-contained and executable
    """

    def __init__(self, output_dir: str = "./output/poc_scripts"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(loader=BaseLoader())

    def generate(self, finding: Finding) -> str:
        """Generate a PoC script for a finding. Returns the file path."""
        if not finding.evidence:
            return ""

        evidence = finding.evidence[0]

        # Prepare headers as JSON string
        headers = dict(evidence.request_headers)
        if not headers:
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
                ),
                "Accept": "*/*",
            }

        headers_json = json.dumps(headers, indent=4)

        # Choose template
        template_str = REPEATER_TEMPLATE

        # Render
        template = self.env.from_string(template_str)
        script = template.render(
            finding=finding,
            evidence=evidence,
            headers_json=headers_json,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

        # Save
        safe_name = (
            finding.vuln_type.value + "_" +
            finding.id + ".py"
        )
        filepath = self.output_dir / safe_name
        filepath.write_text(script, encoding="utf-8")

        logger.info("Generated PoC: %s", filepath)
        return str(filepath)

    def generate_intruder(
        self, finding: Finding, payloads: list[str]
    ) -> str:
        """Generate an Intruder-style fuzzing script."""
        if not finding.evidence:
            return ""

        evidence = finding.evidence[0]

        template = self.env.from_string(INTRUDER_TEMPLATE)
        script = template.render(
            finding=finding,
            evidence=evidence,
            payloads_json=json.dumps(payloads, indent=4),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

        safe_name = f"intruder_{finding.vuln_type.value}_{finding.id}.py"
        filepath = self.output_dir / safe_name
        filepath.write_text(script, encoding="utf-8")

        return str(filepath)
