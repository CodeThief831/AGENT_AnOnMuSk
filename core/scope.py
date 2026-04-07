"""
AGENT ANONMUSK — Scope Validator
==============================
Enforces target scope before every HTTP request and tool invocation.
Prevents the agent from scanning unauthorized targets.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from rich.console import Console

console = Console()


class ScopeValidator:
    """
    Validates URLs and domains against a defined scope.

    Scope file format (one entry per line):
        *.example.com          # wildcard subdomain match
        api.example.com        # exact domain match
        192.168.1.0/24         # IP CIDR range
        !internal.example.com  # exclusion (takes priority)

    Usage:
        validator = ScopeValidator.from_file("scope.txt")
        if validator.is_in_scope("https://test.example.com/api/v1"):
            # proceed with request
    """

    def __init__(
        self,
        include_patterns: list[str],
        exclude_patterns: Optional[list[str]] = None,
    ):
        self.include_patterns = include_patterns
        self.exclude_patterns = exclude_patterns or []
        self._include_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._exclude_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._parse_networks()

    def _parse_networks(self):
        """Parse CIDR notation entries into network objects."""
        for pattern in self.include_patterns:
            try:
                self._include_networks.append(
                    ipaddress.ip_network(pattern, strict=False)
                )
            except ValueError:
                pass  # not a CIDR — it's a domain pattern

        for pattern in self.exclude_patterns:
            try:
                self._exclude_networks.append(
                    ipaddress.ip_network(pattern, strict=False)
                )
            except ValueError:
                pass

    @classmethod
    def from_file(cls, filepath: str) -> "ScopeValidator":
        """Load scope from a text file."""
        path = Path(filepath)
        if not path.exists():
            console.print(
                f"[bold red]⚠ Scope file not found:[/] {filepath}", highlight=False
            )
            console.print(
                "[yellow]Create a scope.txt with target domains (one per line)[/]"
            )
            return cls(include_patterns=[], exclude_patterns=[])

        includes = []
        excludes = []

        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                excludes.append(line[1:].strip())
            else:
                includes.append(line)

        return cls(include_patterns=includes, exclude_patterns=excludes)

    @classmethod
    def from_target(cls, target: str) -> "ScopeValidator":
        """Quick scope from a single target domain (includes *.target)."""
        domain = cls._extract_domain(target)
        return cls(
            include_patterns=[domain, f"*.{domain}"],
            exclude_patterns=[],
        )

    @staticmethod
    def _extract_domain(url_or_domain: str) -> str:
        """Extract bare domain from URL or domain string."""
        if "://" in url_or_domain:
            parsed = urlparse(url_or_domain)
            return parsed.hostname or url_or_domain
        # strip port if present
        return url_or_domain.split(":")[0].strip()

    def _matches_domain(self, domain: str, patterns: list[str]) -> bool:
        """Check if a domain matches any pattern (wildcard-aware)."""
        domain = domain.lower()
        for pattern in patterns:
            pattern = pattern.lower()
            # Direct match
            if domain == pattern:
                return True
            # Wildcard match (*.example.com)
            if fnmatch.fnmatch(domain, pattern):
                return True
        return False

    def _matches_ip(
        self,
        ip_str: str,
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    ) -> bool:
        """Check if an IP address falls within any network range."""
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in networks)
        except ValueError:
            return False

    def is_in_scope(self, url_or_domain: str) -> bool:
        """
        Check if a URL or domain is within the defined scope.
        Returns False if scope is empty (fail-closed).
        """
        if not self.include_patterns:
            return False

        host = self._extract_domain(url_or_domain)

        # Check exclusions first (higher priority)
        if self._matches_domain(host, self.exclude_patterns):
            return False
        if self._matches_ip(host, self._exclude_networks):
            return False

        # Check inclusions
        if self._matches_domain(host, self.include_patterns):
            return True
        if self._matches_ip(host, self._include_networks):
            return True

        return False

    def validate_or_raise(self, url_or_domain: str):
        """Raise ValueError if target is out of scope."""
        if not self.is_in_scope(url_or_domain):
            raise ValueError(
                f"🚫 OUT OF SCOPE: '{url_or_domain}' is not in the defined scope. "
                f"Include patterns: {self.include_patterns}"
            )

    def __repr__(self) -> str:
        return (
            f"ScopeValidator(include={self.include_patterns}, "
            f"exclude={self.exclude_patterns})"
        )
