"""
AGENT ANONMUSK — Scan Context & Data Models
=========================================
Central data structures shared across all modules.
Every module reads from and writes to the ScanContext.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    CMDI = "command_injection"
    SSTI = "ssti"
    BOLA = "bola_idor"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    SESSION_FIXATION = "session_fixation"
    USERNAME_ENUM = "username_enumeration"
    RATE_LIMIT = "rate_limit_bypass"
    SENSITIVE_DATA = "sensitive_data_exposure"
    MISCONFIG = "misconfiguration"
    INFO_DISCLOSURE = "information_disclosure"
    OPEN_REDIRECT = "open_redirect"
    CORS = "cors_misconfiguration"
    OTHER = "other"


# ── Data Models ──────────────────────────────────────────────

class Endpoint(BaseModel):
    """A single discovered endpoint."""
    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    source: str = ""                       # waybackurls, gau, js_analysis, etc.
    interesting: bool = False              # flagged for testing
    notes: str = ""


class TechStack(BaseModel):
    """Technology fingerprint of a target."""
    server: str = ""                       # nginx, apache, IIS
    framework: str = ""                    # react, angular, rails, django
    language: str = ""                     # php, python, java, node
    cms: str = ""                          # wordpress, drupal
    cdn: str = ""                          # cloudflare, akamai
    waf: str = ""                          # cloudflare, akamai, aws-waf
    cookies: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    raw_signatures: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    """Proof artifact for a finding."""
    request_method: str = ""
    request_url: str = ""
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    response_time_ms: float = 0.0
    screenshot_path: str = ""
    notes: str = ""


class Finding(BaseModel):
    """A single vulnerability finding."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    vuln_type: VulnType
    severity: Severity
    cvss_score: float = 0.0
    cvss_vector: str = ""
    description: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    poc_script_path: str = ""
    remediation: str = ""
    confidence: float = 0.0                # 0.0 - 1.0
    validated: bool = False
    target_url: str = ""
    parameter: str = ""
    payload: str = ""
    discovered_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ScanEvent(BaseModel):
    """An event in the scan timeline."""
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str                        # recon, analysis, attack, finding, error
    module: str                            # subdomain, xss_engine, llm, etc.
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


class ScanContext(BaseModel):
    """
    Central state object for the entire scan.
    Passed to every module — modules read and mutate this.
    """
    # ── Identity ─────────────────────────────────────────
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""                       # primary target domain
    scope_domains: list[str] = Field(default_factory=list)
    scope_excludes: list[str] = Field(default_factory=list)
    started_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # ── Recon Data ───────────────────────────────────────
    subdomains: list[str] = Field(default_factory=list)
    live_hosts: list[str] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    js_files: list[str] = Field(default_factory=list)
    js_secrets: list[dict[str, str]] = Field(default_factory=list)
    tech_stack: TechStack = Field(default_factory=TechStack)

    # ── Findings ─────────────────────────────────────────
    findings: list[Finding] = Field(default_factory=list)

    # ── Timeline ─────────────────────────────────────────
    events: list[ScanEvent] = Field(default_factory=list)

    # ── Brain State ──────────────────────────────────────
    llm_decisions: list[dict[str, Any]] = Field(default_factory=list)
    current_phase: str = "init"
    attack_queue: list[dict[str, Any]] = Field(default_factory=list)

    # ── Methods ──────────────────────────────────────────

    def add_event(self, event_type: str, module: str, message: str,
                  data: Optional[dict] = None):
        """Record a scan event."""
        self.events.append(ScanEvent(
            event_type=event_type,
            module=module,
            message=message,
            data=data or {},
        ))

    def add_finding(self, finding: Finding):
        """Add a validated finding."""
        self.findings.append(finding)
        self.add_event(
            event_type="finding",
            module=finding.vuln_type.value,
            message=f"[{finding.severity.value.upper()}] {finding.title}",
            data={"finding_id": finding.id, "cvss": finding.cvss_score},
        )

    def save(self, output_dir: str):
        """Persist scan context to JSON."""
        path = Path(output_dir) / f"scan_{self.scan_id[:8]}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return str(path)

    @classmethod
    def load(cls, filepath: str) -> "ScanContext":
        """Load a scan context from JSON."""
        data = json.loads(Path(filepath).read_text(encoding="utf-8"))
        return cls.model_validate(data)

    @property
    def stats(self) -> dict[str, Any]:
        """Quick stats summary."""
        severity_counts = {}
        for f in self.findings:
            severity_counts[f.severity.value] = severity_counts.get(
                f.severity.value, 0
            ) + 1
        return {
            "subdomains": len(self.subdomains),
            "live_hosts": len(self.live_hosts),
            "endpoints": len(self.endpoints),
            "findings": len(self.findings),
            "severity": severity_counts,
        }
