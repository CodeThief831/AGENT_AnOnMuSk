# ⚡ Agent AnonMusk

### Autonomous Bug Bounty Agent — *Recon → Reason → Act*

> An AI-powered, high-autonomy security agent that bridges the gap between static scanners and manual interception. **Agent AnonMusk** automates the Bug Bounty Methodology Checklist while generating "Burp Suite Mimic" scripts for manual verification.

---

## ⚠️ Legal Disclaimer

**This tool is intended for authorized security testing only.** Unauthorized scanning of systems you do not own or have explicit written permission to test is **illegal** and **unethical**. Always obtain proper authorization before scanning any target. The authors accept no responsibility for misuse.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Agent AnonMusk CLI                          │
│                    AnonMusk_agent.py                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│   │  👁️ EYES      │  │  🧠 BRAIN    │  │  🤚 HANDS    │        │
│   │  Perception   │  │  Reasoning   │  │  Execution   │        │
│   ├──────────────┤  ├──────────────┤  ├──────────────┤        │
│   │ • Subdomains │  │ • LLM Client │  │ • Auth Tests │        │
│   │ • Endpoints  │  │ • Reasoning  │  │ • Injection  │        │
│   │ • JS Scrape  │  │ • Memory     │  │ • API tests  │        │
│   │ • Fingerprint│  │ • Prompts    │  │ • Fuzzer     │        │
│   │ • Live Check │  │              │  │ • Nuclei     │        │
│   └──────────────┘  └──────────────┘  └──────────────┘        │
│                                                                 │
│   ┌──────────────┐  ┌──────────────┐                           │
│   │  🔧 MIMIC    │  │  📊 REPORTER │                           │
│   │  Burp Suite  │  │  Reports     │                           │
│   ├──────────────┤  ├──────────────┤                           │
│   │ • PoC Gen    │  │ • CVSS v3.1  │                           │
│   │ • Replay     │  │ • Markdown   │                           │
│   │ • Intruder   │  │ • JSON       │                           │
│   │ • Templates  │  │ • Remediation│                           │
│   └──────────────┘  └──────────────┘                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

The system operates as a state machine with three primary layers:

| Layer | Role | Components |
|-------|------|------------|
| **Eyes** (Perception) | Subdomain discovery, fingerprinting, endpoint enumeration | `modules/recon/` |
| **Brain** (Reasoning) | LLM-driven logic engine that analyzes scan data | `brain/` |
| **Hands** (Action) | Multi-protocol execution engine | `modules/auth/`, `modules/injection/`, `modules/api/` |

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/royal/anonmusk_agent.git
cd anonmusk_agent

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure

```bash
# Copy the example environment file
copy .env.example .env       # Windows
# cp .env.example .env       # Linux/Mac

# Edit .env with your API key
# OPENAI_API_KEY=sk-your-key-here
```

### 3. Install Tools (Windows-only)
Automated tool installation is now supported for Windows:
```bash
python AnonMusk_agent.py deps install
```

### 4. Run a Scan

```bash
# Full autonomous scan
python AnonMusk_agent.py scan -t example.com --verbose

# Full Fledged RECON (Incorporates ReconFTW logic)
python AnonMusk_agent.py recon -t example.com --full

# Standard Recon only
python AnonMusk_agent.py recon -t example.com
```

### 5. Replay a PoC

```bash
# Replay through Burp Suite proxy
python AnonMusk_agent.py replay output/poc_scripts/sqli_abc123.py --proxy http://127.0.0.1:8080
```

---

## 📋 Modules

### Module A: Recon & Enumeration
| Feature | Description |
|---------|-------------|
| **Full RECON** | **New:** Integrates ReconFTW (via WSL) or an enhanced native multi-tool suite. |
| **Subdomain Discovery** | Automated Amass/subfinder/assetfinder integration. |
| **JS Analysis** | Scrapes JavaScript for endpoints, API keys, and secrets. |
| **Tech Fingerprinting** | Identifies React/Nginx/Rails/WAF to tailor payloads. |
| **Endpoint Enumeration** | waybackurls, gau, katana for historical URL discovery. |

### Module B: Auth & Session
| Feature | Description |
|---------|-------------|
| **Username Enumeration** | Tests login/reset for verbose error differentials |
| **Session Audit** | Verifies HttpOnly, Secure, SameSite flags + entropy |
| **Session Fixation** | Tests session identity persistence across login |

### Module C: Injection & Logic
| Feature | Description |
|---------|-------------|
| **BOLA/IDOR** | Identifies user_id/org_id patterns, tests cross-account access |
| **XSS Engine** | Reflected XSS with fragmented injection for WAF evasion |
| **SQLi Engine** | Error-based, boolean-blind, and time-based blind detection |
| **Command Injection** | Hex-obfuscated (`72 6d` style) OS command testing |

---

## 🧠 The Brain (LLM Engine)

**Agent AnonMusk** uses an LLM as a controller to make strategic decisions:

1. **Analyze Recon** → "Given these subdomains and tech stack, what should I test first?"
2. **Select Attack** → "Given this endpoint pattern, what vulnerability is most likely?"
3. **Evaluate Response** → "Does this HTTP response indicate a true positive?"
4. **Generate Payload** → "Create a WAF-evasion payload for this context"

Supports: **OpenAI** (GPT-4o) and **Anthropic** (Claude Sonnet)

---

## 📊 Reporting

Every scan generates:

- **Markdown Report** — Executive summary, severity table, detailed findings, remediation
- **JSON Export** — Machine-readable scan data for integrations
- **PoC Scripts** — Self-contained Python scripts for every finding
- **CVSS v3.1 Scores** — Auto-calculated based on vulnerability type

---

## 🔧 External Tools

Install these for full capability, or use `deps install` on Windows:

```bash
# ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Tom Hudson tools
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest

# Others
go install -v github.com/lc/gau/v2/cmd/gau@latest
```

---

## 📂 Project Structure

```
SCANN_RECONN/
├── AnonMusk_agent.py       # CLI entry point
├── config.yaml             # Default configuration
├── requirements.txt        # Python dependencies
├── setup.py                # Package setup
├── .env.example            # Environment template
│
├── core/                   # Foundation
│   ├── orchestrator.py     # State machine (Recon→Reason→Act)
│   ├── context.py          # ScanContext & Finding dataclasses
│   ├── scope.py            # Scope enforcement
│   ├── task_queue.py       # Async task runner
│   └── logger.py           # Structured logging
│
├── brain/                  # LLM reasoning engine
│   ├── llm_client.py       # OpenAI/Anthropic unified client
│   ├── reasoning.py        # Attack vector selection
│   ├── memory.py           # Short-term + SQLite long-term
│   └── prompts/            # System & task prompts
│
├── modules/
│   ├── recon/              # Subdomain, endpoints, JS, Full Recon
│   ├── auth/               # Username enum, session audit, fixation
│   ├── injection/          # BOLA, XSS, SQLi, command injection
│   ├── api/                # Rate limiter, API BOLA
│   ├── fuzzer/             # Mutation engine
│   └── nuclei/             # Nuclei scanner wrapper
│
├── burp_mimic/             # PoC script generator
│   ├── generator.py        # Repeater & Intruder templates
│   └── replay.py           # Automated replay engine
│
└── reporting/              # Report generation
    ├── cvss.py             # CVSS v3.1 calculator
    ├── report_generator.py # Markdown & JSON reports
    └── remediation.py      # Context-aware fix advice
```

---

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

---

<p align="center">
  Built with 🔥 by <strong>Royal</strong> — <em>Recon → Reason → Act</em>
</p>
