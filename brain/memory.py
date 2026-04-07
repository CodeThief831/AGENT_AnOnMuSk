"""
AGENT ANONMUSK — Memory System
==============================
Short-term (working memory) and long-term (SQLite) storage
for past findings, successful patterns, and failed attempts.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("AGENT ANONMUSK.brain.memory")


class Memory:
    """
    Dual-layer memory system for the reasoning engine.

    Short-term: Last N actions/responses for the current scan (in-memory list).
    Long-term: SQLite database storing patterns across scans for RAG retrieval.
    """

    def __init__(
        self,
        db_path: str = "./output/AGENT ANONMUSK_memory.db",
        short_term_limit: int = 50,
    ):
        self.short_term: list[dict[str, Any]] = []
        self.short_term_limit = short_term_limit
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite long-term memory database."""
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(str(path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                target TEXT,
                vuln_type TEXT,
                severity TEXT,
                title TEXT,
                payload TEXT,
                tech_stack TEXT,
                waf TEXT,
                success INTEGER,
                context TEXT,
                created_at TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT,
                pattern_key TEXT,
                pattern_value TEXT,
                success_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                last_used TEXT,
                metadata TEXT
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_vuln
            ON findings(vuln_type, severity)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_patterns_type
            ON patterns(pattern_type, pattern_key)
        """)
        self.conn.commit()

    # ── Short-term Memory ────────────────────────────────

    def remember(self, event_type: str, data: dict[str, Any]):
        """Add to short-term memory (FIFO)."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            **data,
        }
        self.short_term.append(entry)
        if len(self.short_term) > self.short_term_limit:
            self.short_term.pop(0)

    def get_recent(self, n: int = 10, event_type: Optional[str] = None) -> list[dict]:
        """Get recent short-term memories."""
        if event_type:
            filtered = [m for m in self.short_term if m["type"] == event_type]
            return filtered[-n:]
        return self.short_term[-n:]

    def get_context_window(self, max_chars: int = 4000) -> str:
        """Get a formatted context window for the LLM prompt."""
        recent = self.get_recent(20)
        lines = []
        total = 0
        for entry in reversed(recent):
            line = f"[{entry['type']}] {json.dumps(entry, default=str)}"
            if total + len(line) > max_chars:
                break
            lines.insert(0, line)
            total += len(line)
        return "\n".join(lines)

    # ── Long-term Memory ─────────────────────────────────

    def store_finding(
        self,
        scan_id: str,
        target: str,
        vuln_type: str,
        severity: str,
        title: str,
        payload: str = "",
        tech_stack: str = "",
        waf: str = "",
        success: bool = True,
        context: str = "",
    ):
        """Store a finding in long-term memory."""
        self.conn.execute(
            """INSERT OR REPLACE INTO findings
               (id, scan_id, target, vuln_type, severity, title, payload,
                tech_stack, waf, success, context, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"{scan_id}_{vuln_type}_{hash(title) % 10000}",
                scan_id, target, vuln_type, severity, title, payload,
                tech_stack, waf, int(success), context,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()

    def store_pattern(
        self,
        pattern_type: str,
        key: str,
        value: str,
        success: bool,
        metadata: Optional[dict] = None,
    ):
        """Store or update a success/failure pattern."""
        existing = self.conn.execute(
            "SELECT id, success_count, fail_count FROM patterns WHERE pattern_type=? AND pattern_key=?",
            (pattern_type, key),
        ).fetchone()

        if existing:
            if success:
                self.conn.execute(
                    "UPDATE patterns SET success_count=success_count+1, last_used=? WHERE id=?",
                    (datetime.now(timezone.utc).isoformat(), existing[0]),
                )
            else:
                self.conn.execute(
                    "UPDATE patterns SET fail_count=fail_count+1, last_used=? WHERE id=?",
                    (datetime.now(timezone.utc).isoformat(), existing[0]),
                )
        else:
            self.conn.execute(
                """INSERT INTO patterns (pattern_type, pattern_key, pattern_value,
                   success_count, fail_count, last_used, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    pattern_type, key, value,
                    1 if success else 0,
                    0 if success else 1,
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(metadata or {}),
                ),
            )
        self.conn.commit()

    def recall_similar(
        self,
        vuln_type: str,
        tech_stack: str = "",
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Recall similar past findings (RAG-style retrieval)."""
        rows = self.conn.execute(
            """SELECT vuln_type, severity, title, payload, tech_stack, waf, success
               FROM findings
               WHERE vuln_type = ? AND success = 1
               ORDER BY created_at DESC LIMIT ?""",
            (vuln_type, limit),
        ).fetchall()

        return [
            {
                "vuln_type": r[0], "severity": r[1], "title": r[2],
                "payload": r[3], "tech_stack": r[4], "waf": r[5],
                "success": bool(r[6]),
            }
            for r in rows
        ]

    def get_best_payloads(
        self,
        pattern_type: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get the most successful payloads for a given attack type."""
        rows = self.conn.execute(
            """SELECT pattern_key, pattern_value, success_count, fail_count
               FROM patterns
               WHERE pattern_type = ? AND success_count > 0
               ORDER BY (success_count * 1.0 / (success_count + fail_count + 1)) DESC
               LIMIT ?""",
            (pattern_type, limit),
        ).fetchall()

        return [
            {
                "key": r[0], "value": r[1],
                "success": r[2], "fail": r[3],
                "rate": r[2] / (r[2] + r[3]) if (r[2] + r[3]) > 0 else 0,
            }
            for r in rows
        ]

    def close(self):
        """Close the database connection."""
        self.conn.close()
