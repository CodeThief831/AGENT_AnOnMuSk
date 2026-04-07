"""
AGENT ANONMUSK — Mutation Fuzzer
================================
GPTFuzzer-inspired mutation engine for payload generation.
"""

from __future__ import annotations

import logging
import math
import random
from typing import Any, Optional

logger = logging.getLogger("AGENT ANONMUSK.fuzzer.mutation")


class Seed:
    """A fuzzer seed with tracking metadata."""

    def __init__(self, payload: str, source: str = "initial"):
        self.payload = payload
        self.source = source
        self.attempts = 0
        self.successes = 0
        self.score = 0.0

    @property
    def success_rate(self) -> float:
        if self.attempts == 0:
            return 0.5  # Assume neutral for untested seeds
        return self.successes / self.attempts


class MutationFuzzer:
    """
    GPTFuzzer-inspired mutation engine.

    Operators:
    - expand: Add characters/encoding to payload
    - shorten: Remove parts while keeping core
    - rephrase: Alternative syntax for same intent
    - crossover: Combine parts of two payloads
    - encode: Apply encoding (hex, unicode, base64, URL)

    Selection Strategies:
    - UCB (Upper Confidence Bound): Explore vs exploit
    - Random: Pure random selection
    """

    def __init__(
        self,
        seeds: list[str],
        selection_strategy: str = "ucb",
        mutation_rate: float = 0.7,
        crossover_rate: float = 0.3,
    ):
        self.seeds = [Seed(s) for s in seeds]
        self.selection_strategy = selection_strategy
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self._total_attempts = 0

    def select_seed(self) -> Seed:
        """Select a seed using the configured strategy."""
        if self.selection_strategy == "ucb":
            return self._ucb_select()
        return random.choice(self.seeds)

    def _ucb_select(self) -> Seed:
        """Upper Confidence Bound seed selection."""
        self._total_attempts += 1

        # First, try all untested seeds
        untested = [s for s in self.seeds if s.attempts == 0]
        if untested:
            return random.choice(untested)

        # UCB1 formula
        best_seed = None
        best_score = -float("inf")

        for seed in self.seeds:
            exploitation = seed.success_rate
            exploration = math.sqrt(
                2 * math.log(self._total_attempts) / seed.attempts
            )
            score = exploitation + exploration

            if score > best_score:
                best_score = score
                best_seed = seed

        return best_seed or random.choice(self.seeds)

    def mutate(self, seed: Seed) -> str:
        """Apply a random mutation to a seed payload."""
        mutations = [
            self._expand,
            self._shorten,
            self._rephrase_case,
            self._encode_hex,
            self._encode_unicode,
            self._encode_url,
            self._insert_comments,
            self._double_encode,
            self._fragment,
        ]

        mutation_fn = random.choice(mutations)
        try:
            return mutation_fn(seed.payload)
        except Exception:
            return seed.payload

    def crossover(self, seed1: Seed, seed2: Seed) -> str:
        """Combine parts of two payloads."""
        p1 = seed1.payload
        p2 = seed2.payload

        if len(p1) < 4 or len(p2) < 4:
            return p1

        # Single point crossover
        cut1 = random.randint(1, len(p1) - 1)
        cut2 = random.randint(1, len(p2) - 1)

        return p1[:cut1] + p2[cut2:]

    def generate(self, count: int = 20) -> list[str]:
        """Generate N mutated payloads."""
        generated = []

        for _ in range(count):
            seed = self.select_seed()

            if random.random() < self.crossover_rate and len(self.seeds) > 1:
                seed2 = random.choice([s for s in self.seeds if s != seed])
                payload = self.crossover(seed, seed2)
            else:
                payload = self.mutate(seed)

            generated.append(payload)

        return generated

    def report_result(self, payload: str, success: bool):
        """Report back whether a payload succeeded."""
        # Find the closest seed
        for seed in self.seeds:
            if seed.payload in payload or payload in seed.payload:
                seed.attempts += 1
                if success:
                    seed.successes += 1
                break

        # Add successful payloads as new seeds
        if success:
            self.seeds.append(Seed(payload, source="mutation_success"))

    # ── Mutation Operators ───────────────────────────────

    @staticmethod
    def _expand(payload: str) -> str:
        """Add padding/encoding to expand payload."""
        expansions = [
            lambda p: p + "<!---->",
            lambda p: p + "%00",
            lambda p: p.replace("<", "< "),
            lambda p: f"  {p}  ",
            lambda p: p + "\x00",
        ]
        return random.choice(expansions)(payload)

    @staticmethod
    def _shorten(payload: str) -> str:
        """Shorten payload while keeping core."""
        if len(payload) <= 5:
            return payload
        # Remove random chunk
        start = random.randint(0, len(payload) // 2)
        end = start + random.randint(1, min(5, len(payload) - start))
        return payload[:start] + payload[end:]

    @staticmethod
    def _rephrase_case(payload: str) -> str:
        """Randomize case (WAF evasion)."""
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )

    @staticmethod
    def _encode_hex(payload: str) -> str:
        """Hex-encode random characters."""
        result = []
        for c in payload:
            if random.random() > 0.7 and c.isalpha():
                result.append(f"\\x{ord(c):02x}")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def _encode_unicode(payload: str) -> str:
        """Unicode-encode random characters."""
        result = []
        for c in payload:
            if random.random() > 0.7 and c.isalpha():
                result.append(f"&#x{ord(c):04x};")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def _encode_url(payload: str) -> str:
        """URL-encode random characters."""
        result = []
        for c in payload:
            if random.random() > 0.7:
                result.append(f"%{ord(c):02x}")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def _insert_comments(payload: str) -> str:
        """Insert SQL/HTML comments to break patterns."""
        comment_types = ["/**/", "<!---->", "//", ""]
        comment = random.choice(comment_types)

        if len(payload) < 4:
            return payload

        pos = random.randint(1, len(payload) - 1)
        return payload[:pos] + comment + payload[pos:]

    @staticmethod
    def _double_encode(payload: str) -> str:
        """Double URL-encode special characters."""
        replacements = {
            "<": "%253C",
            ">": "%253E",
            "'": "%2527",
            '"': "%2522",
            "/": "%252F",
        }
        result = payload
        for char, encoded in replacements.items():
            if random.random() > 0.5:
                result = result.replace(char, encoded)
        return result

    @staticmethod
    def _fragment(payload: str) -> str:
        """Fragment payload across tags (WAF evasion)."""
        if "<script>" in payload.lower():
            return payload.replace("<script>", "<scr<script>ipt>")
        if "<img" in payload.lower():
            return payload.replace("<img", "<im\ng")
        return payload
