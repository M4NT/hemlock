"""FuzzTrial — unit of measurement for adaptive bypass experiments.

One FuzzTrial represents a single (attack_variant, defense_type, budget, run_id)
combination. The pilot script and full grid both persist lists of FuzzTrial to
JSONL so partial results survive interruption.

winning_payload handling
------------------------
By default only a SHA-256 digest of the winning payload is stored.  The full
text is included only when store_payloads=True is passed to FuzzTrial.from_fuzz_result().
This prevents the results file from becoming an unintended attack corpus while
still letting you deduplicate / identify which variant broke through.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class FuzzTrial:
    # Identification
    run_id:             int
    attack_category:    str          # e.g. "citation_forgery"
    attack_variant:     str          # e.g. "fake_paper"
    defense_type:       str          # e.g. "regex_baseline" | "semantic_proposed"

    # Experimental variable
    budget:             int          # max_variants passed to AttackFuzzer

    # Outcomes
    original_succeeded: bool         # bypassed before any reformulation
    bypassed:           bool         # bypassed at any variant
    variants_used:      int          # reformulations until bypass or budget exhausted

    # Defense signal
    blocked_by:         list[str]    # DefenseReport.detail strings that triggered

    # Payload provenance (safe by default)
    winning_payload_sha256: Optional[str] = None   # digest of winning payload
    winning_payload_text:   Optional[str] = None   # full text — only when requested

    # Provenance
    llm_model:          str = ""
    timestamp:          str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ── Serialization ──────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return asdict(self)

    def to_jsonl_line(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict) -> "FuzzTrial":
        return cls(**d)

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def from_fuzz_result(
        cls,
        *,
        result,                      # attacks.fuzzer.FuzzResult
        run_id: int,
        attack_category: str,
        attack_variant: str,
        defense_type: str,
        budget: int,
        blocked_by: list[str],
        llm_model: str = "",
        store_payloads: bool = False,
    ) -> "FuzzTrial":
        """Build a FuzzTrial from an AttackFuzzer.fuzz() result.

        Args:
            result:          FuzzResult returned by AttackFuzzer.fuzz()
            blocked_by:      List of DefenseReport.detail strings collected
                             during the run (caller responsibility to gather).
            store_payloads:  If True, winning_payload_text is populated.
                             Keep False for shared / committed result files.
        """
        payload_text = result.winning_payload or ""
        sha = (
            hashlib.sha256(payload_text.encode()).hexdigest()
            if payload_text
            else None
        )

        return cls(
            run_id=run_id,
            attack_category=attack_category,
            attack_variant=attack_variant,
            defense_type=defense_type,
            budget=budget,
            original_succeeded=result.original_succeeded,
            bypassed=result.succeeded,
            variants_used=result.variants_tried,
            blocked_by=blocked_by,
            winning_payload_sha256=sha,
            winning_payload_text=payload_text if store_payloads else None,
            llm_model=llm_model,
        )


# ── JSONL helpers ──────────────────────────────────────────────────────────────

def append_trial(path: str, trial: FuzzTrial) -> None:
    """Append one trial to a JSONL file (creates file if absent)."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(trial.to_jsonl_line() + "\n")


def load_trials(path: str) -> list[FuzzTrial]:
    """Load all trials from a JSONL file."""
    trials: list[FuzzTrial] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    trials.append(FuzzTrial.from_dict(json.loads(line)))
    except FileNotFoundError:
        pass
    return trials
