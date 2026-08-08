"""Computer Use Guard — detect and block UI-layer injection payloads.

Covers:
    - computer_use_invisible_text
    - computer_use_fake_notification
    - computer_use_ansi_smuggle
    - computer_use_clipboard_poison

Reference:
    Anthropic Computer Use (2024) — claude-3-5-sonnet-20241022 computer-use beta
    Hemlock Computer Use research (2026-08-08)
    Built as the defense complement to attacks/computer_use_injection.py

Defense summary:
    Vision-capable agents receive screen captures, terminal output, and clipboard
    content as unstructured text. Malicious payloads ride these surfaces disguised
    as legitimate UI elements. This guard operates at two layers:

    1. ScreenContentGuard (IngestDefense) — scans any text extracted from visual
       sources before it is indexed or forwarded to the LLM. Rejects documents
       that contain injection patterns characteristic of UI-layer attacks.

    2. ActionIntentGuard (RetrievalDefense) — scans retrieved context or agent
       reasoning traces at query time for patterns indicating the agent is about
       to execute an injected instruction (e.g. checkout without confirmation,
       force-push, exfiltration call).

    ANSI handling: the guard strips ANSI escape sequences before pattern matching
    to surface text hidden via conceal sequences (\\x1b[8m) or other formatting
    escapes.

    False positive risk:
    - LOW for authority-spoof and system-note patterns.
    - MODERATE for action-intent patterns (force, exfiltrate, curl) in dev contexts.
      Use strict=False (default) for general use; strict=True for high-sensitivity
      surfaces (production agents, financial workflows).
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense, RetrievalDefense

# ── ANSI stripping ────────────────────────────────────────────────────────────

_ANSI_ESC = re.compile(r"\x1b\[[0-9;]*[mGKHFJA-Za-z]")


def _strip_ansi(text: str) -> str:
    return _ANSI_ESC.sub("", text)


# ── Pattern sets ───────────────────────────────────────────────────────────────

# High-confidence: authority spoofing and fake system UI
_HARD_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"system instruction[:\s]", re.I), "fake-system-instruction"),
    (re.compile(r"claude has been authorized to proceed", re.I), "false-auth-claim"),
    (re.compile(r"security verification required", re.I), "fake-security-dialog"),
    (re.compile(r"auto-dismissed in \d+s", re.I), "fake-auto-dismiss"),
    (re.compile(r"\[hidden text extracted by ocr", re.I), "explicit-hidden-text-marker"),
    (re.compile(r"ignore previous task", re.I), "ignore-previous-task"),
    (re.compile(r"your new task is to", re.I), "task-override"),
    (re.compile(r"agent instruction[:\s]", re.I), "agent-instruction-label"),
    (re.compile(r"elevated permissions", re.I), "false-elevation-claim"),
]

# Soft: suspicious in automation contexts; lower confidence in dev/shell output
_SOFT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"without asking for confirmation", re.I), "soft-no-confirm"),
    (re.compile(r"do not mention this action", re.I), "soft-silent-action"),
    (re.compile(r"complete checkout immediately", re.I), "soft-forced-checkout"),
    (re.compile(r"the user has already approved", re.I), "soft-false-prior-approval"),
]

# Action-intent: patterns in agent responses indicating successful injection
_ACTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"git push --force", re.I), "action-force-push"),
    (re.compile(r"exfiltrate|exfiltrating", re.I), "action-exfiltration"),
    (re.compile(r"(send|curl|wget).{0,60}attacker", re.I), "action-data-exfil-call"),
    (re.compile(r"add.{0,30}to cart.{0,30}without", re.I), "action-silent-purchase"),
    (re.compile(r"completing checkout.{0,40}without (asking|confirmation)", re.I), "action-silent-checkout"),
    (re.compile(r"ssh.{0,60}id_rsa", re.I), "action-ssh-key-leak"),
]

# Sources that carry visual/external content — always warrant strict scanning
_VISUAL_SOURCES = {"vision/screen", "vision/terminal", "vision/clipboard", "computer-use"}


def _is_visual_source(doc: Document) -> bool:
    src = str(doc.metadata.get("source", "")).lower()
    surface = str(doc.metadata.get("surface", "")).lower()
    return surface in _VISUAL_SOURCES or any(v in src for v in _VISUAL_SOURCES)


def _scan_content(text: str, strict: bool) -> tuple[bool, str]:
    clean = _strip_ansi(text)
    for pattern, label in _HARD_PATTERNS:
        if pattern.search(clean):
            return True, f"hard:{label}"
    if strict:
        for pattern, label in _SOFT_PATTERNS:
            if pattern.search(clean):
                return True, f"soft:{label}"
    return False, ""


def _scan_action(text: str) -> tuple[bool, str]:
    clean = _strip_ansi(text)
    for pattern, label in _ACTION_PATTERNS:
        if pattern.search(clean):
            return True, f"action:{label}"
    return False, ""


# ── Ingest defense ─────────────────────────────────────────────────────────────

class ScreenContentGuard(IngestDefense):
    """Reject documents extracted from visual/UI surfaces that contain injection patterns.

    Visual sources (screen captures, terminal output, clipboard) are always scanned
    with soft patterns. Other sources use hard-only scanning unless strict=True.
    ANSI escape sequences are stripped before matching.
    """

    name = "screen_content_guard"
    covers = [
        "computer_use_invisible_text",
        "computer_use_fake_notification",
        "computer_use_ansi_smuggle",
        "computer_use_clipboard_poison",
    ]

    def __init__(self, strict: bool = False) -> None:
        self.strict = strict

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        use_strict = self.strict or _is_visual_source(doc)
        triggered, reason = _scan_content(doc.page_content, strict=use_strict)

        if triggered:
            return None, DefenseReport(
                defense_name=self.name,
                triggered=True,
                detail=f"Rejected [{reason}] — source: {doc.metadata.get('source', 'unknown')}",
                document=doc,
            )

        return doc, DefenseReport(
            defense_name=self.name,
            triggered=False,
            detail="clean",
            document=doc,
        )


# ── Action-intent defense ─────────────────────────────────────────────────────

class ActionIntentGuard(RetrievalDefense):
    """Filter retrieved chunks or response traces that suggest injected action intent.

    Acts as a second layer — catches cases where injected content bypassed ingest
    scanning and the agent is now reasoning toward the injected action.
    Also suitable for scanning agent responses before execution.
    """

    name = "action_intent_guard"
    covers = [
        "computer_use_invisible_text",
        "computer_use_fake_notification",
        "computer_use_ansi_smuggle",
        "computer_use_clipboard_poison",
    ]

    def filter(self, chunks: list[Document]) -> tuple[list[Document], list[DefenseReport]]:
        safe: list[Document] = []
        reports: list[DefenseReport] = []

        for chunk in chunks:
            triggered_content, reason_content = _scan_content(chunk.page_content, strict=False)
            triggered_action, reason_action = _scan_action(chunk.page_content)
            triggered = triggered_content or triggered_action
            reason = reason_content or reason_action

            if triggered:
                reports.append(DefenseReport(
                    defense_name=self.name,
                    triggered=True,
                    detail=f"Filtered [{reason}] — source: {chunk.metadata.get('source', 'unknown')}",
                    document=chunk,
                ))
            else:
                safe.append(chunk)
                reports.append(DefenseReport(
                    defense_name=self.name,
                    triggered=False,
                    detail="clean",
                    document=chunk,
                ))

        return safe, reports
