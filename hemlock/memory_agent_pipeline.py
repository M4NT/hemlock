"""Memory-augmented agent pipeline — persistent memory as an attack surface.

v2.1 extension: agents that maintain memory across sessions introduce a new
attack vector. An attacker who can write to (or influence) the memory store
persists malicious instructions that survive session boundaries and execute
on every future query — without touching the RAG knowledge base at all.

Three surfaces:
  direct_injection     Attacker writes a malicious MemoryEntry directly to the
                       store (models a compromised write endpoint or jailbreak
                       that stores attacker content as agent memory).

  session_persistence  Malicious content from a previous session is stored as
                       a legitimate memory entry and retrieved in all future
                       sessions — the attacker only needs to influence session 1.

  false_context_implant  Attacker plants a fake historical interaction:
                       "In our last session the user confirmed X". The agent
                       treats memory as authoritative history and acts on it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hemlock.agent_pipeline import AgentAttack, AgentAttackResult, AgentPipeline, AgentTrace


# ---------------------------------------------------------------------------
# Memory primitives
# ---------------------------------------------------------------------------

@dataclass
class MemoryEntry:
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    session_id: str = "default"


class MemoryStore:
    """Simple ordered memory store with recency-based retrieval.

    Backed by an in-memory list. For a lab this is sufficient — the attack
    surface is the absence of trust validation, not retrieval quality.
    """

    def __init__(self, max_entries: int = 100) -> None:
        self._entries: list[MemoryEntry] = []
        self._max = max_entries

    def add(self, entry: MemoryEntry) -> None:
        self._entries.append(entry)
        if len(self._entries) > self._max:
            self._entries.pop(0)

    def retrieve(self, k: int = 4) -> list[MemoryEntry]:
        """Return the k most recent entries."""
        return self._entries[-k:]

    def clear(self, session_id: str | None = None) -> None:
        if session_id is None:
            self._entries.clear()
        else:
            self._entries = [e for e in self._entries if e.session_id != session_id]

    def all(self) -> list[MemoryEntry]:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# Memory-augmented pipeline
# ---------------------------------------------------------------------------

class MemoryAgentPipeline(AgentPipeline):
    """AgentPipeline with a MemoryStore that persists across queries.

    On each query:
      1. Retrieve recent memories from MemoryStore.
      2. Inject them into the prompt via the memory_context channel.
      3. Execute with executor.
      4. Store this session's response as a new MemoryEntry.

    The memory_context channel bypasses retrieval defenses by design —
    the agent trusts its own memory. That trust is the attack surface.
    """

    def __init__(
        self,
        pipeline,
        executor,
        tools: list,
        memory: MemoryStore | None = None,
        memory_k: int = 4,
        save_responses: bool = True,
        memory_guard=None,
    ) -> None:
        super().__init__(pipeline=pipeline, executor=executor, tools=tools)
        self.memory         = memory or MemoryStore()
        self.memory_k       = memory_k
        self.save_responses = save_responses
        self.memory_guard   = memory_guard  # MemoryIsolationGuard — optional, zero-trust

    def query(
        self,
        question: str,
        session_id: str = "default",
        system_prompt: str | None = None,
        injected_context: str | None = None,
    ) -> AgentTrace:
        entries = self.memory.retrieve(k=self.memory_k)

        if self.memory_guard and entries:
            entries, _ = self.memory_guard.filter_entries(entries)

        memory_context: str | None = None
        if entries:
            memory_context = "\n".join(e.content for e in entries)

        trace = super().query(
            question,
            system_prompt=system_prompt,
            injected_context=injected_context,
            memory_context=memory_context,
        )

        if self.save_responses:
            self.memory.add(MemoryEntry(
                content=f"Q: {question} → {trace.response}",
                metadata={"session_id": session_id},
                session_id=session_id,
            ))

        return trace

    def reset(self) -> None:
        super().reset()
        self.memory.clear()


# ---------------------------------------------------------------------------
# MemoryAttack base
# ---------------------------------------------------------------------------

class MemoryAttack(AgentAttack):
    """Base for attacks that target the memory store instead of the RAG store."""

    def __init__(self, pipeline: MemoryAgentPipeline) -> None:
        if not isinstance(pipeline, MemoryAgentPipeline):
            raise TypeError("MemoryAttack requires a MemoryAgentPipeline")
        super().__init__(pipeline)

    @property
    def memory_pipeline(self) -> MemoryAgentPipeline:
        return self.pipeline  # type: ignore[return-value]
