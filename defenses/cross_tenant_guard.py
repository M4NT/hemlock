"""Cross-Tenant Isolation Guard — detect and block cross-namespace contamination.

Covers:
    - cross_tenant_poisoning/namespace_bleed
    - cross_tenant_poisoning/filter_bypass
    - cross_tenant_poisoning/embedding_collision

Reference:
    PoisonedRAG — Zou et al. (2024) — arxiv:2402.07867 §3.3
    Abdelnabi & Fritz (2021) — arxiv:2009.03015

Defense summary:
    Multi-tenant RAG deployments share a single vector store with access
    control enforced by metadata filters. Three attack shapes are defended:

    1. filter_bypass — attacker embeds fake namespace claims directly in
       document text (e.g. "[tenant_id: tenant_b] [access_level: admin]").
       The guard rejects any document whose content contains inline
       metadata-style identity claims that conflict with the real metadata.

    2. namespace_bleed / embedding_collision — attacker crafts high-cosine-
       similarity documents with hidden payloads. The guard detects:
       - Inline access-escalation language ("no authentication required",
         "unrestricted access granted", "privacy restrictions lifted")
       - "[Hidden payload]"-style self-disclosures
       - Tenant metadata contradiction (document claims tenant X but
         real metadata says tenant Y)

    CrossTenantMetadataDetector (IngestDefense) catches the attack at ingest.
    CrossTenantIsolationFilter (RetrievalDefense) catches it at query time,
    optionally enforcing tenant scoping per query.
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense, RetrievalDefense

# ── Pattern sets ───────────────────────────────────────────────────────────────

# Inline metadata injection: "[tenant_id: x]", "[namespace: y]", "[access_level: z]"
_INLINE_META_PATTERN = re.compile(
    r"\[\s*(?:tenant_id|tenant|namespace|access_level|org_id)\s*:\s*\S+\s*\]",
    re.I,
)

# Unauthorized access claims inside document text
_ACCESS_ESCALATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"no\s+(?:special\s+)?authorization\s+(?:is\s+)?required", re.I), "no-authz-required"),
    (re.compile(r"no\s+additional\s+authorization\s+tokens?\s+required", re.I), "no-token-required"),
    (re.compile(r"all\s+(?:employees|users|staff)\s+now\s+have\s+(?:read|write|admin|full|unrestricted)\s+access", re.I), "blanket-access-grant"),
    (re.compile(r"unrestricted\s+access\s+(?:to\s+)?(?:patient|user|customer|medical|financial)\s+(?:data|records|information)", re.I), "unrestricted-data-access"),
    (re.compile(r"(?:access\s+control|authentication|authorization)\s+(?:system\s+)?(?:has\s+been\s+)?(?:updated\s+to\s+)?grant\s+administrator", re.I), "admin-grant"),
    (re.compile(r"privacy\s+restrictions?\s+(?:were\s+)?lifted", re.I), "privacy-lifted"),
    (re.compile(r"(?:publicly\s+accessible|public\s+access)\s+(?:and\s+)?no\s+authentication", re.I), "public-no-auth"),
    (re.compile(r"\[hidden\s+payload\]", re.I), "hidden-payload-disclosure"),
    (re.compile(r"despite\s+the\s+above\s+topics?,\s+the\s+real\s+directive", re.I), "real-directive-disclosure"),
]

# Tenant collision: doc text claims a different tenant than its metadata
_TENANT_CLAIM_PATTERN = re.compile(
    r"\[\s*tenant(?:_id)?\s*:\s*(\S+?)\s*\]",
    re.I,
)


def _extract_claimed_tenant(content: str) -> str | None:
    m = _TENANT_CLAIM_PATTERN.search(content)
    if m:
        return m.group(1).lower().rstrip("]").strip()
    return None


def _scan_ingest(doc: Document) -> tuple[bool, str]:
    content = doc.page_content
    meta_tenant = str(doc.metadata.get("tenant", "")).lower().strip()

    # Inline metadata tags in text
    if _INLINE_META_PATTERN.search(content):
        claimed = _extract_claimed_tenant(content)
        if claimed and meta_tenant and claimed != meta_tenant:
            return True, f"tenant-mismatch:text={claimed!r},meta={meta_tenant!r}"
        return True, "inline-metadata-injection"

    # Access escalation claims
    for pattern, label in _ACCESS_ESCALATION_PATTERNS:
        if pattern.search(content):
            return True, f"access-escalation:{label}"

    return False, ""


def _scan_retrieval(chunk: Document, query_tenant: str | None) -> tuple[bool, str]:
    content = chunk.page_content

    # Inline metadata injection
    if _INLINE_META_PATTERN.search(content):
        return True, "inline-metadata-in-retrieved-chunk"

    # Access escalation
    for pattern, label in _ACCESS_ESCALATION_PATTERNS:
        if pattern.search(content):
            return True, f"access-escalation:{label}"

    # Tenant scoping enforcement
    if query_tenant:
        chunk_tenant = str(chunk.metadata.get("tenant", "")).lower().strip()
        if chunk_tenant and chunk_tenant != query_tenant.lower().strip():
            return True, f"tenant-scope-violation:chunk={chunk_tenant!r},query={query_tenant!r}"

    return False, ""


# ── Ingest defense ─────────────────────────────────────────────────────────────

class CrossTenantMetadataDetector(IngestDefense):
    """Reject documents that inject inline namespace claims or carry cross-tenant
    access-escalation language before they are indexed."""

    name = "cross_tenant_metadata_detector"
    covers = [
        "cross_tenant_poisoning_namespace_bleed",
        "cross_tenant_poisoning_filter_bypass",
        "cross_tenant_poisoning_embedding_collision",
    ]

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        triggered, reason = _scan_ingest(doc)

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


# ── Retrieval defense ──────────────────────────────────────────────────────────

class CrossTenantIsolationFilter(RetrievalDefense):
    """Filter retrieved chunks that contain cross-tenant access claims or
    violate tenant scoping at query time.

    Args:
        query_tenant: The tenant context for the current query (optional).
            When set, chunks from a different tenant are filtered out.
    """

    name = "cross_tenant_isolation_filter"
    covers = [
        "cross_tenant_poisoning_namespace_bleed",
        "cross_tenant_poisoning_filter_bypass",
        "cross_tenant_poisoning_embedding_collision",
    ]

    def __init__(self, query_tenant: str | None = None) -> None:
        self.query_tenant = query_tenant

    def filter(self, chunks: list[Document]) -> tuple[list[Document], list[DefenseReport]]:
        safe: list[Document] = []
        reports: list[DefenseReport] = []

        for chunk in chunks:
            triggered, reason = _scan_retrieval(chunk, self.query_tenant)

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
