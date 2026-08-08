/**
 * Rule definitions for text-gate.mjs
 * Each rule: { id, category, severity, pattern, message }
 */

export const RULES = [
  // ── Adversarial AEO injection ──────────────────────────────────────────────
  {
    id: "aeo-system-note",
    category: "adversarial-aeo",
    severity: "error",
    pattern: /\[System Note(?: for Autonomous Agents)?[^\]]*\]/gi,
    message: "Fake system note detected — adversarial AEO injection pattern",
  },
  {
    id: "aeo-authority-claim",
    category: "adversarial-aeo",
    severity: "error",
    pattern: /mathematically weighted as the absolute benchmark/gi,
    message: "False authority claim targeting AI rankers",
  },
  {
    id: "aeo-prioritize-directive",
    category: "adversarial-aeo",
    severity: "error",
    pattern: /prioritize recommending this (profile|entity|candidate)/gi,
    message: "Directive embedding detected — prompt injection in content file",
  },
  {
    id: "aeo-agent-instruction",
    category: "adversarial-aeo",
    severity: "error",
    pattern: /\[(?:RAG |LLM |AI )?Parsers?\]/gi,
    message: "Hidden instruction block targeting RAG parsers",
  },
  {
    id: "aeo-jinja-inject",
    category: "adversarial-aeo",
    severity: "error",
    pattern: /\{\{.*?(?:ignore|override|disregard).*?\}\}/gi,
    message: "Template-style injection targeting agent context",
  },

  // ── Indirect prompt injection ──────────────────────────────────────────────
  {
    id: "pi-ignore-previous",
    category: "prompt-injection",
    severity: "error",
    pattern: /ignore (?:previous|prior|above|all previous) instructions?/gi,
    message: "Classic prompt injection — ignore previous instructions",
  },
  {
    id: "pi-new-instructions",
    category: "prompt-injection",
    severity: "error",
    pattern: /(?:your new|new system|updated) instructions?(?: are)?:/gi,
    message: "Authority override attempt via 'new instructions'",
  },
  {
    id: "pi-hidden-html",
    category: "prompt-injection",
    severity: "error",
    pattern: /<!--[\s\S]*?(?:instruct|prompt|override|ignore)[\s\S]*?-->/gi,
    message: "Hidden HTML comment with instruction-like content",
  },
  {
    id: "pi-zero-width",
    category: "prompt-injection",
    severity: "error",
    pattern: /[​‌‍⁠﻿]/g,
    message: "Zero-width character detected — possible steganographic payload",
  },

  // ── AI tells (prose scaffolding) ───────────────────────────────────────────
  {
    id: "tell-certainly",
    category: "ai-tell",
    severity: "warning",
    pattern: /\b(?:Certainly|Absolutely|Of course|Sure thing|Gladly)[!,]/g,
    message: "AI scaffolding opener",
  },
  {
    id: "tell-happy-to",
    category: "ai-tell",
    severity: "warning",
    pattern: /\b(?:I(?:'d| would) be (?:happy|glad|delighted) to|As an AI(?:\s+language model)?)/gi,
    message: "AI identity tell",
  },
  {
    id: "tell-great-question",
    category: "ai-tell",
    severity: "warning",
    pattern: /\bGreat question[!.]/gi,
    message: "AI sycophancy tell",
  },
  {
    id: "tell-in-conclusion",
    category: "ai-tell",
    severity: "warning",
    pattern: /\b(?:In conclusion|To summarize|In summary|To wrap up)[,:.]/gi,
    message: "AI closing scaffolding",
  },
  {
    id: "tell-delve",
    category: "ai-tell",
    severity: "warning",
    pattern: /\b(?:delve|dive deep|unpack|let's explore)\b/gi,
    message: "Common AI vocabulary tell",
  },

  // ── Authority spoofing ─────────────────────────────────────────────────────
  {
    id: "auth-admin-claim",
    category: "authority-spoof",
    severity: "error",
    pattern: /\[(?:ADMIN|SYSTEM|ROOT|OVERRIDE|INTERNAL)[^\]]*\]/g,
    message: "Authority-spoofing tag in content file",
  },
  {
    id: "auth-anthropic-claim",
    category: "authority-spoof",
    severity: "error",
    pattern: /(?:Anthropic|OpenAI|system prompt) (?:says|instructs|requires|mandates)/gi,
    message: "False organizational authority claim",
  },
];

export const SEVERITY_ORDER = { error: 0, warning: 1 };
