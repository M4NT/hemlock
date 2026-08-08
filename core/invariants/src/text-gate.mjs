#!/usr/bin/env node
/**
 * text-gate — prose linter for content files
 *
 * Usage:
 *   node src/text-gate.mjs [glob...]          # lint specific files
 *   node src/text-gate.mjs                    # lint default targets
 *   node src/text-gate.mjs --warn-only        # exit 0 even on errors (CI dry-run)
 *
 * Exit codes: 0 = clean, 1 = errors found, 2 = no files matched
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve, relative } from "node:path";
import { globSync } from "node:fs";
import { RULES } from "./rules.mjs";

// ── Config ────────────────────────────────────────────────────────────────────

const ROOT = resolve(import.meta.dirname, "../../../");
const WARN_ONLY = process.argv.includes("--warn-only");

const DEFAULT_TARGETS = [
  "website/public/**/*.txt",
  "website/src/**/*.{md,mdx,html,astro}",
  "AGENTS.md",
  "*.md",
  "docs/**/*.md",
];

const ALWAYS_SKIP = [
  "node_modules",
  ".git",
  "dist",
  ".hemlock",
  "core/invariants/src/rules.mjs", // rules file contains the patterns intentionally
];

// ── Lint engine ───────────────────────────────────────────────────────────────

/** Build a set of line indexes that are inside code fences (``` or ~~~) or indented code blocks. */
function buildCodeLineSet(lines, isMd) {
  const skipped = new Set();
  if (!isMd) return skipped;
  let inFence = false;
  let fenceMarker = "";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!inFence) {
      const m = line.match(/^(`{3,}|~{3,})/);
      if (m) { inFence = true; fenceMarker = m[1][0].repeat(m[1].length); skipped.add(i); continue; }
    } else {
      skipped.add(i);
      if (line.startsWith(fenceMarker)) { inFence = false; fenceMarker = ""; }
      continue;
    }
    // 4-space / tab indented code
    if (/^(?:    |\t)/.test(line)) skipped.add(i);
  }
  return skipped;
}

function lintFile(absPath) {
  let content;
  try {
    content = readFileSync(absPath, "utf8");
  } catch {
    return [];
  }

  const isMd = absPath.endsWith(".md") || absPath.endsWith(".mdx");
  const findings = [];
  const lines = content.split("\n");
  const codeLines = buildCodeLineSet(lines, isMd);

  for (const rule of RULES) {
    for (let i = 0; i < lines.length; i++) {
      // Skip inline code and fenced blocks in markdown docs
      if (codeLines.has(i)) continue;
      // Skip lines with text-gate-ignore annotation
      if (lines[i].includes("text-gate-ignore")) continue;
      // Mask inline code spans so patterns inside `code` don't fire
      const scanLine = isMd ? lines[i].replace(/`[^`]+`/g, (m) => " ".repeat(m.length)) : lines[i];
      rule.pattern.lastIndex = 0;
      const match = rule.pattern.exec(scanLine);
      if (match) {
        findings.push({
          file: relative(ROOT, absPath),
          line: i + 1,
          col: match.index + 1,
          rule: rule.id,
          category: rule.category,
          severity: rule.severity,
          message: rule.message,
          excerpt: lines[i].trim().slice(0, 120),
        });
      }
    }
  }

  return findings;
}

function resolveTargets(patterns) {
  const files = new Set();
  for (const pattern of patterns) {
    try {
      const matches = globSync(pattern, { cwd: ROOT, absolute: true });
      for (const f of matches) {
        if (!ALWAYS_SKIP.some((s) => f.includes(s))) files.add(f);
      }
    } catch {
      // pattern produced no matches
    }
  }
  return [...files];
}

// ── Output ────────────────────────────────────────────────────────────────────

const RESET = "\x1b[0m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const GRAY = "\x1b[90m";
const BOLD = "\x1b[1m";
const GREEN = "\x1b[32m";

function fmt(finding) {
  const color = finding.severity === "error" ? RED : YELLOW;
  const tag = finding.severity === "error" ? "error" : " warn";
  console.log(
    `  ${color}${tag}${RESET}  ${GRAY}${finding.file}:${finding.line}:${finding.col}${RESET}  ${finding.message}`
  );
  if (finding.excerpt) {
    console.log(`         ${GRAY}${finding.excerpt}${RESET}`);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

const cliPatterns = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const patterns = cliPatterns.length > 0 ? cliPatterns : DEFAULT_TARGETS;
const files = resolveTargets(patterns);

if (files.length === 0) {
  console.log(`${YELLOW}text-gate${RESET}: no files matched`);
  process.exit(2);
}

console.log(`\n${BOLD}text-gate${RESET}  scanning ${files.length} file(s)\n`);

const allFindings = [];
for (const f of files) {
  allFindings.push(...lintFile(f));
}

if (allFindings.length === 0) {
  console.log(`${GREEN}✓${RESET}  clean — no issues found\n`);
  process.exit(0);
}

// Group by file
const byFile = {};
for (const f of allFindings) {
  (byFile[f.file] ??= []).push(f);
}

for (const [file, findings] of Object.entries(byFile)) {
  console.log(`${BOLD}${file}${RESET}`);
  for (const f of findings) fmt(f);
  console.log();
}

const errors = allFindings.filter((f) => f.severity === "error").length;
const warnings = allFindings.filter((f) => f.severity === "warning").length;

console.log(
  `${errors > 0 ? RED : YELLOW}${errors} error(s)${RESET}, ${warnings} warning(s) — ${files.length} file(s) scanned\n`
);

process.exit(WARN_ONLY || errors === 0 ? 0 : 1);
