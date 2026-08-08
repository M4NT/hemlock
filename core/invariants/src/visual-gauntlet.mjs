#!/usr/bin/env node
/**
 * visual-gauntlet — headless screenshot diff against baseline
 *
 * Usage:
 *   node src/visual-gauntlet.mjs                    # run all routes
 *   node src/visual-gauntlet.mjs --update-baseline  # capture new baseline
 *   node src/visual-gauntlet.mjs --url http://...   # override base URL
 *
 * Config: .hemlock/gauntlet.json (created on first --update-baseline)
 * Baselines: .hemlock/visual-baseline/*.png
 *
 * Exit codes: 0 = pass, 1 = diff above threshold, 2 = baseline missing
 */

import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";

const ROOT = resolve(import.meta.dirname, "../../../");
const BASELINE_DIR = join(ROOT, ".hemlock/visual-baseline");
const CONFIG_PATH = join(ROOT, "core/invariants/gauntlet.json");

const UPDATE = process.argv.includes("--update-baseline");
const URL_ARG = (() => {
  const i = process.argv.indexOf("--url");
  return i !== -1 ? process.argv[i + 1] : null;
})();

// ── Default config ────────────────────────────────────────────────────────────

const DEFAULT_CONFIG = {
  baseUrl: "http://localhost:3000",
  threshold: 0.02,  // 2% pixel diff allowed
  viewport: { width: 1280, height: 800 },
  routes: [
    { path: "/", name: "home" },
    { path: "/llms.txt", name: "llms-txt" },
  ],
};

// ── Load config ───────────────────────────────────────────────────────────────

function loadConfig() {
  if (existsSync(CONFIG_PATH)) {
    return { ...DEFAULT_CONFIG, ...JSON.parse(readFileSync(CONFIG_PATH, "utf8")) };
  }
  return DEFAULT_CONFIG;
}

// ── Lazy import puppeteer (optional dep) ──────────────────────────────────────

async function getPuppeteer() {
  try {
    const { default: puppeteer } = await import("puppeteer");
    return puppeteer;
  } catch {
    console.error("puppeteer not installed. Run: npm install --workspace=core/invariants");
    process.exit(1);
  }
}

async function getPixelmatch() {
  try {
    const { default: pm } = await import("pixelmatch");
    const { PNG } = await import("pngjs");
    return { pixelmatch: pm, PNG };
  } catch {
    console.error("pixelmatch/pngjs not installed.");
    process.exit(1);
  }
}

// ── Screenshot ────────────────────────────────────────────────────────────────

async function screenshot(page, url, viewport) {
  await page.setViewport(viewport);
  await page.goto(url, { waitUntil: "networkidle0", timeout: 15_000 });
  return page.screenshot({ encoding: "binary", fullPage: false });
}

// ── Diff ──────────────────────────────────────────────────────────────────────

function diffPngs(baselineBuf, currentBuf, pixelmatch, PNG) {
  const baseline = PNG.sync.read(Buffer.from(baselineBuf));
  const current  = PNG.sync.read(Buffer.from(currentBuf));

  if (baseline.width !== current.width || baseline.height !== current.height) {
    return { ratio: 1, reason: `size mismatch: ${baseline.width}×${baseline.height} vs ${current.width}×${current.height}` };
  }

  const { width, height } = baseline;
  const diff = new PNG({ width, height });
  const pixels = pixelmatch(baseline.data, current.data, diff.data, width, height, {
    threshold: 0.1,
  });

  return { ratio: pixels / (width * height), diff };
}

// ── Main ──────────────────────────────────────────────────────────────────────

const RESET = "\x1b[0m";
const RED    = "\x1b[31m";
const GREEN  = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BOLD   = "\x1b[1m";
const GRAY   = "\x1b[90m";

async function run() {
  const config = loadConfig();
  if (URL_ARG) config.baseUrl = URL_ARG;

  mkdirSync(BASELINE_DIR, { recursive: true });

  const puppeteer = await getPuppeteer();
  const { pixelmatch, PNG } = await getPixelmatch();

  const browser = await puppeteer.launch({ headless: "new" });
  const page = await browser.newPage();

  console.log(`\n${BOLD}visual-gauntlet${RESET}  ${config.baseUrl}  ${UPDATE ? "(update mode)" : ""}\n`);

  const results = [];

  for (const route of config.routes) {
    const url = `${config.baseUrl}${route.path}`;
    const baselinePath = join(BASELINE_DIR, `${route.name}.png`);

    let buf;
    try {
      buf = await screenshot(page, url, config.viewport);
    } catch (e) {
      console.log(`  ${YELLOW}skip${RESET}  ${route.name}  ${GRAY}(${e.message})${RESET}`);
      results.push({ name: route.name, status: "skip" });
      continue;
    }

    if (UPDATE) {
      writeFileSync(baselinePath, buf);
      console.log(`  ${GREEN}saved${RESET} ${route.name} → ${route.name}.png`);
      results.push({ name: route.name, status: "saved" });
      continue;
    }

    if (!existsSync(baselinePath)) {
      console.log(`  ${YELLOW} new ${RESET} ${route.name}  ${GRAY}no baseline — run with --update-baseline${RESET}`);
      results.push({ name: route.name, status: "no-baseline" });
      continue;
    }

    const baseline = readFileSync(baselinePath);
    const { ratio, reason } = diffPngs(baseline, buf, pixelmatch, PNG);
    const pct = (ratio * 100).toFixed(2);

    if (ratio > config.threshold) {
      console.log(`  ${RED}fail${RESET}  ${route.name}  ${RED}${pct}% diff${RESET}  (threshold: ${(config.threshold * 100).toFixed(0)}%)`);
      if (reason) console.log(`         ${GRAY}${reason}${RESET}`);
      results.push({ name: route.name, status: "fail", diff: ratio });
    } else {
      console.log(`  ${GREEN}pass${RESET}  ${route.name}  ${GRAY}${pct}% diff${RESET}`);
      results.push({ name: route.name, status: "pass", diff: ratio });
    }
  }

  await browser.close();

  console.log();

  const failed = results.filter((r) => r.status === "fail");
  const missing = results.filter((r) => r.status === "no-baseline");

  if (UPDATE) {
    console.log(`${GREEN}✓${RESET}  baseline updated for ${results.length} route(s)\n`);
    process.exit(0);
  }

  if (missing.length > 0) {
    console.log(`${YELLOW}!${RESET}  ${missing.length} route(s) missing baseline — run with --update-baseline\n`);
    process.exit(2);
  }

  if (failed.length > 0) {
    console.log(`${RED}✗${RESET}  ${failed.length} route(s) failed visual diff\n`);
    process.exit(1);
  }

  console.log(`${GREEN}✓${RESET}  all routes within threshold\n`);
  process.exit(0);
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
