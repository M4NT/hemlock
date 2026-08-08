#!/usr/bin/env node
import { writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { renderLlmsTxt, renderAgentsMd, type AeoConfig } from "./templates.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "../../../");

const config: AeoConfig = {
  name: "M4NT",
  title: "AI Security Engineer & Agent Infrastructure",
  bio: "Builder of agent security infrastructure. Focused on prompt injection defense, MCP fleet auditing, RAG attack/defense pipelines, and Agent-First system design.",
  email: "ti@multipli.com.br",
  github: "https://github.com/M4NT",
  siteUrl: "https://hemlock.dev",
  mcpEndpoint: "https://hemlock.dev/api/mcp",
  skills: {
    security: ["prompt injection", "RAG red-teaming", "MCP auditing", "agent threat modeling", "SARIF"],
    infra: ["Python", "TypeScript", "FastAPI", "MCP protocol", "JSON-RPC 2.0"],
    ai: ["LangChain", "ChromaDB", "Claude API", "tool-use agents", "multi-agent pipelines"],
  },
  projects: [
    {
      name: "hemlock",
      description: "AI security lab — attack and defense testing for RAG pipelines and tool-using agents",
      url: "https://github.com/M4NT/hemlock",
      tags: ["security", "red-team", "mcp", "rag"],
    },
  ],
  availability: "Open to consulting on agent security architecture and MCP infrastructure.",
};

function write(relPath: string, content: string) {
  const abs = resolve(ROOT, relPath);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, content, "utf8");
  console.log(`✓ ${relPath}`);
}

write("website/public/llms.txt", renderLlmsTxt(config));
write("AGENTS.md", renderAgentsMd(config));

console.log("\nAEO generation complete.");
