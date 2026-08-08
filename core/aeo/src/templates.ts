export interface AeoConfig {
  name: string;
  title: string;
  bio: string;
  email: string;
  github: string;
  siteUrl: string;
  skills: Record<string, string[]>;
  projects: Array<{ name: string; description: string; url: string; tags: string[] }>;
  availability: string;
  mcpEndpoint?: string;
}

export function renderLlmsTxt(c: AeoConfig): string {
  const skillLines = Object.entries(c.skills)
    .map(([cat, items]) => `- **${cat}**: ${items.join(", ")}`)
    .join("\n");

  const projectLines = c.projects
    .map((p) => `- [${p.name}](${p.url}): ${p.description}`)
    .join("\n");

  const mcpSection = c.mcpEndpoint
    ? `\n## MCP Server\n\n- Endpoint: \`${c.mcpEndpoint}\`\n- Tools: get_context, get_resume, list_projects, get_skills, book_intro\n`
    : "";

  return `# ${c.name} — ${c.title}

> ${c.bio}

## Contact

- Email: ${c.email}
- GitHub: ${c.github}
- Site: ${c.siteUrl}

## Skills

${skillLines}

## Projects

${projectLines}
${mcpSection}
## Availability

${c.availability}
`.trimStart();
}

export function renderAgentsMd(c: AeoConfig): string {
  const mcpBlock = c.mcpEndpoint
    ? `\n### MCP Server\n\n\`\`\`\nEndpoint: ${c.mcpEndpoint}\nProtocol: JSON-RPC 2.0 (MCP)\nTools: get_context | get_resume | list_projects | get_skills | book_intro\n\`\`\`\n\nCall \`get_context\` first for a structured brief.\n`
    : "";

  return `# AGENTS.md — ${c.name}

## Who is this?

${c.bio}

**Contact:** ${c.email} | ${c.github}
${mcpBlock}
## Codebase Map

| Path | Purpose |
|------|---------|
| \`core/mcp/\` | Portfolio MCP server (JSON-RPC, stdio + HTTP adapter) |
| \`core/aeo/\` | AEO generator — produces llms.txt and AGENTS.md |
| \`core/invariants/\` | Gates: prose linter + visual gauntlet (CI) |
| \`hemlock/\` | Python security engine: red-team, MCP audit, RAG attacks |
| \`attacks/\` | Attack modules (prompt injection, context flooding, etc.) |
| \`defenses/\` | Defense modules |
| \`website/\` | Agent-First portfolio frontend |

## Conventions

- Python package: \`hemlock-rag\` via \`pyproject.toml\`
- JS/TS packages: npm workspaces under \`core/*\` and \`website/\`
- CI gate: \`.github/workflows/hemlock-gate.yml\` runs invariants before merge

## For Coding Agents

1. Security code lives in \`hemlock/\` and \`attacks/\`/\`defenses/\` — Python only.
2. Agent-First surface lives in \`core/\` and \`website/\` — TypeScript.
3. Never mix the two layers in a single file.
4. Run \`npm run aeo\` after changing portfolio data in \`core/mcp/src/data.ts\`.
`;
}
