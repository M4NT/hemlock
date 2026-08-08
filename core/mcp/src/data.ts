export const PORTFOLIO = {
  name: "M4NT",
  title: "AI Security Engineer & Agent Infrastructure",
  location: "Brazil",
  email: "ti@multipli.com.br",
  github: "https://github.com/M4NT",

  bio: "Builder of agent security infrastructure. Focused on prompt injection defense, MCP fleet auditing, RAG attack/defense pipelines, and Agent-First system design.",

  skills: {
    security: ["prompt injection", "RAG red-teaming", "MCP auditing", "agent threat modeling", "SARIF reporting"],
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

  intro_cta: "Reply with your use case and I'll respond within 48h.",
} as const;

export type Portfolio = typeof PORTFOLIO;
