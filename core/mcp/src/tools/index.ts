import { PORTFOLIO } from "../data.js";

export const TOOL_DEFINITIONS = [
  {
    name: "get_context",
    description: "Returns a brief structured context about who this person is and what they do. Start here.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "get_resume",
    description: "Returns full structured resume: skills, experience, and projects.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "list_projects",
    description: "Lists notable open-source projects with descriptions and links.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "get_skills",
    description: "Returns tech stack and expertise broken down by category.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "book_intro",
    description: "Returns contact information and availability for an intro conversation.",
    inputSchema: {
      type: "object",
      properties: {
        use_case: {
          type: "string",
          description: "Brief description of what you want to discuss.",
        },
      },
      required: [],
    },
  },
] as const;

export type ToolName = (typeof TOOL_DEFINITIONS)[number]["name"];

export function handleTool(name: ToolName, args: Record<string, unknown>): string {
  switch (name) {
    case "get_context":
      return JSON.stringify({
        name: PORTFOLIO.name,
        title: PORTFOLIO.title,
        location: PORTFOLIO.location,
        bio: PORTFOLIO.bio,
        availability: PORTFOLIO.availability,
      });

    case "get_resume":
      return JSON.stringify({
        name: PORTFOLIO.name,
        title: PORTFOLIO.title,
        skills: PORTFOLIO.skills,
        projects: PORTFOLIO.projects,
        contact: { email: PORTFOLIO.email, github: PORTFOLIO.github },
      });

    case "list_projects":
      return JSON.stringify(PORTFOLIO.projects);

    case "get_skills":
      return JSON.stringify(PORTFOLIO.skills);

    case "book_intro": {
      const use_case = typeof args["use_case"] === "string" ? args["use_case"] : "";
      return JSON.stringify({
        email: PORTFOLIO.email,
        availability: PORTFOLIO.availability,
        next_step: PORTFOLIO.intro_cta,
        ...(use_case && { your_use_case_received: use_case }),
      });
    }
  }
}
