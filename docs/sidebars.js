module.exports = {
  guide: [
    "overview",
    "concepts",
    "getting-started",
    {
      type: "category",
      label: "Configuration",
      items: [
        "profiles",
        "profile-fields",
        "helm-values",
        "environment-variables",
        "saved-state",
        "configuration-example",
      ],
    },
    {
      type: "category",
      label: "Architecture",
      items: [
        "architecture",
        "code-map",
        "metadata",
        "security",
        "caipe-embedding",
      ],
    },
    {
      type: "category",
      label: "Operate",
      items: [
        "deployment",
        {
          type: "category",
          label: "Authentication & SSO",
          link: { type: "doc", id: "authentication" },
          items: [
            "authentication-keycloak",
            "authentication-okta",
            "mcp-authentication",
          ],
        },
        "packaging",
        "scaling",
        {
          type: "category",
          label: "MCP",
          link: { type: "doc", id: "mcp" },
          items: [
            "mcp-clients",
            "mcp-codex-cli",
            "mcp-claude-cli",
            "mcp-chatgpt-app",
            "mcp-codex-app",
            "mcp-claude-app",
          ],
        },
        "contributing",
      ],
    },
  ],
};
