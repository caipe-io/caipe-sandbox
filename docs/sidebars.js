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
      items: ["deployment", "packaging", "scaling", "mcp", "contributing"],
    },
  ],
};
