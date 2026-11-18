---
title: What is CAIPE Sandbox?
description: Run AI agents in configurable, isolated cloud micro VMs, managed by your platform team.
---

CAIPE Sandbox is a flexible, highly configurable way to run AI agents securely
in cloud-hosted micro VMs. It gives platform engineers a way to provide managed,
isolated environments where developers can run their agents, use their own
credentials and access the tools they need.

Developers choose an environment, connect to it and get to work. Platform teams
control the available configurations, resource limits, access and isolation.

![CAIPE Sandbox portal showing micro VM cards, integration badges, sign-in helpers and terminal access](../static/img/portal-preview.png)

_Example portal with sample data. Your platform team chooses the available profiles and integrations._

## Why sandbox agents?

Agents become much more capable when they can use a shell, run compilers,
install dependencies, edit files and call other tools. That access lets them
build, test and carry out real engineering work.

Giving an agent that access on a developer's laptop or a shared machine carries
risk. An unsafe command, an agent mistake or a malicious instruction can damage
files, expose credentials or interfere with someone else's work.

CAIPE Sandbox moves that execution into dedicated cloud environments. A micro VM
provides a separate execution boundary, while platform controls govern resources,
access and network connectivity. Developers get the tools their agents need
within boundaries managed by their platform team.

## For developers

- **Run your agents and tools.** Choose a profile with the images, tools and
  starting configuration your team provides.
- **Use your own credentials.** Sign in to development tools from inside your
  micro VM using their normal login flows.
- **Connect to your environment.** Open a browser terminal to work with your
  agents, or use tool-specific connections when configured.
- **Match resources to the work.** Choose CPU, memory and storage within the
  limits set by your platform team. Suspend compute when you are done and resume
  later with your persistent files.

## For platform engineers

- **Offer environments that fit your organisation.** Define profiles with
  approved images, startup configuration, tools and resource choices.
- **Set the boundaries.** Configure identity, ownership, sharing, quotas and
  runtime and network policies.
- **Manage centrally.** Provision and manage sandbox lifecycles on Kubernetes,
  with visibility into configuration and runtime status.
- **Choose the underlying technology.** Configure runtime integrations and
  platform services to suit your cluster and security requirements.

Kata provides the micro VM isolation boundary. Integrations such as OpenShell can
add process and network policy, alongside Kubernetes and platform controls.
The selected runtime and deployment configuration determine the protections;
see [Security](security.md) for how these boundaries are enforced.

## Explore CAIPE Sandbox

- [Get started](getting-started.md): deploy the portal and verify your first sandbox.
- [Profiles and configuration](profiles.md): understand how environments are customised.
- [System architecture](architecture.mdx): see the components and their responsibilities.
- [Deployment and packaging](packaging.md): install the platform and choose its integrations,
  including ordinary-container deployments for development and testing.
