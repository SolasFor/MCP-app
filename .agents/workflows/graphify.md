---
name: graphify
description: Build or refresh the local AST-only code graph for MCP App.
---

Run from the current MCP App worktree only. Read AGENTS.md and .graphifyignore; verify exclusions and no unexpected reparse points. Run graphify update . (use the installed CLI, no API keys or additional agents). Report success and graph location, or fall back to direct source search. Do not run the full semantic/LLM pipeline, cloud sync or arbitrary external paths.
