---
description: Execute one approved MCP App roadmap stage with evidence and review
---

1. Read AGENTS.md, ROADMAP.md, PROGRESS.md, relevant criteria and scope.
2. Verify Git/worktree, stage prerequisites, baseline and owner authorization. Stop at N00 if implementation not authorized.
3. Select minimal necessary skills/MCP from docs/antigravity-workflow.md. Use read-only discovery and official docs.
4. Plan stage, threat model and negative tests; isolate branch/worktree. Preserve unrelated files.
5. Implement only approved stage, tests, migrations and docs. Run focused checks, full CI at gate.
6. Record evidence and risks in PROGRESS.md; review diff and create scoped commit/PR. Never bypass failed checks.
7. Stop at acceptance/release boundary for independent review. No automatic merge/release without explicit authorization.
