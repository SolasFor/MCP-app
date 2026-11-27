---
name: mcp-app-audit
description: Use when the owner requests a full audit, security/stability review, Windows startup/ACL regression, release readiness, or broad maintenance of MCP App. Follow the repository audit plan and verify findings before minimal fixes.
---

# MCP App audit

1. Read AGENTS.md and docs/maintenance-audit.md. Check git status, current branch, pyproject.toml, PROGRESS.md and applicable CI. Work in the selected feature worktree; never switch to main silently.
2. Maintain a checklist by P0/P1/P2 and a short findings ledger with evidence (file/line, reproduction, impact, fix, test). Treat previous PASS entries as historical, not fresh results.
3. Start with Windows startup/ACL: trace app/gui.py, app/platform/windows.py, app/paths.py, secret and extension stores, all restrict_path_acl callsites, and packaging. Test only disposable data and normal-user execution. Do not delete vaults or modify real ACLs. A mocked environment-name collision is not a real same-name Windows-account reproduction.
4. Follow the audit matrix sequentially. For each area: inspect relevant modules and existing tests, reproduce a failure if found, make a minimal compatible patch, add a regression test, and run targeted checks. Avoid speculative refactors. Use local Git, Ruff, mypy and unittest first.
5. Use installed skills selectively: Ponytail (if available) for minimal patches; Superpowers systematic-debugging/TDD for difficult findings; Context7 for unfamiliar APIs; Cloudflare documentation for tunnel work; Chrome DevTools for OAuth browser checks; UI/UX Pro Max or Impeccable/Break UI for PyQt6 usability. Never let a web design skill override DESIGN.md or native Qt constraints.
6. Use SonarQube Cloud Quality Gate for PR review; local scanner is optional and requires verified CLI authentication and runtime; see the SonarQube section of the audit plan. If unavailable, mark BLOCKED and continue local checks. Do not transmit source or secrets without approval.
7. Do not spawn Swarm, Boost, Teamwork or independent subagents unless the owner explicitly authorizes them. One selected model or the built-in Orchestrator is sufficient. Preserve security checks; do not broaden permissions to get tests passing.
8. Run the final CI-equivalent checks once, including full unit/integration tests, dependency audit and Windows build/EXE checks when available. Separate real launch/upgrade tests from selftest. Mark inaccessible external systems or devices BLOCKED and unexecuted checks NOT_RUN.
9. Update PROGRESS.md with evidence, residual risk, changed files and next action. Provide a concise audit report and review the diff. No main merge, release, real DNS/ACL changes or external source uploads without approval.

Next-cycle scope: use ROADMAP.md N01/N13 and docs/acceptance-criteria.md; historical completed milestones are not restarted. Do not implement during N00. Follow docs/antigravity-workflow.md for selected model or orchestrator.
