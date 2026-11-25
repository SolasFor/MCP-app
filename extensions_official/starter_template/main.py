"""Minimal starter extension template built with MCP-app Extension SDK v1.0."""
from __future__ import annotations

from typing import Any

from backend.extensions.sdk import ExtensionApp

app = ExtensionApp("starter_template", "1.0.0")


@app.tool("ping", description="Echo a note and confirm data directory persistence.")
def ping(note: str = "pong") -> dict[str, Any]:
    return {"extension": app.extension_id, "version": app.version, "note": note, "data_dir": str(app.data_dir)}


@app.ui_provider()
def describe_ui() -> dict[str, Any]:
    return {"status": "ready"}


if __name__ == "__main__":
    raise SystemExit(app.run_stdio())
