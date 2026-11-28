"""Bounded static safe YAML subset parser for Docker Compose and pnpm-workspace manifests.

Security invariants:
- Pure static text parsing with strict byte, line, node, and nesting bounds.
- Rejects YAML tags (! / !!), anchors (&), aliases (*), merge keys (<<), multi-document
  streams, tab indentation, duplicate mapping keys, top-level include, and external extends.
- Never expands ${VAR} interpolations and never reads or returns environment/env_file values.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

DEFAULT_MAX_YAML_BYTES = 128 * 1024
DEFAULT_MAX_YAML_LINES = 2000
DEFAULT_MAX_YAML_NODES = 1000
DEFAULT_MAX_YAML_DEPTH = 16

_SENSITIVE_KEY_NAMES = frozenset({"environment", "env_file", "secrets"})
_UNQUOTED_TAG_RE = re.compile(r"(?:^|\s)!(?:!|[A-Za-z0-9_./:-]+)")
_ANCHOR_OR_ALIAS_RE = re.compile(r"(?:^|\s)[&*][A-Za-z0-9_.-]+")
_PORT_INT_RE = re.compile(r"^\d{1,5}$")
_BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?\d*$")


class ComposeYamlError(ValueError):
    """Raised when a YAML manifest is malformed or exceeds structural bounds."""


class ComposeYamlSecurityError(ComposeYamlError):
    """Raised when a YAML manifest uses disallowed tags, anchors, aliases, or external refs."""


@dataclass(frozen=True)
class ComposeServiceSummary:
    """Safe static summary of one Docker Compose service (no secret/env values)."""

    name: str
    ports: tuple[int, ...] = ()
    has_environment: bool = False
    has_env_file: bool = False
    source_file: str = "compose.yaml"


@dataclass(frozen=True)
class ComposeStaticSummary:
    """Bounded static summary of a Compose file."""

    services: tuple[ComposeServiceSummary, ...] = ()
    has_top_level_env_file: bool = False
    warnings: tuple[str, ...] = ()


@dataclass
class _ParserState:
    lines: list[str]
    idx: int = 0
    nodes: int = 0
    max_nodes: int = DEFAULT_MAX_YAML_NODES
    max_depth: int = DEFAULT_MAX_YAML_DEPTH

    def bump_node(self) -> None:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise ComposeYamlError(f"YAML exceeds maximum node budget ({self.max_nodes})")


@dataclass
class _QuoteScanState:
    in_single: bool = False
    in_double: bool = False
    escaped: bool = False
    depth: int = 0

    def step(self, ch: str) -> bool:
        """Advance quote/escape state; return True when `ch` is at unquoted top level."""
        if self.escaped:
            self.escaped = False
            return False
        if self.in_double:
            if ch == "\\":
                self.escaped = True
            elif ch == '"':
                self.in_double = False
            return False
        if self.in_single:
            if ch == "'":
                self.in_single = False
            return False
        if ch == "'":
            self.in_single = True
            return False
        if ch == '"':
            self.in_double = True
            return False
        return True


def _strip_comment(line: str) -> str:
    st = _QuoteScanState()
    for pos, ch in enumerate(line):
        if st.step(ch) and ch == "#" and (pos == 0 or line[pos - 1].isspace()):
            return line[:pos].rstrip()
    return line.rstrip()


def _check_unsafe_tokens(stripped: str) -> None:
    if stripped in ("---", "..."):
        return
    if stripped.startswith("%"):
        raise ComposeYamlSecurityError("YAML directives are forbidden")
    if stripped.startswith(("'", '"')):
        return
    if _UNQUOTED_TAG_RE.search(stripped):
        raise ComposeYamlSecurityError("YAML tags (! / !!) are forbidden")
    if _ANCHOR_OR_ALIAS_RE.search(stripped):
        raise ComposeYamlSecurityError("YAML anchors (&) and aliases (*) are forbidden")


def _unquote_scalar(raw: str) -> str:
    s = raw.strip()
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1].replace("''", "'")
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        inner = s[1:-1]
        return (
            inner.replace('\\"', '"')
            .replace("\\\\", "\\")
            .replace("\\n", "\n")
            .replace("\\t", "\t")
        )
    return s


def _split_key_value(content: str) -> tuple[str, str | None]:
    st = _QuoteScanState()
    for pos, ch in enumerate(content):
        if st.step(ch) and ch == ":" and (pos + 1 == len(content) or content[pos + 1].isspace()):
            key_raw = content[:pos].strip()
            rest = content[pos + 1 :].strip()
            if not key_raw:
                raise ComposeYamlError("Empty mapping key in YAML")
            key = _unquote_scalar(key_raw)
            if key == "<<":
                raise ComposeYamlSecurityError("YAML merge key '<<' is forbidden")
            return key, rest
    return "", None


def _flow_step_char(st: _QuoteScanState, ch: str, sep: str) -> bool:
    if not st.step(ch):
        return False
    if ch in ("[", "{"):
        st.depth += 1
        return False
    if ch in ("]", "}"):
        st.depth = max(0, st.depth - 1)
        return False
    return ch == sep and st.depth == 0


def _split_flow_items(inner: str, sep: str = ",") -> list[str]:
    items: list[str] = []
    buf: list[str] = []
    st = _QuoteScanState()
    for ch in inner:
        if _flow_step_char(st, ch, sep):
            if part := "".join(buf).strip():
                items.append(part)
            buf.clear()
        else:
            buf.append(ch)
    if tail := "".join(buf).strip():
        items.append(tail)
    return items


def _parse_flow_dict(inner: str, state: _ParserState, depth: int, *, redact_values: bool) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in _split_flow_items(inner):
        k, rest = _split_key_value(item)
        if rest is None:
            raise ComposeYamlError("Malformed inline YAML mapping entry")
        if k in out:
            raise ComposeYamlSecurityError(f"Duplicate YAML mapping key: {k!r}")
        out[k] = _parse_inline_value(
            rest, state, depth + 1, redact_values=redact_values or (k in _SENSITIVE_KEY_NAMES)
        )
    return out


def _parse_scalar_atom(val: str) -> Any:
    low = val.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"-?\d+", val):
        return int(val)
    return _unquote_scalar(val)


def _parse_inline_value(raw: str, state: _ParserState, depth: int, *, redact_values: bool) -> Any:
    if depth > state.max_depth:
        raise ComposeYamlError(f"YAML exceeds maximum nesting depth ({state.max_depth})")
    val = raw.strip()
    _check_unsafe_tokens(val)
    state.bump_node()
    if not val or val in ("null", "~"):
        return None
    if val.startswith("[") and val.endswith("]"):
        return [
            _parse_inline_value(item, state, depth + 1, redact_values=redact_values)
            for item in _split_flow_items(val[1:-1])
        ]
    if val.startswith("{") and val.endswith("}"):
        return _parse_flow_dict(val[1:-1], state, depth, redact_values=redact_values)
    if redact_values:
        return "[REDACTED]"
    return _parse_scalar_atom(val)


def _skip_block_scalar(state: _ParserState, parent_indent: int) -> None:
    while state.idx < len(state.lines):
        line = state.lines[state.idx]
        if not line.strip():
            state.idx += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= parent_indent:
            return
        state.bump_node()
        state.idx += 1


def _next_significant(state: _ParserState) -> tuple[int, str] | None:
    while state.idx < len(state.lines):
        raw = state.lines[state.idx]
        if "\t" in raw[: len(raw) - len(raw.lstrip(" \t"))]:
            raise ComposeYamlSecurityError("Tab indentation is forbidden in YAML")
        cleaned = _strip_comment(raw)
        if not cleaned.strip():
            state.idx += 1
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        stripped = cleaned[indent:]
        _check_unsafe_tokens(stripped)
        if stripped in ("---", "..."):
            state.idx += 1
            continue
        return indent, stripped
    return None


def _parse_block(state: _ParserState, min_indent: int, depth: int, *, redact_values: bool) -> Any:
    if depth > state.max_depth:
        raise ComposeYamlError(f"YAML exceeds maximum nesting depth ({state.max_depth})")
    nxt = _next_significant(state)
    if nxt is None:
        return None
    indent, stripped = nxt
    if indent < min_indent:
        return None
    if stripped.startswith("- ") or stripped == "-":
        return _parse_list(state, indent, depth, redact_values=redact_values)
    _k, rest = _split_key_value(stripped)
    if rest is not None:
        return _parse_mapping(state, indent, depth, redact_values=redact_values)
    state.idx += 1
    return _parse_inline_value(stripped, state, depth, redact_values=redact_values)


def _parse_value_after_key(
    state: _ParserState,
    rest: str,
    child_indent: int,
    scalar_parent_indent: int,
    depth: int,
    *,
    redact_values: bool,
) -> Any:
    if not rest:
        return _parse_block(state, child_indent, depth + 1, redact_values=redact_values)
    if _BLOCK_SCALAR_RE.fullmatch(rest):
        _skip_block_scalar(state, scalar_parent_indent)
        return "[REDACTED]" if redact_values else ""
    return _parse_inline_value(rest, state, depth + 1, redact_values=redact_values)


def _parse_list_item(
    state: _ParserState,
    after: str,
    list_indent: int,
    depth: int,
    *,
    redact_values: bool,
) -> Any:
    if not after:
        return _parse_block(state, list_indent + 1, depth + 1, redact_values=redact_values)
    if _BLOCK_SCALAR_RE.fullmatch(after):
        _skip_block_scalar(state, list_indent)
        return "[REDACTED]" if redact_values else ""
    k, rest = _split_key_value(after)
    if rest is None:
        return _parse_inline_value(after, state, depth + 1, redact_values=redact_values)
    item_map: dict[str, Any] = {}
    child_redact = redact_values or (k in _SENSITIVE_KEY_NAMES)
    item_map[k] = _parse_value_after_key(
        state, rest, list_indent + 2, list_indent + 1, depth, redact_values=child_redact
    )
    extra = _parse_mapping(
        state, list_indent + 2, depth + 1, redact_values=redact_values, allow_miss=True
    )
    for ek, ev in extra.items():
        if ek in item_map:
            raise ComposeYamlSecurityError(f"Duplicate YAML mapping key: {ek!r}")
        item_map[ek] = ev
    return item_map


def _parse_list(
    state: _ParserState, list_indent: int, depth: int, *, redact_values: bool
) -> list[Any]:
    items: list[Any] = []
    while True:
        nxt = _next_significant(state)
        if nxt is None:
            break
        indent, stripped = nxt
        if indent < list_indent:
            break
        if indent > list_indent:
            raise ComposeYamlError("Unexpected indentation inside YAML list")
        if not (stripped.startswith("- ") or stripped == "-"):
            break
        state.bump_node()
        state.idx += 1
        items.append(
            _parse_list_item(state, stripped[1:].strip(), list_indent, depth, redact_values=redact_values)
        )
    return items


def _validate_mapping_line(
    nxt: tuple[int, str] | None,
    map_indent: int,
    mapping: dict[str, Any],
    allow_miss: bool,
) -> tuple[str, str] | None:
    if nxt is None:
        return None
    indent, stripped = nxt
    if indent < map_indent:
        return None
    if indent > map_indent:
        if allow_miss and not mapping:
            return None
        raise ComposeYamlError("Unexpected indentation inside YAML mapping")
    if stripped.startswith("- ") or stripped == "-":
        return None
    k, rest = _split_key_value(stripped)
    if rest is None:
        raise ComposeYamlError(f"Expected key:value mapping line, got {stripped!r}")
    if k in mapping:
        raise ComposeYamlSecurityError(f"Duplicate YAML mapping key: {k!r}")
    return k, rest


def _parse_mapping(
    state: _ParserState,
    map_indent: int,
    depth: int,
    *,
    redact_values: bool,
    allow_miss: bool = False,
) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    while (entry := _validate_mapping_line(_next_significant(state), map_indent, mapping, allow_miss)) is not None:
        k, rest = entry
        state.bump_node()
        state.idx += 1
        child_redact = redact_values or (k in _SENSITIVE_KEY_NAMES)
        mapping[k] = _parse_value_after_key(
            state, rest, map_indent + 1, map_indent, depth, redact_values=child_redact
        )
    return mapping


def _preprocess_lines(text: str, *, max_bytes: int, max_lines: int) -> list[str]:
    if "\x00" in text:
        raise ComposeYamlSecurityError("NUL byte is forbidden in YAML")
    raw_bytes = text.encode("utf-8", errors="replace")
    if len(raw_bytes) > max_bytes:
        raise ComposeYamlError(f"YAML exceeds size limit ({len(raw_bytes)} > {max_bytes} bytes)")
    lines = text.splitlines()
    if len(lines) > max_lines:
        raise ComposeYamlError(f"YAML exceeds line limit ({len(lines)} > {max_lines})")
    doc_markers = 0
    seen_content = False
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s == "---":
            doc_markers += 1
            if seen_content or doc_markers > 1:
                raise ComposeYamlSecurityError("Multi-document YAML streams are forbidden")
        else:
            seen_content = True
    return lines


def parse_safe_yaml_mapping(
    text: str,
    *,
    max_bytes: int = DEFAULT_MAX_YAML_BYTES,
    max_lines: int = DEFAULT_MAX_YAML_LINES,
    max_nodes: int = DEFAULT_MAX_YAML_NODES,
    max_depth: int = DEFAULT_MAX_YAML_DEPTH,
) -> dict[str, Any]:
    """Parse a bounded safe YAML subset into a dict while redacting env/secret values."""
    lines = _preprocess_lines(text, max_bytes=max_bytes, max_lines=max_lines)
    state = _ParserState(lines=lines, max_nodes=max_nodes, max_depth=max_depth)
    parsed = _parse_block(state, 0, 1, redact_values=False)
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ComposeYamlError("Top-level YAML value must be a mapping")
    return parsed


def _is_external_ref(raw_path: str) -> bool:
    norm = raw_path.strip().replace("\\", "/")
    if not norm:
        return False
    if norm.startswith("/") or ":" in norm:
        return True
    return ".." in PurePosixPath(norm).parts


def _valid_port_num(num: int) -> int | None:
    return num if 1 <= num <= 65535 else None


def _extract_dict_port(entry: dict[str, Any]) -> int | None:
    pub = entry.get("published")
    if isinstance(pub, int) and not isinstance(pub, bool):
        return _valid_port_num(pub)
    if isinstance(pub, str) and _PORT_INT_RE.fullmatch(pub.strip()):
        return _valid_port_num(int(pub.strip()))
    return None


def _extract_str_port(entry: str) -> int | None:
    s = entry.strip().split("/", 1)[0]
    if "$" in s:
        return None
    parts = s.split(":")
    candidate = parts[1] if len(parts) == 3 else (parts[0] if len(parts) in (1, 2) else "")
    return _valid_port_num(int(candidate)) if _PORT_INT_RE.fullmatch(candidate) else None


def _extract_static_port(entry: Any) -> int | None:
    if isinstance(entry, dict):
        return _extract_dict_port(entry)
    if isinstance(entry, int) and not isinstance(entry, bool):
        return _valid_port_num(entry)
    if isinstance(entry, str):
        return _extract_str_port(entry)
    return None


def _check_service_extends(svc_name: str, ext: Any) -> None:
    if isinstance(ext, str) and _is_external_ref(ext):
        raise ComposeYamlSecurityError(f"External compose 'extends' path rejected for service {svc_name!r}")
    if isinstance(ext, dict) and str(ext.get("file") or ""):
        raise ComposeYamlSecurityError(f"External compose 'extends.file' rejected for service {svc_name!r}")


def _summarize_compose_service(
    svc_name: str,
    svc_cfg: dict[str, Any],
    source_file: str,
    warnings: list[str],
) -> ComposeServiceSummary:
    _check_service_extends(svc_name, svc_cfg.get("extends"))
    ports: list[int] = []
    raw_ports = svc_cfg.get("ports")
    if isinstance(raw_ports, list):
        for p_entry in raw_ports:
            parsed_port = _extract_static_port(p_entry)
            if parsed_port is not None and parsed_port not in ports:
                ports.append(parsed_port)
    has_env = "environment" in svc_cfg
    has_env_file = "env_file" in svc_cfg
    if has_env or has_env_file:
        warnings.append(f"{source_file}#{svc_name}: environment/env_file values are not read or expanded")
    return ComposeServiceSummary(
        name=str(svc_name),
        ports=tuple(ports),
        has_environment=has_env,
        has_env_file=has_env_file,
        source_file=source_file,
    )


def parse_safe_compose_yaml(
    text: str,
    *,
    source_file: str = "compose.yaml",
    max_bytes: int = DEFAULT_MAX_YAML_BYTES,
    max_lines: int = DEFAULT_MAX_YAML_LINES,
    max_nodes: int = DEFAULT_MAX_YAML_NODES,
    max_depth: int = DEFAULT_MAX_YAML_DEPTH,
) -> ComposeStaticSummary:
    """Safely extract Docker Compose services and static literal ports without env expansion."""
    doc = parse_safe_yaml_mapping(
        text,
        max_bytes=max_bytes,
        max_lines=max_lines,
        max_nodes=max_nodes,
        max_depth=max_depth,
    )
    if "include" in doc:
        raise ComposeYamlSecurityError("Docker Compose top-level 'include' is forbidden in static discovery")
    warnings: list[str] = []
    has_top_env = "env_file" in doc
    if has_top_env:
        warnings.append(f"{source_file}: env_file references detected (not read)")

    raw_services = doc.get("services")
    if raw_services is None:
        return ComposeStaticSummary(services=(), has_top_level_env_file=has_top_env, warnings=tuple(warnings))
    if not isinstance(raw_services, dict):
        raise ComposeYamlError("Docker Compose 'services' must be a mapping")

    summaries = [
        _summarize_compose_service(str(svc_name), svc_cfg, source_file, warnings)
        for svc_name, svc_cfg in raw_services.items()
        if isinstance(svc_cfg, dict)
    ]
    return ComposeStaticSummary(
        services=tuple(summaries),
        has_top_level_env_file=has_top_env,
        warnings=tuple(warnings),
    )
