#!/usr/bin/env python3
"""Small declaration parser for hash-bound Rust secret-owner sources."""

from __future__ import annotations

import re
from pathlib import Path


class RustContractError(RuntimeError):
    """A registered Rust declaration differs from its reviewed contract."""


def fail(message: str) -> None:
    raise RustContractError(message)


def scrub(source: str) -> str:
    """Remove comments and literals while preserving braces and line layout."""
    output = list(source)
    index = 0
    state = "code"
    depth = 0
    while index < len(source):
        pair = source[index:index + 2]
        char = source[index]
        if state == "code" and pair == "//":
            state = "line"
            output[index:index + 2] = "  "
            index += 2
            continue
        if state == "code" and pair == "/*":
            state = "block"
            depth = 1
            output[index:index + 2] = "  "
            index += 2
            continue
        if state == "block" and pair == "/*":
            depth += 1
            output[index:index + 2] = "  "
            index += 2
            continue
        if state == "block" and pair == "*/":
            depth -= 1
            output[index:index + 2] = "  "
            index += 2
            if depth == 0:
                state = "code"
            continue
        if state == "line":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
            continue
        if state == "block":
            if char != "\n":
                output[index] = " "
            index += 1
            continue
        char_literal = char == "'" and re.match(r"'(?:\\.|[^\\'])'", source[index:])
        if state == "code" and (char == '"' or char_literal):
            state = "string" if char == '"' else "char"
            output[index] = " "
            index += 1
            continue
        if state in {"string", "char"}:
            if char == "\\":
                output[index] = " "
                if index + 1 < len(source):
                    output[index + 1] = " "
                index += 2
                continue
            terminator = '"' if state == "string" else "'"
            if char == terminator:
                state = "code"
            if char != "\n":
                output[index] = " "
            index += 1
            continue
        index += 1
    if state not in {"code", "line"}:
        fail("unterminated Rust comment or literal")
    return "".join(output)


def closing_brace(text: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    fail("unbalanced Rust declaration")


def declaration(text: str, name: str, kinds: set[str]) -> tuple[str, str]:
    pattern = re.compile(rf"\b(struct|enum|trait)\s+{re.escape(name)}\b[^;{{]*([;{{])")
    matches = [match for match in pattern.finditer(text) if match.group(1) in kinds]
    if len(matches) != 1:
        fail(f"Rust declaration {name} is absent, duplicated, or has the wrong kind")
    match = matches[0]
    if match.group(2) == ";":
        return match.group(1), ""
    opening = match.end() - 1
    return match.group(1), text[opening + 1:closing_brace(text, opening)]


def top_level_fields(body: str) -> set[str]:
    fields = set()
    start = 0
    depths = {"{": 0, "(": 0, "[": 0, "<": 0}
    pairs = {"}": "{", ")": "(", "]": "[", ">": "<"}
    parts = []
    for index, char in enumerate(body):
        if char in depths:
            depths[char] += 1
        elif char in pairs and depths[pairs[char]]:
            depths[pairs[char]] -= 1
        elif char == "," and not any(depths.values()):
            parts.append(body[start:index])
            start = index + 1
    parts.append(body[start:])
    for part in parts:
        match = re.search(r"(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:", part)
        if match:
            fields.add(match.group(1))
    return fields


def scope_bodies(text: str, owner: str) -> list[str]:
    bodies = []
    patterns = (
        re.compile(rf"\btrait\s+{re.escape(owner)}\b[^{{]*{{"),
        re.compile(rf"\bimpl\b[^{{;]*\b{re.escape(owner)}\b[^{{;]*{{"),
    )
    for pattern in patterns:
        for match in pattern.finditer(text):
            opening = match.end() - 1
            bodies.append(text[opening + 1:closing_brace(text, opening)])
    return bodies


def function_body(scope: str, name: str) -> str | None:
    pattern = re.compile(rf"\bfn\s+{re.escape(name)}\b[^;{{]*([;{{])")
    matches = list(pattern.finditer(scope))
    if len(matches) != 1:
        return None
    match = matches[0]
    if match.group(1) == ";":
        return ""
    opening = match.end() - 1
    return scope[opening + 1:closing_brace(scope, opening)]


def symbol_parts(target: str) -> tuple[Path, str, str | None]:
    path, symbol = target.split("#", 1)
    if "::" in symbol:
        owner, member = symbol.rsplit("::", 1)
        return Path(path), owner, member
    return Path(path), symbol, None


def validate_type(root: Path, target: str, expected_fields: set[str]) -> None:
    path, owner, member = symbol_parts(target)
    if member is not None:
        fail(f"owner symbol must name a type: {target}")
    text = scrub((root / path).read_text(encoding="utf-8"))
    kind, body = declaration(text, owner, {"struct", "enum"})
    if kind != "struct" or top_level_fields(body) != expected_fields:
        fail(f"owner fields differ from Rust struct {target}")


def validate_callable(root: Path, target: str) -> str:
    path, owner, member = symbol_parts(target)
    text = scrub((root / path).read_text(encoding="utf-8"))
    if member is None:
        pattern = re.compile(rf"(?m)^(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+{re.escape(owner)}\b[^;{{]*([;{{])")
        matches = list(pattern.finditer(text))
        if len(matches) != 1:
            fail(f"free Rust function is absent or duplicated: {target}")
        match = matches[0]
        if match.group(1) == ";":
            return ""
        opening = match.end() - 1
        return text[opening + 1:closing_brace(text, opening)]
    trait_pattern = re.compile(rf"\btrait\s+{re.escape(owner)}\b[^{{]*{{")
    trait_matches = list(trait_pattern.finditer(text))
    if len(trait_matches) == 1:
        opening = trait_matches[0].end() - 1
        body = function_body(text[opening + 1:closing_brace(text, opening)], member)
        if body is None:
            fail(f"Rust trait method is absent or duplicated: {target}")
        return body
    bodies = scope_bodies(text, owner)
    matches = [body for scope in bodies if (body := function_body(scope, member)) is not None]
    if len(matches) != 1:
        fail(f"Rust method is absent or duplicated in its owner: {target}")
    return matches[0]


def validate_cleanup_binding(root: Path, sanitizer: str, callers: list[str]) -> None:
    validate_callable(root, sanitizer)
    sanitizer_leaf = sanitizer.rsplit("::", 1)[-1].split("#")[-1]
    for caller in callers:
        body = validate_callable(root, caller)
        if caller == sanitizer:
            continue
        call = re.compile(rf"(?:\.|\b){re.escape(sanitizer_leaf)}\s*\(")
        if call.search(body) is None:
            fail(f"cleanup caller does not invoke registered sanitizer: {caller}")
