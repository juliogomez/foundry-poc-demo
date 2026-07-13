"""Indexer role. Turns the in-scope target into function-level analysis units,
each with light caller/callee context, so the Detector reasons about one bounded
unit at a time (Foundry: function-scoped units).

Unit = a top-level or nested function/method. For each we capture:
  * stable symbol (module-qualified name)
  * source text WITH 1-based line numbers (so citations resolve to real lines)
  * decorators (surfaces route/auth annotations for the missing-authz rule)
  * callee names invoked inside the body (light dataflow context)
"""
from __future__ import annotations

import ast
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Unit:
    rel_file: str
    symbol: str            # e.g. "flows.create_flow" or "MyClass.method"
    lineno: int            # 1-based start line in the file
    end_lineno: int
    decorators: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    numbered_source: str = ""   # source with "  <lineno>| " prefixes

    @property
    def unit_id(self) -> str:
        return f"{self.rel_file}::{self.symbol}"


def _iter_scope_files(target_root: Path, include: list[str], exclude: list[str]) -> list[Path]:
    files: list[Path] = []
    for pattern in include:
        for p in sorted(target_root.glob(pattern)):
            rel = p.relative_to(target_root).as_posix()
            if any(fnmatch.fnmatch(rel, ex) or fnmatch.fnmatch("**/" + rel, ex) for ex in exclude):
                continue
            if p.is_file() and p.suffix == ".py":
                files.append(p)
    # dedup while preserving order
    seen, out = set(), []
    for f in files:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _decorator_text(dec: ast.expr, source_lines: list[str]) -> str:
    seg = ast.get_source_segment("\n".join(source_lines), dec)
    if seg:
        return seg.strip()
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return dec.attr
    return "<decorator>"


def _callee_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            func = n.func
            if isinstance(func, ast.Name):
                names.append(func.id)
            elif isinstance(func, ast.Attribute):
                names.append(func.attr)
    # unique, keep order
    seen, out = set(), []
    for nm in names:
        if nm not in seen:
            seen.add(nm)
            out.append(nm)
    return out[:40]


def _numbered(source_lines: list[str], start: int, end: int) -> str:
    out = []
    for ln in range(start, end + 1):
        if 1 <= ln <= len(source_lines):
            out.append(f"{ln:6d}| {source_lines[ln - 1]}")
    return "\n".join(out)


def index_target(target_root: Path, include: list[str], exclude: list[str]) -> list[Unit]:
    units: list[Unit] = []
    for path in _iter_scope_files(target_root, include, exclude):
        rel = path.relative_to(target_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        source_lines = text.splitlines()
        try:
            tree = ast.parse(text, filename=rel)
        except SyntaxError:
            continue

        # Track enclosing class names for qualified symbols.
        def visit(node: ast.AST, prefix: str) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    visit(child, f"{prefix}{child.name}.")
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start = child.lineno
                    end = getattr(child, "end_lineno", start) or start
                    decorators = [_decorator_text(d, source_lines) for d in child.decorator_list]
                    units.append(
                        Unit(
                            rel_file=rel,
                            symbol=f"{prefix}{child.name}",
                            lineno=start,
                            end_lineno=end,
                            decorators=decorators,
                            callees=_callee_names(child),
                            numbered_source=_numbered(source_lines, start, end),
                        )
                    )
                    # descend for nested functions too
                    visit(child, f"{prefix}{child.name}.")

        visit(tree, "")
    return units
