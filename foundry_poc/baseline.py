"""Fair agentic baseline.

This is the honest control for the experiment: the SAME model, pointed at the
SAME in-scope files, given a DISCIPLINED prompt that explicitly asks for the same
rigor Foundry enforces (structured findings, exact line citations, no invented
references, dedup, prioritization). A capable coding agent with file access.

What the baseline does NOT have is the harness around the model: no mechanical
evidence gate, no cross-run fingerprint dedup, no provenance log, no budget
governor, no bounded-coverage guarantee. The experiment measures whether those
structural controls make the same model's output more trustworthy - so we must
NOT hobble the baseline's prompt. We ask it for everything; we just don't enforce
any of it mechanically.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

from .config import Config
from .indexer import _iter_scope_files
from .llm import extract_json


BASELINE_SYSTEM = (
    "You are a senior application security engineer performing a code review. "
    "Be rigorous and disciplined: report only real issues, cite exact file and "
    "line numbers, quote the offending line verbatim, do not invent references, "
    "deduplicate findings, and prioritize by severity. Respond with JSON only."
)


def _build_prompt(cfg: Config, files: list[Path]) -> str:
    listing = []
    for p in files:
        rel = p.relative_to(cfg.target_path).as_posix()
        n = len(p.read_text(encoding="utf-8", errors="replace").splitlines())
        listing.append(f"  - {rel} ({n} lines)")
    files_block = "\n".join(listing)
    return f"""TASK: Perform a security code review of the following first-party files
in the repository rooted at your current working directory. Read each file and
identify security weaknesses.

EVALUATION GOALS:
{cfg.goals}

IN-SCOPE FILES (review these; read them from disk):
{files_block}

For every weakness, produce an entry with:
  - file: path relative to the repo root
  - line: the exact line number of the sink/issue
  - weakness_class: a CWE id (e.g. CWE-94)
  - severity: low | medium | high | critical
  - verdict: true-positive | needs-review
  - title: short label
  - rationale: 2-4 sentences grounded in the code
  - evidence: list of {{"file","line","quote"}} where quote is the verbatim line

Requirements: cite only lines that actually exist; quote them verbatim; do not
report the same issue twice; order by severity (critical first).

Return JSON ONLY as:
{{"findings": [ {{...}}, {{...}} ]}}"""


def _mock_output() -> str:
    # Deterministic offline sample that includes a resolvable citation, an
    # out-of-range (hallucinated) line, and a duplicate, to exercise the scorer.
    return json.dumps({"findings": [
        {"file": "src/backend/base/langflow/helpers/flow.py", "line": 327,
         "weakness_class": "CWE-94", "severity": "critical", "verdict": "true-positive",
         "title": "exec of generated function body",
         "rationale": "Generated code is exec'd.",
         "evidence": [{"file": "src/backend/base/langflow/helpers/flow.py", "line": 327,
                       "quote": "exec(compiled_func"}]},
        {"file": "src/backend/base/langflow/helpers/flow.py", "line": 327,
         "weakness_class": "CWE-94", "severity": "critical", "verdict": "true-positive",
         "title": "code execution (duplicate)",
         "rationale": "Same issue reported again.",
         "evidence": [{"file": "src/backend/base/langflow/helpers/flow.py", "line": 327,
                       "quote": "exec(compiled_func"}]},
        {"file": "src/backend/base/langflow/api/v1/validate.py", "line": 9999,
         "weakness_class": "CWE-862", "severity": "high", "verdict": "true-positive",
         "title": "missing auth (hallucinated line)",
         "rationale": "Endpoint lacks auth.",
         "evidence": [{"file": "src/backend/base/langflow/api/v1/validate.py", "line": 9999,
                       "quote": "this line does not exist"}]},
    ]})


def run_baseline(cfg: Config) -> dict:
    files = _iter_scope_files(cfg.target_path, cfg.include_globs, cfg.exclude_globs)
    run_id = "base_" + uuid.uuid4().hex[:12]
    prompt = _build_prompt(cfg, files)

    which = os.environ.get("FOUNDRY_LLM", "cursor").lower()
    started = time.time()
    if which == "mock":
        raw_text = _mock_output()
        usage = {"input_tokens": len(prompt) // 4, "output_tokens": len(raw_text) // 4,
                 "total_tokens": (len(prompt) + len(raw_text)) // 4}
    else:
        from cursor_sdk import Agent, AgentOptions, LocalAgentOptions, ModelSelection
        api_key = os.environ.get("CURSOR_API_KEY")
        if not api_key:
            raise RuntimeError("CURSOR_API_KEY not set for baseline run")
        options = AgentOptions(
            model=ModelSelection(id=cfg.model),
            api_key=api_key,
            local=LocalAgentOptions(cwd=str(cfg.target_path)),
        )
        result = Agent.prompt(f"{BASELINE_SYSTEM}\n\n{prompt}", options)
        raw_text = result.result or ""
        u = result.usage
        usage = {
            "input_tokens": getattr(u, "input_tokens", 0) or 0,
            "output_tokens": getattr(u, "output_tokens", 0) or 0,
            "total_tokens": getattr(u, "total_tokens", 0) or 0,
        }
        if usage["total_tokens"] == 0:
            usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
    duration = time.time() - started

    # parse (best effort); baseline output is unstructured/unenforced by design
    findings = []
    parse_ok = True
    try:
        data = extract_json(raw_text)
        findings = data.get("findings", []) if isinstance(data, dict) else (
            data if isinstance(data, list) else [])
    except Exception:
        parse_ok = False

    normalized = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        normalized.append({
            "file": str(f.get("file", "")),
            "line": int(f.get("line", 0) or 0) if str(f.get("line", "")).strip().lstrip("-").isdigit() else 0,
            "class": str(f.get("weakness_class", f.get("class", "CWE-UNKNOWN"))),
            "severity": str(f.get("severity", "")).lower(),
            "verdict": str(f.get("verdict", "claimed")).lower(),
            "title": str(f.get("title", "")),
            "rationale": str(f.get("rationale", "")),
            "evidence": f.get("evidence", []) if isinstance(f.get("evidence", []), list) else [],
        })

    meta = {
        "run_id": run_id,
        "target": cfg.target_path.name,
        "pinned_ref": cfg.pinned_ref,
        "model": cfg.model,
        "backend": which,
        "files_in_scope": len(files),
        "total_tokens": usage["total_tokens"],
        "duration_s": round(duration, 1),
        "parse_ok": parse_ok,
        "raw_findings": len(normalized),
    }

    out_dir = cfg.reports_dir.parent
    raw_path = out_dir / f"baseline-{run_id}-raw.txt"
    raw_path.write_text(raw_text)
    norm_path = out_dir / f"baseline-{run_id}.json"
    norm_path.write_text(json.dumps(
        {"run_id": run_id, "meta": meta, "usage": usage, "findings": normalized}, indent=2))

    report_md = render_baseline_markdown(cfg, run_id, meta, normalized, parse_ok)
    md_path = out_dir / f"baseline-{run_id}.md"
    md_path.write_text(report_md)
    (out_dir / "baseline-latest.md").write_text(report_md)

    return {"run_id": run_id, "meta": meta, "raw_path": str(raw_path),
            "normalized_path": str(norm_path), "report_path": str(md_path)}


def render_baseline_markdown(cfg: Config, run_id: str, meta: dict,
                             findings: list[dict], parse_ok: bool) -> str:
    """Render the baseline findings as markdown, so you can compare it side by side
    with the Foundry report (out/findings/latest.md).

    Important: the baseline has NO evidence gate. We still show, for each citation,
    whether it *would* resolve against the real code, using the same resolver the
    scorer uses. This is only informative here: the baseline presents its verdicts
    as-is, so you can see with your own eyes when it calls something a confirmed
    true-positive while its citation does not resolve. Foundry would put that in
    needs-review; the baseline does not."""
    from .scorer import _resolve_citation

    by_verdict: dict[str, int] = {}
    for f in findings:
        v = f.get("verdict", "claimed")
        by_verdict[v] = by_verdict.get(v, 0) + 1

    lines: list[str] = []
    lines.append("# Agentic baseline - raw findings (no harness)")
    lines.append("")
    lines.append(f"- **Run:** `{run_id}`")
    lines.append(f"- **Target:** `{meta.get('target')}` @ `{meta.get('pinned_ref')}`")
    lines.append(f"- **Model:** `{meta.get('model')}`  |  **Backend:** `{meta.get('backend')}`")
    lines.append(f"- **Files in scope:** {meta.get('files_in_scope')}  |  "
                 f"**Tokens:** {meta.get('total_tokens')}  |  "
                 f"**Time:** {meta.get('duration_s')}s")
    if not parse_ok:
        lines.append("- **Note:** the model output was not valid JSON, so the parse "
                     "was best effort. This is one of the things the harness does not "
                     "leave to luck.")
    lines.append("")
    lines.append("> This is the output of the same model asked, in good faith, for the "
                 "same rigor, but with nothing around it that enforces the rules. There "
                 "is no evidence gate, no provenance, no bounded stop and no dedup "
                 "between runs. Compare it with `findings/latest.md` from Foundry.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Verdict | Count |")
    lines.append("|---|---|")
    for v in sorted(by_verdict):
        lines.append(f"| {v} | {by_verdict[v]} |")
    lines.append("")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
    ordered = sorted(findings, key=lambda f: (
        0 if f.get("verdict") == "true-positive" else 1,
        order.get(f.get("severity", ""), 4)))

    for i, f in enumerate(ordered, start=1):
        lines.append(f"## {i}. {f.get('title') or '(no title)'}")
        lines.append(f"**Verdict:** `{f.get('verdict')}`  |  **Severity:** "
                     f"`{f.get('severity')}`  |  **Class:** {f.get('class')}")
        lines.append("")
        lines.append(f"- **Location:** `{f.get('file')}` (line {f.get('line')})")
        lines.append("")
        if f.get("rationale"):
            lines.append(str(f["rationale"]))
            lines.append("")
        ev = f.get("evidence") or []
        if isinstance(ev, list) and ev:
            lines.append("**Evidence (citations), checked with the same resolver:**")
            lines.append("")
            for e in ev:
                if not isinstance(e, dict):
                    continue
                efile = str(e.get("file", ""))
                eline = int(e.get("line", 0) or 0) if str(e.get("line", "")).strip().lstrip("-").isdigit() else 0
                equote = str(e.get("quote", ""))
                ok, reason = _resolve_citation(cfg.target_path, efile, eline, equote)
                mark = "resolves" if ok else f"DOES NOT RESOLVE - {reason}"
                lines.append(f"- `{efile}:{eline}` - {mark}")
                if equote.strip():
                    lines.append(f"  > `{equote.strip()}`")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
