"""Reporter role. Converts gated triage results into Finding records (with stable
fingerprints for dedup) and renders a deterministic, auditable Markdown report
ordered by severity then verdict. Every reported finding carries its resolved
citations and a provenance trail."""
from __future__ import annotations

from dataclasses import dataclass

from .fingerprint import compute_fingerprint
from .store import Finding
from .triager import TriageResult

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
VERDICT_ORDER = {"true-positive": 0, "needs-review": 1, "false-positive": 2}


def result_to_finding(r: TriageResult, provenance_ids: list[str]) -> Finding:
    c = r.candidate
    fp = compute_fingerprint(c.rel_file, c.weakness_class, c.symbol)
    evidence = [
        {
            "file": cit.file,
            "line": cit.line,
            "quote": cit.quote,
            "resolved": cit.resolved,
            "reason": cit.reason,
        }
        for cit in r.citations
    ]
    # anchor line = first resolved citation, else candidate hint
    anchor = next((cit.line for cit in r.citations if cit.resolved), c.line_hint)
    return Finding(
        fingerprint=fp,
        rel_file=c.rel_file,
        symbol=c.symbol,
        lineno=anchor,
        weakness_class=c.weakness_class,
        rule_id=c.rule_id,
        verdict=r.verdict,
        severity=r.severity,
        title=r.title,
        rationale=r.rationale,
        evidence=evidence,
        provenance_ids=provenance_ids,
    )


def _sort_key(f: dict) -> tuple:
    return (
        VERDICT_ORDER.get(f.get("verdict", ""), 9),
        SEVERITY_ORDER.get(f.get("severity", ""), 9),
        f.get("rel_file", ""),
        f.get("lineno", 0),
    )


def render_markdown(run_id: str, findings: list[dict], meta: dict) -> str:
    findings = sorted(findings, key=_sort_key)
    by_verdict: dict[str, int] = {}
    for f in findings:
        by_verdict[f["verdict"]] = by_verdict.get(f["verdict"], 0) + 1

    lines: list[str] = []
    lines.append("# Foundry PoC - security findings report")
    lines.append("")
    lines.append(f"- **Run:** `{run_id}`")
    lines.append(f"- **Target:** `{meta.get('target')}` @ `{meta.get('pinned_ref')}`")
    lines.append(f"- **Model:** `{meta.get('model')}`  |  **Backend:** `{meta.get('backend')}`")
    lines.append(f"- **Units analyzed:** {meta.get('units_analyzed')}  |  "
                 f"**Candidates:** {meta.get('candidates')}  |  "
                 f"**Tokens:** {meta.get('total_tokens')}/{meta.get('max_tokens')}")
    lines.append(f"- **Stop reason:** {meta.get('stop_reason')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Verdict | Count |")
    lines.append("|---|---|")
    for v in ("true-positive", "needs-review", "false-positive"):
        lines.append(f"| {v} | {by_verdict.get(v, 0)} |")
    lines.append("")
    lines.append("The findings are ordered by verdict and then severity. Every "
                 "`true-positive` passed the evidence gate (all its citations resolve "
                 "to real lines). The `needs-review` items depend of data flow outside "
                 "the unit, or they had one or more citations that did not resolve.")
    lines.append("")

    for i, f in enumerate(findings, start=1):
        lines.append(f"## {i}. {f['title']}  ")
        lines.append(f"**Verdict:** `{f['verdict']}`  |  **Severity:** `{f['severity']}`  |  "
                     f"**Class:** {f['weakness_class']}  |  **Rule:** `{f['rule_id']}`")
        lines.append("")
        lines.append(f"- **Location:** `{f['rel_file']}` - `{f['symbol']}` (line {f['lineno']})")
        lines.append(f"- **Fingerprint:** `{f['fingerprint']}`")
        lines.append("")
        lines.append(f"{f['rationale']}")
        lines.append("")
        if f["evidence"]:
            lines.append("**Evidence (citations):**")
            lines.append("")
            for e in f["evidence"]:
                mark = "resolved" if e.get("resolved") else f"UNRESOLVED - {e.get('reason','')}"
                q = (e.get("quote") or "").strip()
                lines.append(f"- `{e['file']}:{e['line']}` - {mark}")
                if q:
                    lines.append(f"  > `{q}`")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
