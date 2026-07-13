"""Triager role + Evidence Gate.

The Triager adjudicates a candidate into a verdict (true-positive / false-positive
/ needs-review) with a severity, title, rationale, and STRUCTURED evidence: a list
of {file, line, quote} citations.

The Evidence Gate is the trust mechanism and it is MECHANICAL, not model opinion:
every citation is resolved against the real source on disk. A finding may be
labeled `true-positive` only if it cites at least one resolvable line AND none of
its citations are hallucinated (missing file or out-of-range line, or a quote that
does not match the cited line). Otherwise it is demoted to `needs-review` and the
hallucinated references are recorded. This is what makes the SAME model's output
trustworthy: claims that cannot be verified against code cannot pass as confirmed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .detector import Candidate
from .indexer import Unit
from .llm import LLMBackend, extract_json


@dataclass
class Citation:
    file: str
    line: int
    quote: str
    resolved: bool = False
    reason: str = ""


@dataclass
class TriageResult:
    candidate: Candidate
    verdict: str            # true-positive | false-positive | needs-review
    severity: str           # low | medium | high | critical | none
    title: str
    rationale: str
    citations: list[Citation] = field(default_factory=list)
    gate: dict = field(default_factory=dict)   # gate bookkeeping for provenance
    raw_response: str = ""


TRIAGER_SYSTEM = (
    "You are the Triager in a security evaluation harness. Given a candidate "
    "weakness and the unit source, decide a verdict and justify it ONLY with "
    "citations to specific lines that are shown to you. Every citation's `quote` "
    "must be copied verbatim from the cited line. Do not cite files or lines you "
    "were not shown. Respond with JSON only."
)


def _prompt(candidate: Candidate, unit: Unit, goals: str) -> str:
    return f"""TASK: TRIAGE one candidate weakness.

EVALUATION GOALS:
{goals}

CANDIDATE:
  rule_id: {candidate.rule_id}
  weakness_class: {candidate.weakness_class}
  line_hint: {candidate.line_hint}
  why: {candidate.why}

UNIT: {unit.rel_file}::{unit.symbol}
SOURCE (line-numbered; cite ONLY these lines, file="{unit.rel_file}"):
{unit.numbered_source}

Decide:
- verdict: "true-positive" (exploitable/real as written), "false-positive"
  (rule does not truly apply here), or "needs-review" (plausible but depends on
  data-flow/context not visible in this unit).
- severity: one of low|medium|high|critical (or none if false-positive).
- Provide citations proving your verdict.

Return JSON:
{{"verdict": "...", "severity": "...", "title": "<short>",
  "rationale": "<2-4 sentences grounded in the cited lines>",
  "evidence": [{{"file": "{unit.rel_file}", "line": <int shown above>,
                "quote": "<verbatim text of that line>"}}]}}"""


class Triager:
    def __init__(self, backend: LLMBackend, target_root: Path, goals: str, rules=None):
        self.backend = backend
        self.target_root = Path(target_root)
        self.goals = goals
        self._file_cache: dict[str, list[str]] = {}
        self._rule_by_id = {r.id: r for r in (rules or [])}

    def _rule_criteria(self, rule_id: str) -> str:
        """Render the matched rule's trigger and exclusion criteria so the gate can
        reject patterns the rule explicitly says NOT to flag (e.g. a pervasive,
        low-value idiom). Without this the triager only sees the candidate's `why`."""
        r = self._rule_by_id.get(rule_id)
        if r is None:
            return ""
        parts = []
        if r.trigger_when:
            parts.append("      trigger_when: " + "; ".join(r.trigger_when))
        if getattr(r, "do_not_trigger_when", None):
            parts.append("      do_not_trigger_when (if the candidate matches ANY of "
                         "these, verdict MUST be false-positive): "
                         + "; ".join(r.do_not_trigger_when))
        return ("\n" + "\n".join(parts)) if parts else ""

    def _lines(self, rel_file: str) -> list[str] | None:
        if rel_file in self._file_cache:
            return self._file_cache[rel_file]
        p = (self.target_root / rel_file).resolve()
        try:
            # containment check: never resolve citations outside the target
            p.relative_to(self.target_root)
        except ValueError:
            return None
        if not p.is_file():
            return None
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        self._file_cache[rel_file] = lines
        return lines

    def _resolve_citation(self, cit: Citation, unit: Unit) -> Citation:
        # normalize file: accept the unit's file or a bare basename matching it
        rel = cit.file.strip()
        if rel not in {unit.rel_file} and unit.rel_file.endswith(rel):
            rel = unit.rel_file
        lines = self._lines(rel)
        if lines is None:
            cit.resolved = False
            cit.reason = f"file not found in target: {cit.file}"
            return cit
        if not (1 <= cit.line <= len(lines)):
            cit.resolved = False
            cit.reason = f"line {cit.line} out of range (file has {len(lines)} lines)"
            return cit
        actual = lines[cit.line - 1]
        quote = (cit.quote or "").strip()
        # quote must match the cited line (verbatim, tolerant of whitespace);
        # allow a small window to account for off-by-one line reporting.
        if quote and quote not in actual:
            window = "\n".join(lines[max(0, cit.line - 3): cit.line + 2])
            if quote not in window:
                cit.resolved = False
                cit.reason = "quote does not match cited line or its neighborhood"
                return cit
        cit.resolved = True
        cit.reason = "resolved"
        return cit

    def _apply_gate(self, candidate: Candidate, unit: Unit, data: dict, raw: str) -> TriageResult:
        verdict = str(data.get("verdict", "needs-review")).strip().lower()
        severity = str(data.get("severity", "medium")).strip().lower()
        title = str(data.get("title", candidate.weakness_class)).strip()
        rationale = str(data.get("rationale", "")).strip()

        citations: list[Citation] = []
        for e in data.get("evidence", []) if isinstance(data, dict) else []:
            try:
                citations.append(
                    Citation(
                        file=str(e.get("file", unit.rel_file)),
                        line=int(e.get("line", 0) or 0),
                        quote=str(e.get("quote", "")),
                    )
                )
            except (TypeError, ValueError):
                continue

        # ---- Evidence Gate (mechanical) ----
        for c in citations:
            self._resolve_citation(c, unit)
        resolved = [c for c in citations if c.resolved]
        hallucinated = [c for c in citations if not c.resolved]

        original_verdict = verdict
        demoted = False
        if verdict == "true-positive" and (not resolved or hallucinated):
            verdict = "needs-review"
            demoted = True
            if severity in {"none", ""}:
                severity = "medium"

        gate = {
            "original_verdict": original_verdict,
            "final_verdict": verdict,
            "demoted": demoted,
            "citations_total": len(citations),
            "citations_resolved": len(resolved),
            "citations_hallucinated": len(hallucinated),
            "hallucinated_detail": [
                {"file": c.file, "line": c.line, "reason": c.reason} for c in hallucinated
            ],
        }
        return TriageResult(
            candidate=candidate,
            verdict=verdict,
            severity=severity if verdict != "false-positive" else "none",
            title=title,
            rationale=rationale,
            citations=citations,
            gate=gate,
            raw_response=raw,
        )

    def triage_batch(self, items: list[tuple[Candidate, Unit]]) -> tuple[list[TriageResult], dict]:
        """Adjudicate a batch of candidates in ONE call, then apply the mechanical
        evidence gate to each result in Python. Returns (results, token_usage)."""
        # unique units (include each source once), then candidates referencing them
        unit_index: dict[str, int] = {}
        ordered_units: list[Unit] = []
        for _, u in items:
            if u.unit_id not in unit_index:
                unit_index[u.unit_id] = len(ordered_units)
                ordered_units.append(u)

        unit_blocks = []
        for i, u in enumerate(ordered_units):
            unit_blocks.append(
                f"[UNIT {i}] {u.rel_file}::{u.symbol}\n"
                f"SOURCE (line-numbered; cite ONLY these lines, file=\"{u.rel_file}\"):\n"
                f"{u.numbered_source}"
            )
        cand_blocks = []
        for j, (cand, u) in enumerate(items):
            cand_blocks.append(
                f"[CANDIDATE {j}] unit_index={unit_index[u.unit_id]}  "
                f"rule={cand.rule_id}  class={cand.weakness_class}  "
                f"line_hint={cand.line_hint}\n  why: {cand.why}"
                f"{self._rule_criteria(cand.rule_id)}"
            )

        prompt = f"""TASK: TRIAGE each candidate weakness below.

EVALUATION GOALS:
{self.goals}

UNITS:
{chr(10).join(unit_blocks)}

CANDIDATES:
{chr(10).join(cand_blocks)}

For EACH candidate (by candidate_index), decide:
- verdict: "true-positive" (real/exploitable as written), "false-positive"
  (rule does not truly apply), or "needs-review" (plausible but depends on
  data-flow/context not visible here).
- If a candidate lists `do_not_trigger_when` criteria and the code matches ANY of
  them, the verdict MUST be "false-positive" (the rule explicitly excludes it),
  even if the pattern is technically an instance of the weakness class.
- severity: low|medium|high|critical (or none if false-positive).
- Provide citations that PROVE your verdict; every quote must be verbatim from a
  shown line in the referenced unit.

Return JSON:
{{"results": [
  {{"candidate_index": <int>, "verdict": "...", "severity": "...",
    "title": "<short>", "rationale": "<2-4 sentences grounded in cited lines>",
    "evidence": [{{"file": "<unit file>", "line": <int shown>, "quote": "<verbatim>"}}]}}
]}}"""

        text, usage = self.backend.complete(prompt, system=TRIAGER_SYSTEM)
        try:
            data = extract_json(text)
        except Exception:
            data = {}
        by_index: dict[int, dict] = {}
        for r in (data.get("results", []) if isinstance(data, dict) else []):
            try:
                by_index[int(r.get("candidate_index", -1))] = r
            except (TypeError, ValueError):
                continue

        results: list[TriageResult] = []
        for j, (cand, u) in enumerate(items):
            rdata = by_index.get(j, {"verdict": "needs-review", "severity": "medium",
                                     "title": cand.weakness_class, "rationale": "",
                                     "evidence": []})
            results.append(self._apply_gate(cand, u, rdata, text))
        return results, usage
