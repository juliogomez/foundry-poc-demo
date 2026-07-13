"""Detector role. For one analysis unit, decide which CodeGuard rules plausibly
apply, and (light exploratory pass) flag any other security-relevant pattern even
if no rule covers it. Exploratory hits with no matching rule become rule-gap
candidates downstream (Foundry: detection->prevention flywheel).

The Detector is deliberately *inclusive* (favor recall): it proposes candidates.
The Triager is where discipline (the evidence gate) is applied. This mirrors the
spec's separation of detection from adjudication.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .indexer import Unit
from .llm import LLMBackend, extract_json
from .rules import Rule, corpus_digest


@dataclass
class Candidate:
    unit_id: str
    rel_file: str
    symbol: str
    rule_id: str          # a rule id, or "EXPLORATORY" for a rule-gap candidate
    weakness_class: str
    line_hint: int
    why: str
    unit_lineno: int = 0
    unit_end_lineno: int = 0


DETECTOR_SYSTEM = (
    "You are the Detector in a security evaluation harness. You examine code units "
    "and propose candidate weaknesses. Favor recall, but only propose a candidate "
    "when a rule's trigger condition plausibly holds for that unit. Never invent "
    "line numbers: every line_hint MUST be a line number shown in that unit. "
    "Respond with JSON only, no prose."
)


def _batch_prompt(units: list[Unit], rules: list[Rule], goals: str) -> str:
    blocks = []
    for i, u in enumerate(units):
        blocks.append(
            f"[UNIT {i}] {u.rel_file}::{u.symbol}  (lines {u.lineno}-{u.end_lineno})\n"
            f"DECORATORS: {u.decorators}\n"
            f"SOURCE (line-numbered; cite only these line numbers):\n{u.numbered_source}"
        )
    units_block = "\n\n".join(blocks)
    return f"""TASK: DETECT weaknesses across the following code units.

EVALUATION GOALS:
{goals}

CANDIDATE RULES (propose by id when trigger_when plausibly holds):
{corpus_digest(rules)}

UNITS:
{units_block}

For each weakness you find, emit a candidate tagged with its unit_index.
Return JSON:
{{"candidates": [
  {{"unit_index": <int>,
   "rule_id": "<rule id, or EXPLORATORY if security-relevant but no rule fits>",
   "weakness_class": "<CWE-xxx>",
   "line_hint": <int line number shown in that unit>,
   "why": "<one sentence tying the rule trigger to this code>"}}
]}}
If nothing applies to any unit, return {{"candidates": []}}."""


class Detector:
    def __init__(self, backend: LLMBackend, rules: list[Rule], goals: str):
        self.backend = backend
        self.rules = rules
        self.goals = goals

    def detect_batch(self, units: list[Unit]) -> tuple[list[Candidate], dict, str]:
        """Detect across a batch of units in ONE call (amortizes agent overhead).
        Returns (candidates, token_usage, raw_response)."""
        prompt = _batch_prompt(units, self.rules, self.goals)
        text, usage = self.backend.complete(prompt, system=DETECTOR_SYSTEM)
        candidates: list[Candidate] = []
        try:
            data = extract_json(text)
        except Exception:
            return [], usage, text
        for c in data.get("candidates", []) if isinstance(data, dict) else []:
            try:
                idx = int(c.get("unit_index", -1))
                if not (0 <= idx < len(units)):
                    continue
                unit = units[idx]
                candidates.append(
                    Candidate(
                        unit_id=unit.unit_id,
                        rel_file=unit.rel_file,
                        symbol=unit.symbol,
                        rule_id=str(c.get("rule_id", "EXPLORATORY")),
                        weakness_class=str(c.get("weakness_class", "CWE-UNKNOWN")),
                        line_hint=int(c.get("line_hint", 0) or 0),
                        why=str(c.get("why", "")).strip(),
                        unit_lineno=unit.lineno,
                        unit_end_lineno=unit.end_lineno,
                    )
                )
            except (TypeError, ValueError):
                continue
        return candidates, usage, text
