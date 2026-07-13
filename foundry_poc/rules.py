"""Rule corpus loader (CodeGuard sketch format). Rules are LLM-evaluated detection
patterns; the Detector receives a compact digest of the corpus and decides which,
if any, apply to a given unit."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class Rule:
    id: str
    description: str
    severity: str
    weakness_class: str
    applies_to: list[str]
    trigger_when: list[str]
    do_not_trigger_when: list[str]
    raw: dict

    @property
    def digest(self) -> str:
        applies = "; ".join(self.applies_to) if self.applies_to else ""
        triggers = "; ".join(self.trigger_when) if self.trigger_when else ""
        exclude = "; ".join(self.do_not_trigger_when) if self.do_not_trigger_when else ""
        lines = [
            f"- {self.id} [{self.weakness_class}, severity={self.severity}]",
            f"    applies_to: {applies}",
            f"    trigger_when: {triggers}",
        ]
        if exclude:
            lines.append(f"    do_not_trigger_when (EXCLUSIONS - do not propose these): {exclude}")
        return "\n".join(lines)


def load_rules(rules_dir: Path) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(Path(rules_dir).glob("*.yaml")):
        data = yaml.safe_load(path.read_text()) or {}
        rules.append(
            Rule(
                id=data.get("id", path.stem),
                description=(data.get("description") or "").strip(),
                severity=data.get("severity", "medium"),
                weakness_class=data.get("weakness_class", "CWE-UNKNOWN"),
                applies_to=list(data.get("applies_to", []) or []),
                trigger_when=list(data.get("trigger_when", []) or []),
                do_not_trigger_when=list(data.get("do_not_trigger_when", []) or []),
                raw=data,
            )
        )
    return rules


def corpus_digest(rules: list[Rule]) -> str:
    return "\n".join(r.digest for r in rules)


def rule_by_id(rules: list[Rule], rule_id: str) -> Rule | None:
    for r in rules:
        if r.id == rule_id:
            return r
    return None
