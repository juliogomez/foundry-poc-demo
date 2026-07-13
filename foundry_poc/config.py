"""Config loader. The YAML file IS the customized spec for this PoC: every knob
maps to a Foundry [NEEDS CLARIFICATION] decision (see docs/CUSTOMIZATION.md)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Config:
    raw: dict[str, Any]
    root: Path  # repo root (dir containing config.yaml)

    # ---- convenience accessors -------------------------------------------------
    @property
    def system_name(self) -> str:
        return self.raw.get("system", {}).get("name", "foundry-poc")

    @property
    def target_path(self) -> Path:
        return (self.root / self.raw["target"]["path"]).resolve()

    @property
    def include_globs(self) -> list[str]:
        return list(self.raw["target"].get("include_globs", []))

    @property
    def exclude_globs(self) -> list[str]:
        return list(self.raw["target"].get("exclude_globs", []))

    @property
    def pinned_ref(self) -> str:
        return str(self.raw["target"].get("pinned_ref", ""))

    @property
    def goals(self) -> str:
        return self.raw.get("goals", "").strip()

    @property
    def model(self) -> str:
        return self.raw["llm"]["model"]

    @property
    def backend(self) -> str:
        return self.raw["llm"].get("backend", "cursor")

    @property
    def scratch_cwd(self) -> Path:
        p = (self.root / self.raw["llm"].get("scratch_cwd", ".scratch")).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def max_tokens(self) -> int:
        return int(self.raw["budget"]["max_tokens"])

    @property
    def yield_window(self) -> int:
        return int(self.raw["budget"].get("yield_window", 12))

    @property
    def yield_min_tp_rate(self) -> float:
        return float(self.raw["budget"].get("yield_min_true_positive_rate", 0.05))

    @property
    def severity_scheme(self) -> str:
        return self.raw.get("severity", {}).get("scheme", "low_medium_high_critical")

    @property
    def rules_dir(self) -> Path:
        return (self.root / self.raw.get("rules", {}).get("corpus_dir", "rules")).resolve()

    def out_path(self, key: str, default: str) -> Path:
        p = (self.root / self.raw.get("store", {}).get(key, default)).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def db_path(self) -> Path:
        return self.out_path("db_path", "out/findings.db")

    @property
    def provenance_log(self) -> Path:
        return self.out_path("provenance_log", "out/provenance.jsonl")

    @property
    def reports_dir(self) -> Path:
        p = (self.root / self.raw.get("store", {}).get("reports_dir", "out/findings")).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def rule_gaps_log(self) -> Path:
        return self.out_path("rule_gaps_log", "out/rule-gaps.jsonl")


def load_config(path: str | os.PathLike[str] = "config.yaml") -> Config:
    cfg_path = Path(path).resolve()
    if not cfg_path.exists():
        raise FileNotFoundError(f"config not found: {cfg_path}")
    data = yaml.safe_load(cfg_path.read_text()) or {}
    return Config(raw=data, root=cfg_path.parent)
