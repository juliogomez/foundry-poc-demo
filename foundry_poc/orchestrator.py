"""Orchestrator role. Runs the Foundry pipeline over the in-scope target:

  index -> (per unit) detect -> (per candidate) triage+gate -> report

Enforces the token budget cap (halts cleanly), records full provenance, dedups
findings by fingerprint, logs rule-gaps, and applies a coverage-AND-yield stop
condition. Emits a Markdown report and a normalized JSON artifact for the scorer.
"""
from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import asdict
from pathlib import Path

from .budget import BudgetExceeded, BudgetGovernor
from .config import Config
from .detector import Detector
from .indexer import index_target
from .llm import make_backend
from .reporter import render_markdown, result_to_finding
from .rules import load_rules
from .store import Store
from .triager import Triager


def run_pipeline(cfg: Config, *, limit_units: int | None = None) -> dict:
    backend = make_backend(cfg.model, cfg.scratch_cwd)
    rules = load_rules(cfg.rules_dir)
    units = index_target(cfg.target_path, cfg.include_globs, cfg.exclude_globs)
    if limit_units is not None:
        units = units[:limit_units]

    store = Store(cfg.db_path, cfg.provenance_log, cfg.rule_gaps_log)
    budget = BudgetGovernor(max_tokens=cfg.max_tokens)
    detector = Detector(backend, rules, cfg.goals)
    triager = Triager(backend, cfg.target_path, cfg.goals, rules)

    config_summary = {
        "system": cfg.system_name,
        "target": str(cfg.target_path.name),
        "pinned_ref": cfg.pinned_ref,
        "model": cfg.model,
        "backend": cfg.backend,
        "rules": [r.id for r in rules],
        "units_in_scope": len(units),
        "max_tokens": cfg.max_tokens,
    }
    run_id = store.start_run(config_summary)

    # Batching amortizes the fixed per-call agent overhead of the Cursor SDK.
    BATCH_MAX_UNITS = int(cfg.raw.get("batching", {}).get("detector_max_units", 12))
    BATCH_MAX_LINES = int(cfg.raw.get("batching", {}).get("detector_max_lines", 320))
    TRIAGE_BATCH = int(cfg.raw.get("batching", {}).get("triage_batch_size", 10))

    def _unit_batches(all_units):
        batch, lines = [], 0
        for u in all_units:
            u_lines = (u.end_lineno - u.lineno + 1)
            if batch and (len(batch) >= BATCH_MAX_UNITS or lines + u_lines > BATCH_MAX_LINES):
                yield batch
                batch, lines = [], 0
            batch.append(u)
            lines += u_lines
        if batch:
            yield batch

    unit_lookup = {u.unit_id: u for u in units}
    raw_candidates: list[dict] = []
    all_candidates = []
    triaged_results = []
    yield_window: deque[int] = deque(maxlen=cfg.yield_window)
    units_analyzed = 0
    candidate_count = 0
    stop_reason = "coverage-complete"
    det_ev_by_unit: dict[str, str] = {}

    try:
        # ---- detection sweep (batched) ----
        for batch in _unit_batches(units):
            budget.check()
            candidates, d_usage, d_raw = detector.detect_batch(batch)
            budget.record(d_usage["input_tokens"], d_usage["output_tokens"], d_usage["total_tokens"])
            det_ev = store.log_provenance(
                run_id, "detector.call",
                {"units": [u.unit_id for u in batch], "n_units": len(batch),
                 "n_candidates": len(candidates), "usage": d_usage},
            )
            units_analyzed += len(batch)
            for cand in candidates:
                det_ev_by_unit[cand.unit_id] = det_ev
                raw_candidates.append({
                    "unit": cand.unit_id, "rule_id": cand.rule_id,
                    "weakness_class": cand.weakness_class, "line_hint": cand.line_hint,
                    "why": cand.why, "symbol": cand.symbol, "rel_file": cand.rel_file,
                })
                all_candidates.append(cand)
                candidate_count += 1

        # ---- triage + evidence gate (batched) ----
        for i in range(0, len(all_candidates), TRIAGE_BATCH):
            chunk = all_candidates[i:i + TRIAGE_BATCH]
            items = [(c, unit_lookup[c.unit_id]) for c in chunk]
            budget.check()
            results, t_usage = triager.triage_batch(items)
            budget.record(t_usage["input_tokens"], t_usage["output_tokens"], t_usage["total_tokens"])
            for cand, result in zip(chunk, results):
                tri_ev = store.log_provenance(
                    run_id, "triager.call",
                    {"unit": cand.unit_id, "rule_id": cand.rule_id,
                     "verdict": result.verdict, "gate": result.gate,
                     "usage_shared_for_batch": t_usage},
                )
                if cand.rule_id.upper() == "EXPLORATORY" and result.verdict in {
                    "true-positive", "needs-review"
                }:
                    store.log_rule_gap(run_id, {
                        "unit": cand.unit_id, "symbol": cand.symbol,
                        "weakness_class": cand.weakness_class,
                        "verdict": result.verdict, "why": cand.why,
                        "note": "detector flagged a security-relevant pattern not covered by the rule corpus",
                    })
                finding = result_to_finding(
                    result, provenance_ids=[det_ev_by_unit.get(cand.unit_id, ""), tri_ev])
                store.upsert_finding(run_id, finding)
                triaged_results.append(result)
                yield_window.append(1 if result.verdict == "true-positive" else 0)

        trailing_yield = (sum(yield_window) / len(yield_window)) if yield_window else 0.0
        stop_reason = (
            f"coverage-complete (all {units_analyzed} units); "
            f"trailing true-positive yield={trailing_yield:.2f}"
        )
    except BudgetExceeded as e:
        stop_reason = f"budget-cap: {e}"

    budget_summary = budget.summary()
    store.finish_run(run_id, budget_summary, stop_reason)

    # de-duplicated findings for THIS run
    run_findings = store.findings_for_run(run_id)

    meta = {
        "target": str(cfg.target_path.name),
        "pinned_ref": cfg.pinned_ref,
        "model": cfg.model,
        "backend": cfg.backend,
        "units_analyzed": units_analyzed,
        "candidates": candidate_count,
        "total_tokens": budget_summary["total_tokens"],
        "max_tokens": budget_summary["max_tokens"],
        "stop_reason": stop_reason,
    }

    # ---- artifacts -------------------------------------------------------------
    report_md = render_markdown(run_id, run_findings, meta)
    (cfg.reports_dir / f"{run_id}.md").write_text(report_md)
    (cfg.reports_dir / "latest.md").write_text(report_md)

    normalized = [
        {
            "file": f["rel_file"], "line": f["lineno"], "class": f["weakness_class"],
            "severity": f["severity"], "verdict": f["verdict"],
            "fingerprint": f["fingerprint"], "symbol": f["symbol"], "title": f["title"],
            "evidence": f["evidence"],
        }
        for f in run_findings
    ]
    norm_path = cfg.reports_dir.parent / f"foundry-{run_id}.json"
    norm_path.write_text(json.dumps({
        "run_id": run_id, "meta": meta, "budget": budget_summary,
        "raw_candidate_count": candidate_count,
        "reported_findings": normalized,
    }, indent=2))

    raw_path = cfg.reports_dir.parent / f"foundry-{run_id}-raw-candidates.jsonl"
    with raw_path.open("w") as fh:
        for rc in raw_candidates:
            fh.write(json.dumps(rc) + "\n")

    store.close()
    return {
        "run_id": run_id,
        "meta": meta,
        "budget": budget_summary,
        "reported": normalized,
        "report_path": str(cfg.reports_dir / f"{run_id}.md"),
        "normalized_path": str(norm_path),
        "raw_candidates_path": str(raw_path),
    }
