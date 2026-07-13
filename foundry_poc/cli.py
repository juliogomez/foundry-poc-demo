"""Foundry PoC command line.

  up        verify environment + scope, fetch target if needed
  models    list valid Cursor model slugs (requires CURSOR_API_KEY)
  run       run the Foundry pipeline over the in-scope target
  baseline  run the fair agentic baseline (single disciplined agent)
  score     compare Foundry vs baseline on pre-registered metrics
  status    show the last run summary
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .config import load_config


def _cmd_up(args) -> int:
    cfg = load_config(args.config)
    print(f"system:        {cfg.system_name}")
    print(f"backend:       {cfg.backend}  (FOUNDRY_LLM={os.environ.get('FOUNDRY_LLM','cursor')})")
    print(f"model:         {cfg.model}")
    key = os.environ.get("CURSOR_API_KEY")
    print(f"CURSOR_API_KEY set: {'yes' if key else 'NO (set it before a real run, or use FOUNDRY_LLM=mock)'}")
    print(f"target:        {cfg.target_path}  @ {cfg.pinned_ref}")
    if not cfg.target_path.exists():
        print("  -> target not fetched. Run: bash scripts/fetch_target.sh")
    from .indexer import index_target
    from .rules import load_rules
    rules = load_rules(cfg.rules_dir)
    print(f"rules:         {len(rules)} loaded -> {[r.id for r in rules]}")
    if cfg.target_path.exists():
        units = index_target(cfg.target_path, cfg.include_globs, cfg.exclude_globs)
        print(f"units in scope: {len(units)} across {len({u.rel_file for u in units})} files")
    print(f"token cap:     {cfg.max_tokens}")
    return 0


def _cmd_models(args) -> int:
    from cursor_sdk import Cursor
    try:
        models = Cursor.models.list()
    except Exception as e:  # noqa: BLE001
        print(f"could not list models: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    for m in models:
        print(getattr(m, "id", getattr(m, "name", repr(m))))
    return 0


def _cmd_run(args) -> int:
    cfg = load_config(args.config)
    from .orchestrator import run_pipeline
    summary = run_pipeline(cfg, limit_units=args.limit)
    print(json.dumps(summary["meta"], indent=2))
    print(f"\nreport:          {summary['report_path']}")
    print(f"normalized json: {summary['normalized_path']}")
    print(f"raw candidates:  {summary['raw_candidates_path']}")
    print(f"tokens used:     {summary['budget']['total_tokens']} / {summary['budget']['max_tokens']}")
    return 0


def _cmd_baseline(args) -> int:
    cfg = load_config(args.config)
    from .baseline import run_baseline
    summary = run_baseline(cfg)
    print(json.dumps(summary["meta"], indent=2))
    print(f"\nbaseline raw:        {summary['raw_path']}")
    print(f"baseline normalized: {summary['normalized_path']}")
    return 0


def _cmd_score(args) -> int:
    cfg = load_config(args.config)
    from .scorer import score
    report = score(cfg, foundry_json=args.foundry, baseline_json=args.baseline)
    print(report["markdown"])
    print(f"\nwritten: {report['path']}")
    return 0


def _cmd_status(args) -> int:
    cfg = load_config(args.config)
    import sqlite3
    if not cfg.db_path.exists():
        print("no runs yet.")
        return 0
    conn = sqlite3.connect(str(cfg.db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT 5").fetchall()
    for r in rows:
        budget = json.loads(r["budget_json"] or "{}")
        n = conn.execute(
            "SELECT COUNT(*) c FROM run_findings WHERE run_id=?", (r["run_id"],)
        ).fetchone()["c"]
        print(f"{r['run_id']}  status={r['status']}  findings={n}  "
              f"tokens={budget.get('total_tokens','?')}  stop={r['stop_reason']}")
    conn.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="foundry-poc", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default="config.yaml", help="path to config.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("up", help="verify env + scope").set_defaults(func=_cmd_up)
    sub.add_parser("models", help="list Cursor model slugs").set_defaults(func=_cmd_models)

    rp = sub.add_parser("run", help="run the Foundry pipeline")
    rp.add_argument("--limit", type=int, default=None, help="cap number of units (smoke test)")
    rp.set_defaults(func=_cmd_run)

    sub.add_parser("baseline", help="run the fair agentic baseline").set_defaults(func=_cmd_baseline)

    sp = sub.add_parser("score", help="compare foundry vs baseline")
    sp.add_argument("--foundry", required=True, help="path to foundry-<run>.json")
    sp.add_argument("--baseline", required=True, help="path to baseline-<run>.json")
    sp.set_defaults(func=_cmd_score)

    sub.add_parser("status", help="show recent runs").set_defaults(func=_cmd_status)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
