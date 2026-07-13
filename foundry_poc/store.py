"""Persistence substrate: a SQLite finding store with cross-run dedup keyed on
fingerprint, plus append-only JSONL logs for provenance and rule-gaps.

Every consequential act (LLM call, verdict, dedup decision) is written to the
provenance log so a reviewer can reconstruct exactly why a finding exists
(Foundry: provenance / auditability)."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass
class Finding:
    fingerprint: str
    rel_file: str
    symbol: str
    lineno: int
    weakness_class: str
    rule_id: str
    verdict: str          # true-positive | false-positive | needs-review
    severity: str         # low | medium | high | critical | none
    title: str
    rationale: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    provenance_ids: list[str] = field(default_factory=list)


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at REAL,
    finished_at REAL,
    status TEXT,
    config_json TEXT,
    budget_json TEXT,
    stop_reason TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    rel_file TEXT,
    symbol TEXT,
    lineno INTEGER,
    weakness_class TEXT,
    rule_id TEXT,
    verdict TEXT,
    severity TEXT,
    title TEXT,
    rationale TEXT,
    evidence_json TEXT,
    provenance_json TEXT,
    first_seen_run TEXT,
    last_seen_run TEXT,
    seen_count INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS run_findings (
    run_id TEXT,
    fingerprint TEXT,
    PRIMARY KEY (run_id, fingerprint)
);
"""


class Store:
    def __init__(self, db_path: Path, provenance_log: Path, rule_gaps_log: Path):
        self.db_path = Path(db_path)
        self.provenance_log = Path(provenance_log)
        self.rule_gaps_log = Path(rule_gaps_log)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- runs -----------------------------------------------------------------
    def start_run(self, config_summary: dict) -> str:
        run_id = "run_" + uuid.uuid4().hex[:12]
        self.conn.execute(
            "INSERT INTO runs (run_id, started_at, status, config_json) VALUES (?,?,?,?)",
            (run_id, time.time(), "running", json.dumps(config_summary)),
        )
        self.conn.commit()
        self.log_provenance(run_id, "run.start", {"config": config_summary})
        return run_id

    def finish_run(self, run_id: str, budget_summary: dict, stop_reason: str) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at=?, status=?, budget_json=?, stop_reason=? WHERE run_id=?",
            (time.time(), "done", json.dumps(budget_summary), stop_reason, run_id),
        )
        self.conn.commit()
        self.log_provenance(
            run_id, "run.finish", {"budget": budget_summary, "stop_reason": stop_reason}
        )

    # ---- findings (with cross-run dedup) --------------------------------------
    def upsert_finding(self, run_id: str, f: Finding) -> str:
        """Insert or dedup a finding by fingerprint. Returns 'new' or 'duplicate'."""
        row = self.conn.execute(
            "SELECT fingerprint, seen_count FROM findings WHERE fingerprint=?",
            (f.fingerprint,),
        ).fetchone()
        if row is None:
            self.conn.execute(
                """INSERT INTO findings
                   (fingerprint, rel_file, symbol, lineno, weakness_class, rule_id,
                    verdict, severity, title, rationale, evidence_json, provenance_json,
                    first_seen_run, last_seen_run, seen_count)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    f.fingerprint, f.rel_file, f.symbol, f.lineno, f.weakness_class,
                    f.rule_id, f.verdict, f.severity, f.title, f.rationale,
                    json.dumps(f.evidence), json.dumps(f.provenance_ids),
                    run_id, run_id,
                ),
            )
            status = "new"
        else:
            self.conn.execute(
                "UPDATE findings SET last_seen_run=?, seen_count=seen_count+1 WHERE fingerprint=?",
                (run_id, f.fingerprint),
            )
            status = "duplicate"
        self.conn.execute(
            "INSERT OR IGNORE INTO run_findings (run_id, fingerprint) VALUES (?,?)",
            (run_id, f.fingerprint),
        )
        self.conn.commit()
        self.log_provenance(
            run_id, "finding.upsert",
            {"fingerprint": f.fingerprint, "status": status, "verdict": f.verdict,
             "symbol": f.symbol, "weakness_class": f.weakness_class},
        )
        return status

    def findings_for_run(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            """SELECT f.* FROM findings f
               JOIN run_findings rf ON rf.fingerprint=f.fingerprint
               WHERE rf.run_id=?""",
            (run_id,),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def all_findings(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM findings").fetchall()
        return [self._row_to_dict(r) for r in rows]

    @staticmethod
    def _row_to_dict(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["evidence"] = json.loads(d.pop("evidence_json") or "[]")
        d["provenance_ids"] = json.loads(d.pop("provenance_json") or "[]")
        return d

    # ---- append-only logs -----------------------------------------------------
    def log_provenance(self, run_id: str, event: str, payload: dict) -> str:
        ev_id = "ev_" + uuid.uuid4().hex[:12]
        rec = {
            "id": ev_id,
            "ts": time.time(),
            "run_id": run_id,
            "event": event,
            "payload": payload,
        }
        with self.provenance_log.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
        return ev_id

    def log_rule_gap(self, run_id: str, payload: dict) -> None:
        rec = {"ts": time.time(), "run_id": run_id, **payload}
        with self.rule_gaps_log.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")

    def close(self) -> None:
        self.conn.close()
