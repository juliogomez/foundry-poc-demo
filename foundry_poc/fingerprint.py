"""Stable finding fingerprints for cross-run deduplication (Foundry: Fingerprint
Dedup). A fingerprint must be stable to cosmetic churn (line shifts, reformatting)
but distinct across genuinely different findings.

Design: hash (relative_file, weakness_class, normalized_symbol). We deliberately
do NOT include the line number, because line numbers drift as code above changes;
including them would defeat dedup across runs/revisions. We use the enclosing
function's qualified name as the stable locator instead.
"""
from __future__ import annotations

import hashlib


def compute_fingerprint(rel_file: str, weakness_class: str, symbol: str) -> str:
    basis = "\n".join(
        [
            rel_file.strip().replace("\\", "/"),
            weakness_class.strip().upper(),
            symbol.strip(),
        ]
    )
    return "fp_" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
