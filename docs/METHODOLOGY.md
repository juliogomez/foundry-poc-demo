# Methodology - the controlled experiment

This document is like the registration of the experiment before doing it. I write
it to be read *before* looking at [RESULTS.md](RESULTS.md), so you can judge if the
design is fair in an independent way from what it produced.

## Subjects

- **Target:** [Langflow](https://github.com/langflow-ai/langflow), fixed in the tag
  `1.7.3`, downloaded (never copied inside) by `scripts/fetch_target.sh`.
- **Scope:** the **entire Langflow v1 API layer** - all 25 HTTP
  request-handler modules where external input crosses a trust boundary - plus the
  one helper module with a real `compile()`/`exec()` sink. That is **289
  function-level units**. It is defined in `config.yaml` under
  `target.include_globs`.
- **Scale contrast:** a smaller, hand-curated 12-module slice (107 units) lives in
  `config-narrow.yaml`. Running both shows how the governance wins change with
  scope: at the small scope a single-shot baseline keeps up on breadth; at full v1
  scope it cannot hold 25 modules in one turn and curates a short list instead.
- **Why the API and not all 373 backend files:** the API is the coherent external attack
  surface (the HTTP entry points). Sweeping the entire backend would add cost
  without changing the demonstration. The boundary is principled and transparent, so
  a skeptic can see exactly what was examined.

## The two arms

The two arms use the **same model** (configured in `config.yaml`, through the
Cursor SDK) and see the **same files in scope**.

### Arm A - Foundry (`foundry_poc.cli run`)
All the harness: Indexer -> Detector -> Triager (with the evidence gate that works
in an automatic way) -> Reporter (with the fingerprint dedup), under a budget
governor and a coverage stop, and logging all the provenance.

### Arm B - the fair agentic baseline (`foundry_poc.cli baseline`)
One Cursor agent with **access to the files** of the same scope, with a disciplined
prompt of a senior AppSec reviewer that asks explicitly for: structured findings,
exact line citations, verbatim quotes, no invented references, no duplicates and
severity prioritization. It is the *same model asked to do the same job*, but
with nothing that forces these requirements in an automatic way.

The baseline prompt is NOT made weak on purpose. All the point is to see if the
harness matters even when the plain model is asked, in good faith, for the same
rigor.

## What is different between the arms

Only the **harness**. The baseline does not have:

- an evidence gate that works automatic (citation resolution),
- deduplication by fingerprint between runs,
- an append-only provenance log,
- a token budget governor,
- a bounded and declared coverage/stop condition,
- a separation of the confirmed findings from the `needs-review` ones.

## Metrics defined before (they do not need ground truth)

All the metrics are computed by `foundry_poc/scorer.py` from the two output files
plus the target source. **There is no human judgment and no oracle of known
vulnerabilities**, so no arm can be scored good just by opinion. The *same* checks
are applied to the two arms.

| # | Metric | Definition | Better |
|---|---|---|---|
| 1 | **Confirmed citation resolution** | From the findings that a tool presents like *confirmed* (`verdict = true-positive`), the fraction that would pass the evidence gate: at least 1 cited line resolves to real code AND no citation is hallucinated. | higher |
| 2 | **Hallucinated citations (confirmed set)** | Number of citations in the confirmed set that point to a file that does not exist, a line out of range, or a quote that does not match the cited line. | lower |
| 3 | **Hallucinated citations (all findings)** | The same, but across every finding. | lower |
| 4 | **Structural completeness** | Fraction of findings that have all the required fields `{file, line, class, severity, verdict, evidence}`. | higher |
| 5 | **Duplicate rate** | `1 - unique(file, class, line) / total`, using **the same key for the two arms**. | lower |
| 6 | **Provenance reconstructable** | Can you trace each finding to the calls/decisions that produce it? (This is a property of the harness.) | yes |
| 7 | **Bounded stop** | Did the run stop with a declared rule of budget/coverage, or just when the model felt it was done? | declared |

Metric #1 is the main one. It applies the evidence gate to the **two** arms and asks
the fair question: *from all the things that a tool tells you is a confirmed bug,
how much survives a verification against the real code?*

### Two structural measurements computed from artifacts

Beyond the per-finding metrics above, the scorer computes two things directly from
the finding store and the rule corpus (still no human judgement, still deterministic):

| # | Measurement | Definition | Honesty note |
|---|---|---|---|
| 8 | **Cross-run stability** | From the SQLite store: distinct fingerprints across all runs vs. the naive sum, and how many findings recurred (`seen_count > 1`). | Pre-registered: the dedup/repeatability claim was part of the design from the start. |
| 9 | **Coverage gap + flywheel** | Compare the weakness classes the *baseline* surfaced against the rule corpus the Foundry run actually used (read from the run's stored config), then against the corpus now. Reports gap-at-run, gaps-closed-by-new-rules, and still-open. | Added **after** observing that the baseline ranged wider than our starting corpus. It is an honest response to a real result, not a pre-registered metric - we flag it as such. |

Measurement #9 is the point of the flywheel: it makes "what did the corpus miss, and
did we close it" an auditable computation instead of a hand-wave.

The flywheel also runs in the **opposite** direction - not just adding rules, but
**sharpening** them. In the wide run the `CWE-209` rule fired on a pervasive, low-
value idiom (72 near-identical findings). That noise is itself a signal: we tightened
the rule to confirm only genuinely sensitive leaks, and CWE-209 dropped from 72 to 6
on the next run while the signal-dense classes remained. The before/after counts are
recorded in [RESULTS.md](RESULTS.md); the class breakdown in `out/comparison.md` makes
the long tail visible rather than hiding it.

## The citation resolver (how we decide when it "resolves")

A citation `{file, line, quote}` **resolves** only if:

1. `file` exists inside the target root (we check the path containment), and
2. `1 <= line <= number of lines of the file`, and
3. if there is a `quote`, it appears in the cited line or in a window of +/- 2 lines
   (this tolerates a small off by one in the line number, but rejects an invented
   quote).

This is on purpose generous with the model (a window of +/- 2, substring match), so
the failures are clear fabrications and not just problems of format.

## Reproducibility and controls

- Our target is **fixed** (`1.7.3`), so anybody that runs it again sees the same code.
- The Foundry run is **run again** to show the stable fingerprints and the dedup between runs (see RESULTS).
- All the output files (`out/`) are kept: the Foundry report, the normalized JSON, the raw
  candidate list, the provenance log, the rule gaps, the raw baseline transcript
  and the comparison table.

## What to read next

Next in the guided path: **[ARCHITECTURE.md](ARCHITECTURE.md)** - how the two arms
and the evidence gate described here map to the actual Python modules.