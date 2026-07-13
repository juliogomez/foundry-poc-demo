# Results

These numbers come from a real run against Langflow `1.7.3`, produced by
`foundry_poc.cli run` / `baseline` / `score`. Everything here can be reproduced from
the files in `out/`. The methodology was defined in [METHODOLOGY.md](METHODOLOGY.md)
**before** the run.

The **canonical run is the wide scope**: the entire Langflow v1 API surface (289
function-level units across 25 modules) plus the `compile()/exec()` helper. A smaller
curated 12-module run (`config-narrow.yaml`, artifacts in `out-narrow/`) is kept as a
scale contrast and discussed at the end.

**A word on terms: which number counts which row.** A **finding** is
one candidate weakness the system recorded; each has a verdict. In the representative
run the funnel was: **61** candidates proposed -> **58** *stored* (after in-run dedup)
-> of those, **32** *surfaced* (`confirmed` + `needs-review`, what a human reviews)
and **26** rejected (kept internal, never shown). The two headline comparisons read
**different rows**: **(a) vs. the baseline** uses the **surfaced** row (32); **(b)
against itself** uses the **stored** row (58 here, 64 in the other run), because dedup
tracks the whole store. So "surfaced 32" and "stored 64" are two rows of one funnel,
not a contradiction. We use "finding" throughout - never "issue".

With a strong model (`claude-sonnet-4-6`) and a *fair, disciplined* baseline prompt, there are two separate comparisons.

**(a) Foundry vs. the baseline agent (one run, same model, same code):**

- **Citation quality ties.** Both arms resolve 100% of confirmed citations with
  zero hallucinations. We did not weaken the baseline to manufacture a gap.
- **Foundry surfaces ~2x more findings worth reviewing - 32 vs 15 - but not
  because the model is smarter.** *Here more is better*: a single agent turn curates
  a short headline list, while Foundry sweeps every one of the 289 units under a
  bounded budget. Completeness is a property of the **harness**, not the model.
- **Foundry costs ~10x more tokens (2.05M vs 213k).** It is *not* cheaper. The
  extra spend buys exhaustive coverage + the evidence gate + dedup, under a hard,
  declared cap.

**(b) Foundry against itself (the same pipeline run twice - only to *exhibit*
repeatability; on unchanged code the second run learns nothing new, it stands in for
the next CI run on the next commit):**

- **Across both runs the store held 122 finding-records, deduped to 67 distinct.**
  *Here fewer is better*: the stable-fingerprint dedup collapsed the ~55 repeats, so
  re-running gives you 67 distinct findings to reconcile, not a second wall of 122 to
  diff by hand. Both numbers count the **same population** - all stored findings,
  *including gate-rejected ones* - before vs. after dedup, so it is apples-to-apples.
  (Do not compare this 67 to the 32 in (a): (a) counts **surfaced** findings, (b)
  counts **all stored**. Different populations on purpose.)
- **The flywheel is live.** One run tuned a noisy rule down (CWE-209: 72 -> 6
  surfaced findings) and recorded 2 exploratory rule-gaps (both CWE-346) for a class
  no rule covered yet.

Both directions favor the harness even though one number goes up and the other
down: against the baseline Foundry covers **more** (32 > 15); against itself it
repeats **without multiplying** (67, not 122). Foundry's value is **not** being a
better bug-finder - it is a **governance and repeatability layer** over the same
model: an *enforced* confirmed-vs-needs-review tier, provenance per finding, a
declared bounded stop, stable identity across re-runs, and a corpus that sharpens
itself. One unbounded agent turn cannot give those, however well it behaves.

## Parameters of the run

| Field | Value |
|---|---|
| Target | `langflow` @ `1.7.3` (fixed, downloaded not copied) |
| Model (both arms) | `claude-sonnet-4-6` (through the Cursor SDK) |
| Scope | **289** function-level units across **25** v1 modules + `helpers/flow.py` |
| Foundry LLM calls | **16** (12 batched Detector + 4 batched Triage) |
| Foundry tokens | **2,053,308** (cap 6,000,000, not exhausted) |
| Foundry stop | coverage-complete (all 289 units), trailing TP yield 0.67 |
| Baseline tokens | **213,121** in one single unbounded agent turn |

## Foundry findings (representative run `run_7b35d578cfd2`)

58 findings from 61 candidates, decided by the Triager + evidence gate:

| Verdict | Count |
|---|---|
| **true-positive** (confirmed) | 28 |
| **needs-review** | 4 |
| **false-positive** (rejected) | 26 |

The **32 surfaced** findings (true-positive + needs-review) by severity:
**3 critical, 11 high, 18 medium**. By weakness class:

| Class | Surfaced | |
|---|---|---|
| CWE-639 (IDOR / missing ownership) | 10 | |
| CWE-209 (error info leak) | 6 | *(was 72 before the rule was tuned - see the flywheel)* |
| CWE-22 (path traversal) | 4 | |
| CWE-862 (missing authz) | 4 | |
| CWE-113 (header injection) | 2 | |
| CWE-312 (sensitive-data exposure) | 2 | |
| CWE-346 (origin validation) | 2 | |
| CWE-89 (SQL injection) | 1 | |
| CWE-94 (code injection) | 1 | |

The 26 rejected candidates never reach a reader: the harness surfaces only what
survives the gate (Constitution II). A plain agent has no such internal tier - what
it prints is what you get.

## Headline comparison (`out/comparison.md`)

| Metric | Foundry | Baseline | Better when |
|---|---|---|---|
| Findings surfaced (confirmed + needs-review) | 32 | 15 | - |
| Confirmed / needs-review | **28 / 4** (gate-enforced) | 14 / 1 (self-declared) | see note |
| Confirmed citation resolution (survives the gate) | 100% | 100% | higher |
| Hallucinated citations (confirmed set) | 0 | 0 | lower |
| Hallucinated citations (all) | 0 | 0 | lower |
| Structural completeness | 100% | 100% | higher |
| Duplicate rate (within one run) | 2% | 0% | lower |
| **Provenance reconstructable** | **yes** | **no** | yes |
| **Bounded stop** | **declared** (289 units) | **none** | declared |
| Tokens spent | 2,053,308 (~10x) | 213,121 | see note |

### Key findings

- **The citation quality tied (100% / 0 / 0).** A capable model, asked in good
  faith for rigor, largely delivered it. We did not make the baseline weak to
  manufacture a gap, so we report the tie plainly.
- **The confidence tier is the real difference.** The baseline labeled **14 of its
  15** findings "true-positive". That tier is only a hope that the model declares
  its own doubt - nothing enforces it. Foundry confirmed **28** and held **4** as
  `needs-review`, and a finding reaches confirmed *only if its citations resolve
  against the real source*. A reviewer consuming the baseline cannot know which
  claims were checked; a reviewer consuming Foundry can, because the gate forces the
  separation instead of trusting the model to self-declare it.
- **More findings is completeness, not cleverness.** Foundry's 32 vs the baseline's
  15 is the difference between an exhaustive per-unit sweep and a single turn that
  curates a short list and drops the long tail. Same model; different discipline.
- **More tokens.** Foundry is not cheaper here - it spends ~10x to cover
  all 289 units under a *declared cap*, versus one unbounded turn. The spend buys
  coverage + gate + dedup, not a smarter model.
- **Where the tie is fragile vs where Foundry is guaranteed.** The baseline's clean
  citations are a *hope* that holds for this model, this scope, this prompt. A
  weaker model, a bigger scope, or a sloppier prompt breaks it. Foundry's 100% is a
  *guarantee by construction*: the same automatic gate always runs and demotes
  anything it cannot verify.

## An auditable true positive

From `out/findings/run_7b35d578cfd2.md`, finding `fp_fbde3053ed1387d0`:

**Code injection via `exec()` on user-controlled `display_name`**
(`verdict: true-positive`, `severity: critical`, `CWE-94`) -
`src/backend/base/langflow/helpers/flow.py` - `generate_function_for_flow` (L280).

Line 280 embeds `input_.display_name` into a generated Python source string with
only a `.lower().replace(' ', '_')` normalization that does not neutralize `)`,
`:`, or newlines. Line 327 calls `exec()` over the compiled result.

Its three citations resolved automatically against the real source:

| Citation | Resolved | Quoted line |
|---|---|---|
| `flow.py:280` | yes | `f"{input_.display_name.lower().replace(' ', '_')}: {INPUT_...` |
| `flow.py:300` | yes | `async def flow_function({func_args}):` |
| `flow.py:327` | yes | `exec(compiled_func, globals(), local_scope)  # noqa: S102` |

Provenance chain (`out/provenance.jsonl`): this finding links to the `detector.call`
event `ev_bfa11e88b7bc` and the `triager.call` event `ev_646b334987b0` (from
`run_0285f1964168`, where the finding was first established - it then recurred and
deduped in `run_7b35d578cfd2`, so its stable identity keeps pointing at the original
evidence). You can open the log and read the exact calls, token usage and gate
bookkeeping that produced it. The baseline gives one opaque transcript, with no
per-finding trail.

(Two more criticals in this run are path-traversal + arbitrary directory deletion in
`knowledge_bases.py::delete_knowledge_base` / `delete_knowledge_bases_bulk` - both
reachable `shutil.rmtree(kb_root / user_input)` sinks.)

## The evidence gate in this run

Every confirmed finding's citations resolved, so the gate demoted none this run.
That is the strong model again - and it is exactly why the gate matters as a
*guarantee*, not a filter that only fires sometimes: regardless of whether a given
model hallucinates, the gate makes sure nothing reaches `true-positive` without
machine-checked evidence. (`FOUNDRY_LLM=mock` emits bad citations on purpose so you
can watch the gate demote them.)

## Dedup and stability across runs

The Foundry pipeline was run **twice** (independent LLM calls). These counts are the
**stored** row of the funnel (surfaced + rejected, since dedup tracks the whole
store): the representative run above stored **58**, the other run stored **64** - not
to be confused with the **32** *surfaced* from the representative run. The second run
is here **only to exhibit this property** - on unchanged code it learns nothing new;
it stands in for the next time you run the pipeline (e.g. a later commit), where the
dedup below is what lets you triage only the delta:

- The store holds **67 distinct fingerprints across the two runs, not 122** (the
  naive sum). Re-running did **not** produce a second wall of findings.
- **56 fingerprints recurred** in both runs and collapsed onto their existing
  identity (`seen_count > 1`) instead of duplicating - a ~90% overlap despite model
  non-determinism.
- The identity is `(file, weakness_class, symbol)`, deliberately without a line
  number, so it survives code edits and model jitter. Example: the `flow.py` exec
  finding above carries the same fingerprint `fp_fbde3053ed1387d0` in both runs (and
  in the narrow run too).

One agent turn has no identity between runs: run it twice and you get two unrelated
blobs to diff by hand.

## Rule gaps and the flywheel (detection -> prevention)

The flywheel showed up in **three** concrete ways in this run.

**(a) Sharpening a noisy rule (the "tune the rule" step).** The first wide run fired
the `CWE-209` error-info-leak rule on the pervasive `HTTPException(detail=str(e))`
idiom - **72** near-identical findings, technically valid but low-signal noise, not
72 distinct bugs. That is itself a flywheel signal: a noisy rule is something to
sharpen, not a pile to argue with. We tightened
`rules/py-error-info-leak.yaml` to confirm only genuinely sensitive leaks
(tracebacks, `repr(exc)`, DB/filesystem/subprocess errors, paths/queries) and to
treat the generic idiom as a single systemic note. Result on re-run: **CWE-209 went
from 72 to 6**, and the surfaced set became signal-dense (led by IDOR and path
traversal). Doing this required a real harness fix too - the rule's exclusion
criteria now flow into both the Detector digest and the Triager gate.

**(b) Foundry's own exploratory pass.** The Detector flagged a pattern **no rule
covered** and the Triager judged it worth review, logged in `out/rule-gaps.jsonl`:
**2 rule-gaps** in the representative run, both `CWE-346` (`Origin`/`X-Forwarded-For`
trust in `get_client_ip` and `install_mcp_config`). They recur in both runs, so the
log holds 4 records total (2 x 2) - the count the scorer reports. This is the spec's
FR-040/FR-042 loop running with no second tool.

**(c) The baseline as an illustrative gap source.** Ranging freely, the plain agent
surfaced `CWE-348` (use of less-trusted source) - a class outside the current
13-rule corpus. The scorer computes this gap deterministically (section 3 of
`out/comparison.md`); it becomes the next new rule.

Each new rule carries a `Provenance:` note. The four rules added earlier in the
flywheel (IDOR, header-injection, error-leak, sensitive-data) are already **live in
this run's 13-rule corpus** - the loop's first turn has already paid off.

**The second half - prevention everywhere (US-14 / FR-041).** CodeGuard rules are
*portable*: the same corpus this evaluation grows loads unchanged into an LLM coding
assistant as secure-coding guardrails. A class you teach Foundry to *detect* in
finished code becomes a class the assistant *prevents* at the keystroke, in every
editor, before the next evaluation runs. (The `codeguard-*` rules governing this very
workspace are that same format, already deployed that way.)

## The scale contrast (narrow run, `out-narrow/`)

Run over just 12 curated modules (107 units), the story is different - and that
difference is the point:

- At small scope the single-shot baseline **keeps up on breadth**; it even ranged
  wider than the starting corpus. The governance wins (gate, provenance, bounded
  stop, dedup) are present but the raw counts look like a tie.
- At full v1 scope the baseline **cannot** hold 25 modules in one turn - it curates
  ~15 headline items, while Foundry's per-unit sweep surfaces 32 gated, deduped,
  provenanced findings. The harness's value grows with scope.

This is why "widen the scope" is the honest stress test, and why the wide run is the
canonical one.

## Honest interpretation

- **Foundry is the same model; it is not a smarter bug-finder.** On shared classes
  the arms agree, and citation quality ties.
- **At scale Foundry surfaces more only because it enumerates exhaustively.** That
  is a harness property (completeness under a bounded budget), and it includes a
  long tail a curated pass omits - which is exactly why rule tuning (the flywheel)
  matters.
- **Foundry is not cheaper** - ~10x the tokens - but the spend is bounded by a
  declared cap and buys coverage + gate + dedup.
- **The provable value is governance and repeatability:** enforced
  confirmed/needs-review, provenance per finding, a declared bounded stop, stable
  identity across runs, and a corpus that both grows (rule-gaps) and sharpens (rule
  tuning). One agent turn cannot guarantee these, however well it behaves.

### Reproduce it

```bash
export CURSOR_API_KEY=...
python -m foundry_poc.cli run                 # canonical wide run -> out/
python -m foundry_poc.cli baseline
python -m foundry_poc.cli score --foundry out/foundry-<run>.json \
                                --baseline out/baseline-<run>.json
python -m foundry_poc.cli run                 # again, to see cross-run dedup
python -m foundry_poc.cli status

# the narrow scale-contrast:
python -m foundry_poc.cli --config config-narrow.yaml run
```

## What to read next

Next in the guided path: **[USE-ON-YOUR-OWN-REPO.md](USE-ON-YOUR-OWN-REPO.md)** - now
that you have seen the numbers, point the harness at your own code base.
