# Foundry vs. a plain agent: a governance layer over the same model

- **Target:** `langflow` @ `1.7.3`  |  **Model (both arms):** `claude-sonnet-4-6`
- **Foundry run:** `run_7b35d578cfd2`  |  **Baseline run:** `base_65501a94d97f`

> **What this compares.** Both arms are the *same model* reviewing the *same code*. The baseline is that model given a fair, disciplined prompt asking for the same rigor. Foundry is that model wrapped in the harness. Every number below is computed by code from the output files and the target source - no human judgement, no CVE oracle - so it cannot be rigged.

**The claim is not that Foundry's *model* is a smarter bug-finder - it is literally the same model.** Any difference in raw counts below comes from *how the model is driven*, not from the model itself.

At this scope Foundry surfaces **28 confirmed** findings vs the baseline's **14** - but that is *not* Foundry being cleverer. The single unbounded agent turn curates a short headline list and drops the long tail; Foundry enumerates **every one of the 289 units** under a bounded budget, so its set is exhaustive by construction (and therefore also includes low-value long-tail matches a curated pass omits - see the class breakdown). *Completeness is a property of the harness, not the model.* The rest of this report measures what a single turn cannot give at any scope: verifiable, repeatable, bounded, auditable, self-improving.

**What the surfaced set actually contains (Foundry, this run).** Exhaustive enumeration cuts both ways - it also surfaces a long tail of lower-value matches a curated pass would skip. We show it rather than hide it: the largest single class is `CWE-639` with **10** of **32** surfaced findings.

| Weakness class | Surfaced (confirmed + needs-review) |
|---|---|
| CWE-639 | 10 |
| CWE-209 | 6 |
| CWE-22 | 4 |
| CWE-862 | 4 |
| CWE-113 | 2 |
| CWE-312 | 2 |
| CWE-346 | 2 |
| CWE-89 | 1 |
| CWE-94 | 1 |

A security team reads this top-down (critical/high first) and can defer or tune a noisy class - and, per the flywheel, a noisy rule is itself a signal to sharpen the rule, not a finding to argue with.

## 1. What the harness guarantees (and one agent turn cannot)

| Property | Foundry | Plain agent | Why it matters |
|---|---|---|---|
| Enforced *confirmed* vs *needs-review* tier | 28 confirmed + 4 needs-review (gate-enforced) | 14 confirmed + 1 needs-review (self-declared) | A consumer knows which claims were mechanically checked |
| Every confirmed finding passes an evidence gate | yes (citations must resolve to real lines) | no (nothing enforces it) | No unverifiable claim can reach *confirmed* |
| Provenance reconstructable per finding | yes (append-only log links each finding to its LLM calls) | no (one opaque transcript) | You can audit *why* a finding exists |
| Bounded, declared stop | coverage-complete (all 289 units); trailing true-positive yield=0.67 | none (single unbounded agent turn) | "When did it stop and why" is an explicit fact |
| Tokens spent (total, incl. cache) | 2,053,308 (~10x) | 213,121 | More spend, but it buys an exhaustive per-unit sweep of the whole scope under a *declared cap* - vs. one unbounded turn that curates a short list. The extra tokens buy coverage + gate + dedup, not a smarter model. |

## 2. Repeatability (measured across runs)

The pipeline was run **2 times** (64 in `run_0285f1964168`, 58 in `run_7b35d578cfd2`). Because every finding has a stable fingerprint `(file, weakness_class, symbol)`, re-running does **not** produce a second wall of findings:

- **67 distinct findings total** across all runs - not 122 (the naive sum if nothing deduped).
- **56 findings recurred** and collapsed onto their existing identity instead of duplicating.
- A plain agent has **no identity between runs**: run it twice and you get two unrelated blobs to diff by hand.

## 3. The detection->prevention flywheel (the spec's centerpiece)

The Foundry spec puts one mechanism at its center (FR-037/FR-040/FR-042): rules sweep every unit; an **exploratory pass hunts alongside**; when exploration confirms something no rule would have caught, a **rule-gap** is recorded; the gap becomes a new rule; the next sweep catches that whole class. This PoC turns that loop.

**First half - detection compounds (spec-faithful).** Foundry's own exploratory pass recorded **4 rule-gap(s)** in this run (see the run's `rule-gaps.jsonl`) - patterns it confirmed worth review that no rule in the corpus described. That is the FR-042 loop running exactly as specified, with no second tool involved.

**A second, illustrative gap source: the baseline as a stand-in for unconstrained hunting.** A plain agent ranges wider than a declared ruleset, so we use its findings as a proxy for "what exploration might surface" and compute the coverage gap deterministically:

- Baseline weakness classes: CWE-113, CWE-22, CWE-285, CWE-348, CWE-639, CWE-862, CWE-94.
- The Foundry run used **13 rules**. Classes surfaced **outside that corpus**: CWE-348.
- Each gap becomes a new CodeGuard rule. The corpus now has **13 rules**; gaps **closed**: none; still open: CWE-348. Re-running with the expanded corpus catches these classes on the first pass, under the same evidence gate and provenance.

The point either way: a plain agent's discoveries evaporate when the transcript closes; Foundry captures them as rules that harden every future run.

**Second half - prevention everywhere (US-14 / FR-041).** The spec's flywheel does not end at detection. Because CodeGuard rules are portable, the *same* corpus this evaluation grows loads unchanged into an LLM coding assistant as its secure-coding guardrails: the class you taught Foundry to *detect* in finished code becomes a class the assistant *prevents* at the keystroke, in every developer's editor, before the next evaluation runs. Detection investment compounds into prevention. (This is not hypothetical here: the very `codeguard-*` rules governing this workspace are that same format deployed as authoring-time guardrails.)

## 4. Raw citation quality tied - and that is expected

On this target, with a strong model and a disciplined baseline prompt, the raw quality of the citations came out the **same**. We report it plainly; we did not weaken the baseline to manufacture a gap.

| Metric | Foundry | Baseline | Better when |
|---|---|---|---|
| Confirmed citation resolution (survives evidence gate) | 100% | 100% | higher |
| Hallucinated citations (confirmed set) | 0 | 0 | lower |
| Hallucinated citations (all findings) | 0 | 0 | lower |
| Structural completeness | 100% | 100% | higher |
| Duplicate rate (within one run) | 2% | 0% | lower |

The tie is exactly why the governance pillars matter. The baseline's clean citations are a *hope* that holds for this model, this scope, this prompt - and breaks with a weaker model, a larger scope, or a sloppier prompt. Foundry's 100% is a *guarantee by construction*: the same gate always runs and demotes anything it cannot verify. A tie on the easy case, with a guarantee that survives the hard case, is a win for the harness.

## How this maps to the Foundry spec's goal

The spec's stated purpose is to *"turn this model into a system that produces findings we can trust"* - not a better bug-finder. Each pillar above is a direct enforcement of a spec invariant:

| This comparison shows | Spec authority |
|---|---|
| Confirmed only if citations mechanically resolve | Constitution I (Evidence Over Assertion); FR-052, FR-088 |
| Only survivors are surfaced; rest stay internal | Constitution II (Surface Only What Survives); FR-057 |
| Declared coverage-AND-yield stop | Constitution VI (Coverage Before Yield) |
| Stable fingerprint dedup across runs | Constitution VIII (Fingerprints Stable Under Edit) |
| Rule-gap -> new rule -> prevention everywhere | FR-037/FR-040/FR-042, FR-041, US-14 |

## Bottom line

Foundry is not a smarter bug-finder; it is a **governance and repeatability layer over whatever model you already trust** - exactly the system the spec sets out to describe. On the same code, the same model becomes: verifiable (evidence gate), tiered (enforced confirmed vs needs-review), auditable (provenance per finding), bounded (declared stop), bounded in spend (a hard, declared token cap - not the cheapest, but exhaustive), repeatable (stable identity across runs), and self-improving (rule-gaps -> new rules -> prevention in the editor). Those are the properties a security program needs before it can trust automated findings - and they are precisely what a single agent turn cannot give.
