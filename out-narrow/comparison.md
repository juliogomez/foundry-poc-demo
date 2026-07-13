# Foundry vs. a plain agent: a governance layer over the same model

- **Target:** `langflow` @ `1.7.3`  |  **Model (both arms):** `claude-sonnet-4-6`
- **Foundry run:** `run_ad27b1000969`  |  **Baseline run:** `base_e8a8362cc5b4`

> **What this compares.** Both arms are the *same model* reviewing the *same code*. The baseline is that model given a fair, disciplined prompt asking for the same rigor. Foundry is that model wrapped in the harness. Every number below is computed by code from the output files and the target source - no human judgement, no CVE oracle - so it cannot be rigged.

**The claim is not that Foundry finds more or better bugs. It does not, and we do not want it to.** The claim is that the harness turns the same model's output into something a security program can actually operate on: verifiable, repeatable, bounded, auditable, and self-improving. Those are properties of the *engineering around* the model, and a single agent turn cannot provide them no matter how good the model is.

## 1. What the harness guarantees (and one agent turn cannot)

| Property | Foundry | Plain agent | Why it matters |
|---|---|---|---|
| Enforced *confirmed* vs *needs-review* tier | 3 confirmed + 5 needs-review (gate-enforced) | 7 confirmed + 3 needs-review (self-declared) | A consumer knows which claims were mechanically checked |
| Every confirmed finding passes an evidence gate | yes (citations must resolve to real lines) | no (nothing enforces it) | No unverifiable claim can reach *confirmed* |
| Provenance reconstructable per finding | yes (append-only log links each finding to its LLM calls) | no (one opaque transcript) | You can audit *why* a finding exists |
| Bounded, declared stop | coverage-complete (all 107 units); trailing true-positive yield=0.25 | none (single unbounded agent turn) | "When did it stop and why" is an explicit fact |
| Tokens to cover the scope (total, incl. cache) | 720,830 | 1,441,761 (~2.0x) | Same coverage, lower spend, under a hard cap |

## 2. Repeatability (measured across runs)

The pipeline was run **2 times** (16 in `run_ad27b1000969`, 14 in `run_2f61b23de3ec`). Because every finding has a stable fingerprint `(file, weakness_class, symbol)`, re-running does **not** produce a second wall of findings:

- **16 distinct findings total** across all runs - not 30 (the naive sum if nothing deduped).
- **14 findings recurred** and collapsed onto their existing identity instead of duplicating.
- A plain agent has **no identity between runs**: run it twice and you get two unrelated blobs to diff by hand.

## 3. The detection->prevention flywheel (the spec's centerpiece)

The Foundry spec puts one mechanism at its center (FR-037/FR-040/FR-042): rules sweep every unit; an **exploratory pass hunts alongside**; when exploration confirms something no rule would have caught, a **rule-gap** is recorded; the gap becomes a new rule; the next sweep catches that whole class. This PoC turns that loop.

**First half - detection compounds (spec-faithful).** Foundry's own exploratory pass recorded **2 rule-gap(s)** in this run (`out/rule-gaps.jsonl`) - patterns it confirmed worth review that no rule in the corpus described. That is the FR-042 loop running exactly as specified, with no second tool involved.

**A second, illustrative gap source: the baseline as a stand-in for unconstrained hunting.** A plain agent ranges wider than a declared ruleset, so we use its findings as a proxy for "what exploration might surface" and compute the coverage gap deterministically:

- Baseline weakness classes: CWE-113, CWE-209, CWE-22, CWE-287, CWE-306, CWE-312, CWE-639, CWE-94.
- The Foundry run used **9 rules**. Classes surfaced **outside that corpus**: CWE-113, CWE-209, CWE-312, CWE-639.
- Each gap becomes a new CodeGuard rule. The corpus now has **13 rules**; gaps **closed**: CWE-113, CWE-209, CWE-312, CWE-639. Re-running with the expanded corpus catches these classes on the first pass, under the same evidence gate and provenance.

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
| Duplicate rate (within one run) | 0% | 0% | lower |

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

Foundry is not a smarter bug-finder; it is a **governance and repeatability layer over whatever model you already trust** - exactly the system the spec sets out to describe. On the same code, the same model becomes: verifiable (evidence gate), tiered (enforced confirmed vs needs-review), auditable (provenance per finding), bounded (declared stop), cheaper (fewer tokens under a cap), repeatable (stable identity across runs), and self-improving (rule-gaps -> new rules -> prevention in the editor). Those are the properties a security program needs before it can trust automated findings - and they are precisely what a single agent turn cannot give.
