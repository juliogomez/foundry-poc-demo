# Foundry Security Spec in the real world

This repo is a proof of concept. It implements the
[Foundry security harness specification](https://github.com/CiscoDevNet/foundry-security-spec) and uses it to run a comparison (a small controlled experiment) against a real and complex code base, [Langflow](https://github.com/langflow-ai/langflow).

## Start here

New here? Follow the guided path in order:

1. **[VALUE.md](docs/VALUE.md)** - why it matters.
2. **[METHODOLOGY.md](docs/METHODOLOGY.md)** - the PoC design, the fair baseline, and metrics
3. **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - how the Foundry roles map to the code.
4. **[CUSTOMIZATION.md](docs/CUSTOMIZATION.md)** - how `config.yaml` and `rules/` are your customized spec.
5. **[WALKTHROUGH.md](docs/WALKTHROUGH.md)** - run it yourself.
6. **[RESULTS.md](docs/RESULTS.md)** - the numbers from the real run
7. **[BUILD-YOUR-OWN.md](docs/BUILD-YOUR-OWN.md)** - take it to your own repo by building your own from the spec.

In a hurry? Jump to the [Quickstart](#quickstart) or [What is inside the repo](#what-is-inside-the-repo). 

## The value of this repo

The Foundry spec is a *design*, not off-the-shelf runnable code. It ships as two documents:

- **`spec.md`** - the "seed specification": the agent roles (Indexer, Detector,
  Triager, Reporter, Orchestrator...), the lifecycle a finding goes through, and
  ~130 functional requirements, each with the rationale for *why* it exists. It is
  deliberately left open at every organization-specific decision, which it marks
  `[NEEDS CLARIFICATION: ...]` for the implementer to answer (things like which model? which
  scope? which datastore?).
- **`constitution.md`** - eleven *inviolable principles* the whole design rests on
  (for example: "a finding is `confirmed` only by checkable evidence, never by model
  confidence"). It is called _a constitution_ because it is the top authority every
  implementation must obey: each principle encodes a production failure the Foundry
  authors hit and fixed, and any plan or code derived from the spec is checked
  against it. This PoC upholds the principles it can in a single-process static
  tool (see [VALUE.md](docs/VALUE.md#does-this-align-with-the-foundry-spec)).

This repo is **one worked PoC implementation** of that design: the result of answering
the spec's `[NEEDS CLARIFICATION]` questions for a concrete case: to evaluate a real-world code repo (Langflow), using an LLM. You can (a) clone this repo and reproduce the example,
or (b) use the Foundry spec to [build your own implementation](docs/BUILD-YOUR-OWN.md) on your own stack. See
[ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the roles map and
[CUSTOMIZATION.md](docs/CUSTOMIZATION.md) for the exact files that carry the
customization.

## The question this PoC answers

The question i wanted to answer is simple:

*If i already have a good coding model, what do i really win when i wrap it inside
the Foundry harness?*

The answer that this PoC shows is NOT "it has deeper insight" - it is the **same
model**. The claim is more narrow, but it can be proven:

Foundry is a **governance and repeatability layer over the model you already
trust**. It does not change the model; it changes what you can *rely on* from the
model's output.

- **Governance** here means the harness *enforces rules on the output* so a
  security team can act on it: only evidence-backed claims may be called
  "confirmed", every finding is auditable, the run stops on a declared rule, and
  severity follows a policy you set - nothing rests on the model's unverified
  say-so.
- **Repeatability** means running it again gives you the *same distinct findings,
  deduplicated onto stable fingerprints*, instead of a fresh, differently-worded
  report you have to diff by hand.

## The value of Foundry

Concretely, the same model wrapped in the harness produces output that is:

### Three properties of each finding

The first three below sound alike but answer three *different* questions about a
finding - **is the evidence real? who set the label? can I reprove it later?** - and
each maps to a different piece of the spec:

- **Verifiable** *(is the evidence real?)* - this is about the **content** of one
  finding. Every `confirmed` finding's cited lines are *mechanically resolved against
  the actual source file*: the location exists and the code there is what the finding
  says it is. A claim whose citations don't resolve is demoted. This is the spec's
  Principle I, *Evidence Over Assertion*. *Value: a `confirmed` finding points at code
  that provably exists - you don't reopen the file to check the model didn't invent
  the line or misread it.*
- **Tiered by force** *(who set the label, and is my queue pre-filtered?)* - this is
  not about any single citation but about the **population you receive and how it was
  labeled**. Detection is deliberately high-volume and noisy; only findings that
  *survive* triage are surfaced at all (the rejected ones stay in the internal store),
  and the `confirmed`-vs-`needs-review` line is drawn by the **gate's pass/fail, never
  by the model rating its own confidence**. This is the spec's Principle II, *Surface
  Only What Survives*. *Value: your queue is already filtered to survivors, and the
  tier is an objective record of how much checking a finding withstood - not the
  model's self-assessment.*
- **Auditable** *(can I reprove it later?)* - this is about neither the evidence nor
  the label but the **history** behind them. Each finding links to the exact
  detector/triager LLM calls and the gate decision that produced it, in an
  append-only provenance log. *Value: months later you can reconstruct and defend why
  any finding exists to someone who wasn't in the room - independent of whether they
  trust today's label, they can retrace how it was reached.*

### Three properties of the whole run

The remaining three are about the run as a whole rather than a single finding:

- **Bounded** - the run halts on a declared budget/coverage rule. *Value: predictable
  cost and an honest "we looked everywhere you asked" done-signal, instead of stopping
  when the model happens to feel finished.*
- **Repeatable** - each finding's fingerprint `(file, class, symbol)` ignores line
  numbers and wording, so when a re-run produces the same weakness the store
  recognizes it as the *same distinct finding* (it bumps a counter) instead of filing
  a new one. *Value: you triage the delta as code changes, not the entire list from
  scratch each time.*
- **Self-improving** - a detection->prevention flywheel that grows the **rule
  corpus** over time: a weakness no rule covered is logged as a *rule-gap* and a human
  turns it into a new rule (so the next run detects that class by rule), and a rule
  that fires as noise is a signal to tighten it (we cut CWE-209 from 72 to 6 that
  way). *Value: a one-off observation becomes a durable rule instead of evaporating
  when the session closes - and the same portable rule can move into a coding
  assistant like CodeGuard to prevent the class at authoring time.*

__The same model pointed at the same code, but alone without Foundry, gives you none of these reliably.__

## The demonstration

The demo runs over the **entire Langflow v1 API surface** (289
function-level units across 25 modules). Two *different* comparisons matter here, and
they measure different things - the trick is not to confuse them.

### Let's compare

- **(a) Foundry vs. a fair baseline agent** - same model, same code, one run each.
  Citation quality **ties**: both arms resolve essentially all of their confirmed
  citations against real code, with no hallucinations (we deliberately do not weaken
  the baseline). What differs is **coverage** - Foundry surfaces roughly **twice as
  many findings worth reviewing**, because it sweeps every unit under a bounded budget
  while a single agent turn curates a short headline list. That completeness costs
  about **10x the tokens**: it is not cheaper, and it is not a smarter model.
- **(b) Foundry against itself** - the same pipeline run twice, only to *exhibit
  repeatability*. The two runs come out near-identical, and stable fingerprints
  collapse the union down to roughly one run's worth of **distinct** findings instead
  of a doubled wall of text. This stands in for the next CI run on the next commit,
  where you triage only the **delta**. A plain agent has no such identity between
  runs - two runs stay two unrelated blobs.

Both directions favor the harness for the same reason, and it is **not** that the
model got smarter: Foundry is a **governance and repeatability layer** over the model
you already trust.

The exact numbers behind this summary - the finding funnel
(candidates -> stored -> surfaced), the per-weakness-class breakdown, the headline
metrics table, and a fully worked, auditable finding - live in
**[RESULTS.md](docs/RESULTS.md)** (and `out/comparison.md`). Those metrics are
defined *before* the run in [METHODOLOGY.md](docs/METHODOLOGY.md), need no ground
truth, and are applied identically to both arms, so the comparison can not be gamed.
A narrower 12-module run is included as a scale contrast (see the table below).

---

## Quickstart

Everything is installed inside a local virtual environment (`.venv/`), so it does
not dirty your machine. If you delete the folder, all is gone.

```bash
# 0. Get this implementation
git clone https://github.com/juliogomez/foundry-poc-demo.git foundry-poc-demo
cd foundry-poc-demo

# 1. Create the isolated environment and install the deps only there
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -r requirements.txt

# 2. Download the target (Langflow) in a fixed revision
bash scripts/fetch_target.sh

# 3. Check the environment and the scope (this works offline)
FOUNDRY_LLM=mock python -m foundry_poc.cli up

# 4a. Dry run of all the pipeline OFFLINE with a mock model (always same answer),
#     it validates the plumbing and spends nothing
FOUNDRY_LLM=mock python -m foundry_poc.cli run --limit 10

# 4b. Real run. It uses your Cursor license through the Cursor SDK.
#     Create a key in Cursor Dashboard -> Integrations, then:
export CURSOR_API_KEY=...          # never write this inside the code
python -m foundry_poc.cli up       # confirm the key is visible
python -m foundry_poc.cli models   # list the valid model names
python -m foundry_poc.cli run      # the Foundry pipeline
python -m foundry_poc.cli baseline # the fair agentic baseline
python -m foundry_poc.cli score --foundry out/foundry-<run>.json \
                                 --baseline out/baseline-<run>.json
```

## What is inside the repo

| Path | What it is |
|---|---|
| `foundry_poc/` | A small but real implementation of the Foundry roles (Indexer, Detector, Triager, Reporter, Orchestrator) plus the base parts (store, provenance, budget, fingerprint, evidence gate). |
| `rules/` | A small set of CodeGuard rules (detection patterns that the LLM evaluates). |
| `config.yaml` | The "customized spec" and the **(wide) run**: the whole Langflow v1 API surface. Every option answers a decision the Foundry spec leaves open on purpose (marked `[NEEDS CLARIFICATION]` - a spec convention, not a forgotten placeholder; see [docs/CUSTOMIZATION.md](docs/CUSTOMIZATION.md)). |
| `config-narrow.yaml` | An alternative, smaller scope. Instead of the default glob that sweeps all 25 v1 modules, this config lists **12 specific modules picked by hand** as the highest-signal slice of the attack surface (each entry annotated with why it is included) - 107 units. It is kept as a *scale contrast*: a deliberately small run that shows how the Foundry-vs-baseline picture changes with scope (at small scope the baseline keeps up; at full scope it cannot). Run with `--config config-narrow.yaml`; artifacts land in `out-narrow/`. |
| `scripts/fetch_target.sh` | Downloads Langflow in a fixed revision (we never copy it inside the repo). |
| `docs/` | The tutorial: value, customization, methodology, walkthrough, results, architecture and how to point it to your own repo. |
| `out/` | The generated files: Foundry findings report, baseline report, provenance log, rule gaps, comparison table. |

## The backend

The LLM calls go through the **Cursor SDK** (`cursor-sdk`), that runs Cursor agents
in a programmatic way using your current Cursor plan. You authenticate with a
`CURSOR_API_KEY` that you create in the Cursor dashboard. There is no separate
Anthropic or OpenAI key, and no secret is written to disk or committed. If the key
is not there, every command still works in `FOUNDRY_LLM=mock` mode for the offline
validation of the plumbing.

## A note about honesty

The metrics are computed by `foundry_poc/scorer.py` from the raw files, and the
same checks are applied to the two tools. The baseline is the same model with a
disciplined prompt that asks for the same rigor, so I do not make it weak on
purpose. Whatever the run produces is what `docs/RESULTS.md` reports, including the
places where the harness did not help. See [METHODOLOGY.md](docs/METHODOLOGY.md).
