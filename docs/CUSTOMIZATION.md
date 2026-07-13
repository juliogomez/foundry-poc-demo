# Customization - `config.yaml` and `rules/` are your customized spec

The Foundry seed spec is full on purpose of `[NEEDS CLARIFICATION]` markers:
decisions that it does not take for you, because they are yours to take. In this
PoC these decisions live in two places that you edit in a direct way:

- `config.yaml` - the runtime policy (scope, model, budget, severity, stop rule).
- `rules/*.yaml` - the CodeGuard detection set.

You do not touch Python to customize the evaluation. That is the point.

## The files customized for this PoC

This is the complete list of files that carry the customization: everything
that had to be set to turn the generic Foundry design + engine into "evaluate
Langflow with a Cursor-hosted model." For your own target, these are exactly the
files you touch; everything else (`foundry_poc/*.py`) is the untouched engine.

| File | edited | Our customization | Target-specific? |
|---|---|---|---|
| `config.yaml` | the customized spec | The **wide run**: scope (`api/v1/*.py` + `helpers/flow.py` = 289 units), `goals`, model (`claude-sonnet-4-6`), budget cap, severity scheme, store paths. Each block resolves a spec `[NEEDS CLARIFICATION]`. | Yes (scope + goals are Langflow-shaped) |
| `config-narrow.yaml` | created | The same policy over a hand-curated 12-module scope (107 units), kept as a scale contrast. Run with `--config config-narrow.yaml`. | Yes |
| `goals:` block (inside both configs) | edited | The free-text evaluation mission, injected verbatim into the Detector and Triager prompts. This is *what you look for and what is out of scope*. | Yes |
| `scripts/fetch_target.sh` | edited | `REPO_URL` (Langflow), `PINNED_REF=1.7.3`, `DEST`, and a sanity check that the real `compile()/exec()` sink is present at that revision. | Yes |
| `rules/*.yaml` (13 files) | authored | The CodeGuard detection corpus: Python sinks + framework idioms. 9 authored up front (code/shell/SQL injection, SSRF, path traversal, unsafe deser, hardcoded secret, weak crypto, missing authz); **4 added by the flywheel** (IDOR, header-injection, error-leak, sensitive-data); the error-leak rule was later **sharpened** (CWE-209: 72 → 6). | Language-specific (Python); rules are reusable across Python targets |
| `foundry_poc/indexer.py` | ⚠️ only if your target is **not** Python | The AST unit extractor - the single engine file tied to a language. Python targets need no change; another language means swapping this extractor. | Only for non-Python targets |

**What was NOT customized:** every other module in `foundry_poc/` (the Orchestrator,
Detector, Triager + evidence gate, Reporter, store, budget, fingerprint, llm,
baseline, scorer, cli) and `requirements.txt`. That is the whole design goal - the
*policy* lives in config and rules, the *mechanism* lives in the engine, and you
customize an evaluation without editing the engine.

The rest of this document explains each of the customizable pieces in detail.

## `config.yaml`

Each block down here maps to a decision that the spec leaves open.

### `system.name`
The header of the spec asks "how will your system be called?". This is it. It is
cosmetic, but it goes into the reports and the provenance.

### `target`
It defines *what is evaluated* and, very important, *the boundary of the
evaluation*.

```yaml
target:
  path: "targets/langflow"
  include_globs: [ ... ]   # what is IN scope
  exclude_globs: [ ... ]   # what we take out (tests, generated code)
  pinned_ref: "1.7.3"      # reproducibility
```

- `include_globs` is your **decision of scope**, made explicit. The default
  `config.yaml` sweeps the whole v1 request-handler layer
  (`src/backend/base/langflow/api/v1/*.py`) plus the helper with the real `exec()`
  sink - 289 units, the external attack surface. `config-narrow.yaml` shows the
  opposite style: a hand-picked 12-module list, each entry annotated with one line of
  reason. To sweep more, widen the glob, e.g. `src/backend/base/langflow/**/*.py`.
- `pinned_ref` makes the runs reproducible: everybody that runs it again sees the
  same code.

### `goals`
Free text with the goals of the evaluation, injected the same into the prompts of
the Detector and the Triager. This is your statement of **"what we look for and
what is out of scope"**. Rewrite it to change the mission (for example "focus only
on authz and the isolation between tenants").

### `llm`
The decision of the **model and the backend**.

```yaml
llm:
  backend: "cursor"
  model: "claude-sonnet-4-6"
  scratch_cwd: ".scratch"
```

- `backend: cursor` uses the Cursor SDK (your Cursor license). Put the environment
  variable `FOUNDRY_LLM=mock` to run offline with a stub that always answers the same.
- `model` is confirmed against `python -m foundry_poc.cli models` when the
  `CURSOR_API_KEY` is set. All the system is **agnostic of the model**, change the
  name and the two arms (Foundry and baseline) use the new model.

### `budget`
This is the Constitution VI of the spec ("bounded spend") and the stop rule of the
Coverage-Guide.

```yaml
budget:
  max_tokens: 6000000                 # hard cap, the run stops clean when it passes this
  yield_window: 12                    # trailing window for the yield heuristic
  yield_min_true_positive_rate: 0.05  # yield floor for the coverage-AND-yield stop
```

`max_tokens` is your **ceiling of cost**. The governor checks before every call and
stops with a declared reason instead of spending too much. The default wide
`config.yaml` sets `6000000` (the full v1 sweep lands around ~2.05M, well under it);
`config-narrow.yaml` uses `1500000` for its smaller scope.

### `batching`
The Cursor SDK runs each call like a full agent with a big fixed overhead in the
system prompt (around 50k tokens per call), so the cost is per *call*, not per
*unit*. For this we put many units in one call, to share that fixed overhead
between many units. The content is cheap, the overhead is not.

```yaml
batching:
  detector_max_units: 25
  detector_max_lines: 1200
  triage_batch_size: 20
```

### `severity`
Your **policy of prioritization**. The Reporter puts the findings in buckets with
this scheme. Change it to match your risk framework.

### `rules`
It points to the directory of the CodeGuard set. See down here.

### `store`
Where the files go: the SQLite DB, the provenance log, the reports directory and
the rule gaps log. Almost never changed.

## The CodeGuard set (`rules/*.yaml`)

Each rule is a detection pattern **evaluated by the LLM** (it is not a regex). The
Detector receives a digest of the set and decides which rules apply in a plausible
way to each unit. A rule looks like this:

```yaml
id: codeguard-py-code-injection-exec
description: |
  Detect dynamic code execution with eval()/exec()/compile()+exec() where the code
  argument can come from external or caller supplied input.
languages: [python]
severity: critical
weakness_class: CWE-94
applies_to:
  - functions that call the builtins eval(), exec(), or compile(..., "exec")
trigger_when:
  - the code/string argument is, or comes from, external/caller supplied input
  - and there is no allowlist, sandbox, or restricted globals/locals
example_positive: |
  def run_snippet(body):
      exec(compile(body, "<string>", "exec"), globals(), {})
example_negative: |
  ast.literal_eval(body)   # data only, no code execution
```

To customize the detection:

- **Add a rule:** put a new `rules/py-*.yaml` with the same shape. It is loaded
  automatic. No change of code.
- **Tune a rule:** edit `trigger_when` to make it fire more or less, or change the
  `severity`.
- **Change languages/classes:** the set is just data. A set for Go or JS works the
  same way (this PoC ships Python rules because the target is Python).

## The flywheel of detection -> prevention (rule gaps)

When the *exploratory* pass of the Detector flags something relevant for security
that **no rule covers**, and the Triager judges it real or plausible, the
Orchestrator writes a **rule gap** in `out/rule-gaps.jsonl`. This is the flywheel of
the spec in small: the system tells you where your rule set is blind, so you can
close the gap adding a rule, and this turns a detection of one time into a permanent
prevention.

## What you should NOT need to change

The Python inside `foundry_poc/` is the mechanism of the harness. All the goal of
the design is that the **policy** (scope, goals, model, budget, severity, rules)
lives in config and data, so to customize an evaluation you never need to edit the
engine.

## What to read next

Next in the guided path: **[WALKTHROUGH.md](WALKTHROUGH.md)** - run the pipeline you
just learned to configure, end to end against Langflow.
