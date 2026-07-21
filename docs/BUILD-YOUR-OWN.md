# Take this to your own repo

**This repo is one worked reference implementation - a learning artifact, not a
product, and not a replacement for the Foundry spec.** It exists to show *one* way
the [Foundry spec](https://github.com/CiscoDevNet/foundry-security-spec) can be
resolved for a concrete case (evaluate Langflow, using a Cursor-hosted model). When
you go to your own code, the thing you carry over is the **learnings** this PoC
demonstrates - not this specific engine.

So the destination is the **spec**, and this PoC is the teacher. Concretely, the
learnings live in two docs you should reread with your own context in mind:

- [CUSTOMIZATION.md](CUSTOMIZATION.md) - the exact decisions this PoC made (scope,
  goals, model, budget, severity, the CodeGuard rule corpus) and which spec
  `[NEEDS CLARIFICATION]` each one answers.
- [ARCHITECTURE.md](ARCHITECTURE.md) - how the Foundry roles were merged, split, or
  omitted here, and the cost owned for each choice.

## The recommended path: build your own from the spec

The Foundry spec is a *design* with ~130 requirements and about three dozen
`[NEEDS CLARIFICATION: ...]` decisions it deliberately leaves to the implementer. The
real way to use it on your own repo is to answer those decisions for *your* context
and implement against them - not to fork this PoC and hope its choices fit you.

1. **Read the spec and the constitution.** `spec.md` gives you the roles and the
   finding lifecycle; `constitution.md` gives you the inviolable principles every
   implementation must obey.
2. **Run the [spec-kit](https://github.com/github/spec-kit) `clarify` / `specify`
   workflow** to produce *your* spec: answer the `[NEEDS CLARIFICATION]`s for your
   situation - scope, model, datastore, role decomposition, budget/stop rule,
   severity scheme.
3. **Use this PoC as the worked reference for each answer.** For every decision you
   face, this repo already shows one concrete resolution: the
   [CUSTOMIZATION.md](CUSTOMIZATION.md) file table for scope/goals/model/budget/rules,
   the [ARCHITECTURE.md](ARCHITECTURE.md) role choices (and their documented costs),
   and the evidence-gate + flywheel discipline explained in [VALUE.md](VALUE.md) and
   [RESULTS.md](RESULTS.md).
4. **Implement against your spec.** The durable, portable assets to reuse are the
   **learnings** and the **CodeGuard rule corpus** (`rules/*.yaml`) - which load
   unchanged into a coding assistant as authoring-time guardrails - not this
   particular Python engine.

## Optional: give it a try with this PoC first (NOT a production tool)

If you just want to *feel* the pipeline on your own code before committing to your
own implementation, you can reconfigure this simple example and point it at a
target. Treat this strictly as a quick experiment on a PoC - it is NOT a hardened
scanner and it is NOT how you run a real program.

### 1. Make your code the target

Two options:

**A. Adapt the fetch script (reproducible, i recommend this one).**
Copy `scripts/fetch_target.sh` and change `REPO_URL`, `PINNED_REF` and `DEST` to
your repository and a commit/tag that you want to evaluate. To keep a fixed ref
means that every run is reproducible.

**B. Point to a local checkout.**
Set `target.path` in `config.yaml` to any local directory. (It does not need to be
under `targets/`.)

### 2. Set the scope

Edit `target.include_globs` to the parts of your code base that matter. Start with
your **attack surface**, the code that handles external input:

```yaml
target:
  path: "targets/your-service"
  include_globs:
    - "app/api/**/*.py"
    - "app/handlers/**/*.py"
  exclude_globs:
    - "**/tests/**"
    - "**/migrations/**"
  pinned_ref: "v2.4.0"
```

Keep the scope with a criteria and documented. The future readers (and the
skeptics) should be able to see exactly what was examined. Make it wider when your
budget allows it.

### 3. Say your goals

Rewrite `goals` with your mission. Some examples:

- "Focus on authorization and the isolation of data between tenants, the injection
  is secondary."
- "We handle PII, prioritize the issues of data exposure and logging of secrets."

The text is injected the same into the prompts of the Detector and the Triager, so
it really guides the evaluation.

### 4. Bring your own rules

The `rules/*.yaml` that come with the repo are oriented to Python and general for
frameworks. For your stack:

- **Different language?** Write rules where the `applies_to`/`trigger_when`
  describe the sinks of your language and the idioms of your framework. The engine
  is agnostic of the language, only the set is specific of the language. (Note: the
  unit extractor of `indexer.py` uses the `ast` of Python, so for a target not
  Python you would change the extractor, this is the one part of the engine that is
  specific of the language. All the rest is driven by data.)
- **House rules?** Write your own standards of secure coding like CodeGuard rules,
  so the Triager checks them with citations and not with feeling.

The new rule files are loaded automatic, no change of code.

### 5. Choose your model and budget

- `llm.model`: any name from `python -m foundry_poc.cli models`. The two arms
  (Foundry and baseline) use it, so the comparisons stay apples with apples.
- `budget.max_tokens`: your ceiling of cost. The governor stops clean in the cap.

Estimate the cost first: the units in scope are printed by `foundry_poc.cli up`. In
a rough way, the Foundry arm does one Detector call per batch of units, plus one
Triager call per batch of candidates (see the `batching` section in the config).
Start with a small scope and a tight `--limit`, read the token counter, and then
scale.

### 6. Run, score, iterate

```bash
export CURSOR_API_KEY=...
python -m foundry_poc.cli run
python -m foundry_poc.cli baseline
python -m foundry_poc.cli score --foundry out/foundry-<run>.json --baseline out/baseline-<run>.json
```

Then close the loop: read `out/rule-gaps.jsonl`, turn the gaps that repeat into new
rules, and run again. This is the flywheel of detection -> prevention working over
*your* code base.

## Things to keep in mind

- **This is an example PoC and a reference, not a product - and NOT a substitute at all for the
  spec.** It shows the structure and the value of the spec; it is not a hardened
  scanner, and reconfiguring it is a way to *learn*, not a way to operate a security
  program. For that, build your own implementation from the Foundry spec (above). Treat its
  `true-positive` findings like *verified, worth to review*, and its `needs-review`
  items like leads, not like final verdicts.
- **The trust properties travel.** The evidence gate, the fingerprint dedup, the
  provenance and the bounded stop behave the same in your code and in Langflow,
  and this is the point of putting the policy in the config and the discipline in
  the harness - and the reason those properties are worth rebuilding from the spec
  in whatever implementation you ship.
