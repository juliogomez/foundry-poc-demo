# Use it on your own repository

When the Langflow demo makes sense to you, to point the harness to your own code is
a change of config, not a change of code.

## 1. Make your code the target

Two options:

**A. Adapt the fetch script (reproducible, i recommend this one).**
Copy `scripts/fetch_target.sh` and change `REPO_URL`, `PINNED_REF` and `DEST` to
your repository and a commit/tag that you want to evaluate. To keep a fixed ref
means that every run is reproducible.

**B. Point to a local checkout.**
Set `target.path` in `config.yaml` to any local directory. (It does not need to be
under `targets/`.)

## 2. Set the scope

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

## 3. Say your goals

Rewrite `goals` with your mission. Some examples:

- "Focus on authorization and the isolation of data between tenants, the injection
  is secondary."
- "We handle PII, prioritize the issues of data exposure and logging of secrets."

The text is injected the same into the prompts of the Detector and the Triager, so
it really guides the evaluation.

## 4. Bring your own rules

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

## 5. Choose your model and budget

- `llm.model`: any name from `python -m foundry_poc.cli models`. The two arms
  (Foundry and baseline) use it, so the comparisons stay apples with apples.
- `budget.max_tokens`: your ceiling of cost. The governor stops clean in the cap.

Estimate the cost first: the units in scope are printed by `foundry_poc.cli up`. In
a rough way, the Foundry arm does one Detector call per batch of units, plus one
Triager call per batch of candidates (see the `batching` section in the config).
Start with a small scope and a tight `--limit`, read the token counter, and then
scale.

## 6. Run, score, iterate

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

- **This is a PoC, not a product.** It shows the structure and the value of the
  spec, it is not a hardened scanner. Treat its `true-positive` findings like
  *verified, worth to review*, and its `needs-review` items like leads, not like
  final verdicts.
- **The trust properties travel.** The evidence gate, the fingerprint dedup, the
  provenance and the bounded stop behave the same in your code and in Langflow,
  and this is the point of putting the policy in the config and the discipline in
  the harness.