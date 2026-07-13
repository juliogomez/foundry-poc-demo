# Run all of it yourself

This is a tutorial that you can follow end to end. At the end you will have run the
Foundry pipeline and the fair baseline against Langflow, and produced the comparison
table by yourself.

Everything lives in a local `.venv/`. If you delete the repo folder, nothing stays on
your machine.

## What you are running (spec vs. this repo)

The [Foundry spec](https://github.com/CiscoDevNet/foundry-security-spec) is a
*design* - a constitution plus a `spec.md` with ~130 requirements and about three
dozen `[NEEDS CLARIFICATION: ...]` decisions it deliberately leaves to you. It has
**no code**. This repo is **one worked implementation**: the design with those
decisions resolved for a concrete case (evaluate Langflow, using a Cursor-hosted
model). Two ways to use it:

- **Reproduce this exercise** (what this walkthrough does): clone this repo and run
  the steps below against Langflow.
- **Build your own** from the spec: run the spec through the
  [spec-kit](https://github.com/github/spec-kit) `clarify` / `specify` workflow to
  produce *your* spec, then implement it. This repo is a reference for what the
  output can look like.

Either way, the customization all lives in **data and config, never in the engine**.
The exact files that carry the Langflow customization are listed in
[CUSTOMIZATION.md](CUSTOMIZATION.md#the-files-customized-for-this-poc);
skim that table once before you run so you know what each step is exercising.

## 0. Prerequisites

- Python 3.9+ (tested with 3.14).
- `git` (to clone this repo and to fetch the target).
- A Cursor account. For the real run you need a `CURSOR_API_KEY` (Cursor Dashboard
  -> Integrations). For the free offline dry run you need nothing more.

## 1. Get the code and an isolated environment

```bash
git clone https://github.com/juliogomez/foundry-poc-demo.git foundry-poc-demo
cd foundry-poc-demo

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -r requirements.txt
```

`requirements.txt` brings `cursor-sdk` (the LLM backend) and `PyYAML`. That is all.

## 2. Download the target

```bash
bash scripts/fetch_target.sh
```

This does a shallow clone of Langflow in the tag `1.7.3` into `targets/` (it is
ignored by git, never committed) and it verifies that the `compile()`/`exec()` sink
is present in that revision.

## 3. Check it works

```bash
FOUNDRY_LLM=mock python -m foundry_poc.cli up
```

You will see the model, if the `CURSOR_API_KEY` is set, the rules that are loaded,
and the number of function level units in scope (289 for the default wide config;
use `--config config-narrow.yaml` for the 107-unit curated contrast). This command
reads code but it does not call the model, so it is free and instant.

## 4. Offline free dry run to validate

```bash
FOUNDRY_LLM=mock python -m foundry_poc.cli run --limit 10
```

The `mock` backend returns canned responses always the same, so this exercises all
the pipeline (index -> detect -> triage -> gate -> dedup -> report) without spending
anything. Look at `out/findings/latest.md` to see the shape of the report.

The *numbers* of the mock do not mean anything (it emits some bad citations on
purpose to exercise the gate). Its only purpose is to prove that the wiring works
before you spend tokens.

## 5. The real run

Point the backend to your Cursor license:

```bash
export CURSOR_API_KEY=...        # from Cursor Dashboard -> Integrations
python -m foundry_poc.cli up     # now it should say: CURSOR_API_KEY set: yes
python -m foundry_poc.cli models # optional: list the valid model names
```

If the name in `config.yaml` (`llm.model`) is not in that list, edit it to a valid
one. Then:

```bash
# Arm A: the Foundry harness
python -m foundry_poc.cli run
```

**A note on cost.** The default `config.yaml` is the **wide** run (all 289 v1
units); it lands around ~2.05M tokens and takes roughly 12-15 minutes. For a cheaper
first real run, use the curated scale-contrast scope:
`python -m foundry_poc.cli --config config-narrow.yaml run` (107 units). Both write
to separate output folders (`out/` vs `out-narrow/`), so they never clobber each
other. The token counter and the declared budget cap mean the run stops on its own
terms, never open-endedly.

Watch the token counter. The run stops in the coverage completion or the budget cap,
what comes first, and it prints where it wrote:

- `out/findings/<run>.md` - the report for humans (verdicts, severity, evidence).
- `out/foundry-<run>.json` - normalized findings for the scorer.
- `out/foundry-<run>-raw-candidates.jsonl` - every candidate before the triage.
- `out/provenance.jsonl` - the append-only audit log.
- `out/rule-gaps.jsonl` - weaknesses that no rule covers (the flywheel).

```bash
# Arm B: the fair agentic baseline (same model, same scope, disciplined prompt)
python -m foundry_poc.cli baseline
```

This writes:

- `out/baseline-<run>.md` and `out/baseline-latest.md` - the baseline findings as a
  readable report, so you can compare it side by side with `out/findings/latest.md`
  from Foundry. It shows, for every citation, if it would resolve with the same
  resolver, so you can see with your own eyes when the baseline calls something a
  confirmed true-positive while its citation does not resolve.
- `out/baseline-<run>-raw.txt` - the raw transcript of the agent.
- `out/baseline-<run>.json` - the normalized findings for the scorer.

## 6. Score the comparison

```bash
python -m foundry_poc.cli score \
  --foundry  out/foundry-<run>.json \
  --baseline out/baseline-<run>.json
```

This prints and writes `out/comparison.md` and `out/comparison.json`: the metrics
defined before, with the **same checks applied to the two arms**. To read the two
outputs by hand, open `out/findings/latest.md` (Foundry) next to
`out/baseline-latest.md` (baseline), it is much easier than reading the JSON.

## 7. Show the dedup between runs (optional but it convinces a lot)

Run the Foundry pipeline **again** and check the `status`:

```bash
python -m foundry_poc.cli run
python -m foundry_poc.cli status
```

Because the findings have a key based on a fingerprint without line numbers, the
findings of the second run collapse on top of the ones of the first run in the
store, instead of creating a second wall of duplicates. `out/provenance.jsonl`
records each one like a `duplicate` upsert.

## 8. Inspect the audit trail

Open `out/provenance.jsonl`. Every line is one event, a detector call, a triage
verdict with its gate bookkeeping, a finding upsert. Pick any finding of the report
and trace it back to the exact calls that produce it. This capacity to rebuild the
history is one of the metrics that the baseline can not satisfy in a structural way.

## What to read next

Next in the guided path: **[RESULTS.md](RESULTS.md)** - the numbers from the real run
and how to interpret them.
