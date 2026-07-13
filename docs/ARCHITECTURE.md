# Architecture - how the Foundry roles map to the code

This PoC implements the Foundry roles like small Python modules, each one with one
responsibility. It is minimal on purpose: enough to be faithful to the *structure*
of the spec, and small enough to read it in one afternoon.

## Pipeline

```
                config.yaml  (the customized spec)
                     |
                     v
   +----------+   +----------+   +-----------------------+   +-----------+
   | Indexer  |-->| Detector |-->| Triager + EvidenceGate|-->| Reporter  |
   +----------+   +----------+   +-----------------------+   +-----------+
   function level  rule sweep +    verdict + citation          severity, dedup,
   units with a    exploratory     resolution automatic;       markdown report
   light call      candidates      it puts down the claims     + normalized JSON
   context                         that can not be verified;
                                   it logs the rule gaps
        |              |                    |                      |
        +--------------+--------------------+----------------------+
                     Orchestrator: budget governor, coverage stop,
                     append-only provenance, SQLite store with fingerprint dedup
```

## Modules

| Module | Role / base part | Responsibility |
|---|---|---|
| `indexer.py` | **Indexer** | Parse the files in scope with the `ast` module into *units* of function level. It adds the decorators (this shows the route/auth annotations) and the names of the callees (a light context of data flow). It also numbers every source line so the citations can resolve. |
| `rules.py` | rule set | Load the CodeGuard YAML rules and build a compact digest for the prompts. |
| `detector.py` | **Detector** | For one unit, it asks the model which rules apply in a plausible way, plus a light exploratory pass for security patterns that no rule covers. It prefers recall, and it only emits *candidates*. |
| `triager.py` | **Triager + Evidence Gate** | It decides for each candidate a verdict `true-positive` / `false-positive` / `needs-review` with structured citations, and then it resolves every citation against the source in an automatic way. A `true-positive` without a citation that resolves, or with any hallucinated one, is put down. |
| `reporter.py` | **Reporter** | It assigns the stable fingerprint, orders by verdict/severity, renders a markdown report (always same for same input) with the evidence, and produces the normalized JSON. |
| `orchestrator.py` | **Orchestrator / Coverage-Guide** | It drives the pipeline, forces the token budget (clean stop), applies the coverage-AND-yield stop, dedups with the store, and logs the rule gaps. |
| `store.py` | base part | SQLite store of findings with key on the fingerprint (dedup between runs) plus the append-only JSONL logs of provenance and rule gaps. |
| `budget.py` | base part | The budget governor: it counts the tokens in an accumulative way and it has a hard cap. |
| `fingerprint.py` | base part | Stable identity of a finding, `sha256(file, weakness class, symbol)`. It does not use the line number on purpose, so it survives the changes in the code. |
| `llm.py` | base part | Abstraction of the backend: `cursor` (I'm using the Cursor SDK) and `mock` (offline, always same answer). It returns text plus the token usage. |
| `baseline.py` | control | The runner of the fair agentic baseline. |
| `scorer.py` | evaluation | It applies the same automatic checks to the two arms and emits the comparison. |
| `cli.py` | entry point | `up`, `models`, `run`, `baseline`, `score`, `status`. |

## Which Foundry roles this PoC implements

The spec defines **eight core roles** (Orchestrator, Indexer, Cartographer, Detector,
Triager, Validator, Reporter, Coverage-Guide) and five extensions, and it explicitly
lets an implementer **merge, split, or omit** roles during `/speckit.clarify`
(spec.md §5, the `[NEEDS CLARIFICATION]` on the role decomposition), each with a
documented cost. For this PoC we made the following choices on purpose:

| Core role | Here | Rationale |
|---|---|---|
| **Orchestrator** | implemented | Drives the pipeline; owns the budget governor and the declared stop. |
| **Indexer** | implemented | Function-level units with a light call/decorator context. |
| **Detector** | implemented, **rule-sweep + exploratory merged** | Spec allows the merge, so the two modes share output and downstream handling. Both halves of the flywheel run in one role. |
| **Triager** | implemented (with the **evidence gate**) | The precision gate |
| **Reporter** | implemented | Severity + fingerprint dedup + markdown/JSON. |
| **Coverage-Guide** | **merged into Orchestrator** | Single process, so "coverage" is the coverage-AND-yield stop (Constitution VI) rather than a separate role queueing directed tasks. Cost: no gap-driven task injection; acceptable at this scale. |
| **Cartographer** | **omitted** | No separate architecture/threat-model document generation. Cost: the Triager infers trust boundaries per finding from raw source instead of a shared map - slower and less consistent, but the system still functions. |
| **Validator** | **omitted** | No live testbed, so no clean-room exploit reproduction. Cost: the `exploited` flag (Constitution VII) is never set; findings top out at `true-positive`/`needs-review` because this is a static-only PoC. |

Extensions (Deep-Tester, Variant-Hunter, Attack-Mapper, Remediator, Self-Improver):
**none**, following the spec's own recommendation to say no to all five on a first
build. The rule-gap log is still produced, so a Self-Improver could be added later
with no change to the pipeline.

This is a deliberately minimal-but-faithful cut: enough roles to make the finding
lifecycle and the flywheel real, with the omissions named and their costs owned.

## Important decisions of design (and why)

- **Units of function level.** The Detector reasons about one bounded unit each
  time. This keeps the prompts small, makes the citations resolvable, and follows
  the per unit analysis of the spec. The units are extracted with the `ast` of
  Python, so the extraction gives always the same result and is free.

- **The detection is inclusive, the decision is strict.** The Detector prefers
  recall (propose anything plausible). All the discipline lives in the evidence gate
  of the Triager. This separation is from the spec, and it is what permits that the
  same model is at the same time complete and trustable.

- **The evidence gate is automatic, it is not a second opinion.** It does not ask
  the model "are you sure?". It resolves the citations against the bytes in disk. A
  model can not argue to pass a line number that does not exist.

- **The fingerprints do not use line numbers.** The line numbers move when the code
  above them changes. Using `(file, class, symbol)` makes the identity of a finding
  stable between edits and runs, and this is what makes the dedup have sense.

- **Bounded by design.** The budget governor checks before every LLM call and stops
  clean in the cap. The orchestrator writes a declared stop reason. "When did it
  stop and why" is always an explicit fact.

- **All is logged.** Every detector/triager call and every finding upsert/dedup
  writes a provenance event, so any finding can be traced back to the exact calls
  and decisions that produced it.

See [CUSTOMIZATION.md](CUSTOMIZATION.md) for how `config.yaml` and `rules/` turn
this skeleton into *your* customized spec.

## What to read next

Next in the guided path: **[CUSTOMIZATION.md](CUSTOMIZATION.md)** - how `config.yaml`
and `rules/` turn this engine into *your* customized spec, without touching the code.
