# The value proposition

## The trap that this PoC tries to avoid

It is very easy to build a security demo that "proves" an LLM harness is amazing.
You point a weak baseline to some toy app full of bugs on purpose, you let your
fancy system find the planted bugs, and you say victory. But this proves nothing,
because the comparison was manipulated from the begining.

Here we do the opposite on purpose. The comparison is:

- **Same model** in the two sides (whatever you put in `config.yaml`).
- **Same code** in the two sides (the same files in scope of a real and complex
  project).
- The baseline receives a **fair and disciplined prompt** that asks explicitly for
  the same rigor that the harness forces: structured findings, exact line
  citations, no invented references, no duplicates, prioritization.

If the harness still makes a measurable difference in these conditions, then the
difference comes from the **harness**, not from a game with the cards prepared.

## The thesis

To wrap a good model inside the Foundry harness does not make it more smart, and
it does not make it find more bugs. It makes the security output of the same model
**trustable, repeatable and actionable** by design. Foundry is a **governance
layer over the model you already trust**.

The first three below are easy to conflate - they all involve "the gate" - but each
answers a *different* question and maps to a different spec principle:

- **Verifiable** *(is the evidence real?)* - about the **content** of one finding.
  A `confirmed` finding's citations are mechanically resolved against the real
  source: the cited location exists and says what the finding claims. What cannot be
  resolved is demoted to `needs-review`. This is Principle I, *Evidence Over
  Assertion*.
- **Tiered by force, not by hope** *(who set the label, and is my queue filtered?)* -
  about the **population you receive**, not any single citation. Only findings that
  survive triage are surfaced at all; the rest stay in the store. And the confirmed
  vs needs-review line is drawn by the **gate**, not by the model declaring its own
  confidence. This is Principle II, *Surface Only What Survives*.
- **Repeatable.** Findings have a stable fingerprint, so a second run dedups onto
  the same distinct findings instead of handing you a fresh wall of text to diff.
- **Prioritized** by a severity policy that you declare, not by vibes.
- **Bounded.** The run stops on a declared budget/coverage rule, not at a random
  point and not forever.
- **Auditable** *(can I reprove it later?)* - neither the evidence nor the label
  but the **history** behind them: you can rebuild exactly why each finding exists -
  which LLM calls and gate decision produced it - from an append-only provenance
  log, months later, for someone who wasn't there.
- **Self-improving.** What the harness misses today (because no rule covered it)
  is captured as a rule-gap and folded back into the corpus; and a rule that fires
  too noisily is a signal to *sharpen* it. Both directions are the
  detection->prevention flywheel.

None of these are claims about *insight*. They are claims about the engineering
discipline **around** the model, and this is exactly what a security program needs
before it can trust automatic findings.

## Foundry vs. just the baseline agent - the whole point

This is the question the PoC exists to answer, so read it slowly:

**You already have the model. Why route it through Foundry instead of just asking
the agent "find the vulnerabilities in this code"?**

Both arms are the **same model on the same code**, and the baseline is *not* a
strawman - it is given a senior-AppSec prompt that asks for the exact same rigor
(structured findings, exact citations, no fabrication, no duplicates, severity). It
does a genuinely decent job. So the difference is not "good vs. bad output". The
difference is **what you can do with the output**.

Ask both the same question. Here is what each hands back:

| What you get back | Baseline agent (one turn) | Foundry (same model, wrapped) |
|---|---|---|
| A list of findings | yes | yes |
| Which claims were *mechanically verified* vs. merely asserted | **unknown** - every claim reads equally confident; it self-labeled 14 of 15 "true-positive" | **explicit** - only findings whose citations resolve against real code are `confirmed` (28); the rest are held as `needs-review` (4). The tier is *enforced*, not self-declared |
| Re-run it next week | a fresh, differently-worded blob you diff by hand | the **same stable fingerprints** - 67 distinct across two runs, not 122; what is new / recurring / gone is *computed*, not eyeballed |
| "Why does this finding exist?" | re-read one long transcript and hope | a **per-finding provenance chain** to the exact detector + triager calls and the gate decision |
| "Did it finish? what did it cost?" | it stopped when the model felt done; cost is whatever it was | a **declared stop** (all 289 units covered + trailing yield) under a **hard token cap** |
| A missed weakness class, or a rule firing as noise | gone the moment you close the tab | becomes a **durable new or sharpened rule** |
| Prevent the bug at authoring time, org-wide | nothing to deploy | the **same CodeGuard rules** load into the coding assistant as guardrails |

__The baseline gives you *an answer you have to trust*;
Foundry gives you, from the identical model, *a result you can verify, tier, repeat,
audit, bound, and reuse*__. Trust is a feeling; the second column is a set of
properties a security **program** can build a process on. That is the entire goal.

**When is the baseline actually fine?** For
a one-off look by a single engineer at a small, familiar piece of code, the plain
agent is genuinely useful and far cheaper. Foundry earns its ~10x token cost only
when the findings have to feed a *process*: an issue tracker that must not drown in
duplicates, reviewers who must know which claims were checked, runs that repeat as
the code changes, several targets sharing one growing rule corpus, and a prevention
story that reaches the editor. If none of that applies to you, use the agent. If any
of it does, the properties in the right column are the difference between "a smart
engineer ran an LLM once" and "the organization operates a security capability."

## Why this matters for a practitioner

The right-hand column above is not magic; each guarantee is a concrete mechanism
answering a concrete way a raw LLM review fails at scale. A plain agent has **four**
failure modes that make its output hard to operationalize; the harness attacks each
one structurally:

| Way the raw LLM review fails | What the harness does about it |
|---|---|
| **Confident hallucination**, it cites a line/file/function that does not exist, or it reads the code wrong, and it presents this like a real bug. | The **evidence gate** resolves every citation against the source in an automatic way. A "true positive" that can not be verified is put down to `needs-review`. The model can not promote a claim that is not verifiable. |
| **Noise and repetition**, the same issue said in many ways, and second runs give a different wall of text. | The **fingerprint** gives to each finding a stable identity `(file, weakness class, symbol)`, so the duplicates collapse and the second runs are stable. |
| **No accountability**, you get a wall of text and no way to see how a conclusion was reached, or if the coverage was complete. | The **provenance** logs every LLM call and decision. The **budget governor** and the **coverage stop** make "when did it stop and why" an explicit fact that is declared. |
| **It evaporates**, a free-ranging agent may notice a class of issue, but that observation dies when the transcript closes and nothing makes it repeatable. | The **rule-gap flywheel** captures what falls outside the current corpus and turns it into a new CodeGuard rule, so a one-time observation becomes permanent, reusable prevention subject to the same gate. |

## The breadth trade-off, and the flywheel that answers it

Because Foundry reports over a **declared
ruleset**, a plain agent ranging freely can surface weakness classes the corpus does
not yet cover. This is not a defeat for the harness - it is the input to its
flywheel, which turns in **two** directions:

**Adding rules (coverage grows).** Gaps come first from Foundry's **own exploratory
pass** (FR-040/FR-042): in the wide run it recorded rule-gaps by itself for `CWE-346`
(`Origin`/`X-Forwarded-For` trust in `get_client_ip` and `install_mcp_config`), with
no second tool.
We *additionally* use the baseline as an honest stand-in for "what unconstrained
hunting might surface" (it flagged `CWE-348`, outside the corpus). Each gap becomes a
new CodeGuard rule; the four rules the loop added earlier (IDOR, info-leak,
header-injection, sensitive-data) are already **live** in the current 13-rule corpus.

**Sharpening rules (signal grows).** A rule that fires too much is also a flywheel
signal. In the wide run the `CWE-209` rule matched a pervasive `HTTPException(detail=
str(e))` idiom - 72 near-identical, low-value findings. We tightened the rule to
confirm only genuinely sensitive leaks and re-ran: **CWE-209 dropped from 72 to 6**,
leaving a signal-dense set led by IDOR and path traversal. (This also required a real
harness fix - a rule's exclusion criteria now reach both the Detector and the gate.)

A plain agent's discoveries - and its noise - evaporate when you close the tab. In
Foundry they become durable rules that harden and sharpen every future run. See
section 3 of `out/comparison.md` and the flywheel section of
[RESULTS.md](RESULTS.md).

### The second half: prevention everywhere (US-14)

The spec's flywheel does not stop at detection.
Because CodeGuard rules are **portable**, the same corpus this evaluation grows
loads unchanged into an LLM coding assistant as CodeGuard, as its secure-coding guardrails. The class you taught Foundry to *detect* in finished code becomes a class the assistant
*prevents* at the keystroke, in every developer's editor, before the next
evaluation ever runs. Detection investment here compounds into prevention
everywhere - and prevention shrinks the population the next evaluation has to find.
(Concretely: the `codeguard-*` rules governing this very workspace are that same
format deployed as authoring-time guardrails in CodeGuard.)

## Does this exercise align with the Foundry spec?

The [Foundry spec](https://github.com/CiscoDevNet/foundry-security-spec) is a design,
not a tool, and it states its own value in one sentence:

*"when you write a good detection rule, the system around it will not waste it: the
finding will be **deduplicated, evidence-gated, validated if possible, reported
once, and counted toward done**; and when exploration finds something your rules
missed, the system will tell you which rule to write next."*

Every clause of that sentence, plus the constitution principles it rests on, maps
onto what this PoC actually did in the wide run:

| Spec promise / constitution principle | In this PoC | Status |
|---|---|---|
| **Evidence over assertion** (Principle I): no `true-positive` by judgment; citations mechanically verified | The evidence gate; confirmed findings resolve 100% of citations or are demoted | Demonstrated |
| **Surface only what survives** (Principle II) | of 58 stored findings (from 61 candidates), 26 rejected internally; only 32 surfaced | Demonstrated |
| **Deduplicated / fingerprints stable under edit** (Principle VIII) | `(file, class, symbol)` identity; 67 distinct across two runs, not 122 | Demonstrated |
| **Counted toward done / coverage before yield** (Principle VI) | Stop = "coverage-complete (289 units) + trailing yield", under a token cap | Demonstrated |
| **Reported once** | One deduped report; provenance per finding | Demonstrated |
| **Tell you which rule to write next** (the flywheel: sweep + exploratory hunt -> rule-gap -> generalize) | Detector swept all 289 units; exploratory pass logged rule-gaps for CWE-346 (`get_client_ip`, `install_mcp_config`) | Demonstrated |
| Flywheel step 4 explicitly allows *"a revision of one that should have fired"* | The CWE-209 tuning (72 -> 6) is literally that revision | Demonstrated |
| **Prevention everywhere** (portable CodeGuard into the editor) | Same rules are deployable as authoring guardrails (the `codeguard-*` rules on this workspace are that format) | Faithful (asserted) |

**The two clauses we deliberately do not demonstrate - and why.** The spec sanctions
merging or omitting roles on a first build; we named these in
[ARCHITECTURE.md](ARCHITECTURE.md):

- **"validated if possible" / the `exploited` flag** (Principle VII, the Validator
  role). There is no live testbed here, so findings top out at
  `true-positive`/`needs-review` and nothing is ever marked `exploited`. This is the
  one clause of the value sentence a static PoC honestly cannot show.
- **The parallel-fleet principles** (III heartbeat liveness, IV atomic/mortal claims,
  V rate arbitration, X operator-over-agent, XI atomic persistence). These govern
  *operating a fleet at scale*, not the finding-trust thesis. A single-process PoC
  cannot exercise them, and the spec recommends saying "no to all five extensions"
  first anyway.

## What we are NOT claiming

- We do **not** claim that Foundry is a smarter bug-finder - it is the same model.
  Where it surfaces more (at full scope, ~2x the baseline's confirmed findings) that
  is exhaustive per-unit enumeration, not deeper insight; the raw **citation
  quality** ties. At small scope the counts look even and the baseline can even range
  wider - which the flywheel then absorbs.
- We do **not** claim Foundry is cheaper. At full scope it spends ~10x the tokens of
  a single agent turn; the trade is exhaustive, gated, deduped coverage under a
  declared cap.
- We do **not** claim zero false positives or zero missed bugs (these are negatives
  impossible to prove without a perfect ground truth).
- We do **not** use the known CVEs like a scoreboard. Langflow is chosen because it
  is a realistic, complex, first party Python code base. If its code has some real
  weakness classes, this is just realism, it is not the point.

The point is the **governance and repeatability gap**, measured with the metrics
defined before in [METHODOLOGY.md](METHODOLOGY.md) and reported with honesty in
[RESULTS.md](RESULTS.md).

## What to read next

Next in the guided path: **[METHODOLOGY.md](METHODOLOGY.md)** - the design of the
controlled experiment, the fair baseline, and the metrics defined *before* the run so
the comparison can not be gamed.
