"""LLM backend abstraction.

Two backends:
  * cursor : real completions via the Cursor SDK (uses your Cursor license via
             CURSOR_API_KEY). This is the backend used for the actual demo.
  * mock   : deterministic canned responses so the whole pipeline can be
             exercised OFFLINE (no key, no spend) to validate plumbing.

Select with the FOUNDRY_LLM env var ("cursor" default, or "mock").

Every call returns (text, usage) where usage is a dict with token counts, so the
BudgetGovernor can enforce a hard cap.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class LLMError(RuntimeError):
    pass


def extract_json(text: str) -> Any:
    """Best-effort: pull the first JSON object/array out of an LLM response,
    tolerating markdown fences and surrounding prose."""
    if text is None:
        raise LLMError("empty LLM response")
    t = text.strip()
    # strip ```json ... ``` fences
    fence = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL)
    if fence:
        t = fence.group(1).strip()
    # find first balanced { } or [ ]
    for opener, closer in (("{", "}"), ("[", "]")):
        start = t.find(opener)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(t)):
            if t[i] == opener:
                depth += 1
            elif t[i] == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(t[start : i + 1])
                    except json.JSONDecodeError:
                        break
    raise LLMError(f"no parseable JSON in response: {text[:200]!r}")


@dataclass
class LLMBackend:
    model: str
    scratch_cwd: Path

    def complete(self, prompt: str, *, system: str | None = None) -> tuple[str, dict]:
        raise NotImplementedError


class CursorBackend(LLMBackend):
    """Real backend using the Cursor SDK. Each call is a one-shot local agent
    pointed at an empty scratch dir; we instruct it to answer inline only."""

    def complete(self, prompt: str, *, system: str | None = None) -> tuple[str, dict]:
        from cursor_sdk import Agent, AgentOptions, LocalAgentOptions, ModelSelection

        api_key = os.environ.get("CURSOR_API_KEY")
        if not api_key:
            raise LLMError(
                "CURSOR_API_KEY is not set. Mint one at Cursor Dashboard -> "
                "Integrations, then `export CURSOR_API_KEY=...`."
            )
        message = prompt if system is None else f"{system}\n\n{prompt}"
        options = AgentOptions(
            model=ModelSelection(id=self.model),
            api_key=api_key,
            local=LocalAgentOptions(cwd=str(self.scratch_cwd)),
        )
        try:
            result = Agent.prompt(message, options)
        except Exception as e:  # noqa: BLE001 - surface any SDK error uniformly
            raise LLMError(f"cursor SDK call failed: {type(e).__name__}: {e}") from e
        text = result.result or ""
        usage = result.usage
        usage_dict = {
            "input_tokens": getattr(usage, "input_tokens", 0) or 0,
            "output_tokens": getattr(usage, "output_tokens", 0) or 0,
            "total_tokens": getattr(usage, "total_tokens", 0) or 0,
        }
        if usage_dict["total_tokens"] == 0:
            usage_dict["total_tokens"] = usage_dict["input_tokens"] + usage_dict["output_tokens"]
        return text, usage_dict


class MockBackend(LLMBackend):
    """Deterministic offline backend. Recognizes the task from marker tokens in
    the prompt and returns plausible structured JSON so the pipeline runs end to
    end without a key. Token counts are estimated from text length."""

    def _usage(self, prompt: str, response: str) -> dict:
        approx_in = max(1, len(prompt) // 4)
        approx_out = max(1, len(response) // 4)
        return {
            "input_tokens": approx_in,
            "output_tokens": approx_out,
            "total_tokens": approx_in + approx_out,
        }

    def complete(self, prompt: str, *, system: str | None = None) -> tuple[str, dict]:
        # Heuristic mock: flag exec/eval/pickle/md5/shell patterns; otherwise clean.
        lowered = prompt.lower()
        if "task: detect" in lowered:
            # Offline stub: flag the first unit if any known sink pattern appears in
            # the batch prompt. Enough to exercise the triage plumbing; not fidelity.
            candidates = []
            if re.search(r"func_body|generate_function", prompt):
                candidates.append({
                    "unit_index": 0,
                    "rule_id": "codeguard-py-code-injection-exec",
                    "weakness_class": "CWE-94",
                    "line_hint": self._first_line_with(prompt, ["exec(", "compile("]),
                    "why": "compile()/exec() of a caller-supplied string.",
                })
            resp = json.dumps({"candidates": candidates})
            return resp, self._usage(prompt, resp)

        if "task: triage" in lowered:
            resp = json.dumps({"results": [{
                "candidate_index": 0,
                "verdict": "needs-review",
                "severity": "high",
                "title": "Mock finding",
                "rationale": "Mock triage rationale (offline stub).",
                "evidence": [{"file": "x", "line": 0, "quote": ""}],
            }]})
            return resp, self._usage(prompt, resp)

        resp = json.dumps({"candidates": []})
        return resp, self._usage(prompt, resp)

    @staticmethod
    def _first_line_with(prompt: str, needles: list[str]) -> int:
        for i, line in enumerate(prompt.splitlines(), start=1):
            if any(n in line for n in needles):
                m = re.match(r"\s*(\d+)\s*\|", line)
                if m:
                    return int(m.group(1))
        return 0


def make_backend(model: str, scratch_cwd: Path) -> LLMBackend:
    which = os.environ.get("FOUNDRY_LLM", "cursor").lower()
    if which == "mock":
        return MockBackend(model=model, scratch_cwd=scratch_cwd)
    return CursorBackend(model=model, scratch_cwd=scratch_cwd)
