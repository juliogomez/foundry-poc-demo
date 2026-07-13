"""Budget governor (Foundry Constitution VI: bounded spend). Tracks cumulative
token usage across every LLM call and halts the run cleanly when a hard cap is
crossed, so a run can never spend unboundedly."""
from __future__ import annotations

from dataclasses import dataclass


class BudgetExceeded(Exception):
    """Raised when a call would push cumulative tokens past the cap."""


@dataclass
class BudgetGovernor:
    max_tokens: int
    total_tokens: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0

    @property
    def exhausted(self) -> bool:
        return self.total_tokens >= self.max_tokens

    def check(self) -> None:
        """Call before an LLM request; raises if the cap is already reached."""
        if self.exhausted:
            raise BudgetExceeded(
                f"token cap reached: {self.total_tokens}/{self.max_tokens}"
            )

    def record(self, input_tokens: int, output_tokens: int, total: int | None = None) -> None:
        self.input_tokens += max(0, input_tokens)
        self.output_tokens += max(0, output_tokens)
        self.total_tokens += max(0, total if total is not None else input_tokens + output_tokens)
        self.calls += 1

    def summary(self) -> dict:
        return {
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "max_tokens": self.max_tokens,
            "exhausted": self.exhausted,
        }
