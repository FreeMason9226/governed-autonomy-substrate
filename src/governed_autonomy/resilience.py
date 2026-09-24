"""Fail-closed runtime resilience state machine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ResilienceMode(StrEnum):
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    SAFE = "SAFE"
    RECOVERY = "RECOVERY"


@dataclass(frozen=True)
class ModeTransition:
    previous: ResilienceMode
    current: ResilienceMode
    reason: str


class ResilienceController:
    _allowed = {
        ResilienceMode.NORMAL: {ResilienceMode.DEGRADED, ResilienceMode.SAFE},
        ResilienceMode.DEGRADED: {ResilienceMode.NORMAL, ResilienceMode.SAFE, ResilienceMode.RECOVERY},
        ResilienceMode.SAFE: {ResilienceMode.RECOVERY},
        ResilienceMode.RECOVERY: {ResilienceMode.NORMAL, ResilienceMode.SAFE},
    }

    def __init__(self, mode: ResilienceMode = ResilienceMode.NORMAL) -> None:
        self.mode = mode
        self.history: list[ModeTransition] = []

    def transition(self, target: ResilienceMode, reason: str) -> ModeTransition:
        if not reason:
            raise ValueError("transition reason is required")
        if target == self.mode:
            return ModeTransition(self.mode, self.mode, reason)
        if target not in self._allowed[self.mode]:
            raise ValueError(f"invalid resilience transition: {self.mode} -> {target}")
        transition = ModeTransition(self.mode, target, reason)
        self.mode = target
        self.history.append(transition)
        return transition

    def permits_execution(self) -> bool:
        return self.mode is ResilienceMode.NORMAL