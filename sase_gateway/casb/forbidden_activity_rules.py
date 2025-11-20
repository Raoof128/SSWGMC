from __future__ import annotations

"""Forbidden activity detection for CASB-lite enforcement."""

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class ForbiddenActivity:
    pattern: str
    description: str


DEFAULT_RULES: List[ForbiddenActivity] = [
    ForbiddenActivity(pattern="shadow", description="Shadow IT domain pattern"),
    ForbiddenActivity(pattern="unauthorized-saas", description="Unapproved SaaS login"),
    ForbiddenActivity(pattern="/upload", description="Generic upload endpoint"),
]


def evaluate_activity(url: str) -> list[str]:
    """Return human-readable violations detected in the URL."""

    violations: list[str] = []
    for rule in DEFAULT_RULES:
        if rule.pattern in url:
            violations.append(rule.description)
    return violations
