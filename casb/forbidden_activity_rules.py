"""Forbidden activity detection for CASB-lite enforcement."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ForbiddenActivity:
    pattern: str
    description: str


DEFAULT_RULES: list[ForbiddenActivity] = [
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
