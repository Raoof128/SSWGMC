"""Zero Trust token validation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_TOKENS = {"alice": "token-alice", "bob": "token-bob"}


@dataclass(frozen=True)
class TokenValidationResult:
    """Outcome of validating a presented token."""

    user: str | None
    valid: bool
    reason: str


class ZTNATokenValidator:
    """Mock token validator that maps pre-shared tokens to users."""

    def __init__(
        self, known_tokens: dict[str, str] | None = None, token_store_path: Path | None = None
    ):
        self.token_store_path = (
            token_store_path or Path(__file__).resolve().parents[1] / "config" / "policies.yaml"
        )
        self.known_tokens = known_tokens or self._load_tokens_from_policy()

    def _load_tokens_from_policy(self) -> dict[str, str]:
        if self.token_store_path.exists():
            with self.token_store_path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
                tokens = data.get("tokens") or {}
                if tokens:
                    return tokens
        return DEFAULT_TOKENS

    def validate(self, token: str | None) -> TokenValidationResult:
        if not token:
            return TokenValidationResult(user=None, valid=False, reason="missing token")
        for user, expected in self.known_tokens.items():
            if token == expected:
                return TokenValidationResult(user=user, valid=True, reason="validated")
        return TokenValidationResult(user=None, valid=False, reason="invalid token")
