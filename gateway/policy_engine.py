"""Policy evaluation engine for the Secure Web Gateway."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from auth.device_trust import DevicePosture, DeviceTrust
from auth.ztna_token_validator import TokenValidationResult, ZTNATokenValidator

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PolicyDecision:
    """Represents the decision outcome for a single request."""

    allowed: bool
    reasons: list[str]
    categories: set[str]
    user: str | None
    device: DevicePosture


class PolicyEngine:
    """Evaluates access policies using identity, device, and destination context."""

    def __init__(
        self,
        policy_path: str | Path,
        token_validator: ZTNATokenValidator | None = None,
        device_trust: DeviceTrust | None = None,
    ):
        self.policy_path = Path(policy_path)
        self.token_validator = token_validator or ZTNATokenValidator()
        self.device_trust = device_trust or DeviceTrust()
        self.policy = self._load_policy()

    def _load_policy(self) -> dict:
        if not self.policy_path.exists():
            logger.warning(
                "Policy file not found; falling back to default allow-all policy",
                extra={"path": str(self.policy_path)},
            )
            return {"default_policy": {"allow_all_if_no_match": True}}

        with self.policy_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {"default_policy": {}}

    def reload(self) -> None:
        """Reload policy configuration from disk."""

        self.policy = self._load_policy()

    def _user_policy(self, user: str | None) -> dict:
        return self.policy.get("users", {}).get(user or "", self.policy.get("default_policy", {}))

    def evaluate(
        self,
        token: str | None,
        domain: str,
        categories: Iterable[str],
        device_context: dict,
    ) -> PolicyDecision:
        """Evaluate a request against user, category, and device policies."""

        categories_set = set(categories)
        token_result: TokenValidationResult = self.token_validator.validate(token)
        device_posture = self.device_trust.evaluate(device_context)
        reasons: list[str] = []

        if not token_result.valid:
            reasons.append(f"token failed: {token_result.reason}")
        user_policy = self._user_policy(token_result.user)

        blocked_domains = {domain.lower() for domain in user_policy.get("blocked_domains", [])}
        if domain.lower() in blocked_domains:
            reasons.append("domain blocked by policy")

        blocked_categories = set(user_policy.get("blocked_categories", []))
        blocked_hits = categories_set & blocked_categories
        if blocked_hits:
            reasons.append(f"category blocked: {', '.join(sorted(blocked_hits))}")

        allowed_destinations = set(user_policy.get("allowed_destinations", []))
        if allowed_destinations and domain not in allowed_destinations:
            reasons.append("destination not in allowlist")

        if user_policy.get("device_trust_required", False) and not device_posture.healthy:
            reasons.append("device not trusted")

        allow_all = user_policy.get("allow_all_if_no_match", False)
        allowed = allow_all or not reasons

        logger.debug(
            "Policy decision",
            extra={
                "user": token_result.user,
                "domain": domain,
                "categories": list(categories_set),
                "reasons": reasons,
            },
        )
        return PolicyDecision(
            allowed=allowed,
            reasons=reasons,
            categories=categories_set,
            user=token_result.user,
            device=device_posture,
        )
