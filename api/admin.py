from __future__ import annotations

"""Administrative helpers for policies and configuration."""

from pathlib import Path
from typing import Any, Dict

import yaml

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "policies.yaml"


def load_policies(path: Path | None = None) -> Dict[str, Any]:
    """Load policies from disk, returning an empty structure if missing."""

    policy_path = path or CONFIG_PATH
    if not policy_path.exists():
        return {"default_policy": {"allow_all_if_no_match": True}, "users": {}}
    with policy_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {"default_policy": {}, "users": {}}


def save_policies(payload: Dict[str, Any], path: Path | None = None) -> None:
    """Persist policies to disk."""

    policy_path = path or CONFIG_PATH
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    with policy_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False)
