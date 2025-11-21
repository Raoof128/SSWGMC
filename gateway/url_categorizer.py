from __future__ import annotations

"""Keyword and regex based URL categorization."""

import json
import logging
import re
from pathlib import Path
from typing import Iterable, Set

logger = logging.getLogger(__name__)


class URLCategorizer:
    """Keyword-based URL categorizer using configurable patterns."""

    def __init__(self, categories_path: Path | str):
        path = Path(categories_path)
        if not path.exists():
            raise FileNotFoundError(f"Categories file not found at {path}")
        with path.open("r", encoding="utf-8") as handle:
            self.categories: dict[str, Iterable[str]] = json.load(handle)

    def categorize(self, url: str) -> Set[str]:
        url_lower = url.lower()
        matches: Set[str] = set()
        for category, patterns in self.categories.items():
            for pattern in patterns:
                try:
                    if re.search(pattern.lower(), url_lower):
                        matches.add(category)
                        break
                except re.error as exc:  # defensive guard for malformed regexes
                    logger.warning(
                        "Invalid category pattern", extra={"pattern": pattern, "error": str(exc)}
                    )
                    continue
        return matches or {"Uncategorized"}

    def category_for_domain(self, domain: str) -> Set[str]:
        return self.categorize(domain)


def load_default_categorizer() -> URLCategorizer:
    """Construct a categorizer using the bundled configuration."""

    config_path = Path(__file__).resolve().parents[1] / "config" / "categories.json"
    return URLCategorizer(config_path)
