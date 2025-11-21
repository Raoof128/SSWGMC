from __future__ import annotations

"""DNS filter that checks domains against configurable blocklists."""

import logging
from pathlib import Path
from typing import Iterable, Set

logger = logging.getLogger(__name__)


class DNSFilter:
    """Simple in-memory DNS filter used by the proxy pipeline."""

    def __init__(self, blocklist_paths: Iterable[str | Path]):
        self.blocked_domains: Set[str] = set()
        for path in blocklist_paths:
            self._load_blocklist(Path(path))

    def _load_blocklist(self, path: Path) -> None:
        if not path.exists():
            logger.warning("Blocklist missing", extra={"path": str(path)})
            return
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                domain = line.strip().lower()
                if domain:
                    self.blocked_domains.add(domain)

    def is_blocked(self, domain: str) -> bool:
        normalized = domain.lower()
        return normalized in self.blocked_domains

    def decision(self, domain: str) -> dict[str, str | bool]:
        blocked = self.is_blocked(domain)
        reason = "matched threat blocklist" if blocked else "allowed"
        return {"domain": domain, "blocked": blocked, "reason": reason}


def load_default_dns_filter() -> DNSFilter:
    """Construct a ``DNSFilter`` with bundled blocklists."""

    base = Path(__file__).resolve().parents[1] / "config" / "blocklists"
    paths = [base / "malware_domains.txt", base / "adult_sites.txt", base / "social_media.txt"]
    return DNSFilter(paths)
