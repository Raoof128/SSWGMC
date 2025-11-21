"""File-backed log forwarder that mimics SIEM shipping."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from siem.normalizer import normalize

logger = logging.getLogger(__name__)


class LogForwarder:
    """Simple file-based log forwarder that mimics sending to a SIEM."""

    def __init__(self, destination: Path | None = None):
        self.destination = destination or Path("streamlit_logs/gateway.log")
        self.destination.parent.mkdir(parents=True, exist_ok=True)

    def forward(self, record: dict[str, Any]) -> None:
        """Persist normalized records to disk; errors are logged but not raised."""

        normalized = normalize(record)
        try:
            with self.destination.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(normalized) + "\n")
            logger.debug("Log forwarded", extra={"destination": str(self.destination)})
        except OSError as exc:
            logger.error(
                "Failed to forward log",
                extra={"error": str(exc), "destination": str(self.destination)},
            )
