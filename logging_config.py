"""Central logging configuration for the SASE gateway services."""

from __future__ import annotations

import logging

DEFAULT_FORMAT = "[%(levelname)s] %(asctime)s %(name)s - %(message)s"


def configure_logging(level: int | str = logging.INFO, fmt: str = DEFAULT_FORMAT) -> None:
    """Configure application-wide logging if not already configured.

    Args:
        level: Logging level to set on the root logger.
        fmt: Log message format string.
    """

    root_logger = logging.getLogger()
    if root_logger.handlers:
        return
    logging.basicConfig(level=level, format=fmt)
