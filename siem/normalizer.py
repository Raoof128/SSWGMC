"""Utilities to normalize logs for downstream SIEM ingestion."""

from __future__ import annotations

from typing import Any


def normalize(log_record: dict[str, Any]) -> dict[str, Any]:
    """Convert an enforcement log into a consistent, SIEM-friendly schema."""

    base = {
        "user": log_record.get("user"),
        "domain": log_record.get("domain"),
        "url": log_record.get("url"),
        "categories": log_record.get("categories", []),
        "allowed": log_record.get("allowed", False),
        "reasons": log_record.get("reasons", []),
    }
    base["dlp"] = log_record.get("dlp_findings")
    base["casb"] = log_record.get("casb")
    base["device"] = log_record.get("device")
    base["tls"] = log_record.get("tls")
    return base
