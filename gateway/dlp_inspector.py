"""Lightweight DLP-style payload inspection utilities."""

from __future__ import annotations

import re
from dataclasses import dataclass

SENSITIVE_KEYWORDS: list[str] = ["salary", "passport", "patient", "internal", "confidential"]
AU_PHONE_PATTERN = re.compile(r"\b0\d{1,2}\s?\d{3}\s?\d{3}\b")
MEDICARE_PATTERN = re.compile(r"\b\d{4}\s?\d{5}\s?\d{1}\b")
TFN_PATTERN = re.compile(r"\b\d{3}\s?\d{3}\s?\d{3}\b")


@dataclass(frozen=True)
class DLPInspectionResult:
    """Outcome from scanning a payload for sensitive content."""

    findings: list[str]
    action: str
    blocked: bool

    @property
    def summary(self) -> str:
        """Comma-separated findings summary for logging."""

        return ",".join(self.findings)


def inspect_payload(payload: str | bytes) -> DLPInspectionResult:
    """Inspect a payload for AU-centric sensitive data and keywords.

    Args:
        payload: Raw body content as a string or bytes.

    Returns:
        A ``DLPInspectionResult`` describing the detected findings and action.
    """

    if isinstance(payload, bytes):
        payload_text = payload.decode("utf-8", errors="ignore")
    else:
        payload_text = payload or ""

    findings: list[str] = []
    lowered = payload_text.lower()

    if any(keyword in lowered for keyword in SENSITIVE_KEYWORDS):
        findings.append("sensitive_keyword")
    if AU_PHONE_PATTERN.search(payload_text):
        findings.append("au_phone")
    if MEDICARE_PATTERN.search(payload_text):
        findings.append("medicare")
    if TFN_PATTERN.search(payload_text):
        findings.append("tfn")

    action = "allow"
    if findings:
        action = "block" if {"tfn", "medicare"} & set(findings) else "redact"

    return DLPInspectionResult(findings=findings, action=action, blocked=action == "block")
