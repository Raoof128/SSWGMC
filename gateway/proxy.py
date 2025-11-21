from __future__ import annotations

"""Secure Web Gateway pipeline that orchestrates all enforcement engines."""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Set
from urllib.parse import urlparse

from auth.device_trust import DeviceTrust
from auth.ztna_token_validator import ZTNATokenValidator
from casb.cloud_app_detector import CloudAppDetector
from casb.forbidden_activity_rules import evaluate_activity
from gateway.dlp_inspector import DLPInspectionResult, inspect_payload
from gateway.dns_filter import DNSFilter, load_default_dns_filter
from gateway.policy_engine import PolicyDecision, PolicyEngine
from gateway.tls_metadata_inspector import TLSMetadataInspector
from gateway.url_categorizer import URLCategorizer, load_default_categorizer
from logging_config import configure_logging
from siem.log_forwarder import LogForwarder

configure_logging()
logger = logging.getLogger(__name__)

SUPPORTED_METHODS: Set[str] = {"GET", "POST", "PUT", "DELETE", "PATCH"}


@dataclass(frozen=True)
class ProxyRequest:
    """Normalized proxy input collected from clients."""

    url: str
    method: str = "GET"
    token: str | None = None
    device: Dict[str, Any] = field(default_factory=dict)
    body: str | bytes | None = ""

    @classmethod
    def from_mapping(cls, request: Mapping[str, Any]) -> "ProxyRequest":
        """Instantiate from a plain mapping, providing safe defaults."""

        return cls(
            url=str(request.get("url", "")),
            method=str(request.get("method", "GET")),
            token=request.get("token"),
            device=request.get("device", {}) or {},
            body=request.get("body", ""),
        )


@dataclass
class ProxyResult:
    """Outcome of processing a single proxied request."""

    allowed: bool
    decision: PolicyDecision
    casb_action: str
    dlp_action: str
    tls_metadata: Dict[str, Any]
    log_record: Dict[str, Any] = field(default_factory=dict)


class SecureWebGateway:
    """Coordinates DNS, URL, CASB, DLP, Zero Trust, and policy enforcement."""

    def __init__(
        self,
        *,
        categorizer: URLCategorizer | None = None,
        dns_filter: DNSFilter | None = None,
        token_validator: ZTNATokenValidator | None = None,
        device_trust: DeviceTrust | None = None,
        policy_engine: PolicyEngine | None = None,
        tls_inspector: TLSMetadataInspector | None = None,
        cloud_app_detector: CloudAppDetector | None = None,
        log_forwarder: LogForwarder | None = None,
    ):
        self.categorizer = categorizer or load_default_categorizer()
        self.dns_filter = dns_filter or load_default_dns_filter()
        self.token_validator = token_validator or ZTNATokenValidator()
        self.device_trust = device_trust or DeviceTrust()
        self.policy_engine = policy_engine or PolicyEngine(
            policy_path=self._config_path("policies.yaml"),
            token_validator=self.token_validator,
            device_trust=self.device_trust,
        )
        self.tls_inspector = tls_inspector or TLSMetadataInspector()
        self.cloud_app_detector = cloud_app_detector or CloudAppDetector()
        self.log_forwarder = log_forwarder or LogForwarder()

    def _config_path(self, name: str) -> Path:
        return Path(__file__).resolve().parents[1] / "config" / name

    def process_request(self, request: Mapping[str, Any]) -> ProxyResult:
        """Process a proxy request through DNS, policy, CASB, and DLP checks."""

        proxy_request = ProxyRequest.from_mapping(request)
        parsed = urlparse(proxy_request.url)
        reasons: List[str] = []

        if not proxy_request.url or not parsed.scheme:
            reasons.append("invalid url: missing scheme")
        if not parsed.hostname:
            reasons.append("invalid url: missing host")
        if proxy_request.method.upper() not in SUPPORTED_METHODS:
            reasons.append(f"unsupported method: {proxy_request.method}")

        domain = parsed.hostname or ""
        path = parsed.path or "/"

        dns_decision = (
            self.dns_filter.decision(domain)
            if domain
            else {"blocked": False, "reason": "no domain"}
        )
        categories = (
            self.categorizer.categorize(proxy_request.url)
            if proxy_request.url
            else {"Uncategorized"}
        )
        tls_metadata = self.tls_inspector.inspect(server_name=domain).__dict__

        dlp_result: DLPInspectionResult = (
            inspect_payload(proxy_request.body)
            if proxy_request.method.upper() == "POST"
            else DLPInspectionResult([], "allow", False)
        )
        casb_detection = self.cloud_app_detector.detect(domain, path)
        casb_violations = evaluate_activity(proxy_request.url)
        casb_action = "block" if casb_violations else casb_detection.action

        decision = self.policy_engine.evaluate(
            token=proxy_request.token,
            domain=domain,
            categories=categories,
            device_context=proxy_request.device,
        )

        if dns_decision.get("blocked"):
            reasons.append(dns_decision.get("reason", "blocked by DNS"))
        reasons.extend(decision.reasons)
        if casb_violations:
            reasons.append("CASB violation: " + "; ".join(casb_violations))
        if dlp_result.blocked:
            reasons.append("DLP blocked sensitive content")

        allowed = not reasons and decision.allowed and casb_action != "block"

        log_record = {
            "user": decision.user,
            "domain": domain,
            "url": proxy_request.url,
            "method": proxy_request.method,
            "categories": list(categories),
            "allowed": allowed,
            "reasons": reasons,
            "dlp_findings": dlp_result.summary,
            "casb": {
                "app": casb_detection.app,
                "violations": casb_violations,
                "action": casb_action,
            },
            "device": decision.device.__dict__,
            "tls": tls_metadata,
        }
        logger.info(json.dumps(log_record))
        self.log_forwarder.forward(log_record)

        return ProxyResult(
            allowed=allowed,
            decision=decision,
            casb_action=casb_action,
            dlp_action=dlp_result.action,
            tls_metadata=tls_metadata,
            log_record=log_record,
        )


if __name__ == "__main__":
    gateway = SecureWebGateway()
    sample_request = {
        "url": "https://drive.google.com/upload/doc",
        "method": "POST",
        "body": "customer salary spreadsheet",
        "token": "token-alice",
        "device": {"device_id": "laptop-1", "healthy": True, "posture_score": 85},
    }
    result = gateway.process_request(sample_request)
    print("Allowed" if result.allowed else "Blocked", result.log_record)
