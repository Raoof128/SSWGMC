from __future__ import annotations

"""Cloud application detection to support CASB-lite controls."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class CloudAppDetection:
    """Represents the result of matching traffic against known cloud apps."""

    app: Optional[str]
    action: str
    reason: str


CLOUD_APPS = {
    "dropbox.com": "Dropbox",
    "drive.google.com": "Google Drive",
    "onedrive.live.com": "OneDrive",
    "box.com": "Box",
}


class CloudAppDetector:
    """Detects traffic to managed or monitored cloud applications."""

    def detect(self, domain: str, path: str) -> CloudAppDetection:
        for candidate, app_name in CLOUD_APPS.items():
            if candidate in domain:
                action = "review" if "upload" in path.lower() else "allow"
                reason = f"Traffic matched {app_name}"
                return CloudAppDetection(app=app_name, action=action, reason=reason)
        return CloudAppDetection(app=None, action="allow", reason="No cloud app detected")
