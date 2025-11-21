from __future__ import annotations

"""Device posture evaluation utilities."""

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class DevicePosture:
    """Represents a device's health and posture score."""

    device_id: str
    healthy: bool
    posture_score: int


class DeviceTrust:
    """Evaluates device context for Zero Trust decisions."""

    def __init__(self, minimum_score: int = 70):
        self.minimum_score = minimum_score

    def evaluate(self, device: Dict[str, str | int | bool]) -> DevicePosture:
        healthy_flag = bool(device.get("healthy", True))
        score = int(device.get("posture_score", 80))
        device_id = str(device.get("device_id", "unknown"))
        healthy = healthy_flag and score >= self.minimum_score
        return DevicePosture(device_id=device_id, healthy=healthy, posture_score=score)
