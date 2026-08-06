"""Contractul dintre o regulă de detecție și motor.

Stă singur, fără să importe nimic din `detect`, ca modulele de reguli să se
poată importa între ele. Când `rules` deținea și `DetectionSpec`, și lista de
reguli, orice modul nou de reguli trebuia să importe din `rules`, iar `rules`
trebuia să importe modulul nou ca să îl adauge în listă — import circular, cu
un mesaj care arată ca o problemă de ordine și e de fapt una de structură.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class DetectionSpec:
    rule_id: str
    rule_family: str
    severity: str
    # An attacker address for the network rules; None for an anomaly whose
    # subject is an asset, not a host. actor_key then carries the subject.
    src_ip: str | None
    fingerprint: str
    title: str
    summary: str
    evidence: dict[str, Any]
    event_ids: list[int]
    dst_port: int | None = None
    asset_id: int | None = None
    actor_key: str = ""

    def __post_init__(self) -> None:
        if not self.actor_key:
            self.actor_key = self.src_ip or ""
