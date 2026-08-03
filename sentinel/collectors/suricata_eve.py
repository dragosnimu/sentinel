"""Parse Suricata's eve.json into canonical events.

eve.json is one JSON object per line, many event types (flow, dns, tls, stats,
alert...). We keep only `alert` records — a signature fired — and drop the rest
before the database: the flow/stats firehose has no per-event security value and
would bury the partitions. The high-volume traffic Suricata should not even
inspect is excluded earlier, by the BPF filter; this is the second gate.

Everything below `alert` is attacker-influenced (the signature text is not, but
the payload that triggered it is), so it lands in `raw` and is treated as
untrusted downstream, never interpolated into a command.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from sentinel.model.event import Event

# Suricata alert.severity: 1 = most severe, 3 = informational. Kept as-is in raw;
# the detection rule maps it to Sentinel severities.
_KEEP_EVENT_TYPE = "alert"

# Engine self-diagnostics, not threats. Suricata's own decoder/stream/applayer
# rules describe how the ENGINE saw the traffic ("IPv4 truncated packet",
# "TCPv4 invalid checksum") and fire constantly on any NIC doing segmentation
# offload — measured here at ~96k/day against ~150 real alerts. Storing them
# buries the signal and fills partitions, which is exactly the disk-fill hazard
# this deployment must avoid. Dropped when the engine itself rates them
# informational (severity 3); an engine event it rates 1-2 still gets through.
_ENGINE_PREFIX = "SURICATA "
_INFORMATIONAL = 3


_TS_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>[+-]\d{2}:?\d{2}|Z)?$")


def _parse_ts(raw: str | None) -> datetime | None:
    """Suricata writes '2026-08-03T09:25:00.123456+0000'. Parsed strictly rather
    than handed to fromisoformat, which on Python < 3.11 rejects both the
    colon-less offset and any fractional part that is not exactly 3 or 6 digits."""
    if not raw:
        return None
    m = _TS_RE.match(raw.strip())
    if not m:
        return None
    frac = (m["frac"] or "").ljust(6, "0")[:6]
    tz = m["tz"] or "+00:00"
    if tz == "Z":
        tz = "+00:00"
    elif ":" not in tz:
        tz = tz[:-2] + ":" + tz[-2:]
    try:
        return datetime.fromisoformat(f"{m['base']}.{frac}{tz}")
    except ValueError:
        return None


def parse_suricata(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None
    try:
        rec = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(rec, dict) or rec.get("event_type") != _KEEP_EVENT_TYPE:
        return None

    ts = _parse_ts(rec.get("timestamp"))
    if ts is None:
        return None

    alert = rec.get("alert") or {}
    signature = alert.get("signature") or ""
    severity = alert.get("severity")
    if signature.startswith(_ENGINE_PREFIX) and severity == _INFORMATIONAL:
        return None

    return Event(
        ts=ts,
        source="suricata",
        action="alert",
        src_ip=rec.get("src_ip"),
        src_port=rec.get("src_port"),
        dst_ip=rec.get("dest_ip"),
        dst_port=rec.get("dest_port"),
        proto=(rec.get("proto") or None),
        raw={
            "signature": signature or None,
            "signature_id": alert.get("signature_id"),
            "category": alert.get("category"),
            # Kept as an int so the rule can compare it numerically.
            "severity": severity,
            "action": alert.get("action"),
            "app_proto": rec.get("app_proto"),
        },
    )
