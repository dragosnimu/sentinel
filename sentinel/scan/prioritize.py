"""Turn a raw finding into a 0..100 priority.

Scanning is easy; deciding what to fix first is the hard part. A CVSS 9.8 that
nobody exploits and is not reachable matters less than a CVSS 6.5 that CISA lists
as actively exploited on an internet-facing asset. The score folds in exactly
that:

    severity/CVSS  — how bad if exploited
    EPSS           — probability it is exploited in the next 30 days (FIRST)
    KEV            — CISA says it is being exploited RIGHT NOW (dominant signal)
    exposure       — is the asset reachable from the internet
    criticality    — how much this asset matters (1..5)
    fix available   — an actionable finding outranks one with no fix yet

Deterministic and explainable: the operator can read the number back to its
inputs. The AI layer (P8) may add context, never override the score.
"""

from __future__ import annotations

from typing import Any

_SEV_BASE = {"info": 5, "low": 20, "medium": 45, "high": 68, "critical": 88}


def score(finding: dict[str, Any], *, exposed: bool = False, criticality: int = 3) -> int:
    """Compute the 0..100 priority. `exposed` and `criticality` come from the
    asset the finding is attached to."""
    # Base: the worse of the categorical severity and the CVSS-derived one, so a
    # scanner that only gives CVSS still lands sensibly.
    base = _SEV_BASE.get(finding.get("severity", "medium"), 45)
    cvss = finding.get("cvss")
    if cvss is not None:
        base = max(base, int(float(cvss) * 9))  # 10.0 -> 90

    s = float(base)

    # KEV is the strongest real-world signal: it is being exploited now.
    if finding.get("kev"):
        s += 25

    # EPSS 0..1 -> up to +20. A 0.7 probability is a big push.
    epss = finding.get("epss")
    if epss is not None:
        s += float(epss) * 20

    # An internet-facing asset is where the exploit actually reaches.
    if exposed:
        s += 10

    # Asset importance: 3 is neutral, 5 adds, 1 subtracts.
    s += (int(criticality) - 3) * 4

    # A finding you can act on outranks one with no fix published yet.
    if finding.get("fixed_version"):
        s += 5

    return max(0, min(100, round(s)))
