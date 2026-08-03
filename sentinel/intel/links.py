"""Where to read more about a vulnerability.

One place that knows the URLs, because the alternative is what this file
replaced: an NVD link hardcoded in one template, and a bare CVE id everywhere
else. An operator reading a Telegram alert at 3 a.m. should not have to
copy-paste an identifier into a search engine.

Three sources, and the order is deliberate:

  * **Red Hat first** on package findings. On AlmaLinux the question is almost
    never "what is this CVE" — it is "is my package actually affected, and has
    the fix been backported?" Red Hat's page answers that per RHEL version. NVD
    reports the upstream version range and will call a backported package
    vulnerable when it is not.
  * **NVD** for the CVSS vector, the CWE and the reference list.
  * **CISA KEV** only when the CVE is in the catalogue. A link that is always
    there teaches you to ignore it; one that appears only for something actively
    exploited is worth the glance.

No link is ever built from a string that is not a well-formed CVE id. These
identifiers arrive from scanner output and from IDS signature names — both
attacker-influenceable in the general case — and a URL assembled from
unvalidated input is how an `href` ends up pointing somewhere else entirely.
"""

from __future__ import annotations

import re
from html import escape

# CVE-YYYY-NNNN with four or more digits in the sequence. Anchored: a string
# with anything appended is not a CVE and gets no link.
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.IGNORECASE)

# The unanchored form, for pulling CVEs out of prose — IDS signature names and
# advisory titles routinely carry them ("ET EXPLOIT ... CVE-2021-44228").
CVE_IN_TEXT_RE = re.compile(r"CVE-\d{4}-\d{4,19}", re.IGNORECASE)

NVD = "https://nvd.nist.gov/vuln/detail/{cve}"
REDHAT = "https://access.redhat.com/security/cve/{cve}"
KEV_CATALOG = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    "?search_api_fulltext={cve}"
)


def is_cve(value: object) -> bool:
    return isinstance(value, str) and bool(CVE_RE.match(value))


def cve_url(cve: object) -> str | None:
    """The single best link for this CVE, or None if it is not a CVE."""
    return NVD.format(cve=cve.upper()) if is_cve(cve) else None


def cve_links(cve: object, *, rpm: bool = False, kev: bool = False) -> list[tuple[str, str]]:
    """Every useful link as (label, url), most useful first.

    `rpm` puts Red Hat first — pass it when the finding came from the package
    manager, where backport status is the thing actually being asked about.
    """
    if not is_cve(cve):
        return []
    up = cve.upper()
    links = [("NVD", NVD.format(cve=up))]
    if rpm:
        links.insert(0, ("Red Hat", REDHAT.format(cve=up)))
    if kev:
        links.append(("CISA KEV", KEV_CATALOG.format(cve=up)))
    return links


def cves_in(text: object) -> list[str]:
    """CVE ids mentioned anywhere in a string, uppercased, in order, no repeats.

    Suricata names its rules after what they detect, so the CVE is often right
    there in the signature. Extracting it turns "ET EXPLOIT Apache log4j RCE
    CVE-2021-44228" from a string into something clickable.
    """
    if not isinstance(text, str):
        return []
    seen: dict[str, None] = {}
    for m in CVE_IN_TEXT_RE.findall(text):
        seen.setdefault(m.upper(), None)
    return list(seen)


def cve_html(cve: object, *, rpm: bool = False, kev: bool = False) -> str:
    """One CVE as Telegram HTML: the id links to the best source, then the rest.

    Deliberately not shared with the web templates. Telegram allows a handful of
    tags and ignores `rel`, while the dashboard needs `rel="noreferrer"` so that
    following a link does not tell a third party which CVEs this host has.

    Note there is no "link the CVEs inside this sentence" variant. It was
    written and thrown away: the same identifier then appeared both inside the
    title and on the references line, and turning words blue inside a headline
    costs more reading than the tap it saves.
    """
    links = cve_links(cve, rpm=rpm, kev=kev)
    if not links:
        return escape(str(cve), quote=False) if cve else "—"
    parts = [f'<a href="{links[0][1]}">{escape(str(cve).upper())}</a>']
    parts += [f'<a href="{url}">{escape(name)}</a>' for name, url in links[1:]]
    return " · ".join(parts)
