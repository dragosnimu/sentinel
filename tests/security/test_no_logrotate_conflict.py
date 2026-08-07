"""Sentinel ships no logrotate configuration. This keeps it that way.

The rule looks arbitrary until you have seen the failure. Sentinel used to
install /etc/logrotate.d/sentinel claiming /var/log/nginx/sentinel-*.log and
/var/log/suricata/*, all already claimed by the nginx and suricata packages.

logrotate treats a path claimed twice as a fatal error and skips the entire
file that named it — both files, not one line. So a configuration written to
guarantee rotation became the reason rotation stopped. On a host running a NIDS
it went unnoticed until eve.json and stats.log had grown to most of a gigabyte,
because the only symptom was a service marked `failed` in a list nobody reads.

Read access for the unprivileged collectors does not need a logrotate stanza
either. Default ACLs on the two log directories cover files logrotate creates,
whatever mode and owner the distribution's own config asks for. That is the
mechanism; the stanza only ever looked like it.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEPLOY = REPO / "deploy"
INSTALL_SH = DEPLOY / "install.sh"

# Owned by the distribution's own packages on any RHEL-family host. Claiming
# any of these a second time stops them rotating.
DISTRO_OWNED = (
    "/var/log/nginx/",
    "/var/log/suricata/",
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/httpd/",
)


def test_no_logrotate_directory_is_shipped() -> None:
    assert not (DEPLOY / "logrotate").exists(), (
        "deploy/logrotate/ is back. Before re-adding one, check that every path "
        "it claims is unclaimed by any installed package — logrotate skips the "
        "whole file otherwise, and rotation stops silently."
    )


def test_installer_writes_nothing_into_logrotate_d() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    # `install`/`cp`/`tee` targeting /etc/logrotate.d, ignoring the `rm -f` that
    # cleans up what older versions left behind.
    writes = [
        line.strip()
        for line in text.splitlines()
        if "/etc/logrotate.d" in line
        and re.search(r"\b(install|cp|tee|cat)\b", line)
        and not line.strip().startswith("#")
    ]
    assert not writes, f"installer writes into /etc/logrotate.d: {writes}"


def test_installer_removes_the_old_file() -> None:
    """An upgrade has to undo it — the broken file is already on deployed hosts."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "rm -f /etc/logrotate.d/sentinel" in text


def test_installer_validates_logrotate_afterwards() -> None:
    """Because the next duplicate will come from somewhere else.

    Another package, or an operator's own file, can create exactly this failure
    without Sentinel being at fault. A dry-run parse at install time turns that
    into a warning instead of a full disk.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "logrotate --debug" in text


def test_no_shipped_config_claims_a_distro_path() -> None:
    """Belt and braces: no file anywhere under deploy/ claims these paths.

    The directory check above is exact but narrow. A logrotate stanza dropped
    into deploy/suricata/ or deploy/nginx/ would pass it and fail identically
    in production.
    """
    offenders: list[str] = []
    for path in DEPLOY.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        # A logrotate stanza is a path followed by an opening brace. nginx's own
        # `access_log /var/log/nginx/sentinel-access.log;` is not one, and must
        # not be flagged.
        for match in re.finditer(r"^\s*(/var/log/[^\s{]+(?:\s+/var/log/[^\s{]+)*)\s*\{",
                                 text, re.MULTILINE):
            if any(owned in match.group(1) for owned in DISTRO_OWNED):
                offenders.append(f"{path.relative_to(REPO)}: {match.group(1)}")
    assert not offenders, f"logrotate stanzas claiming distribution paths: {offenders}"
