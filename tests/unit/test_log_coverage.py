"""Regression guards for the log-source audit.

Two of these encode failures found on the live host, where a source LOOKED
covered but silently produced nothing:

  * OpenSSH 9.8+ logs authentication from `sshd-session`, not `sshd`. Matching
    only "sshd" made SSH brute-force detection blind after an OS update.
  * Suricata's own decoder rules fired ~96k times a day against ~150 real
    alerts, burying the signal and filling partitions.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sentinel.collectors.auditd import parse_auditd
from sentinel.collectors.suricata_eve import parse_suricata
from sentinel.collectors.system import parse_system

TS = datetime(2026, 8, 3, 9, 25, tzinfo=timezone.utc)


# --- the sshd-session regression -------------------------------------------
def test_journald_matches_include_sshd_session():
    from sentinel.services.ingest_service import JOURNALD_COMMS
    # OpenSSH 9.8+ splits the worker out; without this, auth logging is invisible.
    assert "sshd-session" in JOURNALD_COMMS
    assert "sshd" in JOURNALD_COMMS          # older releases still log as sshd
    assert "sudo" in JOURNALD_COMMS and "su" in JOURNALD_COMMS


def test_sshd_parser_is_comm_agnostic():
    # The parser works on message text, so the same line parses whichever
    # process emitted it — the fix belongs in the filter, not here.
    from sentinel.collectors.sshd import parse_sshd
    msg = "Failed password for root from 203.0.113.9 port 51234 ssh2"
    ev = parse_sshd(msg, TS)
    assert ev is not None and ev.action == "auth_fail" and ev.src_ip == "203.0.113.9"


# --- the Suricata firehose regression --------------------------------------
def _alert(sig: str, sev: int) -> str:
    return json.dumps({
        "timestamp": "2026-08-03T09:25:00.0+0000", "event_type": "alert",
        "src_ip": "203.0.113.9", "dest_port": 443,
        "alert": {"signature": sig, "severity": sev, "signature_id": 1},
    })


def test_engine_diagnostics_are_dropped():
    # These were 96k/day of the 99k stored. They describe the engine, not a threat.
    assert parse_suricata(_alert("SURICATA IPv4 truncated packet", 3)) is None
    assert parse_suricata(_alert("SURICATA AF-PACKET truncated packet", 3)) is None
    assert parse_suricata(_alert("SURICATA TCPv4 invalid checksum", 3)) is None


def test_real_threat_signatures_survive():
    assert parse_suricata(_alert("ET DROP Dshield Block Listed Source", 2)) is not None
    assert parse_suricata(_alert("ET SCAN Zmap User-Agent (Inbound)", 3)) is not None


def test_serious_engine_event_still_kept():
    # Only the informational tier is dropped; an engine event Suricata itself
    # rates serious must not be silently discarded.
    assert parse_suricata(_alert("SURICATA STREAM excessive retransmissions", 2)) is not None


# --- sudo / su -------------------------------------------------------------
def test_sudo_command_is_privilege_use():
    msg = "deploy : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash"
    ev = parse_system(msg, TS, "sudo")
    assert ev is not None and ev.source == "sudo" and ev.action == "privilege_use"
    assert ev.username == "deploy"
    assert ev.raw["target_user"] == "root"
    assert ev.raw["tty"] == "pts/0"      # must not be swallowed by the wildcard


def test_sudo_without_tty_still_parses():
    # Non-interactive sudo (cron, `sudo -n`, a deploy script) omits TTY entirely.
    # Requiring it silently dropped exactly the automated privilege use that is
    # most worth seeing — observed live on the host.
    msg = "deploy : PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart x"
    ev = parse_system(msg, TS, "sudo")
    assert ev is not None and ev.action == "privilege_use"
    assert ev.raw["tty"] == "none"
    assert ev.raw["command"].startswith("/bin/systemctl")


def test_sudo_failed_attempts():
    ev = parse_system("baduser : 3 incorrect password attempts ; TTY=pts/0", TS, "sudo")
    assert ev is not None and ev.action == "auth_fail" and ev.raw["attempts"] == 3


def test_su_failure_and_success():
    fail = parse_system("FAILED SU (to root) mallory on pts/1", TS, "su")
    assert fail is not None and fail.action == "auth_fail" and fail.raw["target_user"] == "root"
    ok = parse_system(
        "pam_unix(su:session): session opened for user root(uid=0) by deploy(uid=1000)",
        TS, "su")
    assert ok is not None and ok.action == "privilege_use"


def test_irrelevant_system_message_ignored():
    assert parse_system("Starting Daily Cleanup of Temporary Directories", TS, "systemd") is None


# --- auditd ----------------------------------------------------------------
def test_auditd_failed_auth():
    line = ('type=USER_AUTH msg=audit(1754207100.123:456): pid=18625 uid=0 auid=1000 '
            'msg=\'op=PAM:authentication acct="root" exe="/usr/sbin/sshd" '
            'hostname=203.0.113.9 addr=203.0.113.9 terminal=ssh res=failed\'')
    ev = parse_auditd(line)
    assert ev is not None and ev.source == "auditd"
    assert ev.action == "auth_fail"
    assert ev.src_ip == "203.0.113.9" and ev.username == "root"


def test_auditd_successful_auth():
    line = ('type=USER_AUTH msg=audit(1754207100.123:457): acct="deploy" '
            'addr=198.51.100.25 res=success')
    ev = parse_auditd(line)
    assert ev is not None and ev.action == "auth_ok"


def test_auditd_drops_high_volume_noise():
    # SYSCALL/PATH/CWD are the firehose; only curated record types are kept.
    assert parse_auditd('type=SYSCALL msg=audit(1754207100.1:1): arch=c000003e syscall=257') is None
    assert parse_auditd('type=PATH msg=audit(1754207100.1:1): name="/etc/passwd"') is None
    assert parse_auditd("") is None
    assert parse_auditd("not an audit line") is None


def test_auditd_placeholder_address_is_not_an_ip():
    ev = parse_auditd('type=USER_LOGIN msg=audit(1754207100.1:2): acct="root" addr=? res=success')
    assert ev is not None and ev.src_ip is None


def test_auditd_config_change_is_kept():
    # Someone editing the audit rules is itself a security event.
    ev = parse_auditd('type=CONFIG_CHANGE msg=audit(1754207100.1:3): op=remove_rule key="sentinel"')
    assert ev is not None and ev.action == "audit_config_change"


# --- the config must not claim uncollected sources -------------------------
def test_config_does_not_claim_unimplemented_collectors():
    from sentinel.config import IngestConfig
    c = IngestConfig()
    # No collector exists for these; defaulting them true would advertise
    # coverage Sentinel does not have.
    assert c.docker is False
    assert c.fim is False
    assert c.auditd is True and c.journald is True
