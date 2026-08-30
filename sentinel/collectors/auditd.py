"""Parse auditd records into canonical events.

auditd is the kernel's own record of who did what: authentications, privilege
changes, and any syscall the loaded rules watch. It sees things journald cannot
— a file opened, a binary executed — and it is written by the kernel, so a
process that tampers with its own logging cannot erase it.

Only the security-relevant record types are kept. auditd is capable of enormous
volume (a SYSCALL rule on a busy path produces thousands of records a second),
so an unfiltered ingest would be the same disk-fill hazard as the Suricata
decoder firehose. Everything else is dropped before the database.

Fields after the record type are attacker-influenced once an account is
compromised (a chosen filename, a chosen command) — stored verbatim, never
trusted.
"""

from __future__ import annotations

import posixpath
import re
from datetime import datetime, timezone
from typing import Any

from sentinel.logging_setup import get_logger
from sentinel.model.event import ACTIONS, Event
from sentinel.redact import redact

log = get_logger(__name__)

# Record types worth an event, mapped to a canonical action.
_KEEP = {
    "USER_AUTH": "auth_attempt",
    "USER_LOGIN": "login",
    # Ieșirea din sesiune. NUMAI `USER_LOGOUT`.
    #
    # `USER_END` a stat aici o zi, și era greșit: e perechea lui `USER_START`,
    # nu a lui `USER_LOGIN`. PAM deschide și închide un strat pentru fiecare
    # `sudo`, `su` sau modul de autentificare din interiorul sesiunii, iar prima
    # închidere sosea la o secundă după logare — încă din faza de autentificare
    # a lui sshd.
    #
    # Numărat pe jurnalul real, într-o rotație: 31 `USER_LOGIN`, 44 `USER_START`,
    # 44 `USER_END`, 11 `USER_LOGOUT`. Consecința: 1534 de comenzi orfane din
    # 14157, plus un rând-fantomă la fiecare închidere în plus.
    "USER_LOGOUT": "logout",
    "USER_ACCT": "auth_attempt",
    "ANOM_ABEND": "process_crash",       # a segfault can be an exploit landing
    "ANOM_PROMISCUOUS": "promiscuous",   # someone put an interface into promisc
    "AVC": "avc_denial",                 # SELinux denied something
    "USER_CMD": "privilege_use",
    "ADD_USER": "account_change",
    "DEL_USER": "account_change",
    "USER_MGMT": "account_change",
    "ADD_GROUP": "account_change",
    "ROLE_ASSIGN": "account_change",
    "CONFIG_CHANGE": "audit_config_change",  # someone edited the audit rules
}

# ---------------------------------------------------------------------------
# Înregistrările de supraveghere: SYSCALL + PATH + EXECVE
# ---------------------------------------------------------------------------
# Regulile din deploy/audit/sentinel.rules — cele 17 `-w` pe fișiere și cele 8
# pe execve — nu produc niciunul dintre tipurile de mai sus. Produc SYSCALL,
# PATH, EXECVE și PROCTITLE, care până acum erau aruncate la parsare.
#
# Efectul: o cheie SSH scrisă în /root/.ssh, o modificare de sudoers, un cron
# nou, o unitate systemd nouă sau un socat pornit erau înregistrate de kernel,
# scrise în audit.log — și nu ajungeau niciodată în baza de date. Regulile
# arătau ca o acoperire completă a post-compromiterii și nu era nimic în spate.
#
# Firehose-ul de care avertizează antetul modulului e real, așa că filtrul e
# strict: se păstrează DOAR grupurile al căror SYSCALL poartă o cheie
# `sentinel_*`, adică fix regulile noastre. Orice altă regulă de audit de pe
# gazdă — a distribuției, a altui produs — trece mai departe neatinsă.
_WATCH_KEYS = {
    "sentinel_identity": "identity_change",   # passwd, shadow, group
    "sentinel_priv":     "sudoers_change",    # sudoers și sudoers.d
    # sshd_config, /root/.ssh, /home. Cheia e mai largă decât acțiunea: o
    # scriere în /home fără legătură cu SSH e reclasificată `file_write` mai
    # jos, după ce calea e rezolvată.
    "sentinel_ssh":      "ssh_key_change",
    "sentinel_cron":     "cron_change",
    "sentinel_systemd":  "unit_change",
    "sentinel_webroot":  "webroot_change",
    # Three separate keys where there used to be one. They are three different
    # questions — "did someone run a network tool", "did a binary become
    # setuid", "was a kernel module loaded" — and sharing a key meant one
    # detection rule answered all three with the same sentence.
    "sentinel_exec":     "suspicious_exec",   # nc, ncat, socat, wget, curl
    "sentinel_suid":     "suid_change",
    "sentinel_module":   "module_load",
    # Fisiere-momeala (functionalitatea 05): fara motiv legitim sa fie citite,
    # niciodata. Vezi deploy/audit/sentinel.rules pentru ce anume si de ce
    # -p r; regula de detectie e in detect/intrusion.bait_touched.
    "sentinel_bait":     "bait_touched",
    # Istoricul de comenzi: fiecare `execve` dintr-o sesiune cu login.
    #
    # E singura cheie care produce volum de ordinul miilor pe zi, iar antetul
    # modulului avertizează exact despre asta. Ce o face suportabilă e filtrul
    # din regulă, nu unul de aici: `auid!=unset` lasă afară toți daemonii și
    # toate procesele din containere, care n-au sesiune de login în spate.
    "sentinel_cmd":      "command",
}

# ---------------------------------------------------------------------------
# Vocabularul emis
# ---------------------------------------------------------------------------
# Cele două tabele de mai sus sunt sursa acțiunilor pe care colectorul le pune
# într-un Event — plus trei etichete pe care nu le dă o cheie, ci codul:
# rezultatul autentificării, demotarea unei scrieri în /home și eticheta de
# rezervă. `EMITTED_ACTIONS` le adună, ca să poată fi comparate cu
# `model.event.ACTIONS`.
#
# Comparația asta lipsea, și lipsa ei e defectul: regulile livrate produceau
# `sentinel_suid` și `sentinel_module`, tabela de mai sus le traducea în
# `suid_change` și `module_load`, iar modelul nu cunoștea niciuna. Nimic nu lega
# cele două liste, deci au divergat tăcut până la prima înregistrare reală.
#
# Constantele sunt numite, nu scrise în linie, tocmai ca garda din teste să
# citească exact valorile pe care le ramifică codul. O acțiune scrisă direct
# într-o ramură nouă ar ocoli tabelele — de asta garda are și o a doua jumătate,
# care caută în sursa modulului literalele atribuite lui `action`.

# `auth_attempt` nu e o acțiune canonică, ci eticheta intermediară pentru
# USER_AUTH/USER_ACCT: `parse_auditd` o rezolvă din `res=` în una dintre cele
# două de aici. Ținută ca dată, nu ca text în funcție, ca să fie derivabilă.
_RESULT_ACTIONS = {"auth_attempt": ("auth_fail", "auth_ok")}   # (eșec, succes)

# Ce devine o „schimbare de cheie SSH" a cărei cale rezolvată nu are nimic de-a
# face cu SSH — vezi comentariul de la demotare, mai jos.
_SSH_DEMOTED_ACTION = "file_write"

# Eticheta pentru un eveniment a cărui acțiune modelul nu o cunoaște.
_UNMAPPED_ACTION = "unknown"

EMITTED_ACTIONS = frozenset(
    {a for a in (*_KEEP.values(), *_WATCH_KEYS.values()) if a not in _RESULT_ACTIONS}
    | {a for outcomes in _RESULT_ACTIONS.values() for a in outcomes}
    | {_SSH_DEMOTED_ACTION, _UNMAPPED_ACTION}
)

#: Câmpurile pe care auditd le adaugă la sfârșitul liniei, cu numele rezolvate.
#:
#: `auid=1000` e un număr; `AUID="operator"` e răspunsul la «cine». auditd le
#: scrie deja pe amândouă, iar `_FIELD` cere chei numai din litere mici, deci
#: până acum a doua jumătate a liniei era aruncată — de-asta `username` era GOL
#: la fiecare logare reușită, măsurat pe gazdă pe 24 august 2026.
#:
#: Se iau de aici și nu se rezolvă `uid`-ul prin `/etc/passwd`: nucleul a rezolvat
#: numele la momentul faptei. Un cont șters sau redenumit între timp ar face
#: rezoluția noastră să dea alt răspuns decât cel adevărat, sau niciunul.
_ENRICHED = re.compile(r'\b(?P<key>AUID|UID|ACCT|ID|TERMINAL|EXE)="(?P<val>[^"]*)"')

_SERIAL = re.compile(r"msg=audit\(\d+\.\d+:(?P<serial>\d+)\)")

# "type=USER_AUTH msg=audit(1754207100.123:456): pid=1 uid=0 ... res=failed"
_TYPE = re.compile(r"^type=(?P<type>[A-Z_]+)\s")
_STAMP = re.compile(r"msg=audit\((?P<epoch>\d+)\.(?P<ms>\d+):(?P<serial>\d+)\)")
#: Perechile `cheie=valoare` dintr-o inregistrare auditd.
#:
#: Valoarea se opreste si la APOSTROF, nu doar la spatiu. auditd inchide
#: sublinia lui `msg='…'` fara spatiu inainte de campurile imbogatite:
#:
#:     … terminal=ssh res=success'UID="root" AUID="cineva"
#:
#: Fara apostroful din clasa negata, `res` iesea `success'UID="root` in loc
#: de `success`. Nimic nu se plangea — campul exista, avea o valoare, si
#: arata rezonabil intr-un dump. Dar verificarea `res == "success"` din
#: proiectie il respingea, deci FIECARE logare prin sshd era aruncata, iar
#: sesiunile care totusi apareau veneau din calea de rezerva a inchiderii:
#: fara cont, fara adresa, cu `opened_at == closed_at`.
#:
#: Masurat pe gazda pe 24 august 2026, dupa prima livrare a istoricului.
_FIELD = re.compile(r"\b(?P<key>[a-z_]+)=(?P<val>\"[^\"]*\"|[^\s']+)")

# Fields worth carrying. auditd emits dozens per record; these are the ones that
# answer "who, from where, what happened".
_INTERESTING = ("uid", "auid", "acct", "user", "exe", "hostname", "addr",
                "terminal", "res", "op", "cmd", "comm", "unit", "key",
                # `ses` e identificatorul sesiunii de login, dat de nucleu. E
                # singurul lucru care leagă o comandă de logarea care a produs-o:
                # `auid` spune CINE, `ses` spune ÎN CARE dintre sesiunile lui.
                # Fără el, două sesiuni simultane ale aceluiași cont — un deploy
                # și un om — s-ar amesteca într-o singură cronologie.
                "ses")


#: Ce scrie auditd în locul unui nume pe care nu l-a putut rezolva.
#:
#: `"unset"` apare la procesele fără sesiune, `"(unknown)"` la un cont care nu
#: există — adică la fiecare încercare de brute-force cu utilizator inventat.
#: Trecute mai departe, ar deveni nume de utilizator în panou și în alerte, iar
#: `(unknown)` ar ajunge primul în orice clasament de conturi.
_NOT_A_NAME_VALUES = frozenset({"unset", "(unknown)", "?", "", "(none)", "-1",
                                "4294967295"})


#: Cate nume rezolvate se tin in memorie.
#:
#: O gazda are cateva zeci de conturi; plafonul e o plasa impotriva unui `auid`
#: fabricat, nu o optimizare.
_UID_CACHE_MAX = 256
_UID_CACHE: dict[str, str | None] = {}


def _resolve_uid(auid: str | None) -> str | None:
    """Numele contului pentru un `auid` numeric, sau `None`.

    ## De ce exista, desi auditd rezolva deja numele

    `log_format = ENRICHED` face auditd sa adauge `AUID="cineva"` la sfarsitul
    liniei, iar aia e sursa PREFERATA: numele de acolo e cel de la momentul
    faptei, deci un cont redenumit sau sters intre timp nu schimba trecutul.

    Dar nu toate inregistrarile il poarta. Masurat pe gazda pe 24 august 2026:
    4530 de linii cu `AUID=` in jurnalul curent, si totusi logari reusite care se
    terminau la `res=success'`, fara nimic dupa. Cu numele citit numai de acolo,
    alerta spunea «Cont: cont necunoscut» pentru chiar sesiunea operatorului.

    Deci a doua cale, folosita DOAR cand prima tace. Limita ei e scrisa aici ca
    sa nu fie descoperita mai tarziu: rezolvarea se face ACUM, nu la momentul
    faptei, deci un cont redenumit intre timp da alt raspuns, iar unul sters da
    `None`. Pentru un istoric care se citeste la trei luni distanta, asta
    conteaza — de-asta numarul ramane in `raw`, mereu.
    """
    if auid is None:
        return None
    hit = _UID_CACHE.get(auid)
    if hit is not None or auid in _UID_CACHE:
        return hit
    nume: str | None = None
    try:
        import pwd

        nume = pwd.getpwuid(int(auid)).pw_name
    except (ImportError, KeyError, ValueError, OverflowError):
        # `ImportError` pe Windows, unde ruleaza suita; restul pentru un `auid`
        # care nu e un numar sau care nu are cont. Toate inseamna «nu stiu», si
        # «nu stiu» se scrie NULL, nu se inventeaza.
        nume = None
    if len(_UID_CACHE) < _UID_CACHE_MAX:
        _UID_CACHE[auid] = nume
    return nume


def _named(value: str | None) -> str | None:
    """Numele, sau `None` dacă auditd n-a putut rezolva unul."""
    if value is None or value in _NOT_A_NAME_VALUES:
        return None
    return value


def _unquote(v: str) -> str:
    # auditd nests fields inside msg='...', so the LAST field on a line arrives
    # with the wrapper's trailing apostrophe attached (res=failed'). Strip both
    # quote styles, or `res` never compares equal to "failed" and every failed
    # authentication is silently recorded as a success.
    v = v.strip().rstrip("'")
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v.strip('"')


def _canonical_action(action: str, raw: dict[str, Any]) -> str:
    """Acțiunea, dacă modelul o cunoaște; altfel `unknown`, zgomotos.

    `Event.__post_init__` respinge cu ValueError o acțiune din afara lui
    `ACTIONS`. Excepția aia nu costă un eveniment, costă tot turul de ingestie:
    `poll_once` construiește un singur lot din journald, nginx, Suricata și
    auditd, iar excepția iese înainte de inserare ȘI înainte de avansarea
    cursoarelor. Cursorul auditd rămâne pe loc, turul următor recitește exact
    aceleași linii și pică din nou — ingestia se oprește, pentru toate sursele,
    până când rotația jurnalului trece peste înregistrare.

    Deci evenimentul nici nu se aruncă, nici nu ridică: se degradează. Rândul
    ajunge în bază cu cheia de audit și cu acțiunea respinsă păstrate în `raw`,
    deci rămâne căutabil și verificabil. Ce se pierde e alertarea — nicio regulă
    de detecție nu interoghează `unknown` — și fix de asta linia de jurnal e
    ERROR, iar garda din teste oprește divergența înainte de livrare. Un
    eveniment degradat vizibil e o gaură în vizibilitate; un cursor blocat e o
    gaură mai mare, și tăcută.
    """
    if action in ACTIONS:
        return action
    log.error("acțiune auditd absentă din vocabularul modelului",
              extra={"action": action,
                     "audit_key": raw.get("audit_key") or raw.get("key") or "—"})
    raw["unmapped_action"] = action
    return _UNMAPPED_ACTION


def parse_auditd(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None
    m = _TYPE.match(line)
    if not m:
        return None
    rtype = m["type"]
    action = _KEEP.get(rtype)
    if action is None:
        return None

    stamp = _STAMP.search(line)
    if stamp:
        ts = datetime.fromtimestamp(int(stamp["epoch"]), tz=timezone.utc)
    else:
        ts = datetime.now(timezone.utc)

    fields = {}
    for f in _FIELD.finditer(line):
        key = f["key"]
        if key in _INTERESTING and key not in fields:
            fields[key] = _unquote(f["val"])[:200]

    # auditd writes the peer address as addr= (or hostname= on some records);
    # "?" is its placeholder for "not applicable", not an address.
    src_ip = fields.get("addr") or fields.get("hostname")
    if src_ip in ("?", "", "localhost"):
        src_ip = None

    # res=failed / res=success is how auditd reports the outcome; a failed
    # authentication is the one that matters for detection.
    result = fields.get("res")
    if action in _RESULT_ACTIONS:
        failed_action, ok_action = _RESULT_ACTIONS[action]
        action = failed_action if result in ("failed", "0") else ok_action

    # Numele rezolvate de auditd. `acct` lipsește de pe o logare reușită prin
    # SSH — acolo contul e numai în `AUID`/`ID` —, iar fără ele alerta ar spune
    # «cineva s-a logat» fără să poată spune cine.
    enriched = {m["key"]: m["val"] for m in _ENRICHED.finditer(line)}
    nume = (_named(enriched.get("AUID")) or _named(enriched.get("ACCT"))
            or _named(enriched.get("ID"))
            # Ultima cale: rezolvarea numerica. Vezi `_resolve_uid` pentru ce
            # pierde fata de numele scris de auditd la momentul faptei.
            or _resolve_uid(_named(fields.get("auid"))))

    raw = {"record_type": rtype, **fields}
    if enriched:
        raw["enriched"] = enriched
    return Event(
        ts=ts, source="auditd", action=_canonical_action(action, raw),
        src_ip=src_ip,
        # `_named` peste TOATE sursele, nu doar peste cele îmbogățite: `acct` e
        # `"(unknown)"` la fiecare încercare cu un cont inventat, iar pe gazda
        # reală sunt 9200 la două zile. Trecut mai departe, `(unknown)` ar
        # deveni contul cu cele mai multe logări din panou.
        username=(_named(fields.get("acct")) or _named(fields.get("user"))
                  or nume),
        process=fields.get("comm") or fields.get("exe"),
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Corelatorul multi-linie
# ---------------------------------------------------------------------------
# O singură acțiune supravegheată produce mai multe linii care împart același
# serial din `msg=audit(epoch.ms:SERIAL)`:
#
#     type=SYSCALL   ... auid=1000 uid=0 comm="tee" exe="/usr/bin/tee" key="sentinel_ssh"
#     type=CWD       cwd="/tmp"
#     type=PATH      item=1 name="/root/.ssh/authorized_keys" nametype=CREATE
#     type=PROCTITLE proctitle=...
#
# SYSCALL spune cine și cu ce; PATH spune pe ce. Separat, niciuna nu e o alertă
# utilizabilă: „cineva a rulat tee" și „cineva a atins un fișier" nu înseamnă
# nimic; „utilizatorul 1000 a scris în /root/.ssh/authorized_keys" înseamnă tot.
_FIELD_QUOTED = re.compile(r'\bname="(?P<name>[^"]*)"')
_CWD_QUOTED = re.compile(r'\bcwd="(?P<cwd>[^"]*)"')
_EXEC_ARG = re.compile(r'\ba(?P<i>\d+)=(?P<v>"[^"]*"|[^\s]+)')

# Ce scrie auditd când syscall-ul nu a atins niciun nume. Trecute mai departe,
# apar ca fișiere în evidența unei alerte critice.
_NOT_A_NAME = {"(null)", "?", "", "(none)"}

# auditd codifică numele în hex când conține spații sau ghilimele; altfel îl
# scrie între ghilimele. Deci un nume care sosește FĂRĂ ghilimele și e format
# numai din perechi hex e codificat, nu e un nume relativ.
_HEX_NAME = re.compile(r"^(?:[0-9A-F]{2})+$")


def _serial_of(line: str) -> str | None:
    m = _SERIAL.search(line)
    return m["serial"] if m else None


def _decode_name(value: str) -> str:
    """Numele necotat dintr-o înregistrare PATH, decodificat dacă e hex.

    Netratat, blobul hex ar fi luat drept nume relativ și lipit după CWD,
    producând o cale care nu există pe disc — evidență pe care operatorul nu are
    cum să o verifice.
    """
    if _HEX_NAME.match(value):
        try:
            decoded = bytes.fromhex(value).decode("utf-8", "replace")
        except ValueError:
            return value
        # NUL-urile se scot AICI, nu mai jos. `argv` e NUL-separat în nucleu, iar
        # auditd codifică octeții bruți — deci un argument hexa poate purta
        # separatorii în el. PostgreSQL nu acceptă `\u0000` în `text` sau în
        # `jsonb`, iar rândul respins face să eșueze LOTUL ÎNTREG: pe 25 august
        # 2026 asta a oprit ingestia pentru toate sursele, nu doar pentru
        # comenzi.
        #
        # Se înlocuiesc cu spațiu fiindcă asta ȘI SUNT: granița dintre două
        # argumente. Șterse, `bash -cls` ar arăta ca un singur cuvânt.
        return decoded.replace("\x00", " ").strip()
    return value


# ---------------------------------------------------------------------------
# Numele din PATH e relativ la CWD
# ---------------------------------------------------------------------------
# Înregistrările citate mai jos sunt copiate de pe gazdă, cu un singur lucru
# schimbat: numele contului e scris `deploy`, ca peste tot în documentație.
# Depozitul e public, iar contul real e jumătate dintr-o acreditare SSH — vezi
# `tests/security/test_repo_is_sanitised.py`. Nimic din ce demonstrează
# exemplele nu depinde de el: contează că `cwd` și PARENT sunt aceeași cale, nu
# care e ea. Cu `ausearch -a 474918` pe gazdă apare numele adevărat.
#
# O înregistrare PATH poartă numele AȘA CUM L-A VĂZUT syscall-ul. Pentru
# `openat(AT_FDCWD, "rotateCount", O_CREAT)` nucleul scrie name="rotateCount",
# relativ la înregistrarea CWD din același eveniment. CWD era colectat în grup
# și niciodată citit, deci numele relativ ajungea verbatim în `file_path` — iar
# `_best_path` îl prefera, fiindcă el poartă nametype=CREATE, în timp ce calea
# absolută din grup e doar directorul părinte, cu nametype=PARENT.
#
# Așa au ajuns `=` și `rotateCount` să fie citate ca fișiere într-o alertă
# critică de persistență: erau nume relative dintr-un bash care rula în
# /home/deploy. Nucleul avea dreptate; parsarea aruncase jumătatea care le
# dădea sens.
#
# Efectul invers e mai grav decât zgomotul: `cd ~/.ssh && vi config` producea
# file_path="config", care nu se potrivește cu niciun tipar de cale SSH, deci
# era aruncat de îngustarea din detecție — fals-negativ pe exact semnalul
# pentru care există urmărirea.
#
# DAR cwd-ul e baza corectă numai pentru syscall-urile fără descriptor de
# director. La familia `*at()` — `openat`, `renameat`, `unlinkat`, `fchmodat` —
# numele e relativ la dirfd-ul primit ca argument, iar dirfd-ul NU e în
# înregistrare. Forma apare pe gazdă: un `renameat` (syscall 264) al lui `dnf`,
# rulat din /home/deploy, pentru /usr/lib/systemd/system/cpupower.service:
#
#     CWD  cwd="/home/deploy"
#     PATH name="/home/deploy"          nametype=PARENT
#     PATH name="cpupower.service;6a78a6f7"  nametype=DELETE
#     PATH name="cpupower.service"           nametype=CREATE
#
# Directorul real nu apare nicăieri în grup. Lipit de cwd ar da
# „/home/deploy/cpupower.service" — o cale care nu a existat niciodată pe
# disc, și, fiind absolută, una pe care garda de evidență din motor o acceptă ca
# plauzibilă. O minciună absolută e mai rea decât un adevăr incomplet: numele
# relativ, singur, e cel puțin verificabil cu `ausearch -a SERIAL`.
#
# Înregistrarea PARENT nu e nici ea un răspuns. Pentru grupul de mai sus PARENT
# ESTE cwd-ul, nu părintele real — deci rezolvarea față de PARENT ar produce
# exact aceeași cale inventată. PARENT e util ca CONTRAZICERE, nu ca bază: dacă
# părintele absolut din grup nu se potrivește cu cwd, atunci cwd nu e baza.
#
# Deci cwd e bază doar când se poate DOVEDI: syscall cunoscut, toate dirfd-urile
# lui egale cu AT_FDCWD, și niciun PARENT absolut care să-l contrazică. Un
# syscall pe care tabela nu-l cunoaște nu se rezolvă — necunoscutul nu se
# rotunjește în favoarea noastră.

# AT_FDCWD e -100; auditd scrie argumentele în hexazecimal, fără semn.
_AT_FDCWD = frozenset({"ffffff9c", "ffffffffffffff9c", "-100"})

# Syscall x86_64 -> indicii argumentelor care sunt descriptori de director.
# Tuplu gol = syscall fără dirfd, deci numele relative sunt față de cwd.
_DIRFD_ARGS: dict[int, tuple[int, ...]] = {
    2: (), 59: (), 76: (), 82: (), 83: (), 84: (), 85: (), 86: (), 87: (),
    88: (), 90: (), 91: (), 92: (), 94: (), 133: (), 188: (), 189: (), 197: (),
    257: (0,), 258: (0,), 259: (0,), 260: (0,), 261: (0,), 262: (0,),
    263: (0,), 267: (0,), 268: (0,), 269: (0,), 280: (0,), 322: (0,),
    437: (0,), 439: (0,),
    264: (0, 2), 265: (0, 2), 316: (0, 2),
    266: (1,),
}


def _cwd_is_the_base(syscall_no: str | None, args: dict[int, str],
                     paths: list[dict[str, str]], cwd: str | None) -> bool:
    """Se poate dovedi că numele relative din grup sunt față de `cwd`?"""
    if not cwd or not cwd.startswith("/") or cwd in _NOT_A_NAME:
        return False
    if syscall_no is None or not syscall_no.isdigit():
        return False
    dirfds = _DIRFD_ARGS.get(int(syscall_no))
    if dirfds is None:
        return False                      # syscall necunoscut: nu presupunem
    for i in dirfds:
        if args.get(i, "").strip().lower().removeprefix("0x") not in _AT_FDCWD:
            return False                  # dirfd real: baza nu e în înregistrare
    # Contrazicerea: cu AT_FDCWD, părintele pe care îl scrie nucleul e chiar
    # cwd-ul sau un descendent al lui (`touch a/b`). Orice altceva înseamnă că
    # numele nu a fost rezolvat de la cwd, oricât ar spune argumentele.
    root = cwd.rstrip("/") + "/"
    for p in paths:
        name = p.get("name") or ""
        if p.get("nametype") == "PARENT" and name.startswith("/"):
            if name != cwd and not name.startswith(root):
                return False
    return True


def _resolve(name: str | None, base: str | None) -> str | None:
    """Numele din PATH, adus la o cale absolută unde se poate.

    `base` e cwd-ul DOAR dacă `_cwd_is_the_base` a putut dovedi asta; altfel e
    None și numele se întoarce așa cum a venit. „Nu știu unde s-a scris" și „nu
    s-a atins nimic" sunt stări diferite, iar a treia — o cale absolută
    inventată — e mai rea decât amândouă: trece drept evidență verificabilă și
    nu e. Garda din motor refuză să escaladeze o evidență fără cale absolută.
    """
    if not name or name in _NOT_A_NAME:
        return None
    if name.startswith("/"):
        return posixpath.normpath(name)
    if base:
        return posixpath.normpath(posixpath.join(base, name))
    return name


def _best_path(paths: list[dict[str, str]]) -> str | None:
    """Care PATH e subiectul.

    Un singur syscall raportează mai multe PATH-uri: directorul părinte, apoi
    fișierul. `nametype` le distinge — CREATE și DELETE sunt ținta acțiunii,
    PARENT e doar drumul până la ea. Fără preferința asta, jumătate din alerte
    ar arăta „/root/.ssh" în loc de fișierul chiar atins.
    """
    if not paths:
        return None
    for want in ("CREATE", "DELETE", "NORMAL"):
        for p in paths:
            if p.get("nametype") == want and p.get("name"):
                return p["name"]
    named = [p["name"] for p in paths if p.get("name")]
    # Fără nametype util, cel mai lung nume e cel mai specific.
    return max(named, key=len) if named else None


# ---------------------------------------------------------------------------
# Ce înseamnă „legat de SSH" pentru o cale
# ---------------------------------------------------------------------------
# Tiparele sunt scrise în forma LIKE a PostgreSQL fiindcă a doua poartă, cea din
# `detect/intrusion.py`, e o clauză SQL. O singură definiție pentru amândouă: cu
# două liste separate, îngustarea din colector și cea din detecție ar fi divergat
# la prima modificare, iar divergența s-ar fi văzut ca un fals-negativ tăcut.
SSH_PATH_LIKE = ("%/.ssh/%", "%/.ssh", "%sshd_config%", "%authorized_keys%")


def looks_like_ssh_path(path: str) -> bool:
    """Echivalentul în Python al lui `path LIKE ANY(SSH_PATH_LIKE)`."""
    return ("/.ssh/" in path
            or path.endswith("/.ssh")
            or "sshd_config" in path
            or "authorized_keys" in path)


#: Acțiunea produsă de cheia de audit a istoricului de comenzi.
_COMMAND_ACTION = "command"

#: Cât se păstrează din `argv` pentru un eveniment care NU e o comandă.
#:
#: Acolo linia e o dovadă secundară — «ce a rulat când a scris în sudoers» —, iar
#: 400 de caractere ajung. Pentru istoricul propriu-zis se păstrează linia
#: întreagă, fiindcă ea E informația.
_ARGV_BRIEF = 400


def _argv_text(argv: list[str], action: str) -> str:
    """`argv` redactat, tăiat după rolul evenimentului.

    Redactarea vine ÎNAINTE de tăiere, mereu: tăiată întâi, o linie lungă și-ar
    pierde coada, iar un secret aflat dincolo de prag ar fi redactat pe unele
    linii și păstrat pe altele.
    """
    text = redact(" ".join(argv))
    return text if action == _COMMAND_ACTION else text[:_ARGV_BRIEF]


def parse_auditd_group(lines: list[str]) -> Event | None:
    """Un grup de linii cu același serial -> cel mult un eveniment de supraveghere.

    Întoarce None dacă grupul nu poartă o cheie `sentinel_*`, ceea ce e cazul
    pentru marea majoritate a traficului auditd de pe o gazdă obișnuită.
    """
    syscall: dict[str, str] | None = None
    syscall_args: dict[int, str] = {}
    paths: list[dict[str, str]] = []
    exec_argv: list[str] = []
    ts: datetime | None = None
    cwd: str | None = None

    for line in lines:
        m = _TYPE.match(line.strip())
        if not m:
            continue
        rtype = m["type"]
        fields = {f["key"]: _unquote(f["val"]) for f in _FIELD.finditer(line)}

        if ts is None:
            stamp = _STAMP.search(line)
            if stamp:
                ts = datetime.fromtimestamp(int(stamp["epoch"]), tz=timezone.utc)

        if rtype == "SYSCALL":
            syscall = fields
            # a0..a3 nu trec prin `_FIELD` (cheile lui sunt numai litere), iar
            # a0 e chiar dirfd-ul care decide dacă cwd e baza numelor relative.
            syscall_args = {int(m["i"]): _unquote(m["v"])
                            for m in _EXEC_ARG.finditer(line)}
        elif rtype == "CWD":
            # Directorul față de care sunt relative numele din PATH. Colectat
            # deja de `parse_auditd_lines`, până acum niciodată citit.
            q = _CWD_QUOTED.search(line)
            cwd = q["cwd"] if q else _decode_name(fields.get("cwd", ""))
        elif rtype == "PATH":
            # `name` poate conține spații; regexul general se oprește la primul.
            q = _FIELD_QUOTED.search(line)
            if q:
                fields["name"] = q["name"]
            elif "name" in fields:
                fields["name"] = _decode_name(fields["name"])
            paths.append(fields)
        elif rtype == "EXECVE":
            # Regex propriu: `_FIELD` cere chei numai din litere, iar
            # argumentele sunt a0, a1, a2. Fără asta, argv-ul iese gol și
            # alerta rămâne „cineva a rulat socat" — adevărat și inutil.
            #
            # `_decode_name` peste fiecare: auditd scrie HEXAZECIMAL orice
            # argument care conține un spațiu sau ghilimele, exact ca la numele
            # din PATH. Măsurat pe gazdă pe 25 august 2026, `bash -c "…"` sosea
            # ca două sute de caractere hexa — ilizibil pentru operator, și
            # suficient de „amestecat" cât să fie luat de redactare drept token
            # și înlocuit cu masca. Adică fix comanda cea mai interesantă din
            # istoric — un shell cu o linie întreagă în el — era singura care nu
            # se putea citi.
            args = {int(m["i"]): _decode_name(_unquote(m["v"]))
                    for m in _EXEC_ARG.finditer(line)}
            exec_argv = [args[i] for i in sorted(args)]

    if syscall is None:
        return None
    key = syscall.get("key", "").strip('"')
    action = _WATCH_KEYS.get(key)
    if action is None:
        return None

    # Rezolvarea se face după buclă, nu în ramura PATH: CWD sosește de obicei
    # înaintea înregistrărilor PATH, dar nimic din formatul auditd nu o promite,
    # iar dovada că cwd e baza cere grupul întreg — syscall, argumente și PARENT.
    base = cwd if _cwd_is_the_base(syscall.get("syscall"), syscall_args,
                                   paths, cwd) else None
    resolved = [{**p, "name": _resolve(p.get("name"), base)} for p in paths]
    resolved = [p for p in resolved if p["name"]]
    path = _best_path(resolved)

    # `-w /home` e cea mai largă urmărire din fișierul de reguli: nucleul nu
    # cunoaște globuri, deci nu are cum să ceară doar /home/*/.ssh/. Consecința e
    # că fiecare fișier scris de oricine în directorul lui sosește cu cheia
    # `sentinel_ssh`, iar eticheta „schimbare de cheie SSH" pusă aici e ce ridica
    # regula de persistență la CRITIC — 62 de detecții pe scrieri obișnuite.
    #
    # Evenimentul NU se aruncă: rămâne cu acțiunea generică și cu cheia de audit
    # în `raw`, deci rămâne căutabil, volumul stocat e același, iar o clasificare
    # greșită se vede în date. Se pierde doar eticheta falsă.
    #
    # Se demotează DOAR o cale absolută, adică doar atunci când chiar știm ce
    # s-a atins. Fără cale, sau cu un nume relativ pe care nu l-am putut rezolva,
    # acțiunea rămâne neatinsă: „nu știu unde" nu e același lucru cu „nu e nimic",
    # iar a le confunda aici ar transforma o cheie SSH scrisă într-un director pe
    # care nu-l cunoaștem într-o scriere de fișier oarecare. Poarta din
    # `detect/intrusion.py` refuză oricum un eveniment fără cale plauzibilă.
    if (action == "ssh_key_change" and path is not None
            and path.startswith("/") and not looks_like_ssh_path(path)):
        action = _SSH_DEMOTED_ACTION

    # auid e utilizatorul care s-a autentificat iniţial, nu cel curent: după un
    # `sudo su -`, uid e 0 dar auid rămâne cine a intrat. Pentru „cine a făcut
    # asta", auid e răspunsul corect, iar uid minte.
    auid = _named(syscall.get("auid"))
    # Numele, dacă auditd l-a rezolvat. Numărul rămâne în `raw`: e stabil chiar
    # dacă un cont e redenumit, iar numele e ce citește operatorul.
    enriched = {}
    for line in lines:
        enriched.update({m["key"]: m["val"] for m in _ENRICHED.finditer(line)})
    # `auid` NUMERIC decide dacă există o sesiune de login în spate; câmpul
    # îmbogățit spune doar cum se cheamă contul. Ordinea contează: un grup cu
    # `auid=unset` dar cu un `AUID="…"` rămas dintr-un câmp vecin ar primi altfel
    # un cont, iar un proces de daemon ar apărea în istoric ca fapta cuiva.
    nume = ((_named(enriched.get("AUID")) or _resolve_uid(auid) or auid)
            if auid is not None else None)

    raw: dict[str, Any] = {
        "record_type": "SYSCALL", "audit_key": key,
        "syscall": syscall.get("syscall"), "success": syscall.get("success"),
        "uid": syscall.get("uid"), "auid": syscall.get("auid"),
        "comm": syscall.get("comm"), "exe": syscall.get("exe"),
        # REDACTAT înainte de a intra în dicționar, nu la citire: rândul ăsta
        # ajunge într-o tabelă cu retenție nelimitată și pleacă spre agregator.
        # Vezi `sentinel/redact.py` pentru ce prinde și ce nu.
        **({"argv": _argv_text(exec_argv, action)} if exec_argv else {}),
        **({"ses": syscall["ses"]} if syscall.get("ses") else {}),
        **({"auid_name": nume} if nume else {}),
        **({"tty": syscall["tty"]} if syscall.get("tty") else {}),
        **({"ppid": syscall["ppid"]} if syscall.get("ppid") else {}),
        **({"paths": [p["name"] for p in resolved][:6]} if len(resolved) > 1 else {}),
        # Spus explicit, ca „nu știu unde" să fie citibil în date și nu doar
        # dedus din lipsa unui `/` la început: numele e relativ la un director
        # pe care înregistrarea nu îl conține.
        **({"path_relative": True} if path and not path.startswith("/") else {}),
    }

    return Event(
        ts=ts or datetime.now(timezone.utc),
        source="auditd",
        action=_canonical_action(action, raw),
        username=nume,
        process=syscall.get("exe") or syscall.get("comm"),
        pid=int(syscall["pid"]) if syscall.get("pid", "").isdigit() else None,
        file_path=path,
        raw=raw,
    )


def parse_auditd_lines(lines: list[str]) -> list[Event]:
    """Toate liniile dintr-un tur de citire -> evenimente.

    Liniile cu semantică de sine stătătoare (USER_AUTH, ADD_USER, …) trec prin
    parserul de o linie, neschimbat. Restul se grupează pe serial și trec prin
    corelator. Un grup rupt între două citiri produce, în cel mai rău caz, un
    eveniment fără cale — nu o excepţie şi nu o linie pierdută.

    O înregistrare pe care parsarea nu o poate duce până la capăt (o linie
    tăiată de rotația jurnalului, o ștampilă imposibilă) se sare, cu serialul
    scris în jurnal. Alternativa e ce s-a întâmplat aici: excepția urcă în
    `poll_once`, care pierde lotul întreg — inclusiv evenimentele nginx și
    Suricata din el — și nu mai avansează niciun cursor, deci turul următor
    recitește exact aceleași linii și pică identic. Serialul e în jurnal fiindcă
    `ausearch -a SERIAL` găsește pe gazdă înregistrarea sărită.
    """
    out: list[Event] = []
    groups: dict[str, list[str]] = {}
    order: list[str] = []

    for line in lines:
        m = _TYPE.match(line.strip())
        if not m:
            continue
        if m["type"] in _KEEP:
            try:
                ev = parse_auditd(line)
            except Exception as exc:  # noqa: BLE001 - o linie stricată nu are voie să coste lotul
                log.error("înregistrare auditd nefolosibilă, sărită",
                          extra={"serial": _serial_of(line) or "—",
                                 "record_type": m["type"], "detail": str(exc)})
                continue
            if ev is not None:
                out.append(ev)
            continue
        if m["type"] not in ("SYSCALL", "PATH", "EXECVE", "CWD", "PROCTITLE"):
            continue
        serial = _serial_of(line)
        if serial is None:
            continue
        if serial not in groups:
            groups[serial] = []
            order.append(serial)
        groups[serial].append(line)

    for serial in order:
        try:
            ev = parse_auditd_group(groups[serial])
        except Exception as exc:  # noqa: BLE001 - un grup stricat nu are voie să coste lotul
            log.error("grup auditd nefolosibil, sărit",
                      extra={"serial": serial, "lines": len(groups[serial]),
                             "detail": str(exc)})
            continue
        if ev is not None:
            out.append(ev)
    return out
