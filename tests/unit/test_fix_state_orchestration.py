"""Cablajul lui `fix_state` în scanare: ce ajunge în bază și ce ajunge la operator.

Eșecul pe care îl păzește fișierul ăsta, în ansamblu: clasificatorul din
`sentinel/scan/fix_state.py` are testele lui și trece, dar scanarea nu-l cheamă,
sau îl cheamă și ignoră verdictul — și operatorul primește în continuare planuri
`dnf update` fără nimic de instalat. Fișierul pe disc nu e dovadă că a fost
încărcat (tabelul din `CLAUDE.md`).

Constatarea rămâne `open` (decizia operatorului, 29 septembrie 2026: rămâne numărată,
fiindcă gazda e expusă până la repornire). Deci nimic nu se mută în `status`; ce se
verifică e ce ajunge în `raw.fix_state` și ce plecă spre operator:

  * un verdict `pending_reboot` intră în bază și acolo îl citesc planificatorul și
    botul;
  * `unknown` (dovezi necitibile) NU șterge un „în așteptare” dovedit — o cădere a
    lui `rpm` la 03:00 nu are voie să readucă 491 de constatări și planurile lor;
  * `not_pending` (dovezi citite, nu susțin starea) înlocuiește verdictul;
  * cele intrate acum primesc un mesaj integral, KEV-urile rămase în așteptare o
    reamintire — altfel un KEV deschis, fără plan, n-ar avea nicio veste.

Nu există un Postgres în suită: baza de aici e un tabel în memorie care păstrează
`raw` la upsert ca baza reală (rescris întreg), așa că un verdict pierdut la upsert
se vede. Ce NU are: SQL-ul real — vezi `test_findings_fix_pending_repo.py`.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from sentinel.db.repo import findings as fx
from sentinel.scan import announce, fix_state, orchestrator, os_packages
from sentinel.scan.fix_state import NOT_PENDING, PENDING, UNKNOWN

NEW_KERNEL = "5.14.0-687.51.1.el9_8"
RUNNING = "5.14.0-687.46.1.el9_8.x86_64"


def run(coro):
    return asyncio.run(coro)


def _finding(pkg: str, state: str | None, *, cve: str = "CVE-2026-0001",
             severity: str = "high", kev: bool = False, installed: str | None = None):
    f = {"scanner": "dnf", "cve": cve, "package": pkg, "severity": severity,
         "fixed_version": "5.14.0-687.47.1.el9_8", "kev": kev,
         "finding_key": fx.finding_key("dnf", None, pkg, cve, None), "raw": {}}
    if state is not None:
        f["raw"]["fix_state"] = {"state": state, "reason": "test"}
        if installed:
            f["raw"]["fix_state"]["installed"] = installed
    return f


class _Db:
    """Un tabel `findings` în memorie, cu exact comportamentul de care depinde
    scanarea: upsertul rescrie `raw` ÎNTREG, un rând rezolvat rămâne cu `raw`-ul
    lui, iar predicatul „în așteptare” cere `open` ȘI verdictul."""

    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}
        self.calls: list[tuple[str, tuple]] = []
        self.next_id = 1000

    # -- upsert ------------------------------------------------------------
    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        assert "INSERT INTO findings" in sql, sql
        key = args[0]
        row = self.rows.get(key)
        is_new = row is None
        if is_new:
            self.next_id += 1
            row = {"id": self.next_id, "status": "open"}
        elif row["status"] == "resolved":
            row["status"] = "open"
        row.update(finding_key=key, scanner=args[2], cve=args[3], severity=args[7],
                   kev=args[11], package=args[13], fixed_version=args[15],
                   priority=args[18], raw=json.loads(args[20]))
        self.rows[key] = row
        return {"is_new": is_new, "status": row["status"]}

    async def fetchval(self, sql, *args):
        self.calls.append((sql, args))
        return 1

    async def execute(self, sql, *args):
        self.calls.append((sql, args))

    async def fetch(self, sql, *args):
        self.calls.append((sql, args))
        flat = " ".join(sql.split())
        if "raw -> 'fix_state' AS fix_state" in flat:
            keys = set(args[2])
            return [{"finding_key": k, "status": r["status"],
                     "fix_state": (json.dumps(r["raw"]["fix_state"])
                                   if "fix_state" in r["raw"] else None)}
                    for k, r in self.rows.items() if k in keys]
        if "AS installed" in flat:
            out = []
            for r in self.rows.values():
                fs = r["raw"].get("fix_state") or {}
                if r["status"] == "open" and fs.get("state") == fx.FIX_PENDING_REBOOT:
                    out.append({"id": r["id"], "finding_key": r["finding_key"],
                                "cve": r["cve"], "package": r["package"],
                                "severity": r["severity"], "kev": r["kev"],
                                "fixed_version": r["fixed_version"],
                                "priority": r["priority"],
                                "installed": fs.get("installed"),
                                "running": fs.get("running"), "since": fs.get("since")})
            return out
        if "absent_from_latest_scan" in flat:
            seen = set(args[2])
            gone = [r for k, r in self.rows.items()
                    if k not in seen and r["status"] in ("open", "patch_planned", "deferred")]
            for r in gone:
                r["status"] = "resolved"
            return [{"id": r["id"]} for r in gone]
        return []

    def sql(self, needle: str) -> list[tuple[str, tuple]]:
        return [(s, a) for s, a in self.calls if needle in s]

    def status_updates(self) -> list[str]:
        """Orice UPDATE care atinge `status` în afară de închiderea la dispariție."""
        return [s for s, _ in self.calls
                if "UPDATE findings" in s and "SET status" in s
                and "absent_from_latest_scan" not in s]


def _scan_returns(monkeypatch, findings, *, running=RUNNING, error=None):
    async def scan(family):
        return findings, None, {"scanner": "dnf", "family": family, "db_version": None,
                                "fix_state": {"running_kernel": running, "error": error}}

    async def no_kev(db, cves):
        return {}

    monkeypatch.setattr(orchestrator.os_packages, "scan", scan)
    monkeypatch.setattr(orchestrator.kev, "lookup", no_kev)


def _scan(db, monkeypatch, findings, **kw):
    _scan_returns(monkeypatch, findings, **kw)
    return run(orchestrator._run_os_packages(db, "rhel", "schedule"))


# --- statusul nu se mișcă ----------------------------------------------------------
def test_a_pending_finding_stays_open_and_carries_its_verdict_into_the_database(monkeypatch):
    """Ce se strică dacă verdictul e calculat dar nu ajunge în `raw` (scanarea nu-l
    scrie, sau upsertul îl pierde): planificatorul citește `raw.fix_state`, nu-l găsește
    și redactează iar cele cinci planuri `dnf update` — fără nicio eroare.

    Ce se strică dacă scanarea mută constatarea din `open`: cifra „KEV deschise” scade
    cu cele exploatabile, iar panoul spune „2 KEV” peste un nucleu vulnerabil.
    """
    pending = _finding("kernel-core", PENDING, kev=True, installed=NEW_KERNEL)
    other = _finding("openssl", NOT_PENDING, cve="CVE-2026-0002")
    db = _Db()

    out = _scan(db, monkeypatch, [pending, other])

    stored = db.rows[pending["finding_key"]]
    assert stored["status"] == "open"
    assert stored["raw"]["fix_state"]["state"] == PENDING
    assert stored["raw"]["fix_state"]["since"], "lipsește „de când așteaptă”"
    assert db.rows[other["finding_key"]]["raw"]["fix_state"]["state"] == NOT_PENDING
    assert db.status_updates() == [], "scanarea a mutat un status din cauza verdictului"
    assert out["pending_reboot"]["waiting"] == 1
    assert out["pending_reboot"]["entered"] == 1


def test_the_first_sighting_is_announced_in_full_and_not_as_a_reminder(monkeypatch):
    """Intrarea în așteptare = mesajul integral (ce se închide, ce rulează, ce de făcut).
    Reamintirea scurtă e pentru cei care AȘTEPTAU deja: un KEV proaspăt intrat ar primi
    altfel două mesaje în aceeași noapte."""
    kev = _finding("kernel-core", PENDING, kev=True, installed=NEW_KERNEL)
    plain = _finding("kernel", PENDING, cve="CVE-2026-0002", installed=NEW_KERNEL)

    out = _scan(_Db(), monkeypatch, [kev, plain])

    entered = out["_pending"]["entered"]
    assert {r["finding_key"] for r in entered} == {kev["finding_key"], plain["finding_key"]}
    assert entered[0]["installed"] == NEW_KERNEL
    assert out["_pending"]["waiting_kev"] == []


def test_a_kev_that_keeps_waiting_is_reminded_and_a_plain_one_is_not(monkeypatch):
    """A doua noapte: nimic nou, dar un KEV așteaptă în continuare. Fără reamintire ar fi
    `open`, numărat, fără plan și fără nicio veste — exact tăcerea pe care mecanismul
    trebuie s-o evite. Necriticele NU se repetă: e singurul lucru repetat, deci singurul
    pe care operatorul ar ajunge să-l oprească."""
    db = _Db()
    kev = _finding("kernel-core", PENDING, kev=True, installed=NEW_KERNEL)
    plain = _finding("kernel", PENDING, cve="CVE-2026-0002", installed=NEW_KERNEL)
    _scan(db, monkeypatch, [kev, plain])

    second = _scan(db, monkeypatch, [_finding("kernel-core", PENDING, kev=True,
                                              installed=NEW_KERNEL),
                                     _finding("kernel", PENDING, cve="CVE-2026-0002",
                                              installed=NEW_KERNEL)])

    assert second["_pending"]["entered"] == [], "a doua zi n-are intrări noi"
    assert [r["finding_key"] for r in second["_pending"]["waiting_kev"]] == [
        kev["finding_key"]]
    assert second["pending_reboot"]["waiting"] == 2


def test_since_survives_the_next_scan(monkeypatch):
    """Upsertul rescrie `raw` întreg; „de câte zile așteaptă” din reamintire vine din
    verdictul de ieri, dus înainte. Fără el, fiecare mesaj ar spune „de azi”."""
    db = _Db()
    first = _finding("kernel-core", PENDING, kev=True, installed=NEW_KERNEL)
    _scan(db, monkeypatch, [first])
    db.rows[first["finding_key"]]["raw"]["fix_state"]["since"] = "2026-09-20"

    _scan(db, monkeypatch, [_finding("kernel-core", PENDING, kev=True, installed=NEW_KERNEL)])

    assert db.rows[first["finding_key"]]["raw"]["fix_state"]["since"] == "2026-09-20"


# --- unknown nu șterge --------------------------------------------------------------
def test_an_unreadable_host_does_not_erase_a_proven_pending_verdict(monkeypatch):
    """`rpm` a căzut la 03:00: verdictul de azi e `unknown`. Constatarea era în
    așteptare, dovedit, ieri.

    Ce se strică dacă `unknown` se scrie peste: planificatorul vede constatarea ca
    planificabilă, cele cinci planuri revin, iar operatorul vede un sistem care
    oscilează între „așteaptă” și „nu știu” după cum se poartă `rpm`.
    """
    db = _Db()
    key = _finding("kernel-core", PENDING)["finding_key"]
    _scan(db, monkeypatch, [_finding("kernel-core", PENDING, kev=True,
                                     installed=NEW_KERNEL)])

    out = _scan(db, monkeypatch, [_finding("kernel-core", UNKNOWN, kev=True)],
                running=None, error="rpm a căzut")

    fs = db.rows[key]["raw"]["fix_state"]
    assert fs["state"] == PENDING, "un `unknown` a șters verdictul dovedit"
    assert fs["unread"] == "test"
    assert fs["installed"] == NEW_KERNEL, "dovada a dispărut odată cu verdictul"
    assert out["pending_reboot"]["carried"] == 1
    assert out["pending_reboot"]["error"] == "rpm a căzut"
    assert [r["finding_key"] for r in out["_pending"]["waiting_kev"]] == [key], (
        "un KEV păstrat trebuie să rămână în reamintire")
    assert out["_pending"]["entered"] == [], "un verdict păstrat nu e o intrare nouă"


def test_unknown_on_a_finding_never_proven_pending_stays_unknown(monkeypatch):
    """Nu se inventează un „în așteptare”: `unknown` peste nimic rămâne `unknown`, adică
    planificabil ca înainte (nu se știe că așteaptă)."""
    db = _Db()
    f = _finding("kernel-core", UNKNOWN)

    out = _scan(db, monkeypatch, [f], running=None, error="rpm a căzut")

    assert db.rows[f["finding_key"]]["raw"]["fix_state"]["state"] == UNKNOWN
    assert out["pending_reboot"]["unknown"] == 1
    assert out["_pending"] == {"entered": [], "waiting_kev": []}


def test_a_proven_not_pending_replaces_the_pending_verdict(monkeypatch):
    """Dovezile s-au citit și nu mai susțin starea (reparația nu mai e pe disc):
    constatarea redevine planificabilă. Ce se strică dacă `not_pending` ar fi tratat
    ca `unknown`: constatarea ar rămâne ascunsă de planificator cât timp dnf o listează."""
    db = _Db()
    f = _finding("kernel-core", PENDING, installed=NEW_KERNEL)
    _scan(db, monkeypatch, [f])

    out = _scan(db, monkeypatch, [_finding("kernel-core", NOT_PENDING)])

    assert db.rows[f["finding_key"]]["raw"]["fix_state"]["state"] == NOT_PENDING
    assert out["pending_reboot"]["cleared"] == 1
    assert out["pending_reboot"]["waiting"] == 0


def test_after_the_reboot_dnf_stops_listing_and_the_scan_closes_the_finding(monkeypatch):
    """Repornirea: nucleul care rulează are reparația, dnf nu mai listează avizul, iar
    scanarea închide singură constatarea. Cu `status` neatins, asta e tot drumul înapoi —
    fără „redeschidere”.

    Cu un control pozitiv: mai întâi constatarea E în așteptare, altfel „nimic în
    așteptare după repornire” ar putea veni dintr-o listă care n-a avut niciodată ceva."""
    db = _Db()
    f = _finding("kernel-core", PENDING, kev=True, installed=NEW_KERNEL)
    first = _scan(db, monkeypatch, [f])
    assert first["pending_reboot"]["waiting"] == 1

    after = _scan(db, monkeypatch, [], running="5.14.0-687.51.1.el9_8.x86_64")

    assert db.rows[f["finding_key"]]["status"] == "resolved"
    assert after["resolved"] == 1
    assert after["pending_reboot"]["waiting"] == 0
    assert after["_pending"] == {"entered": [], "waiting_kev": []}


# --- mesajele -----------------------------------------------------------------------------
def test_a_new_finding_that_is_already_pending_is_not_announced_as_new(monkeypatch):
    """Mesajul „vulnerabilități noi” cere o acțiune (un patch). Pentru o constatare a
    cărei reparație e deja pe disc nu există niciuna — ar fi al doilea mesaj,
    contradictoriu cu cel despre repornire, pentru aceleași rânduri."""
    pending = _finding("kernel-core", PENDING)
    genuinely_new = _finding("openssl", NOT_PENDING, cve="CVE-2026-0009")

    out = _scan(_Db(), monkeypatch, [pending, genuinely_new])

    assert [f["cve"] for f in out["new_items"]] == ["CVE-2026-0009"]
    assert out["new"] == 2, "numărul de constatări noi nu are voie să se schimbe"


def test_a_family_without_verdicts_touches_no_fix_state_sql(monkeypatch):
    """Pe debian scanerul n-are `raw.fix_state`. Nicio interogare în plus: calea apt
    trebuie să rămână exact ce era."""
    apt = {"scanner": "apt", "cve": None, "package": "libssl3t64", "severity": "medium",
           "fixed_version": "3.0.13-0ubuntu3.5",
           "finding_key": fx.finding_key("apt", None, "libssl3t64", None, None), "raw": {}}

    async def scan(family):
        return [apt], None, {"scanner": "apt", "family": family, "db_version": None}

    async def no_kev(db, cves):
        return {}

    monkeypatch.setattr(orchestrator.os_packages, "scan", scan)
    monkeypatch.setattr(orchestrator.kev, "lookup", no_kev)
    db = _Db()

    out = run(orchestrator._run_os_packages(db, "debian", "schedule"))

    assert not db.sql("fix_state"), "calea apt a atins `fix_state`"
    assert out["pending_reboot"]["waiting"] == 0
    assert out["_pending"] == {"entered": [], "waiting_kev": []}


def test_a_failed_scan_touches_nothing(monkeypatch):
    """O scanare care n-a putut privi nu scrie nimic: verdictele rămân ale celei de
    dinainte. Aceeași regulă ca la `mark_resolved_absent`."""
    async def dead(family):
        return [], "dnf a căzut", {"scanner": "dnf", "family": family, "db_version": None}

    monkeypatch.setattr(orchestrator.os_packages, "scan", dead)
    db = _Db()

    out = run(orchestrator._run_os_packages(db, "rhel", "schedule"))

    assert out["status"] == "failed"
    assert not db.sql("fix_state") and db.status_updates() == []


def test_the_trivy_runs_do_not_touch_fix_state():
    """`fix_state` e doar al scanerului de pachete de sistem. Cele trei `_run_*` au blocuri
    aproape identice (vezi docstring-ul modulului: nu sunt împăturite dinadins), iar o
    editare făcută cu „înlocuiește tot” a strecurat o dată aceeași citire a verdictelor de
    ieri în `_run_trivy_fs` și `_run_trivy_image` — inofensivă azi (nu au verdicte), dar
    o interogare în plus și un cuplaj fals pe o cale care n-are legătură.
    """
    import inspect

    for fn in (orchestrator._run_trivy_fs, orchestrator._run_trivy_image):
        src = inspect.getsource(fn)
        assert "fix_state" not in src and "previous_fix_states" not in src, fn.__name__
    assert "fix_state.reconcile" in inspect.getsource(orchestrator._run_os_packages), (
        "control pozitiv: calea de pachete de sistem trebuie să-l cheme")


# --- cablajul întreg: dnf -> rpm -> verdict -> bază ---------------------------------------
def test_the_whole_chain_from_dnf_output_to_the_stored_verdict(monkeypatch):
    """Frontiera dinspre sistem, până la bază: ieșirea dnf, ieșirea `rpm -qa` și
    `uname -r` intră; verdictul iese scris pe rând. Ce nu e simulat: doar cele trei
    surse externe (dnf, rpm, uname) și baza.

    Ce se strică dacă un link din lanț se rupe (scanerul nu mai cheamă `annotate`,
    orchestratorul nu mai reconciliază): fiecare test de mai sus ar trece, iar
    planificatorul n-ar găsi niciun verdict.
    """
    dnf_out = ("CVE-2026-1111 Important/Sec.  kernel-core-5.14.0-687.47.1.el9_8.x86_64\n"
               "CVE-2026-2222 Important/Sec.  openssl-libs-1:3.5.6-1.el9_8.x86_64\n")
    rpm_out = ("kernel-core\t(none):5.14.0-687.46.1.el9_8\tx86_64\tkernel-5.14.0-687.46.1.el9_8.src.rpm\n"
               "kernel-core\t(none):5.14.0-687.51.1.el9_8\tx86_64\tkernel-5.14.0-687.51.1.el9_8.src.rpm\n"
               "openssl-libs\t1:3.5.5-1.el9_8\tx86_64\topenssl-3.5.5-1.el9_8.src.rpm\n")

    async def fake_dnf(argv, timeout, env=None):
        return 100, dnf_out, ""

    async def fake_rpm():
        return 0, rpm_out, ""

    async def no_kev(db, cves):
        return {}

    monkeypatch.setattr(os_packages, "_run", fake_dnf)
    monkeypatch.setattr(fix_state, "_run_rpm", fake_rpm)
    monkeypatch.setattr(fix_state, "_uname_release", lambda: RUNNING)
    monkeypatch.setattr(orchestrator.kev, "lookup", no_kev)
    db = _Db()

    out = run(orchestrator._run_os_packages(db, "rhel", "schedule"))

    kernel = db.rows[fx.finding_key("dnf", None, "kernel-core", "CVE-2026-1111", None)]
    ssl = db.rows[fx.finding_key("dnf", None, "openssl-libs", "CVE-2026-2222", None)]
    assert kernel["raw"]["fix_state"]["state"] == PENDING
    assert kernel["status"] == "open"
    assert ssl["raw"]["fix_state"]["state"] == NOT_PENDING, (
        "openssl-libs NU are voie: reparația lui nu e instalată")
    assert out["pending_reboot"]["running_kernel"] == RUNNING
    assert out["_pending"]["entered"][0]["installed"] == NEW_KERNEL


# --- run_all: mesajele și sumarul -----------------------------------------------------------
def _cfg():
    return SimpleNamespace(
        scan=SimpleNamespace(enabled=True, os_packages=True, filesystem=False,
                             containers=False, announce_new=True),
        platform=SimpleNamespace(family="rhel"),
        telegram=SimpleNamespace(allowed_chat_ids=[1]), hostname="gazda")


def _wire_run_all(monkeypatch, dnf_result):
    sent: dict[str, list] = {"full": [], "reminder": []}

    async def fake_full(cfg, items, *, running):
        sent["full"].append((list(items), running))
        return 1

    async def fake_reminder(cfg, items, *, running):
        sent["reminder"].append((list(items), running))
        return 1

    async def fake_announce(cfg, findings):
        return 0

    async def fake_dnf(_db, _family, _t):
        return dnf_result

    async def fake_plans(_db, _cfg):
        return {"status": "disabled"}

    async def fake_kev(_db):
        return None

    monkeypatch.setattr("sentinel.intel.kev.refresh", fake_kev)
    monkeypatch.setattr(orchestrator, "_run_os_packages", fake_dnf)
    monkeypatch.setattr(orchestrator, "_draft_plans", fake_plans)
    monkeypatch.setattr(orchestrator.announce, "announce", fake_announce)
    monkeypatch.setattr(orchestrator.announce, "announce_pending_reboot", fake_full)
    monkeypatch.setattr(orchestrator.announce, "announce_pending_reboot_reminder",
                        fake_reminder)
    return sent


def test_the_operator_gets_one_full_message_and_the_summary_stays_small(monkeypatch):
    """`scan_service` scrie TOT sumarul în jurnal. Lista celor 491 de rânduri n-are ce
    căuta acolo, iar mesajul trebuie să plece o singură dată, cu chiar lista, și cu
    nucleul care rulează.

    Ce se strică fără cablaj: constatările ar rămâne `open` fără nicio veste, iar
    operatorul n-ar afla niciodată de ce nu mai primește planuri pentru ele.
    """
    items = [{"id": i, "cve": f"CVE-{i}", "installed": NEW_KERNEL} for i in range(3)]
    sent = _wire_run_all(monkeypatch, {
        "status": "completed", "new_items": [],
        "pending_reboot": {"entered": 3, "running_kernel": RUNNING},
        "_pending": {"entered": items, "waiting_kev": []}})

    summary = run(orchestrator.run_all(object(), _cfg()))

    assert sent["full"] == [(items, RUNNING)] and sent["reminder"] == []
    assert summary["pending_reboot_announced"] == {"chats": 1, "findings": 3}
    assert "_pending" not in summary["dnf"], "lista întreagă a ajuns în sumar"
    assert summary["dnf"]["pending_reboot"]["entered"] == 3


def test_a_waiting_kev_gets_the_reminder_and_nothing_else_does(monkeypatch):
    """Doar reamintirea, doar pentru KEV, doar când nu a plecat deja mesajul integral."""
    kev = [{"id": 1, "cve": "CVE-KEV", "kev": True, "since": "2026-09-26"}]
    sent = _wire_run_all(monkeypatch, {
        "status": "completed", "new_items": [],
        "pending_reboot": {"entered": 0, "running_kernel": RUNNING},
        "_pending": {"entered": [], "waiting_kev": kev}})

    summary = run(orchestrator.run_all(object(), _cfg()))

    assert sent["full"] == [] and sent["reminder"] == [(kev, RUNNING)]
    assert summary["pending_reboot_reminded"] == {"chats": 1, "findings": 1}
    assert "pending_reboot_announced" not in summary


def test_nothing_pending_sends_no_reboot_message(monkeypatch):
    """La fiecare scanare fără nimic în așteptare nu pleacă nimic: un canal care
    repetă aceleași rânduri fără motiv e unul pe care operatorul îl oprește."""
    sent = _wire_run_all(monkeypatch, {
        "status": "completed", "new_items": [],
        "pending_reboot": {"entered": 0, "running_kernel": "x"},
        "_pending": {"entered": [], "waiting_kev": []}})

    summary = run(orchestrator.run_all(object(), _cfg()))

    assert sent == {"full": [], "reminder": []}
    assert "pending_reboot_announced" not in summary
    assert "pending_reboot_reminded" not in summary


def test_a_scanner_that_knows_nothing_about_this_does_not_break_the_pass(monkeypatch):
    """Un rezultat fără cheile astea (trivy, un scaner adăugat mâine): trecerea
    merge mai departe."""
    sent = _wire_run_all(monkeypatch, {"status": "completed", "findings": 12})

    summary = run(orchestrator.run_all(object(), _cfg()))

    assert sent == {"full": [], "reminder": []} and summary["dnf"]["findings"] == 12


# --- livrarea ---------------------------------------------------------------------------------
def _channel(monkeypatch) -> list[str]:
    calls: list[str] = []

    async def fake_send(token, chats, text, **kw):
        calls.append(text)
        return [SimpleNamespace(chat_id=c, ok=True, describe=lambda: "ok") for c in chats]

    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: {"TELEGRAM_BOT_TOKEN": "t"})
    monkeypatch.setattr("sentinel.telegram.direct.send_to_chats", fake_send)
    return calls


ROWS = [{"id": 1, "cve": "CVE-2026-0001", "package": "kernel-core", "severity": "high",
         "kev": False, "installed": NEW_KERNEL}]
KEV_ROWS = [{**ROWS[0], "kev": True, "since": "2026-09-26"}]


def test_the_reboot_message_is_delivered_and_counted_per_chat(monkeypatch):
    """Cu un canal FUNCȚIONAL în spate: altfel `0` ar putea veni din lipsa tokenului,
    iar mesajul ar putea să nu plece vreodată fără ca testul să vadă."""
    calls = _channel(monkeypatch)

    delivered = run(announce.announce_pending_reboot(_cfg(), ROWS, running=RUNNING))

    assert delivered == 1 and len(calls) == 1
    assert "reparațiile sunt instalate" in calls[0]


def test_the_reminder_is_delivered_and_only_for_kev(monkeypatch):
    """Reamintirea zilnică pleacă pe același drum și doar pentru KEV: un rând necritic
    strecurat aici ar transforma singurul mesaj repetat într-un canal de zgomot."""
    calls = _channel(monkeypatch)

    delivered = run(announce.announce_pending_reboot_reminder(
        _cfg(), KEV_ROWS + ROWS, running=RUNNING))

    assert delivered == 1 and len(calls) == 1
    assert "exploatată activ" in calls[0] and "CVE-2026-0001" in calls[0]
    assert run(announce.announce_pending_reboot_reminder(
        _cfg(), ROWS, running=RUNNING)) == 0
    assert len(calls) == 1, "un rând fără KEV a produs o reamintire"


def test_the_switch_stops_both_reboot_messages(monkeypatch):
    """`scan.announce_new: false` oprește canalul de după scanare, nu doar jumătate din
    el. Cu canal funcțional, ca `0` să nu vină din altă parte."""
    calls = _channel(monkeypatch)
    cfg = _cfg()
    cfg.scan.announce_new = False

    assert run(announce.announce_pending_reboot(cfg, ROWS, running="x")) == 0
    assert run(announce.announce_pending_reboot_reminder(cfg, KEV_ROWS, running="x")) == 0
    assert calls == []


def test_an_empty_list_sends_nothing(monkeypatch):
    calls = _channel(monkeypatch)

    assert run(announce.announce_pending_reboot(_cfg(), [], running="x")) == 0
    assert run(announce.announce_pending_reboot_reminder(_cfg(), [], running="x")) == 0
    assert calls == []


def test_a_broken_telegram_does_not_fail_the_scan_here_either(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("rețeaua a căzut")

    monkeypatch.setattr("sentinel.config.get_secrets", boom)

    assert run(announce.announce_pending_reboot(_cfg(), ROWS, running="x")) == 0
    assert run(announce.announce_pending_reboot_reminder(_cfg(), KEV_ROWS, running="x")) == 0
