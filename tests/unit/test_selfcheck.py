"""The self-check, and the failures it exists because of.

Two real outages motivate this file, and both are represented below as tests:

  * the ingest service stayed `active` with zero restarts while its journald
    reader returned nothing for 21 hours, and SSH authentication went unwatched;
  * after a reboot the nftables table simply did not exist, so seven recorded
    blocks were fiction and the next automatic block would have failed silently.

In both, `systemctl is-active` said everything was fine. So the tests that
matter here are about the checks that do not ask systemd.
"""
from __future__ import annotations

import ast
import asyncio
import inspect
import json
import re
import sys
import types
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sentinel.config import SelfcheckSilenceConfig
from sentinel.selfcheck import checks
from sentinel.selfcheck.checks import CheckResult, worst

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)


def run(c):
    return asyncio.run(c)


class _DB:
    def __init__(self, rows=None, val=None, row=None):
        self._rows, self._val, self._row = rows or [], val, row
        self.sql: list[str] = []

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        return self._rows

    async def fetchval(self, sql, *a):
        self.sql.append(sql)
        return self._val

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        return self._row

    async def execute(self, sql, *a):
        self.sql.append(sql)

    async def healthy(self):
        return True


def _cfg(**over):
    base = SimpleNamespace(
        ai=SimpleNamespace(enabled=True),
        # Ca pe `Config`-ul real. Constatarile care tiparesc un moment il scriu
        # in fusul configurat, si il citesc de aici — un dublu fara campul asta
        # ar fi facut verificarea sa pice pe altceva decat pe ce testeaza.
        timezone="Europe/Bucharest",
        # `quiet_hours` și `timezone` sunt pe `TelegramConfig`-ul real și le
        # citește `check_alerting` DIRECT, nu printr-un getattr cu rezervă —
        # vezi `test_no_check_reads_a_config_field_that_does_not_exist`. Fără
        # ele aici, verificarea ar pica pe altceva decât pe ce se testează.
        telegram=SimpleNamespace(enabled=True, allowed_chat_ids=[1],
                                 quiet_hours=None, timezone="Europe/Bucharest"),
        response=SimpleNamespace(auto_block=SimpleNamespace(enabled=False), admin_ip=""),
        # Aceleași valori ca pe `Config()`-ul real: colectorul Suricata e pornit
        # în `ingest`, dar senzorul e oprit până când instalatorul îl aprinde.
        # `check_ingest_sources` le citește DIRECT — vezi
        # `test_no_check_reads_a_config_field_that_does_not_exist` —, iar un dublu
        # rămas în urmă ar face grupul „ingest” să pice pe altceva decât pe ce se
        # testează. `journald` și `flush_interval_ms` sunt citite direct de
        # `_journald_reader`, din același motiv.
        #
        # `nginx: False` aici — spre deosebire de `Config()`-ul real, unde e
        # `True` implicit — dinadins, ca dublul de mai jos: majoritatea
        # testelor din fișierul ăsta nu au nimic de-a face cu nginx și n-au
        # niciun fișier real de arătat lui `_nginx_reader`. Testele care CHIAR
        # testează `ingest:nginx` folosesc `_nginx_cfg`, mai jos, care îl
        # pornește peste un fișier adevărat din `tmp_path`.
        ingest=SimpleNamespace(suricata=True, journald=True, nginx=False,
                               nginx_log_paths=[], flush_interval_ms=1000),
        suricata=SimpleNamespace(enabled=False,
                                 eve_path="/var/log/suricata/eve.json"),
        # `_silence_limit`/`_all_quiet_down_min` citesc secțiunea asta DIRECT —
        # valorile sunt exact cele implicite din `SelfcheckSilenceConfig`, ca
        # un dublu rămas în urmă să nu mute pragurile pe care le testează
        # restul fișierului.
        selfcheck=SimpleNamespace(max_silence_min=SimpleNamespace(
            auditd=60, nginx=180, default=180)),
        # Ca pe `Config`-ul real: `check_ship_lag` citește `cfg.ship.enabled`
        # direct, nu printr-un `getattr` cu valoare de rezervă — vezi
        # `test_no_check_reads_a_config_field_that_does_not_exist` mai jos, care
        # există fiindcă un `getattr` a ținut o verificare moartă un an.
        ship=SimpleNamespace(enabled=False, url="", interval_s=60),
        # Idem pentru `check_beacon_delivery`. Fără câmpul ăsta, un test care
        # cheamă rularea ÎNTREAGĂ ar vedea grupul „beacon" raportat ca stricat,
        # iar cauza — un dublu de configurație rămas în urmă — n-are nicio
        # legătură cu gazda.
        beacon=SimpleNamespace(enabled=False, url="", interval_s=60),
        # `check_command_history_filter` citește cheia înapoi din
        # configurația încărcată. Lipsa secțiunii ar face grupul „history”
        # să pice în orice test care rulează trecerea întreagă, dintr-un
        # motiv care n-are nicio legătură cu gazda.
        history=SimpleNamespace(skip_command_accounts=[]),
    )
    for k, v in over.items():
        setattr(base, k, v)
    return base


# --- a silent collector is only a fault when the others are talking ---------
def _source(name: str, minutes: float):
    return {"source": name, "ultim": NOW - timedelta(minutes=minutes),
            "minute_tacere": minutes}


# --- cititorul journald e judecat pe poziția LUI, nu pe prospețimea jurnalului --
#
# Un jurnal fals, cu exact semantica pe care se sprijină
# `_journal_first_unread`: `seek_cursor` NU ridică pentru un cursor care nu mai
# există în jurnal — poziționează la cea mai apropiată intrare rămasă —, iar
# primul `get_next()` de după căutare întoarce intrarea DE LA cursor, nu pe cea
# de după ea. Testele de mai jos trec prin sonda adevărată, nu peste ea: dacă
# dispare comparația de `__CURSOR` din ea, ori pasul care caută prima intrare
# necitită, se vede aici.
class _FakeJournalReader:
    """`steps_onto_cursor` alege ce întoarce PRIMUL `get_next()` de după un
    `seek_cursor`: intrarea DE LA cursor (ce documentează systemd, și pe ce se
    sprijină `JournaldReader.seek`) sau pe cea de DUPĂ el. Semantica adevărată
    a gazdei nu se poate verifica de pe mașina asta, iar dacă sonda o presupune
    greșit, poziția validă a unui colector viu se citește drept „cursor
    dispărut" — `down` la fiecare cinci minute pe o gazdă sănătoasă. De aia
    testele de mai jos rulează pe amândouă.

    Restul semanticii e cea reală: `seek_cursor` NU ridică pentru un cursor
    care nu mai există (poziționează la cea mai apropiată intrare rămasă), iar
    un `get_next()` care nu mai are ce întoarce lasă poziția neschimbată.
    """

    def __init__(self, entries, steps_onto_cursor=True):
        self._entries = entries
        self._steps_onto_cursor = steps_onto_cursor
        self._loc = 0        # unde a nimerit căutarea
        self._i = None       # indicele intrării curente; None = doar pe un loc
        self.matches: list = []
        self.closed = False

    def add_match(self, **kw):
        self.matches.append(kw)

    def add_disjunction(self):
        self.matches.append("OR")

    def seek_cursor(self, cursor):
        self._loc = next(
            (i for i, e in enumerate(self._entries) if e["__CURSOR"] == cursor), 0)
        self._i = None

    def get_next(self):
        if self._i is None:
            i = self._loc if self._steps_onto_cursor else self._loc + 1
        else:
            i = self._i + 1
        if i >= len(self._entries):
            return {}
        self._i = i
        return self._entries[i]

    def get_previous(self):
        i = self._loc if self._i is None else self._i - 1
        if i < 0 or i >= len(self._entries):
            return {}
        self._i = i
        return self._entries[i]

    def close(self):
        self.closed = True


def _entry(cursor: str, seconds_ago: float):
    """O intrare de jurnal ca cele reale: `python-systemd` construiește
    `__REALTIME_TIMESTAMP` cu fus, deci și dublul o face."""
    return {"__CURSOR": cursor,
            "__REALTIME_TIMESTAMP": (datetime.now(timezone.utc)
                                     - timedelta(seconds=seconds_ago))}


def _fake_journal(monkeypatch, entries, steps_onto_cursor=True):
    """Pune un `systemd.journal` fals în `sys.modules` și întoarce lista
    cititoarelor construite — ca un test să poată dovedi și că jurnalul NU a
    fost deschis deloc, nu doar ce a răspuns."""
    built = []

    def _reader():
        reader = _FakeJournalReader(entries, steps_onto_cursor)
        built.append(reader)
        return reader

    journal_mod = types.ModuleType("systemd.journal")
    journal_mod.Reader = _reader
    systemd_mod = types.ModuleType("systemd")
    systemd_mod.journal = journal_mod
    monkeypatch.setitem(sys.modules, "systemd", systemd_mod)
    monkeypatch.setitem(sys.modules, "systemd.journal", journal_mod)
    return built


# Poziția salvată a colectorului în jurnalul „viu" de mai jos. Vechimile din
# perechea asta sunt deliberat DIFERITE — poziția e de acum 21 de ore, ultima
# intrare din jurnal de acum 5 secunde. Puse pe același număr (cum erau), o
# verificare care măsoară prospețimea jurnalului și una care măsoară distanța
# până la colector dau același verdict, iar testul nu le mai deosebește.
BUSY_STORED_CURSOR = "s=aa;i=1;b=bb;m=1;t=1;x=1"


def _busy_journal():
    """Jurnal care se umple în continuare, cu poziția colectorului rămasă la o
    intrare de acum 21 de ore."""
    return [
        _entry(BUSY_STORED_CURSOR, 21 * 3600),
        _entry("s=aa;i=2;b=bb;m=2;t=2;x=2", 20 * 3600),
        _entry("s=aa;i=3;b=bb;m=3;t=3;x=3", 300),
        _entry("s=aa;i=4;b=bb;m=4;t=4;x=4", 5),
    ]


@pytest.mark.parametrize("steps_onto_cursor", [True, False])
def test_a_reader_frozen_for_21h_beside_a_journal_that_keeps_filling_is_down(
        steps_onto_cursor, monkeypatch):
    """Pata oarbă de 21 de ore, în forma în care chiar s-a întâmplat.

    Cititorul a înghețat, jurnalul continuă să se umple. Un verdict luat din
    vechimea CELEI MAI NOI intrări din jurnal găsește 5 secunde, deci „e doar
    în lucru" și raportează `ok` (măsurat pe ambele gazde, 9 sep 2026, cu
    cursorul înghețat de 21 de ore: 0.08s și 0.04s sub o toleranță de 61s). Pe
    gazda de producție asta înseamnă autentificarea SSH nesupravegheată,
    raportată ca sănătoasă — și e mai rău decât verificarea veche pe rânduri,
    pe care schimbarea asta o înlocuiește. Ce trebuie măsurat e distanța până
    la poziția colectorului: prima intrare NECITITĂ așteaptă de 20 de ore.

    Rulat pe ambele semantici posibile ale primului pas de după `seek_cursor`
    (vezi `_FakeJournalReader`): verdictul nu are voie să depindă de o
    presupunere care nu se poate verifica de aici.
    """
    _fake_journal(monkeypatch, _busy_journal(), steps_onto_cursor)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": BUSY_STORED_CURSOR, "minute": 21 * 60})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "down", sshd.detail
    assert sshd.facts["first_unread_age_s"] > 3600, (
        "verdictul s-a luat din prospețimea jurnalului (ultima intrare, 5s), "
        "nu din cât așteaptă prima intrare necitită a colectorului")
    assert "restart sentinel-ingest" in sshd.action


@pytest.mark.parametrize("steps_onto_cursor", [True, False])
def test_the_same_busy_journal_with_a_caught_up_reader_is_ok(
        steps_onto_cursor, monkeypatch):
    """Perechea testului de mai sus: ACELAȘI jurnal, singura diferență e
    poziția salvată a colectorului. Dacă verdictul nu se schimbă între cele
    două, nu vine din ce pretinde că măsoară — iar un colector sănătos declarat
    `down` la fiecare cinci minute umple canalul până când operatorul nu-l mai
    citește.

    Rulat pe ambele semantici posibile ale primului pas de după `seek_cursor`
    (vezi `_FakeJournalReader`): verdictul nu are voie să depindă de o
    presupunere care nu se poate verifica de aici.
    """
    entries = _busy_journal()
    _fake_journal(monkeypatch, entries, steps_onto_cursor)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": entries[-1]["__CURSOR"], "minute": 3})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "ok", sshd.detail
    assert "first_unread_age_s" not in sshd.facts, (
        "a raportat o întârziere deși după poziția colectorului nu mai e nimic")


def test_a_frozen_reader_stays_down_when_the_journal_itself_goes_quiet(monkeypatch):
    """Verdictul nu are voie să depindă de cât de recent a scris cineva în
    jurnal — nici măcar în direcția „mai severă".

    Cu ramura `down` legată de prospețimea jurnalului, pe producție ea era
    accesibilă doar 27% din timp (măsurat: fracțiunea în care ultima intrare
    potrivită era mai veche de 61s). Un cititor mort ar fi alternat `down` și
    `ok` de la o rulare la alta, iar `runner.run_and_alert` anunță pe Telegram
    o RECUPERARE la fiecare trecere înapoi — recuperări în mijlocul unei pene
    care ține în continuare, de ordinul a o sută de mesaje pe zi."""
    entries = [_entry(BUSY_STORED_CURSOR, 21 * 3600),
               _entry("s=cc;i=2;b=bb;m=2;t=2;x=2", 20 * 3600 + 1800)]
    _fake_journal(monkeypatch, entries)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": BUSY_STORED_CURSOR, "minute": 21 * 60})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "down", sshd.detail


@pytest.mark.parametrize("steps_onto_cursor", [True, False])
def test_a_quiet_host_with_a_caught_up_reader_is_not_an_outage(
        steps_onto_cursor, monkeypatch):
    """Alarma falsă pentru care există schimbarea asta.

    n8n, 9 sep 2026: o singură intrare în blocklist a oprit sursa de
    brute-force care ținea jurnalul `sshd` cald, sshd n-a mai produs niciun
    rând 16h37m cât auditd scria în continuare, iar verificarea veche pe
    tăcerea rândului a acuzat un colector care funcționa — „🔴 Colector «sshd»
    a amuțit". După poziția colectorului nu urmează nicio intrare, deci a citit
    tot ce există: `ok`, oricât de veche ar fi poziția.

    Rulat pe ambele semantici posibile ale primului pas de după `seek_cursor`
    (vezi `_FakeJournalReader`): verdictul nu are voie să depindă de o
    presupunere care nu se poate verifica de aici.
    """
    entries = [_entry("s=dd;i=1;b=bb;m=1;t=1;x=1", (16 * 60 + 37) * 60)]
    _fake_journal(monkeypatch, entries, steps_onto_cursor)
    db = _DB(rows=[_source("auditd", 5), _source("nginx", 5)],
             row={"cursor": entries[0]["__CURSOR"], "minute": 16 * 60 + 37})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "ok", sshd.detail
    assert not sshd.bad


def test_an_entry_written_between_two_polls_is_not_an_outage(monkeypatch):
    """Colectorul își scrie cursorul la fiecare sondare care a citit ceva, deci
    între două sondări jurnalul are în mod normal o intrare nepreluată. Fără
    nicio toleranță, fiecare autentificare SSH ar produce o alertă `down` pe
    gazda cea mai sănătoasă cu putință."""
    entries = [_entry("s=ee;i=1;b=bb;m=1;t=1;x=1", 120),
               _entry("s=ee;i=2;b=bb;m=2;t=2;x=2", 3)]
    _fake_journal(monkeypatch, entries)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": entries[0]["__CURSOR"], "minute": 2})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "ok", sshd.detail
    assert sshd.facts["first_unread_age_s"] <= sshd.facts["tolerance_s"]


def test_the_tail_tolerance_is_derived_from_the_collectors_self_heal_budget():
    """Toleranța trebuie SĂ RĂMÂNĂ derivată din bugetul de auto-reparare al
    cititorului, nu înlocuită cu un număr ales.

    Cu 61s (o sondare + 60 de slack) verificarea acuza coada reconstrucției
    automate care FUNCȚIONEAZĂ. Măsurat pe producție, 10 sep 2026, sonda
    verbatim la 1 Hz: 6 probe din 3450 peste 61s, max 65.46s, fiecare la o
    secundă după „journald reader produced nothing for 60 polls; rebuilding".
    La 288 de rulări de selfcheck pe zi asta e ~0.6 `down` fals pe zi pe
    producție, fiecare urmat la cinci minute de o RECUPERARE falsă — adică
    exact felul de zgomot după care operatorul nu mai citește canalul.

    Nimic nu lega numărul de sursa lui: două mutații plauzibile — împărțirea la
    1000 scoasă (toleranță 1060s) și slack-ul lărgit la 3600s — treceau prin
    TOATĂ suita. Singura aserțiune care-l atingea era relativă și adevărată
    pentru orice toleranță ≥ 3s.

    Podelele de mai jos au păzit multă vreme o singură direcție, iar cealaltă e
    cea care face rău în tăcere: cu `JOURNALD_SELF_HEAL_CYCLES = 10` toleranța
    urcă la 670s — unsprezece minute în care un cititor oprit nu e numit —, și
    TOATĂ suita trecea (5053 passed, 20 skipped). Un prag umflat nu se vede în
    niciun mesaj: verificarea rămâne verde exact atât timp cât e mai leneșă.
    """
    cfg = _cfg()
    flush_s = cfg.ingest.flush_interval_ms / 1000
    un_ciclu = (checks.REBUILD_AFTER_EMPTY_POLLS + 1) * flush_s
    tol = checks._journald_tail_tolerance_s(cfg)

    # Relația, nu litera. Podelele de mai jos păzesc direcțiile în care are
    # voie să se miște.
    assert tol == (checks.JOURNALD_SELF_HEAL_CYCLES * un_ciclu
                   + checks.JOURNALD_TAIL_SLACK_S), (
        f"toleranța ({tol}s) nu mai iese din bugetul de auto-reparare al "
        f"cititorului ({un_ciclu}s pe ciclu) plus slack")

    # DOUĂ cicluri, nu unul: `_rebuild()` pune `_empty_polls` pe zero, deci o
    # reconstrucție care nu prinde din prima mai adună un rând întreg de
    # sondări goale înainte de următoarea. O toleranță de un singur ciclu
    # (121s cu constantele livrate) ar acuza exact asta — aceeași alarmă
    # falsă, într-o mărime mai mică.
    assert tol >= 2 * un_ciclu, (
        f"toleranța ({tol}s) nu acoperă două cicluri de auto-reparare "
        f"({2 * un_ciclu}s): o reconstrucție care nu prinde din prima e "
        f"raportată drept cititor oprit")

    # Și tavanul, fiindcă podeaua singură lasă deschisă exact direcția în care
    # o verificare e reglată până tace. Ce argumentează mecanismul e DOUĂ
    # cicluri plus slack, iar slack-ul e ținut sub un ciclu de aserțiunea
    # următoare — deci numărul argumentat nu poate depăși trei cicluri. Al
    # patrulea e marja unei schimbări viitoare care s-ar argumenta tot din
    # mecanism (o a treia încercare de reconstrucție, de pildă). Peste el,
    # numărul nu mai iese din auto-reparare: `CYCLES = 10` dă 670s, adică
    # unsprezece minute de cititor oprit fără ca cineva să afle.
    assert tol <= 4 * un_ciclu, (
        f"toleranța ({tol}s) a trecut de patru cicluri de auto-reparare "
        f"({4 * un_ciclu}s) — nu mai e bugetul mecanismului, e un prag lărgit "
        f"până tace verificarea, iar pata oarbă se lungește cu el")

    # Slack-ul rămâne slack. Dacă trece de un ciclu întreg, numărul nu mai e
    # derivat din mecanism, e ales cât să tacă verificarea.
    assert checks.JOURNALD_TAIL_SLACK_S <= un_ciclu, (
        f"slack-ul ({checks.JOURNALD_TAIL_SLACK_S}s) a depășit bugetul de "
        f"auto-reparare ({un_ciclu}s) din care ar trebui doar să absoarbă "
        f"zgomotul unei sondări lungi")

    # Și unitatea, exprimată în ce se pierde: pata oarbă de 21 de ore rămâne
    # prinsă cu două ordine de mărime înainte să se întâmple. Cu
    # `flush_interval_ms` neîmpărțit la 1000 toleranța ar fi de ~34 de ore,
    # adică mai lungă decât pana pe care verificarea asta există ca s-o prindă.
    assert 21 * 3600 / tol >= 100, (
        f"toleranța ({tol}s) nu mai e cu două ordine de mărime sub pata oarbă "
        f"de 21 de ore pentru care există verificarea")


def test_the_tail_tolerance_follows_the_rebuild_constant_it_is_derived_from(
        monkeypatch):
    """Dacă pragul de reconstrucție al colectorului se schimbă, toleranța
    trebuie să se miște singură.

    Rescrisă ca literal — 121, 180, orice număr —, relația se rupe tăcut, iar
    la următoarea schimbare a lui `REBUILD_AFTER_EMPTY_POLLS` verificarea ar
    acuza din nou coada unei recuperări care funcționează: chiar defectul
    reparat aici, întors pe ușa din dos, fără ca vreun test să-l vadă.
    """
    from sentinel.collectors import journald_reader

    assert (checks.REBUILD_AFTER_EMPTY_POLLS
            == journald_reader.REBUILD_AFTER_EMPTY_POLLS), (
        "checks.py și-a făcut o copie proprie a pragului de reconstrucție, "
        "deci cele două pot să se depărteze fără să observe nimeni")

    # Intervalul de sondare vine din configurație: o instalare care golește
    # tamponul mai rar are ciclul de auto-reparare mai lung, deci și toleranța.
    lent = _cfg()
    lent.ingest = SimpleNamespace(suricata=True, journald=True,
                                  flush_interval_ms=2000)
    assert checks._journald_tail_tolerance_s(lent) == (
        checks.JOURNALD_SELF_HEAL_CYCLES
        * (checks.REBUILD_AFTER_EMPTY_POLLS + 1) * 2.0
        + checks.JOURNALD_TAIL_SLACK_S), (
        "toleranța nu urmărește `ingest.flush_interval_ms`, deci pe o "
        "instalare cu altă cadență e greșită în tăcere")

    cfg = _cfg()
    inainte = checks._journald_tail_tolerance_s(cfg)
    monkeypatch.setattr(checks, "REBUILD_AFTER_EMPTY_POLLS", 300)
    dupa = checks._journald_tail_tolerance_s(cfg)
    assert dupa > inainte, (
        "pragul de reconstrucție a crescut de cinci ori, toleranța n-a "
        "urmat — deci e un literal, nu o relație")
    assert dupa == (checks.JOURNALD_SELF_HEAL_CYCLES * 301
                    * (cfg.ingest.flush_interval_ms / 1000)
                    + checks.JOURNALD_TAIL_SLACK_S)


def test_an_entry_left_behind_by_the_readers_own_rebuild_is_not_an_outage(
        monkeypatch):
    """Alarma falsă măsurată pe producție, scrisă ca test.

    Cititorul se reface singur după `REBUILD_AFTER_EMPTY_POLLS` sondări goale,
    iar cât se adună sondările alea prima intrare necitită îmbătrânește.
    Măsurat 10 sep 2026 pe producție: `first_unread_age_s` până la 65.46s, la o
    secundă după „rebuilding" în jurnalul serviciului, sub o toleranță de 61s —
    deci `down` pe un colector care tocmai își revenea, urmat la cinci minute
    de o RECUPERARE falsă, la 22 de reconstrucții pe oră (n8n: 59/h).

    90 de secunde e înăuntrul a două cicluri de auto-reparare și în afara
    vechii toleranțe de 61s: exact cazul care trebuie să fie `ok`.
    """
    entries = [_entry("s=ff;i=1;b=bb;m=1;t=1;x=1", 200),
               _entry("s=ff;i=2;b=bb;m=2;t=2;x=2", 90)]
    _fake_journal(monkeypatch, entries)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": entries[0]["__CURSOR"], "minute": 2})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "ok", sshd.detail
    assert not sshd.bad
    # Garda testului: dacă intrarea de probă ajunge sub 61s, testul nu mai
    # acoperă alarma falsă pentru care există și ar trece degeaba.
    assert sshd.facts["first_unread_age_s"] > 61, (
        "proba nu mai e peste vechea toleranță de 61s")


def test_an_entry_older_than_two_self_heal_cycles_is_still_down(monkeypatch):
    """Perechea testului de mai sus: același jurnal, altă vechime a primei
    intrări necitite.

    Toleranța a urcat de la 61s la 182s ca să nu mai acuze o reconstrucție care
    funcționează. Dacă odată cu asta ar fi urcat oriunde — slack lărgit, o
    unitate greșită care o duce la 34 de ore — cititorul oprit n-ar mai fi numit
    deloc, iar pata oarbă de 21 de ore s-ar întoarce sub o suită verde."""
    entries = [_entry("s=gg;i=1;b=bb;m=1;t=1;x=1", 1200),
               _entry("s=gg;i=2;b=bb;m=2;t=2;x=2", 900)]
    _fake_journal(monkeypatch, entries)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": entries[0]["__CURSOR"], "minute": 20})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "down", sshd.detail
    assert sshd.facts["first_unread_age_s"] > sshd.facts["tolerance_s"]
    assert "restart sentinel-ingest" in sshd.action


def test_the_down_message_never_quotes_an_age_below_the_budget_it_exceeded(
        monkeypatch):
    """Alerta nu are voie să se contrazică în propria ei frază.

    Între 183 și 239 de secunde textul ieșea „stă necitită de 3 min — peste
    bugetul de auto-reparare al cititorului (182s)": `_ago` taie la minute
    întregi, deci operatorul citea 180 < 182 și un mesaj care pare greșit.
    Telegram-ul e singurul canal prin care agentul poate spune ceva, iar o
    alertă care nu se susține la citire e o alertă pe care se învață să o
    sară — exact pana pe care fișierul ăsta există ca s-o prevină, mutată din
    cod în text.
    """
    cfg = _cfg()
    # Chiar peste buget, luat DIN buget: legată de 182 cu litera, proba ar
    # ieși din bandă tăcut la prima schimbare a constantelor din care iese
    # toleranța.
    varsta = checks._journald_tail_tolerance_s(cfg) + 8
    entries = [_entry("s=hh;i=1;b=bb;m=1;t=1;x=1", varsta + 400),
               _entry("s=hh;i=2;b=bb;m=2;t=2;x=2", varsta)]
    _fake_journal(monkeypatch, entries)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": entries[0]["__CURSOR"], "minute": 12})
    results = run(checks.check_ingest_sources(db, cfg))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "down", sshd.detail
    # Garda testului: proba trebuie să fie peste buget și sub o oră, adică
    # exact banda în care rotunjirea la minute întregi minte.
    assert (sshd.facts["tolerance_s"] < sshd.facts["first_unread_age_s"]
            < 3600), sshd.facts

    spus = re.search(r"necitită de (\d+)s", sshd.detail)
    assert spus, f"vechimea nu mai e spusă în secunde: {sshd.detail}"
    assert int(spus.group(1)) >= sshd.facts["tolerance_s"], (
        f"mesajul spune o vechime mai mică decât bugetul pe care zice că-l "
        f"depășește: {sshd.detail}")


@pytest.mark.parametrize("steps_onto_cursor", [True, False])
def test_a_cursor_the_journal_no_longer_holds_is_down_not_ok(
        steps_onto_cursor, monkeypatch):
    """Jurnalul s-a rotit (sau a fost golit) peste intrări pe care nu le-a
    citit nimeni.

    `seek_cursor` nu ridică pentru un cursor dispărut: poziționează la cea mai
    apropiată intrare rămasă. Dacă nu se compară `__CURSOR`-ul intrării găsite
    cu cel cerut, pasul următor arată ca „prima intrare necitită" a unei
    poziții valide, iar pe un jurnal proaspăt rotit starea asta s-ar citi drept
    „la zi" — pierdere de intrări raportată ca sănătate.

    Rulat pe ambele semantici posibile ale primului pas de după `seek_cursor`
    (vezi `_FakeJournalReader`): verdictul nu are voie să depindă de o
    presupunere care nu se poate verifica de aici.
    """
    entries = [_entry("s=ff;i=9;b=bb;m=9;t=9;x=9", 6 * 3600),
               _entry("s=ff;i=10;b=bb;m=10;t=10;x=10", 10),
               _entry("s=ff;i=11;b=bb;m=11;t=11;x=11", 8)]
    _fake_journal(monkeypatch, entries, steps_onto_cursor)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": "s=gone;i=1;b=bb;m=1;t=1;x=1", "minute": 8 * 60})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "down", sshd.detail
    assert sshd.facts["cursor_in_journal"] is False
    assert "necitite" in sshd.detail


def test_a_vanished_cursor_over_an_empty_journal_is_unknown_not_down(monkeypatch):
    """Poziția a dispărut ȘI nu mai e nimic după locul ei: nu se poate spune
    dacă s-au șters intrări necitite sau dacă jurnalul n-a avut ce să conțină.
    „Nu știu" și „e stricat" sunt stări diferite, iar a doua trimisă degeaba e
    exact alarma falsă care golește canalul de credit."""
    _fake_journal(monkeypatch, [])
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": "s=gone;i=1;b=bb;m=1;t=1;x=1", "minute": 8 * 60})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "unknown", sshd.detail
    assert not sshd.bad


def test_an_empty_stored_cursor_is_unknown_and_asks_the_journal_nothing(monkeypatch):
    """`collector_cursors.sshd.cursor` NULL sau gol înseamnă „nu există
    poziție", nu „poziție veche".

    Judecat ca un cursor obișnuit, un șir gol nu se potrivește cu nicio intrare
    din jurnal, iar comparația care n-a avut loc iese cu un verdict oricum —
    azi `down`, adică `critical` pe Telegram pentru o întrebare care n-a fost
    pusă. Docstring-ul funcției promite `unknown` exact aici."""
    built = _fake_journal(monkeypatch, _busy_journal())
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": None, "minute": 12})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "unknown", sshd.detail
    assert sshd.facts["cursor_fp"] is None, (
        "lipsa poziției a ieșit ca o amprentă — o poziție inexistentă nu are "
        "ce să semene cu una salvată")
    assert built == [], "a interogat jurnalul deși n-avea poziție de comparat"


# --- ce pleacă de pe gazdă odată cu poziția colectorului -------------------
#
# `facts` e o coloană EXPEDIATĂ: `SELFCHECK_STREAM` din
# sentinel/report/shipper.py o are în `columns`, iar `ship:selfcheck_state` e
# pornit pe gazdă. Ce se pune acolo pleacă la agregatorul extern la fiecare
# rulare a autodiagnosticului.
#
# Un cursor journald ca cele reale ca formă ȘI ca mărime — 124 de caractere
# măsurate pe gazdă —, cu identificatorii INVENTAȚI, fiindcă `s=` (id-ul
# fișierului de jurnal) și `b=` (id-ul de boot al mașinii) sunt exact ce n-are
# voie să plece, iar repository-ul ăsta e public.
LEAKY_CURSOR = ("s=" + "9f" * 16 + ";i=" + "b3" * 4 + ";b=" + "7a" * 16
                + ";m=1a2b3c4d;t=64f0a1b2;x=5d6e7f80")

# Fiecare ramură a lui `_journald_reader` care duce o poziție în `facts`.
# Starea sondei e dată direct, nu prin jurnalul fals: aici nu se testează
# sonda, ci ce publică verificarea DIN FIECARE ramură, iar verdictul așteptat
# stă lângă ea ca să nu treacă un caz care a nimerit altă ramură decât cea pe
# care pretinde că o acoperă.
_LEAK_CASES = [
    ("unavailable", "unavailable", None, "unknown"),
    ("caught_up", "caught_up", None, "ok"),
    ("gone_empty", "gone_empty", None, "unknown"),
    ("behind fără moment", "behind", None, "unknown"),
    ("behind sub toleranță", "behind", 5.0, "ok"),
    ("behind peste toleranță", "behind", 21 * 3600.0, "down"),
    ("gone", "gone", 6 * 3600.0, "down"),
]


def _probe(monkeypatch, state, age_s):
    """Înlocuiește sonda jurnalului cu un răspuns dat."""
    ts = (None if age_s is None
          else datetime.now(timezone.utc) - timedelta(seconds=age_s))

    def _fake(matches, cursor):
        return state, ts, "systemd lipsește"

    monkeypatch.setattr(checks, "_journal_first_unread", _fake)


@pytest.mark.parametrize("nume,state,age_s,asteptat", _LEAK_CASES,
                         ids=[c[0] for c in _LEAK_CASES])
def test_the_journald_cursor_never_leaves_the_host_in_shipped_facts(
        nume, state, age_s, asteptat, monkeypatch):
    """Cursorul journald e `s=<id fișier jurnal>;…;b=<id boot>;…` — DOI
    identificatori ai mașinii, 124 de caractere pe gazdă. Pus în `facts`, el
    pleacă la agregatorul extern la fiecare autodiagnostic, de 288 de ori pe
    zi: identificatorii părăsesc gazda, iar corpul cererii crește în fața unui
    WAF care punctează corpurile și oprește DEFINITIV fluxul după patru
    respingeri — adică exact canalul prin care agentul mai poate spune ceva.

    Aserțiunea e pe VALOARE, nu pe numele cheii: o verificare care se uită doar
    dacă s-a redenumit cheia ar trece în timp ce cursorul brut pleacă mai
    departe sub alt nume. Și nici o bucată din el nu e acceptabilă — orice
    fragment, de la început sau de la sfârșit, e fragment dintr-un
    identificator.

    Cursorul lui `_suricata_reader` (`<inod>:<offset>`) e în afara întrebării
    ăsteia: n-are niciun identificator al mașinii în el. De asta se citește
    aici doar `ingest:sshd`.
    """
    _probe(monkeypatch, state, age_s)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": LEAKY_CURSOR, "minute": 3})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")

    # Garda cazului: dacă ramura s-a mutat, testul nu mai acoperă ce spune.
    assert sshd.status == asteptat, sshd.detail

    blob = json.dumps(sshd.facts, ensure_ascii=False)
    assert LEAKY_CURSOR not in blob, (
        f"poziția întreagă a colectorului pleacă la agregator pe ramura "
        f"„{nume}”: {blob}")
    for token in LEAKY_CURSOR.split(";"):
        assert token not in blob, (
            f"«{token}» din cursor pleacă la agregator pe ramura „{nume}”: "
            f"{blob}")
    for cheie, valoare in sshd.facts.items():
        if not isinstance(valoare, str):
            continue
        # Orice bucată brută a cursorului e, prin definiție, un subșir al lui.
        assert len(valoare) < 3 or valoare not in LEAKY_CURSOR, (
            f"`{cheie}` duce o bucată brută din poziția colectorului "
            f"(«{valoare}») pe ramura „{nume}”")
        assert len(valoare) <= 32, (
            f"`{cheie}` trimite {len(valoare)} de caractere la agregator pe "
            f"ramura „{nume}” — corpul expediat crește în fața WAF-ului care "
            f"oprește fluxul după patru respingeri")


def test_no_facts_in_the_journald_check_is_built_from_the_stored_cursor():
    """Perechea structurală a testului de mai sus, pentru ramurile pe care el
    nu le enumeră.

    Testul de deasupra acoperă cele șapte ramuri de azi. A opta, adăugată
    mâine cu `facts={"cursor": stored_cursor}` în ea, ar trece prin el fără să
    fie atinsă — și abia pe gazdă s-ar vedea că id-ul de boot pleacă din nou.
    Aici se citește FUNCȚIA: nicio valoare din niciun `facts=` al ei nu are
    voie să se atingă de `stored_cursor`, nici întreg, nici feliat.
    """
    arbore = ast.parse(inspect.getsource(checks._journald_reader))
    dicturi = [kw.value for nod in ast.walk(arbore)
               if isinstance(nod, ast.Call)
               for kw in nod.keywords
               if kw.arg == "facts" and isinstance(kw.value, ast.Dict)]
    assert len(dicturi) >= 7, (
        f"s-au găsit doar {len(dicturi)} constatări cu `facts` în "
        "`_journald_reader` — testul se uită în altă parte decât crede")
    for d in dicturi:
        for cheie, valoare in zip(d.keys, d.values):
            nume = [n.id for n in ast.walk(valoare) if isinstance(n, ast.Name)]
            eticheta = getattr(cheie, "value", "?")
            assert "stored_cursor" not in nume, (
                f"`{eticheta}` e construit din poziția brută a colectorului, "
                f"iar `facts` pleacă la agregatorul extern — vezi "
                f"`_cursor_fingerprint`")


def test_the_shipped_position_still_tells_two_runs_apart(monkeypatch):
    """Ce trebuie să RĂMÂNĂ posibil după ce cursorul nu mai pleacă: operatorul
    (și agregatorul) trebuie să poată spune dacă poziția colectorului s-a
    MIȘCAT între două rulări. Fără asta, un cititor înghețat și unul care
    citește arată identic din afara gazdei, iar tăierea ar fi cumpărat
    confidențialitatea cu chiar semnalul pentru care există verificarea.
    """
    def _fp_pentru(cursor):
        _probe(monkeypatch, "caught_up", None)
        db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
                 row={"cursor": cursor, "minute": 3})
        results = run(checks.check_ingest_sources(db, _cfg()))
        sshd = next(r for r in results if r.key == "ingest:sshd")
        assert sshd.status == "ok", sshd.detail
        return sshd.facts["cursor_fp"]

    # Aceeași poziție, două rulări: neschimbată înseamnă neschimbată.
    assert _fp_pentru(LEAKY_CURSOR) == _fp_pentru(LEAKY_CURSOR)

    # Poziția a avansat cu o singură intrare — diferența dintre „cititorul
    # merge" și „cititorul stă" e uneori chiar atât.
    avansat = LEAKY_CURSOR.replace(";i=" + "b3" * 4, ";i=" + "b3" * 3 + "b4")
    assert avansat != LEAKY_CURSOR
    assert _fp_pentru(avansat) != _fp_pentru(LEAKY_CURSOR), (
        "două poziții diferite dau aceeași amprentă — o poziție înghețată se "
        "citește de la distanță ca una care se mișcă")

    # Și lungimea, fiindcă ea decide cât de des mint comparațiile de mai sus.
    # Sub 8 caractere hexa (32 de biți) coliziunile devin plauzibile la 288 de
    # rulări pe zi, iar o coliziune spune „poziția nu s-a mișcat" despre un
    # cititor care citește — tăcere falsă, nu alarmă falsă. Peste 16 nu se
    # cumpără nimic: rămâne doar corp de cerere în plus, în fața WAF-ului care
    # oprește fluxul după patru respingeri.
    assert 8 <= checks.CURSOR_FINGERPRINT_HEX <= 16, (
        f"amprenta poziției are {checks.CURSOR_FINGERPRINT_HEX} caractere — "
        f"prea scurtă se ciocnește (o poziție care se mișcă se citește ca "
        f"înghețată), prea lungă doar umflă corpul expediat")


def test_a_journal_entry_without_a_timestamp_is_unknown_not_a_zero_lag(monkeypatch):
    """O intrare de jurnal fără `__REALTIME_TIMESTAMP` nu are vechime, iar „nu
    are vechime" nu e „e de acum".

    Citită ca zero, întârzierea iese sub orice toleranță și un cititor oprit de
    o noapte se raportează `ok` — aceeași boală ca măsurarea cantității
    greșite, doar mai tăcută, fiindcă aici nici nu se vede că lipsește ceva.
    Verificat: mutația care întorcea `now()` pentru o intrare fără moment nu
    pica niciun test."""
    entries = _busy_journal()
    del entries[1]["__REALTIME_TIMESTAMP"]      # chiar prima intrare necitită
    _fake_journal(monkeypatch, entries)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": BUSY_STORED_CURSOR, "minute": 21 * 60})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "unknown", sshd.detail
    assert "__REALTIME_TIMESTAMP" in sshd.detail


def test_journald_reader_is_unknown_when_systemd_is_unavailable():
    """Fără dublu: `_journal_first_unread` cade pe importul real (și lipsă pe
    mașina asta) de `systemd` și trebuie să spună «nu știu», nu să inventeze
    «ok» — un `ok` inventat aici ar șterge o constatare reală pe o gazdă unde
    verificarea chiar n-a putut să se uite."""
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)],
             row={"cursor": "s=x", "minute": 1})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "unknown", sshd.detail
    assert not sshd.bad


def test_journald_reader_is_unknown_not_ok_when_the_cursor_row_is_missing(monkeypatch):
    """Un rând din `collector_cursors` care nu s-a scris niciodată, ori a fost
    șters, nu are voie să se citească drept «e bine» — vezi docstring-ul
    modulului despre constatările retrase."""
    _fake_journal(monkeypatch, _busy_journal())
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)], row=None)
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "unknown", sshd.detail


def test_sudo_and_su_liveness_still_comes_from_the_reader_not_the_row(monkeypatch):
    """Obligația schimbării: scoțând dovada pe rândul sshd pentru sudo/su, ele
    nu au voie să rămână nedovedite. `_journald_reader` acoperă toate trei din
    același cititor, deci un cititor oprit se vede sub `ingest:sshd` chiar și
    când sudo tace de un an (condus de om, `ok` oricum) — și chiar și când
    jurnalul e plin, ceea ce e cazul în care premisa veche cădea."""
    _fake_journal(monkeypatch, _busy_journal())
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2),
                   _source("sudo", 60 * 24 * 365)],
             row={"cursor": BUSY_STORED_CURSOR, "minute": 21 * 60})
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "down", (
        "cititorul mort trebuia prins — el e dovada de viață pentru sudo/su")
    sudo = next(r for r in results if r.key == "ingest:sudo")
    assert sudo.status == "ok" and not sudo.bad


def test_journald_disabled_in_config_says_so_instead_of_being_unknown_forever(monkeypatch):
    """Aceeași alegere ca la `ship:lag` cu `ship.enabled: false`: un operator
    care a oprit dinadins colectarea din jurnal trebuie să vadă «oprit», nu un
    «nu știu» permanent, care arată ca o verificare stricată."""
    built = _fake_journal(monkeypatch, _busy_journal())
    cfg = _cfg()
    cfg.ingest = SimpleNamespace(suricata=True, journald=False, nginx=False,
                                 nginx_log_paths=[], flush_interval_ms=1000)
    db = _DB(rows=[_source("auditd", 2), _source("nginx", 2)], row=None)
    results = run(checks.check_ingest_sources(db, cfg))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "ok" and sshd.facts["configured"] is False
    assert not any("collector_cursors" in s for s in db.sql), (
        "a citit cursorul „sshd” deși jurnalul e oprit din `ingest`")
    assert built == [], "a deschis jurnalul deși e oprit din `ingest`"


def test_the_journald_probe_matches_exactly_what_the_collector_matches(monkeypatch):
    """Sonda și cititorul viu trebuie să întrebe jurnalul același lucru.

    Dacă sonda ar potrivi altceva (de exemplu doar `sshd`, fără
    `sshd-session`, `sudo` și `su`), cursorul salvat de colector ar putea
    aparține unei intrări pe care sonda n-o vede — și atunci ea ar citi poziția
    validă a unui colector viu drept „cursor dispărut din jurnal", adică `down`
    pe o gazdă sănătoasă."""
    from sentinel.services.ingest_service import JOURNALD_COMMS

    built = _fake_journal(monkeypatch, _busy_journal())
    db = _DB(rows=[_source("auditd", 2)],
             row={"cursor": BUSY_STORED_CURSOR, "minute": 21 * 60})
    run(checks.check_ingest_sources(db, _cfg()))
    assert len(built) == 1, "sonda n-a deschis jurnalul"
    asked = [m["_COMM"] for m in built[0].matches if isinstance(m, dict)]
    assert asked == list(JOURNALD_COMMS), asked
    assert built[0].matches.count("OR") == len(JOURNALD_COMMS) - 1, (
        "grupurile nu mai sunt legate prin SAU — vezi `apply_matches`")
    assert built[0].closed, "cititorul de probă a rămas deschis"


# --- S9: this check must not scan the whole raw_events retention window ----
def test_ingest_sources_query_is_bounded_not_a_full_retention_scan():
    """Measured: `raw_events` at 4.7 GB, this check on a 5-minute selfcheck
    timer, and the query used to read `WHERE ts > now() - interval '30
    days'` — the entire default retention window, every single pass. No
    verdict here needs data older than a few hours (`DEFAULT_MAX_SILENCE_MIN`
    is 180 minutes); the window must be bounded to something on that order,
    not the retention period."""
    db = _DB(rows=[_source("sshd", 5)])
    run(checks.check_ingest_sources(db, _cfg()))
    assert db.sql, "verificarea n-a interogat deloc raw_events"
    sql = " ".join(db.sql[0].split())
    assert "raw_events" in sql
    assert "30 days" not in sql, (
        "interogarea tot citește toată fereastra de retenție de 30 de zile")
    assert "make_interval(hours" in sql or "interval" in sql.lower(), (
        "fereastra de scanare nu mai e mărginită deloc")


def test_ingest_sources_scan_window_is_bounded_to_hours_not_days():
    """The bound itself must stay small — a regression back to a many-day
    window would pass the string check above (still "an interval") while
    reintroducing the same full-table scan under a different unit."""
    margin = checks.DEFAULT_MAX_SILENCE_MIN * 2
    assert checks.RAW_EVENTS_INGEST_SCAN_HOURS <= 72, (
        f"fereastra de scanare a crescut la {checks.RAW_EVENTS_INGEST_SCAN_HOURS}h "
        f"— înapoi spre o scanare pe zile întregi din raw_events")
    assert checks.RAW_EVENTS_INGEST_SCAN_HOURS * 60 >= margin, (
        "fereastra e mai mică decât marja necesară peste cel mai lung prag "
        "per-sursă — un colector legitim de tăcut ar ieși din interogare "
        "înainte să apuce să fie evaluat pe pragul lui")


def test_the_shipped_default_patience_is_read_out_of_the_dataclass():
    """`DEFAULT_MAX_SILENCE_MIN` e singurul loc din modul care mai numește
    răbdarea implicită, iar niciun verdict nu-l citește: `_silence_limit`
    întreabă CONFIGURAȚIA. O constantă care nu conduce nimic nu e contrazisă
    de nimic — pusă pe 999, toată suita trecea (5053 passed, 20 skipped) —,
    dar ea e ce citește omul care vine să afle „cu ce pleacă o instalare".

    Ce se strică pentru operator dacă cele două se depărtează: fereastra de
    scanare de mai sus e dimensionată pe ea (`RAW_EVENTS_INGEST_SCAN_HOURS`,
    cu marja calculată din valoarea asta), și tot ea e numărul din care se
    argumentează pragurile în comentariile secțiunii. Un al doilea exemplar
    scris de mână se învechește tăcut la prima schimbare a valorii livrate, iar
    argumentele construite pe el rămân în picioare arătând corect.
    """
    assert checks.DEFAULT_MAX_SILENCE_MIN == SelfcheckSilenceConfig().default, (
        "constanta din checks.py nu mai e valoarea livrată de "
        "`SelfcheckSilenceConfig.default` — e o a doua copie, scrisă de mână")
    # Și că e chiar CEA MAI LUNGĂ răbdare livrată: fereastra de scanare își ia
    # marja din ea, iar dacă un câmp per-sursă o depășește, marja aia e
    # calculată pe numărul greșit.
    livrate = SelfcheckSilenceConfig()
    assert checks.DEFAULT_MAX_SILENCE_MIN == max(
        getattr(livrate, f) for f in
        (*checks.NAMED_SILENCE_SOURCES, "default")), (
        "răbdarea implicită nu mai e cea mai lungă dintre cele livrate, deci "
        "marja ferestrei de scanare e argumentată pe alt număr decât cel real")


def test_a_quiet_night_is_not_an_outage():
    """Everything quiet together is a quiet host. Blaming each collector
    individually would be six alerts for one non-problem — and six false alerts
    is how a channel gets muted."""
    db = _DB(rows=[_source("sshd", 500), _source("nginx", 400),
                   _source("suricata", 380)])
    results = run(checks.check_ingest_sources(db, _cfg()))
    per_source = [r for r in results if r.key.startswith("ingest:") and r.key != "ingest:all"]
    assert all(not r.bad for r in per_source)
    # But it IS reported once, at the top: everything silent is not normal either.
    assert any(r.key == "ingest:all" and r.status == "down" for r in results)


def test_a_short_pause_does_not_declare_the_host_down():
    """18 alerte «toate sursele au amuțit» în două zile pe o gazdă sănătoasă,
    fiecare urmată de «nu se mai raportează» — măsurat pe o gazdă Docker unde
    activitatea trăiește mai ales în containere: golul cel mai mare din 24h era
    exact 5 minute, cadența naturală a gazdei, nu o pană. Vechiul prag de 5
    minute confunda pauza asta cu tăcerea totală."""
    db = _DB(rows=[_source("auditd", 6), _source("sshd", 6), _source("nginx", 6)])
    results = run(checks.check_ingest_sources(db, _cfg()))
    assert not any(r.key == "ingest:all" for r in results), (
        "o pauză de 6 minute pe o gazdă altfel sănătoasă a fost raportată ca "
        "«toate sursele au amuțit»")


def test_silence_past_the_chattiest_sources_own_limit_is_down():
    """Peste pragul celei mai vorbărețe surse urmărite (azi 60 de minute, de la
    auditd), tăcerea încetează să fie o pauză normală — și tot acolo prinde
    pana reală de 21 de ore, de douăzeci de ori mai repede decât ea."""
    limit = checks._all_quiet_down_min(_cfg())
    db = _DB(rows=[_source("auditd", limit + 1), _source("sshd", limit + 30),
                   _source("nginx", limit + 60)])
    results = run(checks.check_ingest_sources(db, _cfg()))
    all_quiet = next(r for r in results if r.key == "ingest:all")
    assert all_quiet.status == "down"
    assert "amuțit" in all_quiet.title


def test_silence_exactly_at_the_limit_is_not_yet_down():
    """Limita e o graniță, nu o presupunere: la exact pragul celei mai
    vorbărețe surse, gazda poate fi încă într-o pauză legitimă."""
    limit = checks._all_quiet_down_min(_cfg())
    db = _DB(rows=[_source("auditd", limit), _source("sshd", limit),
                   _source("nginx", limit)])
    results = run(checks.check_ingest_sources(db, _cfg()))
    assert not any(r.key == "ingest:all" for r in results)


def test_the_row_silence_threshold_no_longer_governs_nginx():
    """`selfcheck.max_silence_min.nginx` used to be the knob this test proved
    live (Change 2, Aug 2026: a raised value had to reach the verdict). It
    stopped being true on 23 Sep 2026 — see the measurement above
    `CURSOR_BACKED_SOURCES` in checks.py: nginx moved there, so no
    `max_silence_min.nginx` value, raised or not, changes `ingest:nginx` any
    more. The field stays on `SelfcheckSilenceConfig` only so already-deployed
    `sentinel.yaml` files keep loading (`nginx: 180` has shipped in
    `deploy/config/sentinel.yaml.tmpl` since S9, and a live config is never
    rewritten) — what actually keeps it from quietly driving a verdict again
    is its exclusion from `NAMED_SILENCE_SOURCES`, asserted here.

    The mechanism that replaced it is proved below, in the nginx cursor
    section: a caught-up cursor after eleven hours of row silence stays `ok`
    (the n8n case), and a frozen cursor over a file that kept growing is
    still `down` regardless of what this field says.
    """
    assert "nginx" not in checks.NAMED_SILENCE_SOURCES, (
        "nginx a revenit în lista de praguri pe tăcere — verdictul lui ar "
        "veni din nou din cât de recent a scris cineva pe site, nu din "
        "cititor")
    assert "nginx" in checks.CURSOR_BACKED_SOURCES
    # Câmpul chiar mai există și se mai poate încărca — ștergerea lui ar
    # opri fiecare gazdă instalată cu `nginx: 180` deja scris pe disc.
    assert SelfcheckSilenceConfig(nginx=1440).nginx == 1440


def test_one_source_past_its_own_limit_is_blamed_even_if_others_are_merely_quiet():
    """`auditd` la 70 de minute (peste limita lui proprie de 60) trebuie acuzat
    NOMINAL — chiar dacă nimic n-a scris în ultimele 5 minute — pentru că
    verdictul pe sursă și verdictul colectiv folosesc acum ACELAȘI prag. Cu
    două praguri diferite (5 pentru acuzarea individuală, 60 pentru cel
    colectiv), fereastra 5–60 nu producea NICIUN verdict pentru auditd: nici
    acuzat pe nume, nici acoperit de `ingest:all` — o pană reală dispărea de
    pe panou."""
    db = _DB(rows=[_source("auditd", 70), _source("nginx", 10), _source("sshd", 15)])
    results = run(checks.check_ingest_sources(db, _cfg()))
    auditd = next(r for r in results if r.key == "ingest:auditd")
    assert auditd.status == "down", (
        "auditd (70 min, peste limita lui de 60) trebuia acuzat individual — "
        "nginx (10) și sshd (15) încă scriu, deci gazda nu e liniștită")
    assert "amuțit" in auditd.title
    per_source = [r for r in results if r.key.startswith("ingest:")
                  and r.key not in ("ingest:all", "ingest:auditd")]
    assert all(not r.bad for r in per_source)
    assert not any(r.key == "ingest:all" for r in results), (
        "auditd e deja acuzat pe nume — «ingest:all» ar fi un al doilea "
        "verdict pentru aceeași pană")


def test_a_real_fault_is_never_withdrawn_by_a_single_sudo_keystroke():
    """Pana de 21 de ore cu un `sudo` tastat la ora 20 nu mai trece prin
    fereastra 5–60: cu un singur prag, `sudo` la 30 de minute ține
    `ingest:auditd` acuzat pe nume în tot restul penei — niciodată nu dispare
    de pe panou, care ar fi anunțat operatorului 55 de minute de recuperare
    în mijlocul unei pene totale.

    Doar `auditd` mai e verificat aici pe rând: `nginx` e cursor-backed din
    23 sep 2026 (vezi `CURSOR_BACKED_SOURCES`) și, în dublul de configurație
    de mai jos (`_cfg()`), oprit — verdictul lui propriu nu mai vine din
    rândul ăsta. Rândul `nginx` rămâne în interogare doar ca să contribuie la
    `freshest`/`others_are_live`, ceea ce testul de mai jos nu verifică."""
    db = _DB(rows=[_source("auditd", 1260), _source("nginx", 1260),
                   _source("sshd", 1260), _source("sudo", 30)])
    results = run(checks.check_ingest_sources(db, _cfg()))
    auditd = next((x for x in results if x.key == "ingest:auditd"), None)
    assert auditd is not None and auditd.status == "down", (
        "ingest:auditd a dispărut de pe panou — o pană de 21h ascunsă de un "
        "singur «sudo» la 30 de minute")
    sudo = next(r for r in results if r.key == "ingest:sudo")
    assert sudo.status == "ok" and not sudo.bad


def test_a_dead_journald_reader_is_blamed_even_beside_a_live_cursor_source():
    """`journald` (auditd) mort de 4 ore lângă un rând `suricata` vechi de
    20 de minute nu mai dispare în `ingest:all`: cu un singur prag, rândul
    suricata ține pragul comun jos, iar auditd rămâne acuzat pe nume — nu se
    pierde sub «ingest:all», care pe gazda de producție ar fi ascuns exact
    colectorul mort.

    `nginx` a ieșit din verificarea pe nume aici pentru același motiv ca mai
    sus: e cursor-backed și oprit în dublul de configurație, deci verdictul
    lui propriu (`ok`, „oprit în configurație”) nu mai are legătură cu vârsta
    rândului."""
    db = _DB(rows=[_source("auditd", 240), _source("nginx", 240),
                   _source("sshd", 240), _source("suricata", 20)])
    results = run(checks.check_ingest_sources(db, _cfg()))
    auditd = next((x for x in results if x.key == "ingest:auditd"), None)
    assert auditd is not None and auditd.status == "down", (
        "ingest:auditd nu a fost acuzat lângă un rând suricata recent")
    assert not any(r.key == "ingest:all" for r in results), (
        "colectorul mort e deja acuzat pe nume — «ingest:all» n-ar adăuga "
        "nimic, ar dubla verdictul")


def test_all_quiet_threshold_is_pinned_to_the_smallest_per_source_limit():
    """`_all_quiet_down_min` trebuie SĂ RĂMÂNĂ derivat din pragurile per-sursă
    configurate, nu înlocuit cu o constantă coincidentă: o mutație care
    schimbă `min` în `max` (prag 180, de trei ori mai permisiv) sau care-l
    înlocuiește cu 10 — chiar valoarea care a produs 18 alerte «toate au
    amuțit» în ~45 de ore pe o gazdă sănătoasă — trecea neobservată prin toate
    cele 18 fișiere de test care importă `sentinel.selfcheck`, fiindcă nimic
    nu lega constanta de sursa ei."""
    cfg = _cfg()
    limits = cfg.selfcheck.max_silence_min
    assert checks._all_quiet_down_min(cfg) == min(
        getattr(limits, name) for name in checks.NAMED_SILENCE_SOURCES)
    assert checks._all_quiet_down_min(cfg) >= 30, (
        "sub 30 de minute pragul se apropie de cadența naturală măsurată pe "
        "gazda Docker (goluri de până la 5.02 minute) — flapping-ul de 18 "
        "alerte în ~45 de ore poate reveni fără ca vreun test s-o observe")


def test_all_quiet_threshold_follows_configuration_not_the_shipped_defaults():
    """Punctul întregii secțiuni 2: pragurile devin per-instalare. Un operator
    care ridică `nginx` la un număr mare NU are voie să ridice și pragul
    colectiv pe ascuns — cele două praguri configurate rămân `auditd` (60) și
    `nginx`, iar podeaua urmează minimul configurat, nu constanta veche."""
    cfg = _cfg()
    cfg.selfcheck = SimpleNamespace(max_silence_min=SimpleNamespace(
        auditd=45, nginx=1440, default=1440))
    assert checks._all_quiet_down_min(cfg) == 45


def test_the_collective_floor_is_taken_from_the_named_sources_not_from_default():
    """`default` e rezerva pentru colectorii fără câmp propriu, nu răbdarea
    vreunei surse urmărite — și dacă intră în podeaua colectivă, un operator
    care coboară `default` ca să fie mai sever cu un colector oarecare coboară
    pe ascuns și pragul lui `ingest:all`, adică readuce flapping-ul de 18
    alerte «toate au amuțit» în ~45 de ore de pe gazda Docker sănătoasă.

    Configurația de aici e aleasă ca cele două răspunsuri SĂ DIFERE: minimul
    câmpurilor numite e 60, minimul cu `default` inclus ar fi 30. Cu
    `auditd=45, nginx=1440, default=1440` — singura configurație testată până
    acum — ambele dau același număr, deci nimic nu prindea diferența."""
    cfg = _cfg()
    cfg.selfcheck = SimpleNamespace(max_silence_min=SimpleNamespace(
        auditd=60, nginx=180, default=30))
    assert checks._all_quiet_down_min(cfg) == 60
    # Și efectul, nu doar numărul: la 45 de minute de tăcere totală podeaua de
    # 60 înseamnă „încă e o pauză legitimă", iar cu `default` inclus (30) s-ar
    # fi emis `ingest:all` — `critical` pe o gazdă care doar respira.
    db = _DB(rows=[_source("auditd", 45), _source("nginx", 45)])
    results = run(checks.check_ingest_sources(db, cfg))
    assert not any(r.key == "ingest:all" for r in results), (
        "podeaua colectivă a coborât la `default`, deci o gazdă liniștită de "
        "45 de minute e raportată ca pană totală")


def test_a_human_driven_source_is_never_an_alert():
    """`sudo` and `su` produce events only when a person acts. A server nobody
    logged into for a day emits zero sudo events, and that is the healthy state.

    This shipped with a 24h threshold and fired on the first quiet day —
    "SENTINEL NU FUNCȚIONEAZĂ COMPLET", advising a restart of a service that was
    working. No duration may reproduce that, so the test uses a year."""
    for name in ("sudo", "su"):
        db = _DB(rows=[_source(name, 60 * 24 * 365), _source("suricata", 1),
                       _source("nginx", 2)])
        r = next(x for x in run(checks.check_ingest_sources(db, _cfg()))
                 if x.key == f"ingest:{name}")
        assert r.status == "ok", f"{name} după un an de liniște: {r.detail}"
        assert not r.bad
        # Still visible to the operator — silenced, not hidden.
        assert "normal" in r.detail


def test_human_driven_sources_carry_no_threshold():
    """Belt and braces: the two sets must not overlap. A threshold left behind
    among `NAMED_SILENCE_SOURCES` would be dead code that looks authoritative,
    and the next person to read it would reinstate the bug."""
    assert not (checks.HUMAN_DRIVEN & checks.NAMED_SILENCE_SOURCES)


def test_the_shared_journald_reader_still_has_a_watched_source():
    """sudo and su are exempt because sshd proves the reader is alive — they
    all come from ONE reader with one `_COMM` match set. If sshd ever stopped
    being watched, or stopped sharing that reader, the exemption would
    silently become a blind spot.

    sshd's proof no longer comes from `NAMED_SILENCE_SOURCES` — it is in
    `CURSOR_BACKED_SOURCES` instead, judged by `_journald_reader` on the
    reader's own cursor (see that dataclass's docstring for why the row
    threshold was removed)."""
    from sentinel.services.ingest_service import JOURNALD_COMMS
    assert "sshd" in checks.CURSOR_BACKED_SOURCES, (
        "sshd nu mai e supravegheat; sudo/su rămân neacoperite")
    assert "sshd" not in checks.HUMAN_DRIVEN
    for comm in ("sshd", "sudo", "su"):
        assert comm in JOURNALD_COMMS, f"{comm} nu mai vine din același cititor"
    assert "sshd" in JOURNALD_COMMS, "sshd nu mai vine din același cititor"


# --- suricata: cititorul se măsoară pe offset, nu pe rânduri ---------------
#
# Faptele din spatele testelor de mai jos sunt măsurate pe gazda de producție
# pe 28 august 2026, în ziua în care pragul de 30 de minute a
# produs 6 alerte `critical` — care trec de `/mute`, deci sună noaptea — pe un
# colector care citea corect: `eve.json` creștea cu ~333 MB/zi, cursorul
# colectorului avansa cu 164 156 de octeți în 35 de secunde peste același inod,
# iar ultimele 200 de linii ale fișierului conțineau ZERO `event_type: alert`.
# În 24 de ore, sursa avusese 7 goluri de peste 30 de minute, cel mai mare de
# 1h00m11s, în timp ce nginx și auditd scriau continuu.


def _eve(tmp_path, size: int):
    """Un `eve.json` adevărat de `size` octeți. Întoarce (cale, inod, mărime).

    Fișier real, nu un `os.stat` păcălit: mărimea și inodul sunt tocmai faptele
    pe care verificarea le compară cu offsetul, iar un dublu ar fi lăsat
    netestat exact `_stat_size_inode`.
    """
    import os as _os

    p = tmp_path / "eve.json"
    p.write_bytes(b"x" * size)
    st = _os.stat(p)
    return str(p), st.st_ino, st.st_size


def _suricata_cfg(path: str, **over):
    cfg = _cfg(**over)
    cfg.suricata = SimpleNamespace(enabled=True, eve_path=path)
    return cfg


def _cursor_row(cursor: str, idle_min: float):
    return {"cursor": cursor, "minute": idle_min}


def test_an_hour_without_a_suricata_alert_is_not_a_broken_collector(tmp_path):
    """Falsul pozitiv măsurat pe 28 august: 6 alerte `critical` într-o zi.

    Suricata scrie în `raw_events` doar ce se potrivește cu o semnătură, deci o
    oră fără nicio alertă e purtarea normală a unei gazde pe care nu s-a
    declanșat nimic. Judecată prin comparație cu nginx și auditd — care scriu un
    rând pe conexiune — tăcerea aia arăta ca o pană, iar `critical` trece peste
    `/mute`: operatorul era trezit de un colector care citea.

    Faptul care spune că citește e OFFSETUL care avansează, și el avansa.
    """
    path, inode, size = _eve(tmp_path, 4096)
    db = _DB(rows=[_source("suricata", 60), _source("nginx", 1), _source("auditd", 1)],
             row=_cursor_row(f"{inode}:{size}", 0.2))
    results = run(checks.check_ingest_sources(db, _suricata_cfg(path)))

    sur = [r for r in results if r.key == "ingest:suricata"]
    assert len(sur) == 1, f"un singur verdict pentru suricata, nu {len(sur)}"
    assert sur[0].status == "ok", (
        "un colector al cărui offset avansează a fost raportat ca defect fiindcă "
        "n-a avut ce raporta")
    assert not any(r.bad for r in results if r.key.startswith("ingest:suricata"))


def test_a_frozen_suricata_cursor_over_a_growing_file_is_down(tmp_path):
    """Pana pe care verificarea veche n-o putea vedea deloc.

    Cititorul moare peste un `eve.json` care continuă să crească: IDS-ul scrie,
    nimic nu ia. Vechea verificare ar fi tăcut oricât — pe gazdă suricata are
    goluri de peste o oră în purtare normală, deci pragul ei nu deosebea cazul
    ăsta de o noapte fără semnături. Aici se vede din singurul fapt care-l
    dovedește: offsetul stă, fișierul a crescut peste el.
    """
    path, inode, size = _eve(tmp_path, 400_000)
    db = _DB(rows=[_source("suricata", 90), _source("nginx", 1)],
             row=_cursor_row(f"{inode}:0", 34.0))
    results = run(checks.check_ingest_sources(db, _suricata_cfg(path)))

    sur = next(r for r in results if r.key == "ingest:suricata")
    assert sur.status == "down", "cititorul mort peste un fișier viu nu a fost prins"
    assert "sentinel-ingest" in sur.action
    assert sur.facts["unread_bytes"] == size


def test_a_frozen_cursor_over_a_file_that_stopped_growing_blames_the_sensor(tmp_path):
    """Cauza e alta, deci remediul trebuie să fie altul.

    Dacă `eve.json` nu mai crește, colectorul a citit tot ce există: nu el s-a
    oprit, ci Suricata. Un „systemctl restart sentinel-ingest" aici n-ar schimba
    nimic, iar operatorul ar reporni serviciul greșit la 3 dimineața. Cheie
    separată, mesaj separat.
    """
    path, inode, size = _eve(tmp_path, 4096)
    db = _DB(rows=[_source("suricata", 200), _source("nginx", 1)],
             row=_cursor_row(f"{inode}:{size}", 40.0))
    results = run(checks.check_ingest_sources(db, _suricata_cfg(path)))

    sur = next(r for r in results if r.key == "ingest:suricata")
    assert sur.status == "ok", "colectorul a fost acuzat pentru tăcerea senzorului"
    sensor = next(r for r in results if r.key == "ingest:suricata:sensor")
    assert sensor.status == "degraded"
    assert "suricata" in sensor.action and "sentinel-ingest" not in sensor.action


def test_a_rotated_eve_json_the_reader_never_picked_up_is_down(tmp_path):
    """Rotația pe care cititorul n-a urmat-o e tot o pată oarbă.

    Un cititor viu trece pe inodul nou în cel mult o citire, deci un cursor rămas
    pe inodul vechi după 34 de minute înseamnă că nimeni nu citește — chiar dacă
    fișierul nou e mic. Fără cazul ăsta, comparația mărime-offset ar fi dat un
    număr negativ și verificarea ar fi raportat „senzorul tace", adică serviciul
    greșit.
    """
    path, inode, size = _eve(tmp_path, 8192)
    db = _DB(rows=[_source("suricata", 120), _source("nginx", 1)],
             row=_cursor_row(f"{inode + 1}:900000", 34.0))
    results = run(checks.check_ingest_sources(db, _suricata_cfg(path)))

    sur = next(r for r in results if r.key == "ingest:suricata")
    assert sur.status == "down"
    assert sur.facts["rotated"] is True
    assert sur.facts["unread_bytes"] == size


def test_a_truncated_eve_json_the_reader_never_rewound_is_down(tmp_path):
    """`logrotate` cu `copytruncate` taie fișierul sub cursor, la același inod.

    Un cititor viu o vede și reia de la zero (`read_new_lines`: `if start > size:
    start = 0`), deci cursorul lui s-ar fi mișcat. Rămas pe loc, tot ce a scris
    Suricata de atunci e necitit. Scăderea `mărime - offset` iese aici NEGATIVĂ,
    deci nu trece niciun prag: fără ramura asta, un cititor mort era raportat ca
    „senzorul tace", iar operatorul repornea serviciul greșit.
    """
    path, inode, size = _eve(tmp_path, 300_000)
    db = _DB(rows=[_source("suricata", 120), _source("nginx", 1)],
             row=_cursor_row(f"{inode}:154153955", 34.0))
    results = run(checks.check_ingest_sources(db, _suricata_cfg(path)))

    sur = next(r for r in results if r.key == "ingest:suricata")
    assert sur.status == "down"
    assert sur.facts["truncated"] is True and sur.facts["unread_bytes"] == size
    assert not any(r.key == "ingest:suricata:sensor" for r in results)


def test_a_missing_suricata_cursor_is_unknown_not_ok(tmp_path):
    """„Nu știu" și „e bine" nu au voie să arate la fel.

    Runner-ul șterge din `selfcheck_state` cheile pe care o rulare completă nu
    le-a emis, și socotește „revenit la normal" orice cheie care nu mai e `bad`.
    Un `ok` inventat aici ar stinge o constatare adevărată și i-ar trimite
    operatorului o revenire care nu s-a întâmplat.
    """
    path, _inode, _size = _eve(tmp_path, 4096)
    db = _DB(rows=[_source("nginx", 1)], row=None)
    results = run(checks.check_ingest_sources(db, _suricata_cfg(path)))

    sur = next(r for r in results if r.key == "ingest:suricata")
    assert sur.status == "unknown", "lipsa cursorului a fost citită ca sănătate"


def test_an_unreadable_eve_json_is_unknown_not_a_verdict(tmp_path):
    """Cu fișierul necitibil, cele două cauze nu se pot deosebi — deci nu se aleg.

    Un `down` aici ar trimite operatorul să repornească un colector care poate
    citea; un `ok` ar ascunde o pată oarbă. Singurul răspuns adevărat e că
    întrebarea n-a primit răspuns.
    """
    path = str(tmp_path / "nu-exista" / "eve.json")
    db = _DB(rows=[_source("suricata", 120), _source("nginx", 1)],
             row=_cursor_row("123:456", 40.0))
    results = run(checks.check_ingest_sources(db, _suricata_cfg(path)))

    sur = next(r for r in results if r.key == "ingest:suricata")
    assert sur.status == "unknown"
    assert not any(r.key == "ingest:suricata:sensor" for r in results)


def test_suricata_keeps_a_verdict_when_it_has_no_rows_at_all(tmp_path):
    """O sursă fără niciun rând iese din interogarea pe 30 de zile — și tocmai
    atunci întrebarea „mai citește cineva?" e cea care contează.

    Cât timp verdictul venea din rânduri, o gazdă pe care Suricata n-a potrivit
    nimic o lună întreagă nu mai avea NICIO cheie `ingest:suricata`, deci nici
    acoperire. Verdictul pe cursor se produce indiferent de rânduri.
    """
    path, inode, size = _eve(tmp_path, 4096)
    db = _DB(rows=[_source("nginx", 1), _source("auditd", 2)],
             row=_cursor_row(f"{inode}:{size}", 1.0))
    results = run(checks.check_ingest_sources(db, _suricata_cfg(path)))

    sur = next(r for r in results if r.key == "ingest:suricata")
    assert sur.status == "ok"
    assert "nicio alertă în fereastra de 30 de zile" in sur.detail


def test_suricata_is_not_judged_against_its_neighbours_any_more():
    """Premisa scrisă în cod era falsă, iar un prag rămas în hartă o reînvie.

    nginx și auditd scriu un rând pe conexiune; suricata scrie un rând pe
    potrivire de semnătură. Comparația dintre ele nu poate răspunde la „e stricat
    colectorul?", și exact ea a produs alertele `critical` din 28 august.
    """
    assert "suricata" not in checks.NAMED_SILENCE_SOURCES, (
        "suricata a revenit în lista de praguri pe tăcere, deci e judecată din nou "
        "prin comparație cu vecini cu care nu e comparabilă")
    assert "suricata" in checks.CURSOR_BACKED_SOURCES
    assert not (checks.CURSOR_BACKED_SOURCES & checks.NAMED_SILENCE_SOURCES)


def test_the_neighbour_comparison_still_covers_the_row_driven_collectors():
    """Reparația nu are voie să însemne „taci peste tot".

    auditd A prins pana reală de 21 de ore, iar rândul lui chiar e proporțional
    cu traficul, deci pragul lui rămâne — configurabil acum, dar tot pe nume.
    sshd ȘI nginx au ieșit din listă: sshd fiindcă rândul lui nu mai e, singur,
    dovada de viață (vezi `SelfcheckSilenceConfig`); nginx fiindcă rândul lui e
    proporțional cu traficul, dar traficul unei gazde poate fi legitim zero
    (n8n, panou privat) — vezi comentariul de deasupra `CURSOR_BACKED_SOURCES`
    din checks.py pentru măsurătoarea de pe 23 sep 2026.
    """
    assert "auditd" in checks.NAMED_SILENCE_SOURCES, (
        "auditd și-a pierdut pragul de tăcere — verificarea care a prins "
        "pata oarbă de 21 de ore nu-l mai acoperă")
    assert "sshd" not in checks.NAMED_SILENCE_SOURCES
    assert "nginx" not in checks.NAMED_SILENCE_SOURCES


def test_suricata_turned_off_in_config_says_so_instead_of_vanishing(tmp_path):
    """O cheie absentă îl lasă pe operator să ghicească de ce.

    Aceeași alegere ca la `ship:lag` cu `ship.enabled: false`: dezactivarea se
    spune, nu se arată printr-un spațiu gol în panou.
    """
    path, inode, size = _eve(tmp_path, 4096)
    cfg = _suricata_cfg(path)
    cfg.suricata = SimpleNamespace(enabled=False, eve_path=path)
    db = _DB(rows=[_source("nginx", 1)], row=_cursor_row(f"{inode}:{size}", 0.5))
    results = run(checks.check_ingest_sources(db, cfg))

    sur = next(r for r in results if r.key == "ingest:suricata")
    assert sur.status == "ok" and sur.facts["configured"] is False


def test_the_toggle_in_ingest_decides_whether_the_cursor_is_read_at_all(tmp_path):
    """Colectorul se oprește din DOUĂ chei, iar una singură era fixată de un test.

    `cfg.ingest.suricata` e cea care spune dacă `sentinel-ingest` mai citește
    `eve.json`; `cfg.suricata.enabled` spune dacă senzorul e pornit. Dacă prima
    nu mai e citită, pe o gazdă care a oprit colectorul dinadins verificarea ar
    judeca un cursor pe care nimeni nu-l mai scrie și l-ar raporta înghețat —
    adică `down`, adică `critical`, adică o alertă care trece de `/mute` despre
    ceva ce a cerut chiar operatorul.
    """
    path, inode, size = _eve(tmp_path, 4096)
    cfg = _suricata_cfg(path)
    cfg.ingest = SimpleNamespace(suricata=False, journald=False, nginx=False,
                                 nginx_log_paths=[], flush_interval_ms=1000)
    db = _DB(rows=[_source("nginx", 1)], row=_cursor_row(f"{inode}:{size}", 90.0))
    results = run(checks.check_ingest_sources(db, cfg))

    sur = next(r for r in results if r.key == "ingest:suricata")
    assert sur.status == "ok" and sur.facts["configured"] is False, (
        "`ingest.suricata: false` nu mai oprește verdictul pe cursor")
    assert not any("collector_cursors" in s for s in db.sql), (
        "a citit cursorul „suricata” deși colectorul e oprit din `ingest` — "
        "verdictul ar veni dintr-un rând pe care nimeni nu-l mai scrie")


def test_the_cursor_verdict_survives_the_no_rows_at_all_branch(tmp_path):
    """O gazdă fără niciun eveniment nu are voie să piardă verdictul pe cursor.

    Ramura „niciun rând în 30 de zile" iese devreme și întoarce singură lista de
    rezultate. Runner-ul reconciliază `selfcheck_state` cu cheile pe care le emite
    o rulare, deci un `ingest:suricata` absent din ea e citit ca o constatare pe
    care verificarea a retras-o: operatorului i s-ar arăta o revenire care nu s-a
    întâmplat, pe cititorul de `eve.json`, exact pe gazda unde nu scrie nimeni
    altcineva ca să se observe.
    """
    path, inode, size = _eve(tmp_path, 4096)
    db = _DB(rows=[], row=_cursor_row(f"{inode}:{size}", 0.5))
    results = run(checks.check_ingest_sources(db, _suricata_cfg(path)))

    sur = next((r for r in results if r.key == "ingest:suricata"), None)
    assert sur is not None and sur.status == "ok", (
        "verdictul pe cursor a dispărut pe ramura «niciun eveniment în 30 de "
        "zile», deci runner-ul retrage constatarea despre cititorul eve.json")
    assert any(r.key == "ingest:any" and r.status == "down" for r in results), (
        "ramura de pană totală de colectare nu mai raportează nimic")


# --- nginx: același cititor generalizat pe mai multe fișiere ---------------
#
# Măsurat pe n8n, 23 septembrie 2026, 09:55 UTC, ca root — ziua în care
# `ingest:nginx` a raportat `down`, „🔴 SENTINEL NU FUNCȚIONEAZĂ COMPLET”, cu
# sfatul `systemctl restart sentinel-ingest`, peste un colector care în chiar
# acel moment prelua evenimente de la auditd:
#
#   * /var/log/nginx/sentinel-access.log: 13 349 octeți, 71 de linii, ultima
#     scriere 22 sep 22:10 UTC — 11h45m înainte de rulare;
#   * collector_cursors[nginx:/var/log/nginx/sentinel-access.log] =
#     „2359886:13349” — inod:offset, cu offsetul EGAL cu mărimea fișierului:
#     cititorul citise tot ce exista;
#   * ultimele cereri din fișier: GET / și GET /login la 01:09-01:10 ora
#     locală, de la reverse-proxy-ul propriu al operatorului — panoul n8n e
#     privat, deschis o dată pe zi;
#   * sentinel-ingest activ din 06:42, auditd la 09:55:30, detectorul la
#     09:55:02 — orice altă sursă vie în aceeași secundă.
#
# Testele de mai jos sunt perechea „tăcere legitimă / cititor mort” pentru
# nginx, la fel ca la suricata și sshd mai sus.
def _access_log(tmp_path, size: int, name: str = "access.log"):
    """Un access log adevărat de `size` octeți. Întoarce (cale, inod, mărime).

    Fișier real, nu un dublu: `_nginx_path_state` compară mărimea și inodul
    REALE cu offsetul din cursor, iar un dublu ar lăsa netestat exact
    `_stat_size_inode`."""
    import os as _os

    p = tmp_path / name
    p.write_bytes(b"x" * size)
    st = _os.stat(p)
    return str(p), st.st_ino, st.st_size


def _nginx_cfg(path_or_paths, **over):
    cfg = _cfg(**over)
    paths = [path_or_paths] if isinstance(path_or_paths, str) else list(path_or_paths)
    cfg.ingest = SimpleNamespace(suricata=True, journald=True, nginx=True,
                                 nginx_log_paths=paths, flush_interval_ms=1000)
    return cfg


def test_a_caught_up_nginx_cursor_after_eleven_hours_of_row_silence_is_ok(tmp_path):
    """Cazul de azi, cu numerele reale măsurate pe n8n. Vechea verificare
    (rând tăcut peste pragul de 180 de minute) acuza un colector care citise
    deja tot fișierul — traficul vizitatorilor era folosit drept puls, iar un
    panou nevizitat arăta identic cu un colector mort."""
    path, inode, size = _access_log(tmp_path, 13349)
    idle_min = 11 * 60 + 45
    db = _DB(rows=[_source("auditd", 1), _source("nginx", idle_min)],
             row=_cursor_row(f"{inode}:{size}", idle_min))
    results = run(checks.check_ingest_sources(db, _nginx_cfg(path)))

    nginx = next(r for r in results if r.key == "ingest:nginx")
    assert nginx.status == "ok", (
        f"un cititor care a citit tot fișierul a fost raportat mort: "
        f"{nginx.detail}")
    assert not nginx.bad


def test_a_frozen_nginx_cursor_over_a_growing_file_is_down(tmp_path):
    """Perechea cazului de mai sus: cititorul chiar a murit peste un fișier pe
    care nginx continuă să-l scrie. Fișierul crește, cursorul stă — proba pe
    care verificarea trebuie să continue s-o prindă, ca `ingest:suricata` mai
    sus."""
    path, inode, size = _access_log(tmp_path, 400_000)
    db = _DB(rows=[_source("nginx", 90), _source("auditd", 1)],
             row=_cursor_row(f"{inode}:0", 34.0))
    results = run(checks.check_ingest_sources(db, _nginx_cfg(path)))

    nginx = next(r for r in results if r.key == "ingest:nginx")
    assert nginx.status == "down", nginx.detail
    assert "sentinel-ingest" in nginx.action
    assert nginx.facts["unread_bytes"] == size


def test_a_missing_nginx_cursor_is_unknown_not_ok(tmp_path):
    """„Nu știu” și „e bine” nu au voie să arate la fel — vezi motivul identic
    la `test_a_missing_suricata_cursor_is_unknown_not_ok`."""
    path, _inode, _size = _access_log(tmp_path, 4096)
    db = _DB(rows=[_source("auditd", 1)], row=None)
    results = run(checks.check_ingest_sources(db, _nginx_cfg(path)))

    nginx = next(r for r in results if r.key == "ingest:nginx")
    assert nginx.status == "unknown", "lipsa cursorului a fost citită ca sănătate"


def test_an_empty_nginx_cursor_is_unknown_not_ok(tmp_path):
    path, _inode, _size = _access_log(tmp_path, 4096)
    db = _DB(rows=[_source("auditd", 1)], row=_cursor_row("", 5.0))
    results = run(checks.check_ingest_sources(db, _nginx_cfg(path)))

    nginx = next(r for r in results if r.key == "ingest:nginx")
    assert nginx.status == "unknown"


def test_a_malformed_nginx_cursor_is_unknown_not_ok(tmp_path):
    path, _inode, _size = _access_log(tmp_path, 4096)
    db = _DB(rows=[_source("auditd", 1)], row=_cursor_row("not-a-cursor", 5.0))
    results = run(checks.check_ingest_sources(db, _nginx_cfg(path)))

    nginx = next(r for r in results if r.key == "ingest:nginx")
    assert nginx.status == "unknown"


def test_an_unreadable_nginx_file_is_unknown_not_a_verdict(tmp_path):
    """`_nginx_path_state` verificat direct: `nginx_log_paths` se rezolvă
    printr-un glob, deci un fișier devenit ilizibil ÎNTRE glob și stat nu se
    poate provoca portabil printr-un test care trece prin
    `check_ingest_sources`. Ramura e aceeași ca la suricata: cu fișierul și
    cursorul necomparabile, verdictul e „nu știu”, nu o ghicire."""
    path = str(tmp_path / "nu-exista" / "access.log")
    db = _DB(row=_cursor_row("123:456", 40.0))
    status, detail, _facts = run(checks._nginx_path_state(db, path))
    assert status == "unknown"
    assert "nu s-a putut citi" in detail


def test_a_rotated_nginx_log_the_reader_never_picked_up_is_down(tmp_path):
    """Rotația pe care cititorul n-a urmat-o — aceeași pată oarbă ca la
    suricata: fără ramura `rotated`, `mărime - offset` ar ieși dintr-un
    calcul fals și verificarea ar raporta „la zi”."""
    path, inode, size = _access_log(tmp_path, 8192)
    db = _DB(rows=[_source("nginx", 120), _source("auditd", 1)],
             row=_cursor_row(f"{inode + 1}:900000", 34.0))
    results = run(checks.check_ingest_sources(db, _nginx_cfg(path)))

    nginx = next(r for r in results if r.key == "ingest:nginx")
    assert nginx.status == "down"
    assert nginx.facts["rotated"] is True
    assert nginx.facts["unread_bytes"] == size


def test_a_truncated_nginx_log_the_reader_never_rewound_is_down(tmp_path):
    """`logrotate` cu `copytruncate` sub același inod — scăderea directă ar
    ieși negativă și n-ar trece de niciun prag fără ramura `truncated`."""
    path, inode, size = _access_log(tmp_path, 300_000)
    db = _DB(rows=[_source("nginx", 120), _source("auditd", 1)],
             row=_cursor_row(f"{inode}:900000", 34.0))
    results = run(checks.check_ingest_sources(db, _nginx_cfg(path)))

    nginx = next(r for r in results if r.key == "ingest:nginx")
    assert nginx.status == "down"
    assert nginx.facts["truncated"] is True and nginx.facts["unread_bytes"] == size


def test_nginx_turned_off_in_config_says_so_instead_of_vanishing(tmp_path):
    """Aceeași alegere ca la `ship:lag`/suricata: dezactivarea se spune, nu se
    arată printr-un spațiu gol în panou."""
    path, inode, size = _access_log(tmp_path, 4096)
    cfg = _nginx_cfg(path)
    cfg.ingest.nginx = False
    db = _DB(rows=[_source("auditd", 1)], row=_cursor_row(f"{inode}:{size}", 0.5))
    results = run(checks.check_ingest_sources(db, cfg))

    nginx = next(r for r in results if r.key == "ingest:nginx")
    assert nginx.status == "ok" and nginx.facts["configured"] is False


def test_no_nginx_files_match_the_glob_is_unknown_not_silence(tmp_path):
    """Un glob care nu potrivește nimic nu e „nimic de raportat” — configurația
    cere colectarea, dar n-are ce cursor să compare."""
    cfg = _nginx_cfg(str(tmp_path / "nu-exista-deloc-*.log"))
    db = _DB(rows=[_source("auditd", 1)], row=None)
    results = run(checks.check_ingest_sources(db, cfg))

    nginx = next(r for r in results if r.key == "ingest:nginx")
    assert nginx.status == "unknown"


def test_the_nginx_cursor_verdict_survives_the_no_rows_at_all_branch(tmp_path):
    """Aceeași grijă ca la suricata: ramura „niciun rând în 30 de zile” iese
    devreme și nu are voie să piardă verdictul pe cursor."""
    path, inode, size = _access_log(tmp_path, 4096)
    db = _DB(rows=[], row=_cursor_row(f"{inode}:{size}", 0.5))
    results = run(checks.check_ingest_sources(db, _nginx_cfg(path)))

    nginx = next((r for r in results if r.key == "ingest:nginx"), None)
    assert nginx is not None and nginx.status == "ok"
    assert any(r.key == "ingest:any" and r.status == "down" for r in results)


def test_multiple_tailed_files_the_worst_one_decides(tmp_path):
    """`nginx_log_paths` e o listă de glob-uri — un host cu mai multe vhost-uri
    poate urmări mai multe fișiere. Un singur cititor mort trebuie să tragă
    verdictul în jos chiar dacă restul sunt la zi, altfel un al doilea fișier
    sănătos ar ascunde primul.

    Fișierul căzut stă la MIJLOC în ordinea alfabetică (`a`, `b` căzut, `c`),
    dinadins: cu doar două fișiere, cel căzut ar fi fost și primul, și ultimul
    din `states` — orice implementare care ia poziția în loc de stare
    (`list(states)[-1]`, `next(iter(states))`, `max(states)` pe chei) ar fi
    nimerit din întâmplare. Cu trei fișiere și cel căzut la mijloc, doar
    verificarea care compară STAREA fiecăruia mai poate nimeri."""
    ok_path, ok_inode, ok_size = _access_log(tmp_path, 4096, name="a-access.log")
    dead_path, dead_inode, _dead_size = _access_log(
        tmp_path, 400_000, name="b-access.log")
    ok2_path, ok2_inode, ok2_size = _access_log(tmp_path, 2048, name="c-access.log")
    cfg = _nginx_cfg(str(tmp_path / "*-access.log"))

    by_name = {
        f"nginx:{ok_path}": _cursor_row(f"{ok_inode}:{ok_size}", 0.2),
        f"nginx:{dead_path}": _cursor_row(f"{dead_inode}:0", 34.0),
        f"nginx:{ok2_path}": _cursor_row(f"{ok2_inode}:{ok2_size}", 0.1),
    }

    class _MultiDB(_DB):
        async def fetchrow(self, sql, *a):
            self.sql.append(sql)
            return by_name.get(a[0] if a else None)

    db = _MultiDB(rows=[_source("nginx", 1), _source("auditd", 1)])
    results = run(checks.check_ingest_sources(db, cfg))

    nginx = next(r for r in results if r.key == "ingest:nginx")
    assert nginx.status == "down", nginx.detail
    assert dead_path in nginx.detail and ok_path in nginx.detail and ok2_path in nginx.detail, (
        "detaliul trebuie să numească TOATE cele trei fișiere, nu doar pe cel căzut")
    # `_nginx_reader` promite explicit că `facts` vin din fișierul cu starea
    # cea mai rea, nu din primul sau ultimul din glob și nu din cheia maximă —
    # `a-access.log` (`ok_path`) e primul alfabetic, `c-access.log` (`ok2_path`)
    # e ultimul și e și cheia lexicografic maximă, dar cel viu e `b-access.log`
    # (`dead_path`), la mijloc, cu 400 000 de octeți necitiți. Dacă `worst_path`
    # ar lua orice cheie din `states` care nu depinde de STARE (de exemplu
    # `next(iter(states))`, `list(states)[-1]` sau `max(states)`), `facts` ar
    # arăta un fișier SĂNĂTOS — `unread_bytes` 0 — în timp ce verdictul rămâne
    # `down`; un operator care se uită doar la `facts` din panou ar fi mințit
    # despre care fișier a picat.
    assert nginx.facts["unread_bytes"] == 400_000, (
        "facts trebuie să vină din fișierul CĂZUT (b-access.log), nu din "
        "primul, ultimul sau cel cu cheia maximă din glob")


# --- garda punctului orb: o sursă nouă nu are voie să cadă neclasificată ----
def test_every_collector_source_is_classified_somewhere():
    """Punctul orb generalizat: nginx a scăpat fiindcă `source="nginx"` exista
    într-un colector real, dar nu aparținea niciunei mulțimi din checks.py —
    pragul implicit de tăcere l-a prins, tăcut, cu mecanismul greșit pentru ce
    era. O sursă nouă care nu e clasificată de NIMENI trebuie să pice AICI, nu
    să apară ca o alarmă falsă pe o gazdă vie, luni mai târziu.

    Rundele 1 și 2 scanau colectoarele după `Event(source=…)` prin AST, ca să
    deriveze CE se emite azi. Amândouă au pierdut, fiindcă „ce sintaxă poate
    produce un `source=`” nu e o listă închisă: poziția din semnătură
    (`Event(ts, "apache", "request", …)`), un apel prin atribut
    (`_ev.Event(source=…)`), un `**{"source": …}`, un alias de import
    (`E = Event`), un colector dintr-un subdirector pe care `glob("*.py")` nu
    îl vede, un al doilea regex undeva în pachet — runda 2 a închis o parte
    din ele, și tot a mai rămas o formă. Un scanner de sintaxă pierde mereu
    fiindcă sintaxa nu se termină.

    De aceea garda de mai jos nu mai citește codul colectoarelor ca să
    ghicească ce emit — citește `SOURCES` din `sentinel/model/event.py`, care
    e impusă de `Event.__post_init__` la RULARE, indiferent cum a fost
    construit `Event`-ul. Orice sursă declarată acolo trebuie să fie, exact:
    fie clasificată (`NAMED_SILENCE_SOURCES` / `CURSOR_BACKED_SOURCES` /
    `HUMAN_DRIVEN` / `DEFAULT_JUDGED_SOURCES`), fie numită, cu motiv, în
    `DECLARED_NOT_EMITTED_SOURCES` — a treia stare („nu e nicăieri”) nu
    există, verificat prin egalitate de mulțimi, nu prin scanare de cod. Cele
    șase forme de sintaxă de mai sus devin toate IRELEVANTE pentru garda asta:
    orice ar scrie un colector nou, dacă valoarea nu e deja pe `SOURCES`,
    `Event.__post_init__` o respinge singur la rulare; dacă e deja pe
    `SOURCES` (una din cele cinci declarate-dar-neemise azi), scanarea
    sintaxei n-ar fi contat oricum — decizia de clasificare a rămas pe
    dezvoltatorul care scrie colectorul, la fel cum a rămas pentru fiecare
    sursă clasificată deja aici.

    O scanare AST rămâne mai jos, dar demovată la verificare încrucișată, nu
    sursă de adevăr: dacă găsește un `source="literal"` real într-un colector,
    verifică doar că numele e un membru legitim al `SOURCES` — un typo acolo
    ar da oricum `ValueError` la runtime, deci asta prinde din timp, nu
    înlocuiește garda de mai sus. N-are nevoie să vadă toate formele, fiindcă
    nimic din ea nu mai decide clasificarea.
    """
    from pathlib import Path

    from sentinel.model.event import SOURCES

    classified = (checks.NAMED_SILENCE_SOURCES | checks.CURSOR_BACKED_SOURCES
                 | checks.HUMAN_DRIVEN | checks.DEFAULT_JUDGED_SOURCES)
    declared_not_emitted = set(checks.DECLARED_NOT_EMITTED_SOURCES)
    unclassified = set(SOURCES) - classified

    assert unclassified == declared_not_emitted, (
        f"set(SOURCES) - classified e {sorted(unclassified)}, dar "
        f"DECLARED_NOT_EMITTED_SOURCES numește {sorted(declared_not_emitted)} "
        f"— orice sursă din Event.SOURCES trebuie fie clasificată (NAMED_"
        f"SILENCE_SOURCES / CURSOR_BACKED_SOURCES / HUMAN_DRIVEN / DEFAULT_"
        f"JUDGED_SOURCES), fie numită cu motiv în DECLARED_NOT_EMITTED_"
        f"SOURCES — o sursă care cade prin amândouă e exact punctul orb în "
        f"care a picat nginx până pe 23 sep 2026")

    # Verificare încrucișată, deliberat slabă (vezi docstring): un `source=`
    # literal găsit într-un colector trebuie să fie un membru real al
    # `SOURCES`. Nu încearcă să vadă toate formele de sintaxă — cele pe care
    # nu le vede sunt pur și simplu absente din `found`, iar asta nu schimbă
    # nimic din verificarea de mai sus.
    collectors_dir = (Path(__file__).resolve().parents[2]
                      / "sentinel" / "collectors")
    found: set[str] = set()
    for path in sorted(collectors_dir.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and getattr(node.func, "id", None) == "Event"):
                continue
            for kw in node.keywords:
                if (kw.arg == "source" and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)):
                    found.add(kw.value.value)

    # Garda gărzii: dacă expresia de mai sus încetează să vadă `Event(source=…)`,
    # bucla de mai jos rulează pe o mulțime goală și n-ar mai verifica nimic —
    # exact tiparul „listă parametrizată ieșită goală și sărită tăcut” din
    # CLAUDE.md. Scanarea de aici NU e sursa de adevăr pentru clasificare (vezi
    # docstring), dar tot trebuie să găsească ceva ca să dovedească măcar că
    # citește fișierele corecte.
    assert found, "scanarea n-a găsit niciun `Event(source=…)` — verifică expresia AST"
    assert found <= set(SOURCES), (
        f"{sorted(found - set(SOURCES))} apare ca `source=` literal într-un "
        f"colector, dar nu e pe `SOURCES` în sentinel/model/event.py — orice "
        f"eveniment real de la sursa asta ridică ValueError la rulare")


def test_no_events_at_all_is_reported():
    """Zero rânduri în 30 de zile e o pană totală de colectare, și trebuie spusă.

    Căutat pe CHEIE, nu pe poziția din listă: verdictele judecate pe cursor sunt
    produse înaintea acestei ramuri (ca să supraviețuiască ei), deci `results[0]`
    nu mai e `ingest:any`. O aserțiune pe poziție ar fi trecut verde peste
    dispariția ramurii.
    """
    db = _DB(rows=[])
    results = run(checks.check_ingest_sources(db, _cfg()))
    any_key = next(r for r in results if r.key == "ingest:any")
    assert any_key.status == "down"


# --- the firewall table has to actually exist ------------------------------
def test_a_missing_nftables_table_is_down(monkeypatch):
    """The other real outage: Sentinel recorded seven active blocks and the
    kernel held none, for a day, with nothing said."""
    monkeypatch.setattr(checks, "_nft_table_present", lambda: (False, "absentă"))
    results = run(checks.check_enforcement(_DB(val=7), _cfg()))
    assert results[0].status == "down"
    assert "Nicio blocare nu are efect" in results[0].detail
    assert "force-step 29" in results[0].action


def test_kernel_and_database_disagreement_is_reported(monkeypatch):
    monkeypatch.setattr(checks, "_nft_table_present", lambda: (True, "table inet sentinel {}"))
    from sentinel.respond import actions
    monkeypatch.setattr(actions, "live_count", _async(0))
    results = run(checks.check_enforcement(_DB(val=7), _cfg()))
    count = next(r for r in results if r.key == "nft:count")
    assert count.status == "degraded"
    assert "7 în bază · 0 în nftables" in count.detail


def test_agreement_is_ok(monkeypatch):
    monkeypatch.setattr(checks, "_nft_table_present", lambda: (True, "table inet sentinel {}"))
    from sentinel.respond import actions
    monkeypatch.setattr(actions, "live_count", _async(7))
    results = run(checks.check_enforcement(_DB(val=7), _cfg()))
    assert next(r for r in results if r.key == "nft:count").status == "ok"


# Aici a stat `test_the_admin_address_missing_from_the_allowlist_is_flagged`,
# cu docstring-ul „The anti-lockout invariant, checked rather than assumed."
# Era presupus: verificarea citea `cfg.response.admin_ip`, câmp pe care
# `ResponseConfig` nu-l are, deci cheia `nft:allowlist` nu s-a emis niciodată în
# producție. Testul trecea fiindcă își fabrica un `SimpleNamespace(admin_ip=…)`
# pe care `Config`-ul real nu-l poate produce — un test verde peste cod mort,
# exact tiparul „aserțiune pe prezența unui nume, nu pe decizia luată din el".
#
# Verificarea a fost scoasă (vezi comentariul din `check_enforcement`), deci și
# testul. Testul de mai jos păzește ce a mai rămas: că un `Config` real chiar nu
# poate produce cheia — ca nimeni să nu reintroducă garda fără câmp.
def test_no_check_reads_a_config_field_that_does_not_exist():
    """Un `getattr(cfg.x, "y", None)` pe un câmp inexistent nu dă eroare: dă
    `None`, iar verificarea din spatele lui nu rulează niciodată. Așa a stat
    invariantul anti-lockout, nerulat și necontestat, cu un test verde peste el.

    Fiecare câmp de configurație citit de verificări trebuie să existe pe
    dataclass-ul real, nu doar pe obiectul fabricat de teste.

    Expresia s-a uitat până pe 15 august 2026 DOAR la `getattr(cfg.response, …)`.
    Consecința era cea obișnuită pentru o gardă îngustă: singura linie din
    `checks.py` care se potrivea cu tiparul păzit — `getattr(getattr(cfg,
    "beacon", None), "enabled", False)`, în `check_units` — era exact cea la care
    testul nu se uita. Acum se caută ambele forme, pe orice secțiune.
    """
    import inspect

    from sentinel.config import Config, ResponseConfig

    src = inspect.getsource(checks)
    cfg = Config()

    SECTIUNE = r"getattr\(\s*cfg\s*,\s*[\"'](\w+)[\"']"
    CAMP = r"getattr\(\s*cfg\.(\w+)\s*,\s*[\"'](\w+)[\"']"

    # Garda gărzii, și e obligatorie aici: azi `checks.py` nu mai are niciun
    # `getattr` pe `cfg`, deci ambele bucle de mai jos sunt goale. O expresie
    # stricată ar găsi tot nimic, buclele s-ar sări la fel, și testul ar trece
    # verde uitându-se la nimic — chiar tiparul „listă parametrizată ieșită goală
    # și sărită tăcut" din CLAUDE.md. Măsurat: mutația care strică expresia
    # trecea VERDE fără proba asta.
    #
    # Proba e o sursă fabricată care conține exact cele două forme. Dacă
    # expresiile încetează să le vadă, se vede aici, indiferent ce conține
    # `checks.py`.
    proba = ('if not getattr(cfg, "beacon", None):\n'
             '    x = getattr(cfg.response, "admin_ip", None)\n')
    assert re.findall(SECTIUNE, proba) == ["beacon"], \
        "expresia pentru `getattr(cfg, \"<secțiune>\")` nu mai vede forma"
    assert re.findall(CAMP, proba) == [("response", "admin_ip")], \
        "expresia pentru `getattr(cfg.<secțiune>, \"<câmp>\")` nu mai vede forma"

    # `getattr(cfg, "<secțiune>", …)` — secțiunea trebuie să existe pe `Config`.
    sectiuni = re.findall(SECTIUNE, src)
    for name in sectiuni:
        assert hasattr(cfg, name), (
            f"o verificare citește cfg.{name} printr-un getattr cu valoare de "
            f"rezervă, iar `Config` n-are secțiunea asta — deci rezerva e ce se "
            f"folosește, la fiecare rulare, tăcut")

    # `getattr(cfg.<secțiune>, "<câmp>", …)` — câmpul trebuie să existe pe ea.
    campuri = re.findall(CAMP, src)
    for sectiune, attr in campuri:
        assert hasattr(cfg, sectiune), f"cfg.{sectiune} nu există"
        assert hasattr(getattr(cfg, sectiune), attr), (
            f"o verificare citește {sectiune}.{attr}, care nu există pe "
            f"dataclass-ul real — verificarea din spatele lui nu rulează niciodată")

    # Numărul măsurat, ca lista să nu poată ieși goală în tăcere: o expresie
    # stricată n-ar mai găsi nimic, buclele de mai sus s-ar sări, iar testul ar
    # trece verde fără să se fi uitat la nimic. Exact felul de test care a costat
    # deja o pană aici. Azi `checks.py` nu mai are niciun `getattr` pe `cfg`;
    # dacă apare unul, numărul se ridică ODATĂ cu el.
    assert len(sectiuni) + len(campuri) == 0, (
        f"au apărut {len(sectiuni) + len(campuri)} citiri prin getattr pe `cfg` "
        f"({sectiuni}, {campuri}). Nu sunt interzise, dar numărul de aici e o "
        f"măsurătoare: ridică-l odată cu ele, ca bucla să nu se poată goli tăcut")

    # Și câmpul mort anume, ca reintroducerea lui să pice aici.
    assert not hasattr(ResponseConfig(), "admin_ip"), \
        "admin_ip a fost adăugat — atunci verificarea allowlist trebuie rescrisă și testată"
    assert hasattr(cfg, "response")


# --- the detection loop -----------------------------------------------------
def test_a_stalled_detector_is_down():
    """Ingesting into a table nobody reads is a convincing imitation of working:
    the event count rises and no incident is ever raised."""
    db = _DB(row={"cursor": "1", "updated_at": NOW, "minute": 90})
    assert run(checks.check_detection_loop(db))[0].status == "down"


def test_a_recent_detector_is_ok():
    db = _DB(row={"cursor": "1", "updated_at": NOW, "minute": 2})
    assert run(checks.check_detection_loop(db))[0].status == "ok"


# --- the alerting channel itself -------------------------------------------
def test_a_stopped_bot_is_down(monkeypatch):
    """If this is broken, nothing else the self-check finds can reach anyone."""
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "failed")
    result = run(checks.check_alerting(_DB(val=0), _cfg()))[0]
    assert result.status == "down"
    assert "nicio alertă nu poate ajunge" in result.detail


class _QueueDB:
    """O bază care răspunde separat la cele două întrebări ale lui `check_alerting`.

    `_DB` întoarce aceleași rânduri la orice `fetch`, iar verificarea face acum
    două citiri diferite — coada și preferințele de liniște. Un dublu care le
    confundă ar fi răspuns la a doua cu rânduri de notificări, adică ar fi picat
    dintr-un motiv care n-are nicio legătură cu ce se testează.

    Dublul APLICĂ predicatele din `WHERE`, nu le ignoră. Fără asta, instrucțiunea
    nu se execută nicăieri în suită: `AND channel = 'telegram'` și
    `AND enqueued_at < now() - interval '10 minutes'` puteau fi șterse amândouă
    cu suita verde, deși pe prima se sprijină explicit motivarea scrisă în
    `check_alerting` („`channel` filtrează exact rândurile pe care le golește
    `_push_notifications`"). Cheile din `_WHERE` sunt chiar TEXTUL căutat în
    SQL-ul trimis: o clauză scoasă din `checks.py` face dublul să nu mai
    filtreze, rândul nepotrivit intră în număr, iar testele care îl exclud pică.
    Scrisă altfel, într-o clauză rescrisă de mână aici, ar fi fost a doua copie a
    aceleiași reguli — și tot verde.
    """

    _WHERE = {
        "channel = 'telegram'": lambda g: g["channel"] == "telegram",
        "enqueued_at < now() - interval '10 minutes'": lambda g: g["age_min"] > 10,
    }

    def __init__(self, groups=None, prefs=None, prefs_error=None, queue_error=None):
        self._groups = groups or []
        self._prefs = prefs or []
        self._prefs_error = prefs_error
        self._queue_error = queue_error
        self.sql: list[str] = []

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        if "FROM notifications" in sql:
            if self._queue_error:
                raise self._queue_error
            trecute = [g for g in self._groups
                       if all(pred(g) for text, pred in self._WHERE.items()
                              if text in sql)]
            # Numai coloanele pe care le proiectează `SELECT`: `channel` și
            # vechimea sunt intrări ale filtrului, nu răspuns pentru verificare.
            return [{k: g[k] for k in ("severity", "kind", "tried", "n")}
                    for g in trecute]
        if "telegram_chats" in sql:
            if self._prefs_error:
                raise self._prefs_error
            return self._prefs
        return []


def _grp(n=1, severity="high", kind="selfcheck", tried=False,
         channel="telegram", age_min=30):
    """Un grup din coadă, plus cele două câmpuri pe care le citește `WHERE`-ul.

    Valorile implicite sunt cele care TREC filtrul, ca toate testele scrise
    înaintea lui să însemne exact ce însemnau.
    """
    return {"severity": severity, "kind": kind, "tried": tried, "n": n,
            "channel": channel, "age_min": age_min}


def _chat(chat_id=1, quiet_hours=None, muted_until=None, timezone_name=None):
    """Un rând din `telegram_chats`, în forma pe care o citește `all_prefs`."""
    return {"chat_id": chat_id, "quiet_hours": quiet_hours,
            "muted_until": muted_until, "timezone": timezone_name,
            "quiet_set_at": None}


# Fereastra măsurată pe gazdă pe 28 august 2026: `21:00-09:00`, fusul chat-ului.
NIGHT = "21:00-09:00"


def _at(local_hhmm: str, monkeypatch):
    """Fixează ceasul verificării la o oră LOCALĂ din fusul chat-ului."""
    from zoneinfo import ZoneInfo

    h, m = (int(x) for x in local_hhmm.split(":"))
    moment = datetime(2026, 8, 27, h, m, tzinfo=ZoneInfo("Europe/Bucharest"))

    class _Clock(datetime):
        @classmethod
        def now(cls, tz_=None):
            return moment.astimezone(tz_) if tz_ else moment

    monkeypatch.setattr(checks, "datetime", _Clock)


def test_a_running_bot_that_delivers_nothing_is_degraded(monkeypatch):
    """Running and failing to send is the same outcome as stopped.

    `attempts > 0` înseamnă că expeditorul a încercat și rândul e tot în coadă.
    Nicio fereastră de liniște nu explică asta.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    db = _QueueDB(groups=[_grp(n=12, tried=True)])
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "degraded"
    assert result.facts["blocked"] == 12


def test_a_queued_row_on_another_channel_is_not_the_telegram_channel_s_fault(monkeypatch):
    """`AND channel = 'telegram'` — verificarea răspunde despre UN canal.

    `notifications` e coada tuturor canalelor. Azi fiecare rând de pe gazdă e
    `telegram`, deci clauza nu schimbă nimic observabil — dar în ziua în care se
    adaugă al doilea canal, fără ea o coadă de e-mail nelivrată ar fi raportată
    ca „Telegram nu mai livrează", cu `journalctl -u sentinel-telegram` ca
    acțiune sugerată. Operatorul ar căuta ore întregi în serviciul sănătos.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    db = _QueueDB(groups=[_grp(n=12, tried=True, channel="email")])
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "ok", result.detail
    assert result.facts == {"blocked": 0, "held": 0}


def test_a_row_enqueued_a_minute_ago_is_not_a_stuck_queue(monkeypatch):
    """`AND enqueued_at < now() - interval '10 minutes'` — pragul, nu decorul.

    Expeditorul golește coada la interval; un rând pus acolo acum o clipă e
    normalul, nu o defecțiune. Fără prag, fiecare rulare care prinde coada în
    lucru ar raporta „mesaje care trebuiau trimise stau de peste 10 minute" —
    un canal care se plânge de propria funcționare, adică exact alarma falsă
    repetată care duce la oprirea lui.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    db = _QueueDB(groups=[_grp(n=12, tried=True, age_min=1)])
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "ok", result.detail
    assert result.facts == {"blocked": 0, "held": 0}


def test_a_message_held_by_quiet_hours_is_not_reported_as_blocked(monkeypatch):
    """Constatarea falsă din fiecare noapte, și bucla care se hrănea singură.

    Pe gazdă, chat-ul avea `21:00-09:00`. Șase mesaje `selfcheck` cu
    `attempts = 0` stăteau în coadă între 22:53 și 07:04, ținute de fereastră
    exact cum spune `_push_notifications` că trebuie ținute — iar trei dintre
    ele erau chiar alerta „notificări blocate în coadă". Numărate, verificarea
    raporta în fiecare noapte că nu mai ajunge nimic la operator, apoi punea
    raportul ăla în aceeași coadă și îl număra data viitoare.

    Un operator care primește asta 200 de nopți la rând oprește canalul.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    _at("23:30", monkeypatch)
    db = _QueueDB(groups=[_grp(n=6, severity="high", kind="selfcheck")],
                  prefs=[_chat(1, quiet_hours=NIGHT, timezone_name="Europe/Bucharest")])
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "ok", result.detail
    assert result.facts == {"blocked": 0, "held": 6}
    # Și se SPUNE, ca „activ" să nu acopere o coadă care chiar are ceva în ea.
    assert "6 mesaje ținute" in result.detail


def test_a_never_muted_message_still_in_the_queue_IS_blocked(monkeypatch):
    """Scutirea de la liniște nu e o scuză de a rămâne în coadă.

    Un `login` — „cineva tocmai a intrat pe server" — trece prin orice fereastră
    prin construcție. Dacă unul e tot `queued` după zece minute, nu-l ține
    liniștea: îl ține o defecțiune, iar aia e chiar vestea pe care operatorul
    trebuie s-o primească.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    _at("23:30", monkeypatch)
    db = _QueueDB(groups=[_grp(n=1, severity="high", kind="login")],
                  prefs=[_chat(1, quiet_hours=NIGHT, timezone_name="Europe/Bucharest")])
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "degraded"
    assert result.facts["blocked"] == 1


def test_a_critical_message_still_in_the_queue_IS_blocked(monkeypatch):
    """A doua jumătate a scutirii: severitatea, nu felul.

    `NEVER_MUTED_SEVERITIES` e ce duce mai departe „o parte din Sentinel s-a
    oprit" în timpul ferestrei. Ținut acolo, ar fi exact vestea care nu are voie
    să aștepte până la 09:00.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    _at("23:30", monkeypatch)
    db = _QueueDB(groups=[_grp(n=2, severity="critical", kind="selfcheck")],
                  prefs=[_chat(1, quiet_hours=NIGHT, timezone_name="Europe/Bucharest")])
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "degraded"
    assert result.facts["blocked"] == 2


def test_outside_the_quiet_window_everything_old_still_counts(monkeypatch):
    """Reparația nu are voie să orbească verificarea ziua.

    La 10:00, cu fereastra `21:00-09:00` încheiată, un mesaj de zece minute în
    coadă înseamnă că bucla de golire nu mai rulează. Aia e defecțiunea pentru
    care există verificarea, și trebuie să se vadă exact ca înainte.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    _at("10:00", monkeypatch)
    db = _QueueDB(groups=[_grp(n=6, severity="high", kind="selfcheck")],
                  prefs=[_chat(1, quiet_hours=NIGHT, timezone_name="Europe/Bucharest")])
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "degraded"
    assert result.facts == {"blocked": 6, "held": 0}


def test_quiet_hours_do_not_excuse_a_message_the_sender_already_tried(monkeypatch):
    """Noaptea, un rând cu `attempts > 0` e tot blocat.

    Ținerea nu atinge `attempts` — asta scrie `_push_notifications`, și pe asta
    se sprijină deosebirea. Dacă fereastra ar acoperi și rândurile încercate, o
    livrare care eșuează toată noaptea ar fi raportată ca liniște.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    _at("23:30", monkeypatch)
    db = _QueueDB(groups=[_grp(n=3, kind="selfcheck", tried=True),
                          _grp(n=6, kind="selfcheck", tried=False)],
                  prefs=[_chat(1, quiet_hours=NIGHT, timezone_name="Europe/Bucharest")])
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "degraded"
    assert result.facts == {"blocked": 3, "held": 6}


def test_a_quiet_window_on_only_one_of_two_chats_holds_nothing(monkeypatch):
    """Dacă măcar un chat ascultă, mesajul pleacă la el.

    `_push_notifications` ține numai când TOATE chat-urile permise tac. O
    verificare care s-ar mulțumi cu „unul e pe mute" ar ierta o coadă care chiar
    nu se golește către cineva care aștepta.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    _at("23:30", monkeypatch)
    db = _QueueDB(groups=[_grp(n=4, kind="selfcheck")],
                  prefs=[_chat(1, quiet_hours=NIGHT, timezone_name="Europe/Bucharest")])
    result = run(checks.check_alerting(db, _cfg(
        telegram=SimpleNamespace(enabled=True, allowed_chat_ids=[1, 2],
                                 quiet_hours=None, timezone="Europe/Bucharest"))))[0]
    assert result.status == "degraded"
    assert result.facts["blocked"] == 4


def test_with_no_allowed_chat_a_full_queue_is_not_called_quiet(monkeypatch):
    """„Nu e nimeni de anunțat" nu e „e liniște".

    Fără niciun chat permis, expeditorul ține fiecare rând la nesfârșit — pentru
    el e alegerea bună, nu pierde alerta. Citit ca liniște de verificare, ar
    însemna un „canalul e activ" veșnic peste o coadă din care nu pleacă nimic
    către nimeni.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    _at("23:30", monkeypatch)
    db = _QueueDB(groups=[_grp(n=9, kind="selfcheck")], prefs=[])
    result = run(checks.check_alerting(db, _cfg(
        telegram=SimpleNamespace(enabled=True, allowed_chat_ids=[],
                                 quiet_hours=NIGHT, timezone="Europe/Bucharest"))))[0]
    assert result.status == "degraded"
    assert result.facts["blocked"] == 9


def test_a_chat_without_a_row_of_its_own_falls_back_to_the_deployment_window(monkeypatch):
    """Un chat care n-a folosit niciodată `/mute` tace tot după fereastra livrată.

    `telegram_chats` primește un rând abia la prima preferință. Dacă verificarea
    ar citi „fără rând" ca „fără liniște", mesajele ținute de fereastra din
    `sentinel.yaml` ar fi numărate ca blocate — aceeași alarmă falsă în fiecare
    noapte, doar pe altă cale.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    _at("23:30", monkeypatch)
    db = _QueueDB(groups=[_grp(n=6, kind="selfcheck")], prefs=[])
    result = run(checks.check_alerting(db, _cfg(
        telegram=SimpleNamespace(enabled=True, allowed_chat_ids=[1],
                                 quiet_hours=NIGHT, timezone="Europe/Bucharest"))))[0]
    assert result.status == "ok", result.detail
    assert result.facts == {"blocked": 0, "held": 6}


def test_a_message_held_by_an_adhoc_mute_is_not_reported_as_blocked(monkeypatch):
    """`/mute 2h` ține la fel de legitim ca fereastra recurentă.

    Operatorul care cere liniște pentru o oră de mentenanță nu trebuie să
    primească, la sfârșitul ei, o alertă care spune că mesajele lui erau
    blocate. Ar fi un canal care se plânge de exact ce i s-a cerut să facă.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    _at("12:00", monkeypatch)
    pana = datetime(2026, 8, 27, 13, 0, tzinfo=timezone.utc)
    db = _QueueDB(groups=[_grp(n=5, kind="selfcheck")],
                  prefs=[_chat(1, muted_until=pana)])
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "ok", result.detail
    assert result.facts == {"blocked": 0, "held": 5}


def test_unreadable_quiet_preferences_are_unknown_not_ok(monkeypatch):
    """Dacă nu se poate citi liniștea, nu se poate ști dacă e ținut sau blocat.

    „Nu știu" și „e în regulă" sunt stări diferite. Colapsate, o eroare de bază
    ar produce un canal raportat sănătos exact când nimeni nu mai poate spune
    dacă e.
    """
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    db = _QueueDB(groups=[_grp(n=6, kind="selfcheck")],
                  prefs_error=RuntimeError("relation telegram_chats does not exist"))
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "unknown"
    assert "liniște" in result.detail


def test_an_unreadable_queue_is_unknown_not_ok(monkeypatch):
    """Aceeași regulă pentru coada însăși: o citire care crapă nu e „activ"."""
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    db = _QueueDB(queue_error=RuntimeError("connection reset"))
    result = run(checks.check_alerting(db, _cfg()))[0]
    assert result.status == "unknown"


def test_the_check_does_not_write_its_own_quiet_hours_rule():
    """Două mecanisme de aceeași formă se despart tăcut.

    Regula de liniște e a lui `telegram/quiet.py`. Dacă verificarea ar începe
    să parseze singură ferestre sau să-și scrie propria listă de feluri scutite,
    cele două ar putea da răspunsuri diferite despre același mesaj, iar cel
    greșit ar fi mereu cel pe care nu-l testează nimeni.
    """
    import inspect
    import textwrap

    # Numai CODUL, fără docstring și fără comentarii: `ast.unparse` le lasă pe
    # amândouă afară. Altfel testul ar fi căzut pe propria explicație a deciziei
    # — o aserțiune despre proză, nu despre ce execută funcția, adică exact
    # felul de test care trece sau pică din motive greșite.
    fn = ast.parse(textwrap.dedent(inspect.getsource(checks.check_alerting))).body[0]
    corp = fn.body[1:] if isinstance(fn.body[0], ast.Expr) else fn.body
    cod = "\n".join(ast.unparse(n) for n in corp)

    assert "quiet" in cod, "proba a ieșit goală: nu s-a extras corpul funcției"
    for interzis in ("NEVER_MUTED", "parse_window", "parse_schedule", "Window("):
        assert interzis not in cod, (
            f"`check_alerting` conține `{interzis}` — liniștea e rescrisă aici, "
            f"deci există două reguli care se pot contrazice")
    for chemat in ("quiet.silent_chats", "quiet.all_silent", "quiet.passes_anyway"):
        assert chemat in cod, f"`{chemat}` nu mai e chemat; regula a fost copiată?"


def test_alert_telegram_is_deliberately_not_exempt_from_quiet_hours():
    """Decizia, ținută de un test ca să nu se schimbe din reflex.

    O alertă despre coadă călătorește PRIN coadă: fiecare cauză care o produce
    oprește și livrarea ei, deci scutirea de la liniște n-ar face-o să ajungă —
    ar trezi operatorul pentru o veste care tot nu pleacă. Cazul în care canalul
    chiar e orb e `down`, deci `critical`, deci trece prin
    `NEVER_MUTED_SEVERITIES`, iar `runner._announce` îl scoate pe lângă bot.

    Dacă cineva decide altfel, decizia se ia aici, nu prin adăugarea tăcută a
    unui șir într-o listă de siguranță ținută deliberat scurtă.
    """
    from sentinel.telegram import quiet

    assert "selfcheck" not in quiet.NEVER_MUTED_KINDS
    assert "alert:telegram" not in quiet.NEVER_MUTED_KINDS
    assert not quiet.passes_anyway("high", "selfcheck")
    # Jumătatea care TREBUIE să treacă trece în continuare.
    assert quiet.passes_anyway("critical", "selfcheck")


# --- isolation --------------------------------------------------------------
def test_a_crashing_check_does_not_stop_the_run(monkeypatch):
    """A self-check that goes quiet for the same reason everything else does is
    worthless. It has to report its own breakage."""
    async def _boom(db, cfg):
        raise RuntimeError("nft exploded")

    monkeypatch.setattr(checks, "CHECKS", (("enforcement", _boom),
                                           ("autonomy", checks.check_autonomy)))
    results = run(checks.run_all(_DB(), _cfg()))
    assert any(r.key == "selfcheck:enforcement" and r.status == "unknown" for r in results)
    assert any(r.key == "mode:autoblock" for r in results), "the run stopped early"


def test_worst_of_ranks_down_below_degraded():
    assert worst([CheckResult("a", "A", "ok"), CheckResult("b", "B", "down")]) == "down"
    assert worst([CheckResult("a", "A", "ok"), CheckResult("b", "B", "degraded")]) == "degraded"
    assert worst([CheckResult("a", "A", "ok")]) == "ok"
    assert worst([]) == "unknown"


# --- alerting policy --------------------------------------------------------
def test_the_alert_says_what_to_do():
    """A message that reports a fault without a next step is a message that
    turns into a support request."""
    from sentinel.selfcheck.runner import format_alert

    text = format_alert(
        [CheckResult("nft:table", "Tabela nftables lipsește", "down",
                     detail="absentă", action="deploy.sh --force-step 29")], [])
    assert "SENTINEL NU FUNCȚIONEAZĂ COMPLET" in text
    assert "force-step 29" in text


def test_degraded_alone_does_not_shout():
    from sentinel.selfcheck.runner import format_alert

    text = format_alert([CheckResult("x", "Ceva", "degraded", detail="d")], [])
    assert "NU FUNCȚIONEAZĂ COMPLET" not in text
    assert "degradat" in text


def test_recovery_is_announced():
    """Only telling people when things break trains them to assume the last
    message is still true."""
    from sentinel.selfcheck.runner import format_alert

    text = format_alert([], [CheckResult("x", "Colector sshd", "ok")])
    assert "Revenit la normal" in text and "Colector sshd" in text


def test_a_selfcheck_that_says_something_STOPPED_is_never_muted():
    """Jumatatea pentru care exista scutirea, si numai ea.

    Ținută până la 06:00, o veste care spune că o parte din agent s-a oprit ar
    face ca orele în care nu te uiți la telefon să fie exact orele în care nimeni
    nu se uită nici la server.

    `runner._announce` pune `critical` exact când vreun rezultat e `down`, deci
    severitatea POARTĂ deja distincția — nu mai e nevoie de o scutire pe fel.
    """
    from sentinel.telegram.quiet import passes_anyway

    assert passes_anyway("critical", "selfcheck"), (
        "o autoverificare care spune că ceva s-a OPRIT nu trece prin mute")


def test_a_selfcheck_that_only_says_DEGRADED_is_held():
    """Cealaltă jumătate, și motivul pentru care regula s-a îngustat.

    `degraded` înseamnă, prin definiția din `check_ship_lag`, „pe gazdă nu s-a
    oprit nimic; ce e în urmă e o copie din afara ei". Ținută sub scutirea făcută
    pentru o oprire reală, vestea aia a devenit exact ce scutirea voia să
    prevină: un canal care sună degeaba și pe care operatorul îl închide.

    Cerut de operator pe 24 august 2026, după câteva zile de „Sentinel
    funcționează degradat" primite în perioada de mute.

    Ținut NU e pierdut — vezi
    `test_a_held_notification_stays_queued_instead_of_being_marked_failed`.
    """
    from sentinel.telegram.quiet import passes_anyway

    assert not passes_anyway("high", "selfcheck"), (
        "un `degraded` trece prin mute, deci mute-ul nu înseamnă nimic pentru "
        "canalul care sună cel mai des")
    assert not passes_anyway(None, "selfcheck")


def test_a_dead_bot_escalates_to_a_direct_send():
    """A message about a dead bot, queued for that bot, is a message nobody
    reads. This is the only place in the codebase that sends outside the bot,
    and it exists because the alternative is silence that looks like health."""
    import inspect

    from sentinel.selfcheck import runner

    src = inspect.getsource(runner._announce)
    assert 'r.key.startswith("alert:")' in src
    assert "_send_direct" in src


def test_the_selfcheck_never_repairs_anything():
    """A self-check that fixes what it finds is one whose findings stop being
    read, and restarting a security daemon turns a visible fault into an
    intermittent one."""
    import ast
    from pathlib import Path

    # Checked at the CALL SITES, not by grepping for strings: the module is full
    # of `action="systemctl restart …"` telling the OPERATOR what to run, and a
    # text search cannot tell advice from execution.
    read_only_verbs = {"is-active", "show", "list", "status", "list-timers"}
    for name in ("checks.py", "runner.py"):
        path = (Path(__file__).resolve().parents[2] / "sentinel" / "selfcheck" / name)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            fname = getattr(fn, "id", None) or getattr(fn, "attr", None)
            if fname not in ("_systemctl", "run", "Popen", "check_output", "system"):
                continue
            literals = [a.value for a in ast.walk(node)
                        if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            for v in literals:
                assert v not in ("restart", "start", "stop", "reload", "enable",
                                 "disable", "add", "flush", "delete", "insert"), \
                    f"{name} executes a mutating command: {fname}({literals})"
            # `_systemctl` forwards *args, so where a verb IS given literally it
            # has to be one that only looks.
            if fname == "_systemctl" and literals:
                assert literals[0] in read_only_verbs, \
                    f"{name}: systemctl {literals[0]} is not read-only"


def _async(value):
    async def _f(*a, **k):
        return value
    return _f


# --- o constatare pe care nimeni n-o mai calculează -------------------------
#
# Pe 9 august 2026, la 07:00, toate sursele au tăcut și `ingest:all` s-a scris cu
# `down`. La 08:25 și-au revenit, deci verificarea a încetat s-o mai emită — și
# nimic nu împăca tabela de stare cu ce emisese rularea. Botul i-a arătat
# operatorului „🔴 Sentinel nu funcționează complet" încă 26 de ore, peste 317
# rulări verzi consecutive, cu vechimea rândului blocat prezentată drept durata
# unei pene.
#
# Testele de mai jos rulează scenariul real: cheia apare cu `down`, dispare din
# rularea următoare, iar operatorul trebuie să vadă verde. Și scenariul invers:
# aceeași cheie dispare fiindcă rularea s-a întrerupt, caz în care starea ei NU
# are voie să fie curățată.
class _StateDB:
    """`selfcheck_state` și `selfcheck_runs`, cât să se poată juca mai multe rulări.

    Reimplementează în Python semantica instrucțiunilor SQL — deci dovedește
    logica runner-ului, nu SQL-ul însuși. Ce nu poate arăta fișierul ăsta:
    dacă PostgreSQL acceptă `NOT (key = ANY($1::text[]))` și dacă migrația 0021
    se aplică. Alea se verifică pe o bază reală.
    """

    def __init__(self):
        self.state: dict[str, dict] = {}
        self.runs: list[dict] = []
        self.notifications: list[str] = []
        self.sql: list[tuple[str, tuple]] = []

    def _now(self):
        return datetime.now(timezone.utc)

    async def fetch(self, sql, *a):
        self.sql.append((sql, a))
        if "FROM selfcheck_state" in sql:
            return [dict(v) for v in self.state.values()]
        if "FROM selfcheck_runs" in sql:      # ORDER BY started_at DESC LIMIT 2
            return list(reversed(self.runs))[:2]
        return []

    async def fetchrow(self, sql, *a):
        self.sql.append((sql, a))
        if "FROM selfcheck_runs" in sql:
            return self.runs[-1] if self.runs else None
        if "FROM selfcheck_state" in sql:
            # `check_dashboard_latency` își recitește starea de dinainte, ca o
            # oscilație în jurul pragului să nu producă un mesaj la fiecare
            # trecere. Un dublu care ar întoarce mereu None ar face testul de
            # histerezis să treacă fără să atingă histerezisul.
            return self.state.get(a[0]) if a else None
        return None

    async def fetchval(self, sql, *a):
        self.sql.append((sql, a))
        return 0

    async def execute(self, sql, *a):
        self.sql.append((sql, a))
        if "INSERT INTO selfcheck_state" in sql:
            key, status, title, detail, _facts, keep_since = a
            old = self.state.get(key)
            self.state[key] = {
                "key": key, "status": status, "title": title, "detail": detail,
                "since": old["since"] if (old and keep_since) else self._now(),
                "last_seen": self._now(), "stale": False,
                "last_alert_at": old["last_alert_at"] if old else None,
            }
        elif "DELETE FROM selfcheck_state" in sql:
            keep = set(a[0])
            for key in [k for k in self.state if k not in keep]:
                del self.state[key]
        elif "UPDATE selfcheck_state SET stale" in sql:
            keep = set(a[0])
            for key, row in self.state.items():
                if key not in keep:
                    row["stale"] = True
        elif "UPDATE selfcheck_state SET last_alert_at" in sql:
            for key in a[0]:
                if key in self.state:
                    self.state[key]["last_alert_at"] = self._now()
        elif "INSERT INTO selfcheck_runs" in sql:
            duration_ms, worst_status, checks_run, checks_bad = a
            self.runs.append({
                "started_at": self._now(), "worst_status": worst_status,
                "checks_run": checks_run, "checks_bad": checks_bad,
                "duration_ms": duration_ms})
        elif "INSERT INTO notifications" in sql:
            self.notifications.append(a[-1])

    async def healthy(self):
        return True


def _outcome(results, failed=()):
    async def _run_groups(db, cfg):
        return checks.RunOutcome(list(results), tuple(failed))
    return _run_groups


_LIVE = CheckResult("ingest:suricata", "Colector „suricata”", "ok",
                    detail="ultimul eveniment acum 1 min")
_ALL_QUIET = CheckResult("ingest:all", "Toate sursele au amuțit", "down",
                         detail="cea mai recentă acum 94 min")


def _panel(db) -> str:
    """Ce vede operatorul la /selfcheck, din aceleași rânduri."""
    pytest.importorskip("telegram")
    from types import SimpleNamespace as NS

    from sentinel.telegram import views

    sent: list[str] = []

    class _Msg:
        async def reply_text(self, text, **kw):
            sent.append(text)

    msg = _Msg()
    run(views.cmd_selfcheck(NS(effective_message=msg, message=msg),
                            NS(bot_data={"db": db}, args=[])))
    return sent[0]


def test_a_finding_the_check_stopped_producing_stops_being_red(monkeypatch):
    """Scenariul real, cap-coadă.

    O cheie condiționată apare cu `down`, condiția dispare, deci verificarea nu
    o mai emite. Fără reconciliere rândul rămâne `down` pentru totdeauna și
    panoul îi spune operatorului că agentul de securitate e stricat, cât timp
    nimeni nu șterge rândul cu mâna. A durat 26 de ore și 317 rulări verzi.
    """
    from sentinel.selfcheck import runner

    db = _StateDB()

    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))
    assert db.state["ingest:all"]["status"] == "down"
    assert "nu funcționează complet" in _panel(db)

    # Sursele revin: verificarea nu mai are ce emite pentru cheia asta.
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE]))
    run(runner.run_and_alert(db, _cfg()))
    assert "ingest:all" not in db.state, "restul rămâne și ține panoul roșu"

    # A treia rulare: operatorul vede verde.
    summary = run(runner.run_and_alert(db, _cfg()))
    assert summary["worst"] == "ok"
    panel = _panel(db)
    assert "Totul funcționează" in panel
    assert "Toate sursele au amuțit" not in panel


def test_a_key_that_disappears_because_a_feature_was_turned_off_recovers_too(monkeypatch):
    """`ingest:all` a fost prinsă fiindcă a ținut 26 de ore. Una care se stinge
    repede ar fi invizibilă — de exemplu `unit:sentinel-ai.service`.

    `check_units` sare peste unitatea AI când `ai.enabled` e fals. Ordinea reală
    care doare: unitatea intră în `down`, operatorul dezactivează stratul AI ca
    să oprească zgomotul, cheia nu se mai emite — și panoul rămâne roșu pentru o
    unitate pe care nimeni n-o mai pornește, la nesfârșit."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    other = CheckResult("unit:sentinel-web.service", "Serviciul sentinel-web", "ok")
    ai_down = CheckResult("unit:sentinel-ai.service", "Serviciul sentinel-ai",
                          "down", detail="stare: failed · reporniri: 12")

    monkeypatch.setattr(runner, "run_groups", _outcome([other, ai_down]))
    run(runner.run_and_alert(db, _cfg()))
    assert "nu funcționează complet" in _panel(db)

    # `ai.enabled = false` — check_units nu mai emite cheia deloc.
    monkeypatch.setattr(runner, "run_groups", _outcome([other]))
    run(runner.run_and_alert(db, _cfg()))
    assert "unit:sentinel-ai.service" not in db.state
    assert "Totul funcționează" in _panel(db)


# --- verificări care nu emit nimic când n-au putut să se uite ---------------
def test_an_unreadable_install_tree_is_unknown_not_silence(monkeypatch, tmp_path):
    """`step_package` din install.sh face `rm -rf` apoi `cp -r`, iar timerul de
    autoverificare bate la 5 minute în tot acest timp. `rglob("*.py")` poate ieși
    gol sau poate cursa un fișier care dispare.

    Verificarea returna `[]` — nicio cheie, nicio excepție — deci rularea se
    raporta COMPLETĂ, iar runner-ul ștergea constatarea `code:current` și îi
    spunea operatorului că nu se mai raportează. Constatarea aia e „servicii
    rulează cod vechi", adevărată tocmai în minutele din jurul unei instalări."""
    lib = tmp_path / "lib" / "sentinel"
    lib.mkdir(parents=True)

    def _explode(*a, **k):
        raise OSError("No such file or directory")

    monkeypatch.setattr(checks.Path, "rglob", _explode)
    monkeypatch.setattr(checks, "Path", lambda *a: lib)

    results = run(checks.check_running_code_is_current(_StallDB()))
    assert [r.key for r in results] == ["code:current"]
    assert results[0].status == "unknown"
    assert not results[0].bad


def test_an_unreadable_proc_stat_is_unknown_not_silence(monkeypatch, tmp_path):
    """A doua ieșire tăcută din aceeași funcție, pe cealaltă ramură.

    Fără `btime` nu se poate converti momentul pornirii unui serviciu din
    monotonic în timp real, deci întrebarea „a pornit înainte sau după
    instalare?" n-are răspuns. Un `return []` aici raporta din nou o rulare
    completă fără cheia `code:current`, iar constatarea era ștearsă."""
    import builtins

    lib = tmp_path / "lib" / "sentinel"
    lib.mkdir(parents=True)
    (lib / "x.py").write_text("# cod", encoding="utf-8")
    monkeypatch.setattr(checks, "Path", lambda *a: lib)
    # Un serviciu chiar a pornit, deci bucla ajunge la citirea lui /proc/stat.
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "123456789")

    real_open = builtins.open

    def _no_proc(path, *a, **k):
        if str(path) == "/proc/stat":
            raise OSError("Permission denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", _no_proc)

    results = run(checks.check_running_code_is_current(_StallDB()))
    assert [r.key for r in results] == ["code:current"]
    assert results[0].status == "unknown"
    assert "/proc/stat" in results[0].detail


def test_a_missing_install_tree_stays_silent(monkeypatch, tmp_path):
    """Singura tăcere rămasă, și singura sigură: pe o gazdă fără arbore instalat
    cheia nu s-a emis niciodată, deci nu există constatare de retras."""
    monkeypatch.setattr(checks, "Path", lambda *a: tmp_path / "nu-exista")
    assert run(checks.check_running_code_is_current(_StallDB())) == []


def _stale_install(tmp_path, code_mtime=2_000_000.0):
    """Un arbore instalat al cărui `.py` are un mtime controlat de test."""
    import os

    lib = tmp_path / "lib" / "sentinel"
    lib.mkdir(parents=True)
    f = lib / "x.py"
    f.write_text("# cod", encoding="utf-8")
    os.utime(f, (code_mtime, code_mtime))
    return lib


def _patch_boot(monkeypatch, btime=1_000_000):
    """`/proc/stat` fals, cu `btime` controlat — restul fișierelor citite normal."""
    import builtins
    import io

    real_open = builtins.open

    def _fake_open(path, *a, **k):
        if str(path) == "/proc/stat":
            return io.StringIO(f"btime {btime}\n")
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", _fake_open)


def test_a_single_stale_look_is_not_yet_a_finding(monkeypatch, tmp_path):
    """Fereastra normală a unui deploy: pasul 24 copiază, pasul 32 repornește pe
    rând, iar autodiagnosticul poate bate ÎN mijlocul ei. O singură privire cu
    servicii stale nu are voie să sune — asta e exact alarma falsă măsurată pe
    n8n, de două ori într-o zi, cu toate cele șase servicii deja repornite la
    secunde după."""
    lib = _stale_install(tmp_path)
    monkeypatch.setattr(checks, "Path", lambda *a: lib)
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "5000000")  # 5s de la boot
    _patch_boot(monkeypatch)

    results = run(checks.check_running_code_is_current(_StallDB()))
    assert [r.key for r in results] == ["code:current"]
    assert results[0].status == "unknown", "prima privire a sunat ca o degradare"
    assert not results[0].bad
    assert results[0].facts["looks"] == 1


def test_a_second_consecutive_stale_look_is_the_finding(monkeypatch, tmp_path):
    """Ce prinde verificarea: un serviciu lăsat pe cod vechi RĂMÂNE așa la
    nesfârșit — nimic nu-l repornește singur. A doua privire consecutivă, pe
    ACEEAȘI instalare, e semnalul care desparte asta de un deploy obișnuit
    prins din mers; fereastra reală măsurată (sub 2 minute pe ambele gazde de
    producție) e de trei ori mai scurtă decât intervalul de 5 minute dintre
    două priviri, deci un deploy normal nu ajunge niciodată la a doua."""
    lib = _stale_install(tmp_path)
    monkeypatch.setattr(checks, "Path", lambda *a: lib)
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "5000000")
    _patch_boot(monkeypatch)

    db = _StallDB()
    first = run(checks.check_running_code_is_current(db))
    assert first[0].status == "unknown"

    second = run(checks.check_running_code_is_current(db))
    assert second[0].status == "degraded", "a doua privire la rând nu a fost prinsă"
    assert second[0].bad
    assert second[0].facts["looks"] == 2
    assert "systemctl restart" in second[0].action


def test_a_healthy_look_resets_the_stale_counter(monkeypatch, tmp_path):
    """Un deploy care se termină NU are voie să lase un contor pregătit —
    altfel următorul deploy obișnuit ar moșteni o privire străină și ar suna
    din prima lui privire reală, nu din a doua."""
    lib = _stale_install(tmp_path)
    monkeypatch.setattr(checks, "Path", lambda *a: lib)
    _patch_boot(monkeypatch)

    db = _StallDB()

    monkeypatch.setattr(checks, "_systemctl", lambda *a: "5000000")  # stale
    first = run(checks.check_running_code_is_current(db))
    assert first[0].status == "unknown"
    assert db.store["code:current:stale"]["events_seen"] == 1

    monkeypatch.setattr(checks, "_systemctl", lambda *a: "0")  # „nu a pornit”: sănătos
    healthy = run(checks.check_running_code_is_current(db))
    assert healthy[0].status == "ok"
    assert db.store["code:current:stale"]["events_seen"] == 0, (
        "revenirea la sănătos nu a resetat contorul")

    # A treia privire, din nou stale, pe ACEEAȘI instalare: dacă resetul de mai
    # sus n-a funcționat, asta ar veni deja „degraded" (a treia la rând).
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "5000000")
    third = run(checks.check_running_code_is_current(db))
    assert third[0].status == "unknown", "contorul nu s-a resetat cu adevărat"
    assert third[0].facts["looks"] == 1


def test_a_new_deploy_does_not_inherit_the_previous_ones_stale_look(monkeypatch, tmp_path):
    """Două instalări diferite pot cădea în aceeași fereastră de 5 minute — de
    exemplu o corecție rapidă trimisă imediat după alta. Fără să lege
    numărătoarea de instalarea CONCRETĂ (`code_mtime`), a doua ar moșteni
    privirea primeia și ar suna „degradat" din propria ei primă privire, pe
    propriul ei deploy transitoriu — exact alarma falsă pe care pragul de două
    priviri există s-o oprească, doar mutată pe alt deploy."""
    import os

    lib = _stale_install(tmp_path, code_mtime=2_000_000.0)
    monkeypatch.setattr(checks, "Path", lambda *a: lib)
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "5000000")
    _patch_boot(monkeypatch)

    db = _StallDB()
    first = run(checks.check_running_code_is_current(db))
    assert first[0].status == "unknown"

    # O instalare NOUĂ, în aceeași fereastră: fișierele au alt mtime.
    os.utime(lib / "x.py", (3_000_000.0, 3_000_000.0))

    second = run(checks.check_running_code_is_current(db))
    assert second[0].status == "unknown", (
        "a doua instalare a moștenit numărătoarea primeia")
    assert second[0].facts["looks"] == 1


def test_the_stale_look_counter_survives_a_selfcheck_restart(monkeypatch, tmp_path):
    """Contorul stă în `collector_cursors`, nu în memoria procesului — la fel ca
    `ship:<flux>:stall` și `BEACON_REFUSALS_BEFORE_FINDING`. Dacă ar fi ținut
    într-o variabilă locală, o repornire a `sentinel-selfcheck` exact între cele
    două priviri ar uita prima și n-ar mai escalada niciodată o instalare care
    chiar a rămas blocată peste o repornire de-astea."""
    lib = _stale_install(tmp_path)
    monkeypatch.setattr(checks, "Path", lambda *a: lib)
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "5000000")
    _patch_boot(monkeypatch)

    db1 = _StallDB()
    first = run(checks.check_running_code_is_current(db1))
    assert first[0].status == "unknown"

    # „Procesul repornește": un client nou, aceeași bază de date dedesubt.
    db2 = _StallDB()
    db2.store = db1.store
    second = run(checks.check_running_code_is_current(db2))
    assert second[0].status == "degraded", (
        "contorul nu a supraviețuit peste o repornire a procesului")


def test_an_unreadable_ruleset_still_reports_the_blocklist_comparison(monkeypatch):
    """Aceeași regulă, celălalt loc unde se aplica: când regulile nftables nu se
    pot citi, `check_enforcement` ieșea devreme și nu mai emitea `nft:count`.

    Rularea rămâne completă (nimeni n-a ridicat), deci o constatare adevărată —
    „blocklistul din bază nu corespunde cu kernelul" — era ștearsă fiindcă
    verificarea n-a putut să se uite."""
    monkeypatch.setattr(checks, "_nft_table_present",
                        lambda: (None, "Operation not permitted"))
    monkeypatch.setenv("INVOCATION_ID", "test")
    results = run(checks.check_enforcement(_DB(val=7), _cfg()))
    keys = {r.key for r in results}
    assert keys == {"nft:table", "nft:count"}
    assert all(r.status == "unknown" for r in results)
    assert all(not r.bad for r in results)


def test_the_operator_is_told_the_red_line_is_gone(monkeypatch):
    """Operatorul a primit „🔴 Toate sursele au amuțit". Dacă nimeni nu-i spune
    că nu mai e cazul, ultimul mesaj rămâne adevărul lui — iar panoul, reparat,
    contrazice în tăcere alerta.

    Mesajul spune exact cât se știe: verificarea nu mai produce constatarea. Nu
    „revenit la normal" — o cheie poate dispărea și fiindcă verificarea nu o mai
    acoperă (o unitate dezactivată în config, o sursă ieșită din fereastra de 30
    de zile), iar diferența nu se poate stabili de aici."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))
    db.notifications.clear()

    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE]))
    summary = run(runner.run_and_alert(db, _cfg()))

    assert summary["withdrawn"] == ["ingest:all"]
    assert db.notifications, "nimeni nu i-a spus operatorului"
    text = db.notifications[-1]
    assert "Toate sursele au amuțit" in text
    # Subiectul e „Constatări", nu instanța: mesajul e trimis sub antetul
    # „Instanță: <nume>", iar o frază fără subiect propriu ("Nu se mai
    # raportează") citită imediat după acel antet se poate parsa ca despre
    # instanță, nu despre constatare — exact citirea greșită din 23 septembrie
    # 2026 (patru ore după o pană reală de 20 de ore).
    assert "Constatări care nu se mai raportează" in text
    assert "Revenit la normal" not in text, "afirmă mai mult decât se știe"


def test_the_withdrawal_heading_names_the_finding_not_the_instance():
    """Titlul retragerii era „⚪ Nu se mai raportează" — fără subiect propriu.

    Fiecare mesaj trimis de agentul ăsta e stampilat pe primul rând cu
    „Instanță: <nume>" (`sentinel/telegram/identity.py`). Citită imediat sub
    acel rând, o frază fără subiect propriu se leagă gramatical de el:
    „Instanță: productie … nu se mai raportează" citește ca „instanța nu se
    mai raportează" — exact opusul retragerii (care e despre o CONSTATARE, nu
    despre gazdă) și exact citirea pe care a dat-o operatorul pe 23 septembrie
    2026, patru ore după o pană reală de 20 de ore.

    Aserțiunea e pe mesajul ASAMBLAT de `format_alert`, lipit sub stampila de
    instanță așa cum ajunge la operator — nu pe o constantă din `runner.py`,
    ca reformularea să nu poată trece testul doar fiindcă cele două citesc
    aceeași sursă.

    O singură aserțiune, pe fraza întreagă și îngroșată — nu perechea
    negativă/pozitivă de dinainte ("Nu se mai raportează</b>" not in heading,
    "Constatări" in heading), care lăsa un gol între ele: negativa era legată
    de `</b>`, deci pica doar dacă titlul revenea EXACT la textul vechi, cu
    tot cu etichetă; pozitiva nu ținea deloc la formatare. O mutație care
    scoate doar `<b>…</b>` din titlu — subiectul „Constatări" rămâne, doar
    accentul vizual dispare — trecea nevăzută pe lângă amândouă: pozitiva o
    ignora, iar negativa nu mai găsea substring-ul ei (cu „Nu" cu literă mare,
    care oricum nu apare în textul curent — „nu" e cu literă mică). Aserțiunea
    de-acum verifică fraza întreagă, inclusiv `<b>`/`</b>`, deci prinde și
    pierderea subiectului, și pierderea formatării.
    """
    from sentinel.selfcheck import runner

    withdrawn = [{"key": "ship:lag:event_rollup_1h:stall",
                 "title": "Expedierea fluxului „event_rollup_1h” s-a înțepenit",
                 "status": "degraded", "since": None}]
    text = runner.format_alert(bad=[], recovered=[], state={}, withdrawn=withdrawn)
    stamped = "Instanță: productie (1c39ad90)\n\n" + text

    heading = next(l for l in stamped.splitlines() if "⚪" in l)
    assert "<b>Constatări care nu se mai raportează</b>" in heading, (
        f"titlul retragerii nu (mai) numește constatarea, cu accentul vizual pe "
        f"care îl au celelalte titluri din mesaj — citit sub stampila de "
        f"instanță pare o afirmație despre gazdă, nu despre constatare: "
        f"{heading!r}")


def test_a_withdrawn_ok_row_is_not_announced(monkeypatch):
    """Un rând care era deja verde și dispare nu e o veste. Un mesaj pentru
    fiecare non-eveniment e felul în care canalul ajunge să nu mai fie citit."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    extra = CheckResult("unit:sentinel-ai.service", "Serviciul sentinel-ai", "ok")
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, extra]))
    run(runner.run_and_alert(db, _cfg()))
    db.notifications.clear()

    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE]))
    summary = run(runner.run_and_alert(db, _cfg()))
    assert "unit:sentinel-ai.service" not in db.state
    assert summary["withdrawn"] == []
    assert not db.notifications


def test_an_interrupted_run_does_not_clean_up_state(monkeypatch):
    """Celălalt sens al aceleiași greșeli. O cheie poate lipsi dintr-o rulare și
    fiindcă grupul care o produce a crăpat — atunci ștergerea ar transforma o
    verificare stricată într-un buletin de sănătate curat. Exact schimbul pe
    care întreg pachetul ăsta există ca să-l împiedice."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))
    db.notifications.clear()

    # Grupul „ingest" crapă: nu emite nicio cheie a lui, doar propriul eșec.
    broken = CheckResult("selfcheck:ingest", "Verificarea „ingest” a eșuat", "unknown",
                         detail="connection reset")
    monkeypatch.setattr(runner, "run_groups", _outcome([broken], failed=("ingest",)))
    summary = run(runner.run_and_alert(db, _cfg()))

    assert "ingest:all" in db.state, "starea a fost curățată de o rulare incompletă"
    assert db.state["ingest:all"]["status"] == "down"
    assert db.state["ingest:all"]["stale"] is True
    assert summary["withdrawn"] == []
    assert summary["incomplete"] == ["ingest"]
    assert not db.notifications, "o rulare întreruptă nu anunță nicio revenire"


def test_a_kept_row_is_shown_as_a_finding_not_as_an_outage(monkeypatch):
    """„de 27h 54m" lângă un titlu care descrie o pană curentă se citește ca
    durata penei. Era vechimea rândului blocat.

    Un rând păstrat peste o rulare întreruptă e ultima constatare cunoscută, nu
    starea de acum, iar panoul trebuie să spună asta cu cuvinte."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))

    broken = CheckResult("selfcheck:ingest", "Verificarea „ingest” a eșuat", "unknown")
    monkeypatch.setattr(runner, "run_groups", _outcome([broken], failed=("ingest",)))
    run(runner.run_and_alert(db, _cfg()))

    panel = _panel(db)
    assert "Neevaluate la ultima rulare" in panel
    assert "constatare veche de" in panel
    assert "ultima constatare, nu starea de acum" in panel
    # Nu dispare din verdict: ultimul lucru știut e că era stricat.
    assert "nu funcționează complet" in panel
    # Iar verificarea care a crăpat e vizibilă, nu tăcută.
    assert "a eșuat" in panel


def test_the_next_complete_run_finally_clears_what_the_crash_preserved(monkeypatch):
    """Altfel „păstrează la rulare incompletă" ar fi doar o altă cale către un
    rând care nu moare niciodată."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))
    broken = CheckResult("selfcheck:ingest", "Verificarea „ingest” a eșuat", "unknown")
    monkeypatch.setattr(runner, "run_groups", _outcome([broken], failed=("ingest",)))
    run(runner.run_and_alert(db, _cfg()))
    assert db.state["ingest:all"]["stale"] is True

    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE]))
    run(runner.run_and_alert(db, _cfg()))
    assert "ingest:all" not in db.state
    assert "Totul funcționează" in _panel(db)


def test_a_run_that_produced_nothing_deletes_nothing(monkeypatch):
    """Zero rezultate nu e dovadă că totul e în regulă, e dovadă că nimic n-a
    rulat. Reconcilierea pe o listă goală ar goli toată tabela — versiunea cea
    mai zgomotoasă a bug-ului pe care fișierul ăsta îl repară."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))

    monkeypatch.setattr(runner, "run_groups", _outcome([]))
    run(runner.run_and_alert(db, _cfg()))
    assert set(db.state) == {"ingest:suricata", "ingest:all"}


def test_a_crashed_group_is_named_by_the_run(monkeypatch):
    """Reconcilierea se sprijină pe „rularea a văzut tot". Dacă `run_groups` ar
    raporta o rulare crăpată drept completă, ștergerea ar porni exact în cazul
    în care nu are voie."""
    async def _boom(db, cfg):
        raise RuntimeError("nft exploded")

    monkeypatch.setattr(checks, "CHECKS", (("enforcement", _boom),
                                           ("autonomy", checks.check_autonomy)))
    outcome = run(checks.run_groups(_DB(), _cfg()))
    assert outcome.failed_groups == ("enforcement",)
    assert outcome.complete is False
    assert any(r.key == "mode:autoblock" for r in outcome.results), "rularea s-a oprit"

    monkeypatch.setattr(checks, "CHECKS", (("autonomy", checks.check_autonomy),))
    assert run(checks.run_groups(_DB(), _cfg())).complete is True


def _service_log(monkeypatch, summary):
    """Rulează `sentinel selfcheck` cu un rezumat dat și întoarce (nivel, mesaj)."""
    from sentinel.services import selfcheck_service as svc

    class _FakeDB:
        def __init__(self, *a, **k):
            pass

        async def connect(self):
            pass

        async def close(self):
            pass

    async def _fake_run(db, cfg, *, quiet=False):
        return summary

    seen: list[tuple[str, str]] = []
    monkeypatch.setattr(svc, "get_config", lambda: _cfg())
    monkeypatch.setattr(svc, "Database", _FakeDB)
    monkeypatch.setattr(svc, "run_and_alert", _fake_run)
    monkeypatch.setattr(svc.log, "warning", lambda m, **k: seen.append(("warning", m)))
    monkeypatch.setattr(svc.log, "info", lambda m, **k: seen.append(("info", m)))
    run(svc._main(True, False))
    return seen


_CLEAN = {"worst": "ok", "checks": 33, "bad": [], "new": [], "recovered": [],
          "withdrawn": [], "incomplete": [], "duration_ms": 710}


def test_an_incomplete_run_is_not_logged_as_clean(monkeypatch):
    """O rulare în care un grup a crăpat nu găsește defecte fiindcă nu s-a
    uitat, iar `worst()` clasează `unknown` deasupra lui `degraded`, deci codul
    de ieșire e 0 și systemd e mulțumit.

    Se loga „selfcheck clean", la INFO — exact cuvântul pe care operatorul îl
    caută, pus pe singura rulare care n-a dovedit nimic, invizibilă la
    `journalctl -p warning`."""
    seen = _service_log(monkeypatch, {**_CLEAN, "worst": "unknown",
                                      "incomplete": ["enforcement"]})
    assert seen == [("warning", "selfcheck found problems")]


def test_a_complete_clean_run_is_still_logged_as_clean(monkeypatch):
    """Reversul: dacă ORICE rulare s-ar loga ca problemă, avertismentul n-ar mai
    însemna nimic."""
    assert _service_log(monkeypatch, _CLEAN) == [("info", "selfcheck clean")]


def test_a_timer_whose_state_cannot_be_read_stays_on_the_list(monkeypatch):
    """`systemctl` care nu răspunde (lipsă, eroare, timeout de 10s) returnează
    un șir gol. Verificarea sărea peste cheie — iar de când o cheie absentă
    dintr-o rulare completă e ștearsă, o singură sondă lentă ar retrage o
    constatare `down` și i-ar spune operatorului că nu mai e raportată.

    „Nu se știe" și „e bine" sunt stări diferite."""
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "")
    results = run(checks.check_timers(_cfg()))
    assert results, "timerele au dispărut din rulare"
    assert {r.status for r in results} == {"unknown"}
    assert all(not r.bad for r in results)
    assert "nu am putut citi" in results[0].detail


# --- watchdog:state -----------------------------------------------------
#
# `check_timers` above proves the timer keeps firing — it said "active"
# throughout the real outage this exists for. Measured on production,
# 4-7 September 2026: sentinel-watchdog.service ran every minute, the timer
# stayed active, and `save_state` still failed on every single pass because
# root had no write access into the state directory. Nothing here asked
# whether the state actually got written.
def test_uptime_seconds_reads_the_first_column_of_proc_uptime(monkeypatch):
    """Every test in this file that touches the boot-grace branch monkeypatches
    `_uptime_seconds()` itself, so a defect in its own body — reading the
    wrong column of `/proc/uptime` (column 1 is uptime, column 2 is idle
    time), or the wrong index entirely — would pass every one of them
    untouched. This is the one test against the function's real body: a fake
    two-column `/proc/uptime` line, asserting the value returned is uptime,
    not idle time."""
    import builtins
    import io

    real_open = builtins.open

    def _fake_open(path, *a, **k):
        if str(path) == "/proc/uptime":
            return io.StringIO("13291.52 26000.10\n")
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", _fake_open)

    assert checks._uptime_seconds() == 13291.52


def test_watchdog_state_ok_when_fresh(tmp_path, monkeypatch):
    """A state file the watchdog just wrote must read back healthy — this is
    what a working anti-lockout deadman looks like from the outside."""
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    state = tmp_path / "state.json"
    state.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(checks, "WATCHDOG_STATE_PATH", state)

    result = run(checks.check_watchdog_state())[0]
    assert result.status == "ok"


def test_watchdog_state_down_when_stale(tmp_path, monkeypatch):
    """A state file that has stopped changing while the timer keeps firing
    every 60s means `save_state` is failing on every run — the exact
    production defect, where the journal warning scrolled by for three days
    unread and nothing on the panel said so."""
    import os as _os
    import time as _time

    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    # A long-booted host: rules out the boot-grace branch below so this test
    # is exercising the ordinary staleness path, not a coincidence of
    # whatever uptime the machine running the suite happens to have.
    monkeypatch.setattr(checks, "_uptime_seconds", lambda: 999_999.0)
    state = tmp_path / "state.json"
    state.write_text("{}", encoding="utf-8")
    old = _time.time() - (checks.WATCHDOG_STATE_STALE_AFTER_MIN + 20) * 60
    _os.utime(state, (old, old))
    monkeypatch.setattr(checks, "WATCHDOG_STATE_PATH", state)

    result = run(checks.check_watchdog_state())[0]
    assert result.status == "down"
    assert "sentinel-watchdog" in result.action


def test_watchdog_state_down_when_missing_but_timer_active(tmp_path, monkeypatch):
    """A missing state file while the timer is active is the literal
    production shape: the installer's tmpfiles step never created (or never
    re-created, on an upgraded host) the directory root needs to write into."""
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    monkeypatch.setattr(checks, "_uptime_seconds", lambda: 999_999.0)
    monkeypatch.setattr(checks, "WATCHDOG_STATE_PATH", tmp_path / "missing" / "state.json")

    result = run(checks.check_watchdog_state())[0]
    assert result.status == "down"
    assert "tmpfiles" in result.action


def test_watchdog_state_says_nothing_when_the_timer_is_not_active(tmp_path, monkeypatch):
    """An uninstalled, stopped, or failed watchdog timer already has its own
    finding under `timer:sentinel-watchdog.timer` (`check_timers`, which reads
    the same `is-active` this check does) — this check has nothing to add
    about a unit that is not currently running, and must not invent a second,
    confusingly-worded alarm about a directory that was never going to be
    written to anyway.

    Falsifies the old `is-enabled` check: an operator can deliberately stop
    the timer (`systemctl stop sentinel-watchdog.timer`) while leaving it
    enabled for the next boot. `is-enabled` would still answer "enabled" and
    this check would report a misleading "directory probably not writable"
    for a watchdog that is simply not running right now on purpose.
    """
    def _fake_systemctl(*args):
        if args[0] == "is-enabled":
            return "enabled"
        if args[0] == "is-active":
            return "inactive"
        return ""

    monkeypatch.setattr(checks, "_systemctl", _fake_systemctl)
    monkeypatch.setattr(checks, "WATCHDOG_STATE_PATH", tmp_path / "missing" / "state.json")

    assert run(checks.check_watchdog_state()) == []


def test_watchdog_state_unknown_when_systemctl_does_not_answer(monkeypatch):
    """`systemctl` answering nothing is not evidence the watchdog is fine —
    the same discrimination `check_timers` already makes for this exact unit."""
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "")

    result = run(checks.check_watchdog_state())[0]
    assert result.status == "unknown"


def test_watchdog_state_path_is_read_from_the_watchdog_module_not_duplicated():
    """A path copied here by hand could drift from `watchdog.py`'s own
    default and nobody would notice until a real deploy disagreed with
    itself — the check would watch a file the watchdog never writes."""
    from pathlib import Path

    from sentinel.respond import watchdog

    assert checks.WATCHDOG_STATE_PATH == Path(watchdog._DEFAULT_STATE_FILE)


def test_watchdog_state_registered_in_the_run():
    """O verificare care nu e în `CHECKS` nu rulează niciodată — vezi
    `test_the_history_check_is_registered_in_the_run` pentru precedent.
    Fără ea, `check_watchdog_state` poate rămâne corect și testat, dar
    `sentinel selfcheck` nu-l cheamă niciodată, iar panoul nu vede tăcerea
    watchdog-ului nici măcar o dată."""
    assert "watchdog_state" in [nume for nume, _ in checks.CHECKS]


def test_watchdog_state_stays_unknown_freshly_after_boot_even_when_stale(tmp_path, monkeypatch):
    """A reboot after any downtime longer than the stale threshold leaves a
    state file that is genuinely old (from before the host went down) at the
    exact moment the first post-boot selfcheck runs — both timers share
    `OnBootSec=90`, so the watchdog may not have written yet. Reporting `down`
    here means every reboot pages the operator with a false alarm immediately
    followed by a recovery. Falsify by deleting the uptime read: the stale
    branch alone (proven by `test_watchdog_state_down_when_stale`) would fire
    unconditionally and this test would go red."""
    import os as _os
    import time as _time

    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    monkeypatch.setattr(checks, "_uptime_seconds", lambda: 45.0)  # well before OnBootSec=90
    state = tmp_path / "state.json"
    state.write_text("{}", encoding="utf-8")
    old = _time.time() - 3 * 60 * 60  # 3 hours old: from before a long downtime
    _os.utime(state, (old, old))
    monkeypatch.setattr(checks, "WATCHDOG_STATE_PATH", state)

    result = run(checks.check_watchdog_state())[0]
    assert result.status != "down", (
        "a stale state file within the post-boot grace window must not page "
        "the operator — the watchdog simply has not run yet"
    )


def test_watchdog_state_reports_down_once_past_the_boot_grace(tmp_path, monkeypatch):
    """The other half of the grace window: once the host has been up long
    enough that the watchdog has certainly had its chance to run
    (`WATCHDOG_STATE_STALE_AFTER_MIN + WATCHDOG_BOOT_GRACE_MIN` minutes), a
    stale file is a real fault again — the grace window must not swallow the
    production defect it exists next to."""
    import os as _os
    import time as _time

    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    grace_s = (checks.WATCHDOG_STATE_STALE_AFTER_MIN + checks.WATCHDOG_BOOT_GRACE_MIN) * 60
    monkeypatch.setattr(checks, "_uptime_seconds", lambda: grace_s + 60)
    state = tmp_path / "state.json"
    state.write_text("{}", encoding="utf-8")
    old = _time.time() - (checks.WATCHDOG_STATE_STALE_AFTER_MIN + 20) * 60
    _os.utime(state, (old, old))
    monkeypatch.setattr(checks, "WATCHDOG_STATE_PATH", state)

    result = run(checks.check_watchdog_state())[0]
    assert result.status == "down"


# --- the unit ---------------------------------------------------------------
def test_the_timer_starts_soon_after_boot():
    """Both real outages were post-reboot states. Waiting five minutes to learn
    the machine came back wrong is four minutes too many."""
    from pathlib import Path

    timer = (Path(__file__).resolve().parents[2] / "deploy" / "systemd"
             / "sentinel-selfcheck.timer").read_text(encoding="utf-8")
    assert "OnBootSec=" in timer
    assert "OnUnitActiveSec=5min" in timer


def test_the_unit_can_read_the_ruleset_but_not_change_it():
    """Reading nftables needs NET_ADMIN. Bounded to exactly that: changing the
    ruleset is the executor's job and nobody else's."""
    from pathlib import Path

    unit = (Path(__file__).resolve().parents[2] / "deploy" / "systemd"
            / "sentinel-selfcheck.service").read_text(encoding="utf-8")
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in unit
    assert "User=sentinel" in unit
    # Findings are not failures of this unit.
    assert "SuccessExitStatus=0 1 2" in unit


def test_the_anti_lockout_watchdog_was_left_alone():
    """It is root, dependency-free, and must stay tiny. Merging the self-check
    into it would make the one component that has to work when everything else
    has failed depend on everything else."""
    from pathlib import Path

    unit = (Path(__file__).resolve().parents[2] / "deploy" / "systemd"
            / "sentinel-watchdog.service").read_text(encoding="utf-8")
    assert "selfcheck" not in unit
    assert "User=root" in unit


def test_being_unable_to_read_the_ruleset_is_not_the_same_as_it_missing(monkeypatch):
    """Opposite conclusions. "Table missing" means the host is unprotected; "I
    was not allowed to look" means the check is broken. Reporting the first when
    the second is true is a false alarm about the most serious thing this file
    can say — and a channel that cries wolf about total loss of protection is a
    channel that stops being read."""
    monkeypatch.setattr(checks, "_nft_table_present",
                        lambda: (None, "Operation not permitted (you must be root)"))
    # Sub systemd, unde sfatul despre capabilitate e cel corect. Varianta
    # rulată manual e verificată separat, mai jos.
    monkeypatch.setenv("INVOCATION_ID", "test")
    result = run(checks.check_enforcement(_DB(val=0), _cfg()))[0]
    assert result.status == "unknown"
    assert "nu știu dacă blocarea funcționează" in result.detail
    assert "CAP_NET_ADMIN" in result.action


def test_a_service_running_older_code_than_is_installed_is_flagged(monkeypatch, tmp_path):
    """A deploy copies files; only a restart makes a process use them. When
    those come apart, the fix is on disk and the bug is in memory, and "is this
    fixed on the server?" has no answer you can trust.

    Found the hard way: the installer restarted two of six units."""
    import inspect

    src = inspect.getsource(checks.check_running_code_is_current)
    assert "ActiveEnterTimestampMonotonic" in src
    assert "systemctl restart" in src          # the action tells you the fix
    assert "code:current" in src


def test_the_installer_restarts_every_service():
    """Two of six is a partial upgrade that reports success."""
    from pathlib import Path

    install = (Path(__file__).resolve().parents[2] / "deploy"
               / "install.sh").read_text(encoding="utf-8")
    order = install.split("local -a order=(", 1)[1].split(")", 1)[0]
    for unit in ("sentinel-executor", "sentinel-web", "sentinel-ingest",
                 "sentinel-detect", "sentinel-telegram"):
        assert unit in order, f"{unit} is never restarted by a deploy"


# --- boot reconciliation ----------------------------------------------------
def test_reconcile_calls_block_with_the_signature_that_exists():
    """A keyword that does not exist raises at the moment it is needed — which
    for `--reapply` is after a reboot, when nobody is watching."""
    import inspect

    from sentinel.respond import actions, reconcile as rec

    params = inspect.signature(actions.block).parameters
    src = inspect.getsource(rec.reconcile)
    for kw in ("ttl=", "reason=", "by="):
        assert kw in src
        assert kw.rstrip("=") in params


def test_reconcile_corrects_the_database_not_the_kernel_by_default():
    """The kernel is the truth about what is blocked; after a reboot that truth
    is "nothing". Re-applying by default would quietly remove the escape hatch
    the whole design leans on."""
    import inspect

    from sentinel.respond import reconcile as rec

    src = inspect.getsource(rec.reconcile)
    # The default branch runs from `if not reapply:` to its own `return`.
    # Splitting on `for row in missing:` would not work — the default branch
    # opens with one of those too.
    default = src.split("if not reapply:", 1)[1].split("return result", 1)[0]
    assert "mark_unblocked" in default
    assert "actions.block" not in default


def test_the_release_is_written_down_with_a_reason():
    """An attacker who was blocked and is now not is a fact worth finding later."""
    import inspect

    from sentinel.respond import reconcile as rec

    assert "repornire" in inspect.getsource(rec.reconcile)


def test_the_executor_recreates_the_table_before_accepting_work():
    """Every block against a missing table fails. Recreating it after the socket
    opens would leave a window where blocking silently does nothing."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[2] / "executor"
           / "sentinel_executor.py").read_text(encoding="utf-8")
    body = src.split("def main(", 1)[1]
    assert body.index("ensure_table()") < body.index("socket.socket")


def test_the_executor_restores_the_allowlist_but_not_the_blocklist():
    """A table with drop rules and no allowlist is how you firewall your own
    address. A table WITH the blocklist restored is how a reboot stops being an
    escape from a self-inflicted block."""
    from pathlib import Path

    commands = (Path(__file__).resolve().parents[2] / "executor"
                / "commands.py").read_text(encoding="utf-8")
    body = commands.split("def ensure_table", 1)[1].split("\ndef ", 1)[0]
    assert "NFT_ALLOWLIST_FILE" in body
    # Strip the docstring as well as the comments: it EXPLAINS that blocks are
    # not restored, so a naive text search finds the word it is looking for in
    # the sentence promising the opposite.
    code = body.split('"""')[2] if body.count('"""') >= 2 else body
    code = "\n".join(l for l in code.splitlines() if not l.strip().startswith("#"))
    assert "blocklist" not in code.lower(), "the blocklist is being restored"


# --- un mesaj care nu trimite operatorul pe pistă greșită ------------------
def test_nft_check_distinguishes_a_hand_run_from_a_misconfigured_unit(monkeypatch):
    """Capabilitățile vin de la unitate, nu de la utilizator.

    `sudo -u sentinel sentinel selfcheck --print` nu primește CAP_NET_ADMIN
    oricât de corectă ar fi unitatea. Mesajul vechi trimitea operatorul să
    verifice un fișier care era deja bun — iar cine e trimis de două ori după
    un non-problem se oprește din citit ieșirea.
    """
    import asyncio as _a
    from types import SimpleNamespace
    from sentinel.selfcheck import checks as c

    monkeypatch.setattr(c, "_nft_table_present", lambda: (None, "Operation not permitted"))
    cfg = SimpleNamespace(response=SimpleNamespace(admin_ip=None))

    monkeypatch.delenv("INVOCATION_ID", raising=False)
    hand = _a.run(c.check_enforcement(None, cfg))[0]
    assert "Rulat manual" in hand.detail
    assert "systemctl start sentinel-selfcheck" in (hand.action or "")

    monkeypatch.setenv("INVOCATION_ID", "abc123")
    unit = _a.run(c.check_enforcement(_DB(val=0), _cfg()))[0]
    assert "Rulat manual" not in unit.detail
    assert "AmbientCapabilities" in (unit.action or "")

    # În ambele cazuri starea rămâne „nu știu" — a nu putea citi regulile NU e
    # o dovadă că blocarea funcționează.
    assert hand.status == unit.status == "unknown"


def test_a_direct_alert_telegram_refused_is_not_logged_as_delivered(monkeypatch, caplog):
    """The escalation path exists for the moment the bot is dead. Until now it
    logged "selfcheck alerted directly" after any POST that did not raise — so
    a 400 ("chat not found", "bot was blocked by the user") produced the same
    line as a delivered message.

    That is the last channel there is, reporting success it did not have. The
    operator would read one warning about a dead bot and believe they had been
    told; nothing else would ever mention it again.

    The fake asserts Telegram's contract: 200 + {"ok": true, "result":
    {"message_id": N}} is delivery, a 4xx with {"ok": false, "description": …}
    is not.
    """
    import asyncio as _a
    import logging

    import httpx

    from sentinel import config as config_mod
    from sentinel.config import Secrets
    from sentinel.selfcheck import runner

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode("utf-8")
        if '"chat_id": 222' in body or '"chat_id":222' in body:
            return httpx.Response(400, json={"ok": False,
                                             "description": "Bad Request: chat not found"})
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 3}})

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda **kw: real_client(transport=transport, **kw))
    monkeypatch.setattr(config_mod, "get_secrets",
                        lambda: Secrets({"TELEGRAM_BOT_TOKEN": "fixture-token"}))

    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=[111, 222]))
    with caplog.at_level(logging.INFO, logger="sentinel.selfcheck.runner"):
        _a.run(runner._send_direct(cfg, "botul nu răspunde"))

    levels = {r.levelno: r.getMessage() for r in caplog.records}
    assert logging.ERROR in levels, "the refused chat was never reported"
    assert "did not reach every chat" in levels[logging.ERROR]
    assert logging.WARNING in levels, "the chat that DID receive it went unreported"


# ---------------------------------------------------------------------------
# Filtrul de istoric: „configurat" și „în vigoare" sunt afirmații diferite
# ---------------------------------------------------------------------------
def _cu_uid(monkeypatch, uid_of):
    """Rezolvarea conturilor, cu o bază de conturi fabricată.

    Gazda de test nu are `sentinel-deploy` în `/etc/passwd`, iar pe Windows nu
    există `pwd` deloc — deci fără injecția asta testele ar proba platforma pe
    care rulează, nu decizia verificării.
    """
    from sentinel.config import resolve_skip_command_accounts as real

    monkeypatch.setattr(checks, "resolve_skip_command_accounts",
                        lambda n: real(n, uid_of=uid_of))


def _istoric(**over):
    """Un `cfg` cu secțiunea `history`, plus dublul de bază pentru efect."""
    return _cfg(history=SimpleNamespace(**over))


@pytest.fixture(autouse=True)
def _config_intr_un_loc_care_nu_exista(monkeypatch, tmp_path):
    """`sentinel.yaml.new` se caută lângă configurația încărcată.

    Pe o mașină pe care fișierul ăla chiar există — gazda —, testele care nu-l
    fabrică singure ar citi starea gazdei și ar pica sau ar trece în funcție de
    ea. Toate pornesc de la „nu există", iar cine are nevoie de el îl scrie.
    """
    monkeypatch.setattr(checks, "CONFIG_PATH", tmp_path / "sentinel.yaml")


def _felie(username, fara_terminal, cu_terminal=0, ora=0):
    """Comenzile unui cont într-o ORĂ, despărțite după terminal.

    Se dau ca grupuri, nu ca rânduri, ca un test să poată descrie 174 839 de
    comenzi fără să le construiască. Cine le numără cum e treaba dublului, iar
    el CITEȘTE regula din instrucțiunea primită — vezi `_HistDB.fetch`.

    `ora` e câte ore în urmă e găleata. Gruparea pe oră e chiar unitatea în care
    s-au măsurat și furtuna de deploy, și munca de om.
    """
    inceput = NOW - timedelta(hours=ora)
    return {"username": username,
            "ora": inceput.replace(minute=0, second=0, microsecond=0),
            "fara_terminal": fara_terminal,
            "cu_terminal": cu_terminal,
            "oldest": inceput - timedelta(minutes=59),
            "newest": inceput}


class _HistDB(_DB):
    """Dublu care răspunde la CELE DOUĂ interogări ale verificării.

    Se cere textul instrucțiunii, nu doar rezultatul: verificarea trebuie să
    întrebe despre rândurile care N-AR TREBUI SĂ EXISTE, nu despre configurație.
    Parametrii se rețin, fiindcă o fereastră schimbată tăcut e chiar felul în
    care verificarea ar înceta să vadă un deploy fără ca nimic să pice.

    Regula de terminal NU e reimplementată din memorie: se citește din chiar
    instrucțiunea dată, cu chiar tiparul trimis ca parametru. O interogare care
    ar pierde `FILTER`-ul ar număra și comenzile tastate de un om — și ar
    răspunde exact ca dublul care „știe" răspunsul bun.
    """

    def __init__(self, *, total=0, interzise=0, newest=None, felie=None):
        super().__init__()
        self.total, self.interzise, self.newest = total, interzise, newest
        self.felie = felie if felie is not None else []
        self.params: list[tuple] = []

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        self.params.append(a)
        assert "FROM session_commands" in sql, sql
        assert "ORDER BY ts DESC" in sql, sql
        assert "LIMIT $1" in sql, sql
        # Felia se ia după `ts DESC` ÎNAINTE de orice filtrare pe `tty`: predicatul
        # de terminal n-are voie să apară în `WHERE`-ul CTE-ului (înainte de
        # `LIMIT`), altfel costul ar depinde de câte comenzi cu terminal are gazda,
        # iar felia n-ar mai fi mărginită prin construcție. Mutat acolo, testul
        # ăsta pică; lăsat în `FILTER`-ul de după CTE, trece.
        assert "tty IS NULL OR tty !~" not in sql.split("LIMIT $1")[0], sql

        tipar = a[2]
        are_filtru = "FILTER (WHERE tty IS NULL OR tty !~ $3)" in sql
        # Și gruparea se citește din instrucțiune: fără ora din `GROUP BY`,
        # serverul întoarce O SINGURĂ găleată pe cont, adică totalul lui pe toată
        # felia. Dublul trebuie să facă la fel, altfel testul care spune «o zi
        # întinsă nu e o furtună» ar trece peste chiar interogarea care nu mai
        # poate deosebi ziua de rafală.
        pe_ora = "GROUP BY 1, 2" in sql
        randuri: dict[tuple, dict] = {}
        for g in self.felie:
            comenzi = [(None, g["fara_terminal"]), ("pts0", g["cu_terminal"])]
            total = sum(n for _, n in comenzi)
            fara = (sum(n for tty, n in comenzi
                        if tty is None or not re.match(tipar, tty))
                    if are_filtru else total)
            cheie = (g["username"], g["ora"]) if pe_ora else (g["username"],)
            r = randuri.setdefault(cheie, {
                "username": g["username"], "ora": g["ora"], "total": 0,
                "fara_terminal": 0, "oldest": g["oldest"], "newest": g["newest"]})
            r["total"] += total
            r["fara_terminal"] += fara
            r["oldest"] = min(r["oldest"], g["oldest"])
            r["newest"] = max(r["newest"], g["newest"])
        return list(randuri.values())

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        self.params.append(a)
        assert "FROM session_commands" in sql, sql
        assert "tty IS NULL OR tty !~" in sql, sql
        # `newest` trebuie să fie `max(ts)` peste RÂNDURILE INTERZISE, nu peste
        # toate: un `max(ts)` nefiltrat ar aluneca pe o comandă tastată legitim și
        # ar data „acum" un set de rânduri interzise vechi, acuzând filtrul pentru
        # ce a scris procesul dinainte.
        assert "max(ts) FILTER" in sql, sql
        return {"total": self.total, "interzise": self.interzise,
                "newest": self.newest}


def test_an_empty_history_section_is_reported_as_dropping_nothing():
    """Lista goală, pe o gazdă unde nimic n-o contrazice, e o stare VALIDĂ.

    O gazdă care păstrează tot istoricul e implicitul livrat, nu o defecțiune —
    deci nu are voie să iasă roșu. Ce s-a schimbat pe 25 august 2026 e că `ok`-ul
    ăsta nu mai vine din configurație: se dă numai după ce datele au fost
    întrebate și n-au arătat nicio furtună, și după ce s-a verificat că nu zace
    un `sentinel.yaml.new` care cere altceva.
    """
    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=[])))[0]
    assert r.status == "ok", "lista goală raportată ca defect"
    assert r.key == "history:filter"
    assert "gol" in r.detail
    assert "datele n-o contrazic" in r.detail, (
        "`ok`-ul nu spune pe ce se sprijină, deci nu se poate deosebi de unul "
        "dat înainte de orice întrebare pusă bazei")


def test_an_unmerged_new_file_makes_the_empty_filter_a_finding(tmp_path, monkeypatch):
    """Starea reală a gazdei pe 25 august 2026, raportată `ok` de prima scriere.

    `/etc/sentinel/sentinel.yaml` era din 20 august și NU avea secțiunea
    `history:`; lângă el stăteau `sentinel.yaml.new` și `inventory.yaml.new` din
    25 august, neîmbinate. Verificarea ieșea pe ramura «listă goală» și întorcea
    `ok` înainte de orice SQL — deci verificarea scrisă tocmai ca să deosebească
    intenția de efect nu deosebea «am ales să nu arunc nimic» de «nimeni n-a
    îmbinat fișierul», iar în tabelă erau 1 266 de rânduri interzise.

    Discriminatorul e chiar fișierul: dacă `.new` cere conturi pe care
    configurația încărcată nu le are, filtrul pe care operatorul crede că l-a
    pornit nu rulează nicăieri.
    """
    monkeypatch.setattr(checks, "CONFIG_PATH", tmp_path / "sentinel.yaml")
    (tmp_path / "sentinel.yaml.new").write_text(
        "history:\n  skip_command_accounts:\n    - sentinel-deploy\n",
        encoding="utf-8")

    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=[])))[0]
    assert r.status == "degraded", "configurația neîmbinată a trecut drept aleasă"
    assert "sentinel-deploy" in r.detail
    assert "sentinel.yaml.new" in r.detail
    assert "diff" in r.action, "operatorul nu primește pasul care arată diferența"
    assert r.facts["unmerged_accounts"] == ["sentinel-deploy"]


def test_a_new_file_that_says_the_same_thing_is_not_a_finding(tmp_path, monkeypatch):
    """Instalatorul scrie `.new` la FIECARE rulare, îmbinat sau nu.

    Dacă simpla lui prezență ar fi un defect, verificarea ar fi roșie permanent
    pe orice gazdă livrată de două ori — iar o constatare care nu se stinge
    niciodată e cum ajunge operatorul să nu mai citească niciuna.
    """
    monkeypatch.setattr(checks, "CONFIG_PATH", tmp_path / "sentinel.yaml")
    (tmp_path / "sentinel.yaml.new").write_text(
        "history:\n  skip_command_accounts:\n    - sentinel-deploy\n"
        "web:\n  port: 8443\n", encoding="utf-8")

    _cu_uid(monkeypatch, lambda _n: 1002)
    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=["sentinel-deploy"])))[0]
    assert r.status == "ok", r.detail


def test_a_stale_new_file_does_not_call_a_hand_merged_filter_unmerged(
        tmp_path, monkeypatch):
    """Reacția firească la constatarea de deasupra n-are voie s-o facă permanentă.

    Operatorul citește «configurația filtrului n-a fost îmbinată», deschide
    `/etc/sentinel/sentinel.yaml` și adaugă contul de mână. Atât trebuia făcut, și
    filtrul chiar rulează după repornire. Dar `.new` rămâne pe disc așa cum era —
    pe gazdă e cel din 25 august 2026, fără secțiunea `history:` deloc.

    Comparate pe EGALITATE, cele două fișiere ar face constatarea roșie pentru
    totdeauna, cu un text care spune exact pe dos: că filtrul nu e îmbinat,
    tocmai când el e cel care rulează. Iar o constatare care nu se stinge
    niciodată e cum ajunge operatorul să nu mai citească niciuna — și ar lua cu
    ea furtunile adevărate, care se raportează sub aceeași cheie.
    """
    monkeypatch.setattr(checks, "CONFIG_PATH", tmp_path / "sentinel.yaml")
    # Un `.new` dinaintea filtrului: valid, doar că nu știe de `history:`.
    (tmp_path / "sentinel.yaml.new").write_text(
        "web:\n  port: 8443\n", encoding="utf-8")

    _cu_uid(monkeypatch, lambda _n: 1002)
    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=["sentinel-deploy"])))[0]
    assert r.status == "ok", r.detail
    assert r.facts["unmerged_new"] is True, (
        "cazul n-a mai trecut prin ramura care citește `.new`, deci nu probează "
        "nimic despre comparația dintre cele două fișiere")
    assert r.facts["unmerged_missing"] == []

    # Celălalt sens, în același test, ca reparația să nu poată fi «nu mai compar
    # deloc»: un cont cerut de `.new` și absent din cea încărcată rămâne roșu,
    # chiar dacă încărcată numește alte conturi.
    (tmp_path / "sentinel.yaml.new").write_text(
        "history:\n  skip_command_accounts:\n    - sentinel-deploy\n"
        "    - altcineva\n", encoding="utf-8")
    r2 = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=["sentinel-deploy"])))[0]
    assert r2.status == "degraded", r2.detail
    assert r2.facts["unmerged_missing"] == ["altcineva"]
    assert "altcineva" in r2.detail


def test_a_new_file_that_cannot_be_read_is_unknown_not_ok(tmp_path, monkeypatch):
    """„Nu pot citi" și „nu e nimic acolo" nu au voie să arate la fel.

    Un `.new` cu drepturi greșite sau cu YAML stricat lasă întrebarea «filtrul
    încărcat e cel scris de instalator?» fără răspuns. Raportat `ok`, ar fi exact
    tiparul din `CLAUDE.md`: un mecanism care confirmă că n-a găsit nimic, când
    de fapt n-a putut să se uite.
    """
    monkeypatch.setattr(checks, "CONFIG_PATH", tmp_path / "sentinel.yaml")
    (tmp_path / "sentinel.yaml.new").write_text(
        "history:\n  skip_command_accounts:\n   - a\n  - b\n", encoding="utf-8")

    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=[])))[0]
    assert r.status == "unknown", r.detail
    assert "sentinel.yaml.new" in r.detail


def test_a_storm_on_an_account_outside_the_filter_is_a_finding():
    """Întrebarea pusă DATELOR, care nu depinde de ce a tastat cineva.

    Măsurat pe gazdă: `scripts/deploy.sh` cerea `--user`, deci deploy-urile
    rulau sub contul de logare al operatorului și scriau 174 839, 456 133 și
    2 158 596 de comenzi fără terminal pe oră sub numele lui. Contul ăla NU e în
    filtru și nici nu poate fi — sub el rulează și diagnosticele lui.

    Nicio verificare pe configurație n-ar fi văzut asta: configurația era
    perfect corectă, doar că deploy-ul nu rula sub contul pe care îl numea. Aici
    se întreabă cine scrie, nu ce s-a configurat, deci se vede la fel de bine o
    invocație cu contul vechi, un cont nou apărut sau o secțiune neîmbinată.
    """
    # O oră de deploy, sub cea mai săracă măsurată (174 839), plus o oră liniștită
    # a aceluiași cont: rafala NU are voie să se dilueze în medie.
    db = _HistDB(felie=[_felie("operator", 174_839, cu_terminal=200, ora=1),
                        _felie("operator", 40, ora=0),
                        _felie("root", 0, cu_terminal=30, ora=0)])
    r = run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=[])))[0]

    assert r.status == "degraded", r.detail
    # Cu ghilimelele din mesaj: „operator" e și un cuvânt care apare prin
    # texte, iar o căutare simplă ar putea trece fără ca numele contului să fie
    # spus vreodată.
    assert "„operator”" in r.detail, r.detail
    assert r.facts["top_account"] == "operator"
    assert r.facts["top_peak_hour"] == 174_839, (
        "ora de vârf s-a pierdut într-o medie peste toată felia")
    assert any("ORDER BY ts DESC" in s for s in db.sql), (
        "verificarea n-a întrebat datele deloc")

    # Contra-proba pentru chiar mecanismul de mai sus: aceleași 174 879 de
    # comenzi, dar întinse peste 24 de ore de rutină, NU sunt o furtună. Fără
    # cazul ăsta, un prag pus pe TOTAL în loc de pe oră ar trece neobservat.
    intinse = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("operator", 7_286, ora=h) for h in range(24)]),
        _istoric(skip_command_accounts=[])))[0]
    assert intinse.status == "ok", intinse.detail


def test_a_slice_full_of_typed_commands_is_not_a_storm():
    """Regula e despre comenzile FĂRĂ terminal, și numai despre ele.

    Cineva care compilează la tastatură produce zeci de mii de `execve` într-o
    oră, toate cu `pts0`. Numărate ca automatizare, ar da o constatare roșie
    pentru munca omului — și, mai rău, ar cere ștergerea exact a istoricului care
    are valoare de securitate. Filtrul viu le păstrează; verificarea trebuie să
    se uite la aceleași rânduri ca el.
    """
    r = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("om", 0, cu_terminal=60_000, ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert r.status == "ok", r.detail
    assert r.facts["top_peak_hour"] == 0
    assert "niciuna fără terminal" in r.detail


def test_the_storm_is_attributed_to_the_burst_not_to_the_biggest_total():
    """Contul cu cele mai multe rânduri nu e neapărat cel care face rău.

    Pe gazdă, contul de logare al operatorului are 2,79 milioane de comenzi fără
    terminal adunate în luni de zile, iar contul de automatizare are 1 365. Un
    „cel mai activ" ales după TOTAL ar numi mereu primul cont și ar raporta
    liniștit ritmul lui — adică o rafală de deploy pe alt cont ar trece
    neobservată exact fiindcă victoria la total e deja luată.

    Ce contează e ora de vârf: cine a scris cele mai multe într-o oră.
    """
    felie = [_felie("om", 3_000, cu_terminal=50, ora=h) for h in range(20)]
    felie.append(_felie("automat", 25_000, ora=0))
    r = run(checks.check_command_history_filter(
        _HistDB(felie=felie), _istoric(skip_command_accounts=[])))[0]

    assert r.facts["top_account"] == "automat", (
        "contul numit e cel cu totalul cel mai mare, nu cel care a făcut rafala")
    assert r.facts["top_peak_hour"] == 25_000
    assert r.status == "degraded", r.detail


def test_a_day_of_human_diagnostics_is_not_a_storm():
    """Contra-cazul, și e cel care decide dacă alerta merită citită.

    Măsurat pe gazdă după migrarea pe contul de deploy: operatorul a scris 2 438
    de comenzi fără terminal într-o oră, apoi 355 — `ssh gazdă 'ceva'` n-are
    terminal, deci diagnosticul de la distanță arată exact ca o automatizare, în
    formă, și diferă doar în ritm. Un prag care ar semnala asta ar da o
    constatare la fiecare zi de lucru, iar un canal care se plânge zilnic degeaba
    nu mai e citit când se plânge de un deploy adevărat.
    """
    r = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("operator", 2_438, cu_terminal=120, ora=1),
                       _felie("operator", 355, cu_terminal=20, ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert r.status == "ok", r.detail
    assert "2438" in r.detail.replace(" ", "") or "2 438" in r.detail


def test_the_report_says_how_far_back_the_sample_could_see():
    """O felie de 20 000 de comenzi nu e o fereastră de 48 de ore.

    Interogarea e mărginită dinadins — rulează la 5 minute pe o tabelă de
    milioane de rânduri —, deci pe o gazdă vorbăreață ea vede ultimele minute,
    nu ultimele două zile. Spus «în ultimele 48 de ore n-am văzut nimic», ăsta ar
    fi un raport mai tare decât măsurătoarea din spatele lui: exact felul în care
    un instrument de monitorizare începe să mintă fără să greșească un număr.
    """
    plina = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("cineva", 0, cu_terminal=checks.HISTORY_SAMPLE,
                              ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert plina.facts["sample_capped"] is True
    assert "cele mai recente" in plina.detail
    assert f"{checks.HISTORY_WINDOW_H} de ore" not in plina.detail, (
        "raportul pretinde fereastra întreagă peste o felie care n-a atins-o")

    scurta = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("cineva", 0, cu_terminal=12, ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert scurta.facts["sample_capped"] is False
    assert f"{checks.HISTORY_WINDOW_H} de ore" in scurta.detail

    # Și cazul care contează cel mai mult, fiindcă e cel de pe o gazdă vie: felia
    # e plină ȘI are comenzi fără terminal, doar că într-un ritm de om. Aici se
    # tipărește ritmul, iar odată cu el trebuie să se vadă pe ce interval a fost
    # măsurat — altfel „~995/h" citit lângă „ultimele 48 de ore" descrie o gazdă
    # care n-a fost măsurată.
    plina_cu_comenzi = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("cineva", (checks.HISTORY_SAMPLE - 100) // 24,
                              cu_terminal=5, ora=h) for h in range(24)]),
        _istoric(skip_command_accounts=[])))[0]
    assert plina_cu_comenzi.status == "ok", plina_cu_comenzi.detail
    assert plina_cu_comenzi.facts["sample_capped"] is True
    assert "cele mai recente" in plina_cu_comenzi.detail
    assert f"{checks.HISTORY_WINDOW_H} de ore" not in plina_cu_comenzi.detail


def test_the_window_and_the_sample_are_what_the_query_receives():
    """Cele două numere care decid dacă verificarea poate vedea ceva.

    Schimbat tăcut din 48 în 1, `HISTORY_WINDOW_H` ar lăsa suita verde și ar face
    ca starea cea mai importantă — un deploy care scrie sub contul greșit — să nu
    mai fie prinsă aproape niciodată: un deploy nu rulează în fiecare oră. Nimic
    nu-l lega de vreun test până acum.
    """
    db = _HistDB(felie=[])
    run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=[])))

    assert db.params, "interogarea de date n-a fost făcută deloc"
    limita, ore, tipar = db.params[0]
    assert limita == checks.HISTORY_SAMPLE
    assert ore == checks.HISTORY_WINDOW_H
    assert tipar == checks.REAL_TTY_SQL, (
        "felia folosește alt tipar de terminal decât filtrul viu")

    # Și valorile în sine, cu motivul lor: o fereastră de o oră n-ar prinde
    # niciun deploy, iar o felie de câteva sute n-ar deosebi o furtună de zgomot.
    assert checks.HISTORY_WINDOW_H >= 24, (
        "fereastra a coborât sub o zi; un deploy nu rulează zilnic")
    assert checks.HISTORY_SAMPLE >= 3 * checks.HISTORY_STORM_PER_H, (
        "felia nu e mult mai mare decât pragul, iar ora se numără din chiar ea: "
        "o furtună tăiată de granița dintre două ore ar sta sub prag în amândouă "
        "gălețile, adică cea mai violentă ar fi cea mai ușor de ratat")
    assert checks.HISTORY_STORM_PER_H > 2_438, (
        "pragul ar semnala cea mai încărcată oră de muncă omenească măsurată")
    assert checks.HISTORY_STORM_PER_H < 174_839, (
        "pragul ar rata cea mai săracă oră de deploy măsurată")


def test_the_storm_threshold_fires_exactly_at_the_boundary():
    """`>=` sau `>` pe prag decide dacă ora care atinge fix pragul e o furtună.

    Pragul e ales ca media geometrică între cea mai săracă oră de deploy și cea
    mai bogată oră de om, tocmai ca granița să cadă între ele. O oră care e FIX
    pe prag e ritm de automatizare, nu de om, deci comparația trebuie să fie
    inclusivă (`>=`). Schimbată tăcut în `>`, ora de la fix prag ar trece drept
    normală și un deploy care nimerește exact pragul n-ar mai fi raportat — iar
    testele care doar fixează constanta n-ar prinde-o, fiindcă valoarea nu s-a
    schimbat, doar comparația care o alimentează.
    """
    la_prag = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("automat", checks.HISTORY_STORM_PER_H, ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert la_prag.status == "degraded", (
        "ora care atinge fix pragul a trecut drept normală: `>` în loc de `>=` "
        "ratează exact granița")
    assert la_prag.facts["top_peak_hour"] == checks.HISTORY_STORM_PER_H

    sub_prag = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("automat", checks.HISTORY_STORM_PER_H - 1, ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert sub_prag.status == "ok", sub_prag.detail


def test_a_configured_account_that_does_not_exist_is_degraded(monkeypatch):
    """Un cont scris greșit dă un filtru care nu potrivește niciodată nimic.

    `is_dropped_command` compară pe egalitate exactă. Secțiunea arată
    configurată, tabela crește cu 405 777 de rânduri la fiecare deploy, și nimic
    nu spune nimic. Exact starea pe care verificarea asta există s-o facă
    vizibilă.
    """
    _cu_uid(monkeypatch, lambda _n: None)
    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=["nu-exista"])))[0]
    assert r.status == "degraded"
    assert "nu-exista" in r.detail


def test_an_unreadable_account_database_is_unknown_not_ok(monkeypatch):
    """„Nu știu" și „e în regulă" nu au voie să arate la fel.

    Fără baza de conturi nu se pot afla uid-urile, iar rândurile scrise cu `auid`
    numeric — 87 935 pe gazdă — scapă filtrului. Raportat `ok`, reconcilierea din
    runner ar șterge o constatare reală și i-ar arăta operatorului o revenire
    care nu s-a întâmplat.
    """
    def orb(_n):
        raise OSError("nu se poate citi /etc/passwd")

    _cu_uid(monkeypatch, orb)
    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=["sentinel-deploy"])))[0]
    assert r.status == "unknown"
    assert "nu știu" in r.detail.lower() or "nu pot" in r.detail.lower()


def test_a_row_the_rule_forbids_means_the_filter_is_not_in_effect(monkeypatch):
    """Faptul, nu intenția — dar numai un rând scris DUPĂ ce filtrul putea acționa.

    `docs/ISTORIC-SESIUNI.md` propunea

        journalctl -u sentinel-ingest | grep commands_skipped

    care potrivea ÎNTOTDEAUNA: `commands_skipped` e mereu în `extra`, iar
    `JSONFormatter` scrie și zerourile. Nu deosebea «am aruncat 405 777 de
    rânduri» de «secțiunea n-a fost îmbinată niciodată».

    Ce deosebește cele două e un rând pe care regula îl interzice, scris DUPĂ ce
    filtrul putea acționa. Un `max(ts)` nefolosit făcea verificarea să acuze
    filtrul și pentru rânduri vechi: reprodus pe gazdă (2026-08-26), 1 871 de
    rânduri `sentinel-deploy` scrise ÎNAINTE ca filtrul să existe rămâneau în
    fereastra de 48h; după ce operatorul adăuga contul și repornea, panoul
    devenea roșu ~48h cu două cauze false și o acțiune care nu arăta nimic, și
    îngropa sub aceeași cheie furtunile adevărate. Cel mai devreme moment în care
    filtrul putea acționa e ultima pornire a serviciului de ingestie.
    """
    _cu_uid(monkeypatch, lambda _n: 998)

    async def pornit_acum_2h(_unit):
        return NOW - timedelta(hours=2)
    monkeypatch.setattr(checks, "_service_started_at", pornit_acum_2h)

    # Nou: cea mai recentă comandă interzisă e de acum 5 minute, DUPĂ pornire —
    # filtrul rula deja când a fost scrisă, deci chiar nu e în vigoare.
    db = _HistDB(total=405_777, interzise=405_777,
                 newest=NOW - timedelta(minutes=5))
    r = run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r.status == "degraded", r.detail
    assert "nu e în vigoare" in r.title
    assert "405777" in r.detail.replace(" ", "") or "405 777" in r.detail
    assert r.facts["rows_forbidden"] == 405_777
    assert any("session_commands" in s for s in db.sql), (
        "verificarea n-a întrebat tabela deloc: ar raporta despre configurație, "
        "nu despre efect")

    # Vechi: aceleași rânduri interzise, dar cea mai recentă e de acum 40 de ore —
    # ÎNAINTE de ultima pornire a filtrului. Le-a scris procesul dinainte; a le
    # numi „filtrul nu e în vigoare" e acuzația care aprindea panoul degeaba.
    db_vechi = _HistDB(total=405_777, interzise=405_777,
                       newest=NOW - timedelta(hours=40))
    rv = run(checks.check_command_history_filter(
        db_vechi, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert rv.status != "degraded", rv.detail
    assert "nu e în vigoare" not in rv.title
    assert "nu e în vigoare" not in rv.detail
    # Faptul, dat operatorului: data celui mai recent rând interzis apare, ca s-o
    # poată lega de momentul îmbinării.
    # În fusul CONFIGURAT, cu marcajul lui: operatorul verifică momentul ăsta în
    # `journalctl`, care îi arată ora locală. Dat în UTC, l-ar trimite să caute
    # cu trei ore alături.
    assert checks._ceas(NOW - timedelta(hours=40), "Europe/Bucharest") in rv.detail
    assert rv.facts["newest_forbidden"] == (NOW - timedelta(hours=40)).isoformat()


def test_an_active_storm_outside_the_filter_is_not_swallowed_by_old_rows(monkeypatch):
    """O furtună ACTIVĂ pe alt cont nu are voie să stea sub verdele dat rândurilor vechi.

    B1 a stins un roșu fals: rânduri interzise VECHI ale contului configurat
    (scrise înainte ca filtrul să existe) rămân în fereastra de 48h și, singure,
    dau acum `ok`. Dar ramura aia întoarce `ok` ÎNAINTE de ramura de furtună de
    dedesubt — deci în cele ~48h cât rândurile vechi zac, o furtună reală de
    automatizare pe un cont din AFARA filtrului, sub aceeași cheie `history:filter`,
    e înghițită și panoul rămâne verde. Exact cazul din
    `test_a_storm_on_an_account_outside_the_filter_is_a_finding`, dar cu rânduri
    interzise vechi prezente simultan: un deploy rulat pe contul de logare al
    operatorului nu produce niciun semnal.
    """
    _cu_uid(monkeypatch, lambda _n: 998)

    async def pornit_acum_2h(_unit):
        return NOW - timedelta(hours=2)
    monkeypatch.setattr(checks, "_service_started_at", pornit_acum_2h)

    # Contul configurat: 1 871 de rânduri interzise, cea mai recentă de acum 40 de
    # ore — ÎNAINTE de pornire, deci singure ar da `ok` (cazul B1). SIMULTAN,
    # contul `operator`, din afara filtrului, scrie 174 839 de comenzi fără
    # terminal într-o oră: furtună activă, peste prag.
    db = _HistDB(total=1_871, interzise=1_871, newest=NOW - timedelta(hours=40),
                 felie=[_felie("operator", 174_839, cu_terminal=200, ora=1),
                        _felie("operator", 40, ora=0)])
    r = run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r.status == "degraded", r.detail
    assert "„operator”" in r.detail, r.detail
    assert r.facts["top_account"] == "operator"
    assert r.facts["top_peak_hour"] == 174_839
    assert "din afara filtrului" in r.title, (
        "furtuna de pe contul neconfigurat a fost raportată ca altceva, sau "
        "verdele rândurilor vechi a acoperit-o")


def test_old_forbidden_rows_without_a_storm_stay_ok(monkeypatch):
    """Non-regresie B1: rânduri interzise vechi rămân `ok`, cu sau fără furtună.

    Garda adăugată deasupra n-are voie să reînvie roșul fals pe care B1 l-a
    stins. Două sub-cazuri:

    1. un cont din afara filtrului prezent dar SUB prag (nu e furtună), plus
       rânduri interzise vechi ale contului configurat → `ok`;
    2. mai tare: chiar o furtună VECHE pe CONTUL configurat însuși (toate
       rândurile de dinaintea pornirii) trebuie să rămână `ok`. Contul filtrului
       nu are voie să cadă prin la ramura de furtună, care l-ar acuza cu «n-ar fi
       trebuit scrise» — exact roșul fals pentru rânduri vechi. Fără clauza
       `top.username not in skip.matches` din gardă, sub-cazul ăsta devine roșu.
    """
    _cu_uid(monkeypatch, lambda _n: 998)

    async def pornit_acum_2h(_unit):
        return NOW - timedelta(hours=2)
    monkeypatch.setattr(checks, "_service_started_at", pornit_acum_2h)

    # Sub-cazul 1: cont din afara filtrului, sub prag.
    db = _HistDB(total=1_871, interzise=1_871, newest=NOW - timedelta(hours=40),
                 felie=[_felie("operator", checks.HISTORY_STORM_PER_H - 1, ora=1)])
    r = run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r.status == "ok", r.detail
    assert "nu e în vigoare" not in r.title
    assert "nu e în vigoare" not in r.detail

    # Sub-cazul 2: furtună VECHE pe chiar contul configurat (toate rândurile
    # dinaintea pornirii de acum 2h — ora 41 e cu mult înainte).
    db2 = _HistDB(total=174_879, interzise=174_879, newest=NOW - timedelta(hours=40),
                  felie=[_felie("sentinel-deploy", 174_839, ora=41)])
    r2 = run(checks.check_command_history_filter(
        db2, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r2.facts["top_account"] == "sentinel-deploy"
    assert r2.status == "ok", r2.detail
    assert "n-ar fi trebuit scrise" not in r2.detail, (
        "furtuna VECHE a contului configurat a căzut prin la ramura de furtună și "
        "a reînviat roșul fals pentru rânduri de dinaintea filtrului")


def test_the_numeric_spelling_is_part_of_what_the_check_looks_for(monkeypatch):
    """Verificarea trebuie să caute AMBELE ortografii ale contului.

    Dacă ar întreba doar despre nume, cele 87 935 de rânduri scrise cu `auid`
    numeric n-ar apărea în numărătoare — iar verificarea ar raporta `ok` peste
    exact golul pe care există s-o umple.
    """
    _cu_uid(monkeypatch, lambda _n: 998)
    db = _HistDB()
    r = run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r.status == "ok"
    assert sorted(r.facts["matches"]) == ["998", "sentinel-deploy"]


def test_no_rows_at_all_is_not_reported_as_proof_that_the_filter_works(monkeypatch):
    """Zero rânduri interzise într-o fereastră fără niciun deploy arată exact ca
    zero rânduri interzise pe o gazdă care aruncă cum trebuie.

    Verificarea nu are voie să spună «filtrul funcționează» despre asta. Spune ce
    a văzut — nimic — și că nimic nu e o dovadă.
    """
    _cu_uid(monkeypatch, lambda _n: 998)
    r = run(checks.check_command_history_filter(
        _HistDB(total=0, interzise=0),
        _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r.status == "ok"
    assert "NU e o dovadă" in r.detail, (
        "verificarea pretinde că filtrul aruncă, pe o fereastră în care n-a "
        "văzut niciun rând")


def test_the_history_check_is_registered_in_the_run():
    """O verificare care nu e în `CHECKS` nu rulează niciodată.

    E chiar felul de defect pe care fișierul ăsta îl păzește peste tot: cod
    corect, testat, și niciodată chemat.
    """
    assert "history" in [nume for nume, _ in checks.CHECKS]


# --- ship_lag: prag de vârstă pe flux + detector de înțepenire ---------------
#
# Două pene stau în spatele acestor teste. Prima: `session_commands`, fluxul cu
# cel mai mare volum, rămâne normal în urmă mai mult decât restul, iar la 15
# minute producea o constatare pe funcționarea sănătoasă — zgomot pe care
# operatorul învață să-l ignore. A doua, cea care a durat ore: cursorul lui NU
# avansa deloc (un WAF refuza loturile), iar a aștepta pragul de vârstă ridicat
# înainte de a alarma ar fi lăsat oprirea nevăzută ore în șir. Cele două sunt
# diagnostice diferite și au chei diferite.
from sentinel.report.shipper import StreamLag


class _StallDB:
    """`collector_cursors` cât să se joace mai multe rulări ale detectorului.

    Reimplementează în Python semantica upsertului pe cheia `ship:<flux>:stall`,
    deci dovedește logica detectorului — starea ținută între rulări —, nu SQL-ul.
    Un `_DB` care întoarce o singură valoare canonică pentru orice `fetchrow` nu
    poate arăta ce vede detectorul: că VALOAREA cursorului e neschimbată de la
    rularea trecută. Fără o stare care evoluează, testul de non-regresie (un flux
    care se scurge normal) și cel de înțepenire ar arăta identic.
    """

    def __init__(self):
        self.store: dict[str, dict] = {}

    async def fetchrow(self, sql, *a):
        return self.store.get(a[0])

    async def execute(self, sql, *a):
        name, cursor, events = a[0], a[1], a[2]
        self.store[name] = {"cursor": cursor, "events_seen": events}

    async def fetchval(self, sql, *a):
        return None


def _ship_cfg():
    return _cfg(ship=SimpleNamespace(enabled=True, url="https://agg.invalid",
                                     interval_s=60))


def _patch_ship(monkeypatch, lags):
    """Fă `check_ship_lag` să vadă exact `lags` și o cheie de expediere prezentă."""
    from sentinel.report import shipper

    async def fake_lag(db, streams=None):
        return list(lags)

    monkeypatch.setattr(shipper, "lag", fake_lag)
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(has=lambda n: True))


def _sc_lag(cursor, pending, oldest_min, stream="session_commands"):
    """Un flux append-only (cursor pe `id`): `clock_ahead_s`/`trigger` = None."""
    return StreamLag(stream=stream, cursor=cursor, floor=None, pending=pending,
                     oldest_pending_min=oldest_min)


def _key(results, key):
    for r in results:
        if r.key == key:
            return r
    return None


def test_session_commands_thirty_minutes_behind_but_advancing_is_not_a_finding(monkeypatch):
    """Zgomotul din care s-a cerut pragul de 6h.

    `session_commands` are cel mai mare volum și rămâne legitim în urmă cu minute.
    Sub pragul lui de 6h, cu un cursor care AVANSEAZĂ la fiecare rundă, nu e nici
    înțepenit, nici „rămas în urmă" — la 15 minute ar fi produs o constatare pe
    funcționarea normală, iar o alarmă pe normal e una peste care operatorul
    învață să treacă și atunci nu mai vede nici restanța adevărată.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    for cursor in (100, 130):
        _patch_ship(monkeypatch, [_sc_lag(cursor, pending=5, oldest_min=30)])
        results = run(checks.check_ship_lag(db, cfg))

    # Cursorul avansează la fiecare rulare, deci cheia `:stall` NU are voie să
    # fie `degraded` — dar e emisă totuși, cu `ok`, ca runner-ul să poată
    # anunța o revenire adevărată dacă flux ar fi fost înțepenit înainte.
    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None and stall.status == "ok", (
        "un flux care se scurge normal a fost numit înțepenit")
    r = _key(results, "ship:lag:session_commands")
    assert r is not None and r.status == "ok", (
        "30 de minute a fost raportat ca restanță, deși pragul lui e de 6 ore")


def test_session_commands_seven_hours_behind_is_an_age_finding(monkeypatch):
    """Peste 6h, restanța lui `session_commands` E o constatare.

    Ridicarea pragului la 6 ore nu are voie să însemne „niciodată": o copie
    externă rămasă în urmă cu 7 ore e incompletă și trebuie spus. Cursorul
    avansează — deci e vârstă, nu înțepenire.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    for cursor in (100, 130):
        _patch_ship(monkeypatch, [_sc_lag(cursor, pending=5, oldest_min=420)])
        results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None and stall.status == "ok", (
        "cursorul avansează — nu are voie să fie numit înțepenit")
    r = _key(results, "ship:lag:session_commands")
    assert r is not None and r.status == "degraded"
    assert "rămas în urmă" in r.title


def test_a_cursor_frozen_while_the_backlog_grows_is_a_stall(monkeypatch):
    """Pana reală: cursorul nu mai înaintează DELOC în timp ce sosește muncă.

    A aștepta pragul de vârstă (6h) pentru asta e greșit — oprirea trebuie prinsă
    în minute. Constatarea are cheie DISTINCTĂ de cea de vârstă, ca mesajul să
    spună „nu mai înaintează", nu „a rămas în urmă": sunt diagnostice diferite,
    cu acțiuni diferite. Restanța e sub pragul de 6h (30 min), deci ce prinde
    aici e înțepenirea, nu vârsta.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    results = []
    for pending in (5, 40, 120):
        _patch_ship(monkeypatch, [_sc_lag(200, pending=pending, oldest_min=30)])
        results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None and stall.status == "degraded", (
        "cursorul înghețat 3 rulări cu restanța în creștere nu a fost prins")
    assert "nu mai înaintează" in stall.detail
    assert stall.facts["pending_at_freeze"] == 5 and stall.facts["pending"] == 120
    assert _key(results, "ship:lag:session_commands") is None, (
        "a raportat si constatarea de varsta pe un flux sub pragul de 6h")


def test_a_cleared_stall_re_emits_ok_on_the_same_key(monkeypatch):
    """Ce se strică pentru operator dacă asta pică: o revenire din înțepenire
    redevine RETRAGERE („⚪ Nu se mai raportează") în loc de REVENIRE („🟢
    Revenit la normal"), fiindcă înainte de reparație cheia `:stall` era
    emisă DOAR cât timp fluxul era înghețat — o dezghețare o făcea pur și
    simplu să dispară din rulare. Măsurat pe 23 septembrie 2026: 20 de
    înțepeniri reale s-au stins peste zi, iar operatorul a citit retragerea
    ca pe o veste proastă, la patru ore după o pană reală de 20 de ore.

    Rulează verificarea pe o stare cu stall (3 priviri înghețate, restanța
    crescând), apoi pe una fără (cursorul a avansat), și confirmă că a doua
    rulare produce `ok` pe ACEEAȘI cheie — nu absența ei.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    results = []
    for pending in (5, 40, 120):
        _patch_ship(monkeypatch, [_sc_lag(200, pending=pending, oldest_min=30)])
        results = run(checks.check_ship_lag(db, cfg))
    stalled = _key(results, "ship:lag:session_commands:stall")
    assert stalled is not None and stalled.status == "degraded", (
        "pregătirea nu a produs o înțepenire — testul de revenire nu testează nimic")

    _patch_ship(monkeypatch, [_sc_lag(260, pending=5, oldest_min=2)])
    results2 = run(checks.check_ship_lag(db, cfg))

    recovered = _key(results2, "ship:lag:session_commands:stall")
    assert recovered is not None, (
        "cheia :stall a dispărut din rulare când fluxul s-a dezghețat — "
        "runner-ul o va citi drept RETRAGERE, nu revenire")
    assert recovered.status == "ok", (
        f"fluxul dezghețat nu a produs 'ok' pe cheia lui: {recovered.status}")


def test_a_stall_recovery_is_announced_as_recovered_not_withdrawn(monkeypatch):
    """Aceeași cauză, văzută prin `runner.run_and_alert`, unde se decide de
    fapt ce citește operatorul. `_key(...).status == "ok"` de mai sus arată că
    verificarea produce faptul corect; testul ăsta arată că runner-ul îl
    clasează corect — în `recovered`, nu în `withdrawn` — și că mesajul
    trimis spune „Revenit la normal”, nu „Constatări care nu se mai
    raportează”.
    """
    from sentinel.selfcheck import runner

    stall_key = "ship:lag:session_commands:stall"
    stalled = CheckResult(
        stall_key, "Expedierea fluxului „session_commands” s-a înțepenit",
        "degraded", detail="cursorul a rămas pe loc 3 rulări la rând")

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, stalled]))
    run(runner.run_and_alert(db, _cfg()))
    db.notifications.clear()

    recovered_result = CheckResult(
        stall_key, "Expedierea fluxului „session_commands” nu e înțepenită", "ok",
        detail="cursorul nu e înghețat")
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, recovered_result]))
    summary = run(runner.run_and_alert(db, _cfg()))

    assert summary["recovered"] == [stall_key], (
        f"o revenire reală a fost clasată greșit: {summary}")
    assert summary["withdrawn"] == [], (
        f"revenirea a fost clasată drept retragere: {summary}")
    text = db.notifications[-1]
    assert "Revenit la normal" in text
    assert "Constatări care nu se mai raportează" not in text


def test_a_stream_gone_unreadable_is_not_reported_as_a_stall_recovery(monkeypatch):
    """Un flux care iese din citire (`ship:lag:<flux>:unreadable`) nu are voie
    să apară drept revenire a înțepenirii — asta AR fi confirmarea intenției
    (verificarea „a rulat fără eroare pe stall") în locul efectului (fluxul
    e acum ilizibil, nu vindecat). Cheia `:stall` trebuie pur și simplu să nu
    mai fie emisă în runda în care fluxul devine ilizibil, ca runner-ul s-o
    citească drept RETRAGERE, nu revenire.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    results = []
    for pending in (5, 40, 120):
        _patch_ship(monkeypatch, [_sc_lag(200, pending=pending, oldest_min=30)])
        results = run(checks.check_ship_lag(db, cfg))
    assert _key(results, "ship:lag:session_commands:stall").status == "degraded"

    broken = StreamLag(stream="session_commands", cursor=200, floor=None,
                       pending=120, oldest_pending_min=30,
                       error="relation \"session_commands\" does not exist")
    _patch_ship(monkeypatch, [broken])
    results2 = run(checks.check_ship_lag(db, cfg))

    assert _key(results2, "ship:lag:session_commands:stall") is None, (
        "un flux devenit ilizibil a mai emis cheia :stall — poate fi citit "
        "greșit drept revenire")
    unreadable = _key(results2, "ship:lag:session_commands:unreadable")
    assert unreadable is not None and unreadable.status == "unknown"


def test_a_frozen_cursor_with_a_backlog_that_does_not_grow_is_not_a_stall(monkeypatch):
    """Falsul pozitiv măsurat pe 28 august, verbatim: „deși 1 randuri asteapta".

    Un cursor care nu se mișcă răspunde la „a plecat ceva?", nu la „mai merge
    expeditorul?". Cu un singur rând restant care nu se înmulțește, răspunsul
    corect la prima e „n-avea mare lucru de trimis", iar textul „nu mai
    înaintează deloc" e fals. Alerta a plecat de două ori într-o zi și, fiindcă
    își revenea singură, a costat de fiecare dată încă un mesaj de revenire.

    Ce ține în picioare acoperirea: un rând care chiar nu pleacă îmbătrânește, și
    de asta răspunde pragul de VÂRSTĂ, cu întrebarea potrivită.

    De la 23 septembrie 2026, cheia `:stall` nu mai lipsește pe cazul ăsta — se
    scrie `ok` la fiecare privire în care `is_stalled` e fals, ca dispariția ei
    să nu mai fie citită drept retragere (vezi `test_a_cleared_stall_re_emits_ok_on_the_same_key`).
    Ce rămâne testat aici e că fluxul NU e numit înțepenit, nu că cheia lipsește.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    results = []
    for _ in range(4):
        _patch_ship(monkeypatch,
                    [_sc_lag(56882, pending=1, oldest_min=5, stream="incidents")])
        results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:incidents:stall")
    assert stall is not None and stall.status == "ok", (
        "un flux cu un singur rând restant, care nu se înmulțește, a fost numit "
        "înțepenit")
    r = _key(results, "ship:lag:incidents")
    assert r is not None and r.status == "ok"


def test_a_mutable_stream_whose_watermark_advances_is_not_a_stall(monkeypatch):
    """Cauza celor 7 alerte `incidents:stall` din 28 august.

    Pe un flux mutabil cursorul e PERECHEA `(cursor_at, cheie)`. Jumătatea-cheie
    repornește la fiecare filigran nou de la ultimul rând al lotului, deci un
    incident deschis care se actualizează des o ține pe aceeași valoare rundă
    după rundă — în timp ce poziția reală înaintează. Măsurat pe gazdă: alerta
    spunea „a rămas la valoarea 56882" în timp ce `collector_cursors` avea
    `ship:incidents` cu `cursor = 54661`, scris cu cinci minute mai târziu.

    Comparată pe pereche, poziția asta e în mișcare și nu e o înțepenire.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    results = []
    for minute in (10, 15, 20, 25):
        item = StreamLag(
            stream="incidents", cursor=56882, floor=None, pending=3 + minute,
            oldest_pending_min=8.0, clock_ahead_s=0.0,
            cursor_at=datetime(2026, 8, 28, 12, minute, tzinfo=timezone.utc),
            updated_at_trigger=True)
        _patch_ship(monkeypatch, [item])
        results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:incidents:stall")
    assert stall is not None and stall.status == "ok", (
        "un flux mutabil al cărui filigran înaintează a fost numit înțepenit "
        "fiindcă doar jumătatea-cheie a cursorului arăta la fel")


def test_a_mutable_stream_whose_whole_position_is_frozen_is_still_caught(monkeypatch):
    """Reparația de mai sus nu are voie să lase fluxurile mutabile neacoperite.

    Dacă stă și `cursor_at`, și cheia, fluxul chiar e oprit — și trebuie spus,
    altfel copia din afara gazdei încetează să crească fără ca nimeni să afle.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    results = []
    for pending in (4, 30, 90):
        item = StreamLag(
            stream="incidents", cursor=56882, floor=None, pending=pending,
            oldest_pending_min=25.0, clock_ahead_s=0.0,
            cursor_at=datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc),
            updated_at_trigger=True)
        _patch_ship(monkeypatch, [item])
        results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:incidents:stall")
    assert stall is not None and stall.status == "degraded", (
        "un flux mutabil cu poziția întreagă înghețată și restanța în creștere "
        "nu a mai fost prins")


def test_a_stall_is_not_declared_inside_one_shipping_round(monkeypatch):
    """Pragul numără PRIVIRI, iar o privire nu e o rundă de expediere.

    Temporizatorul autodiagnosticului e la 5 minute, deci trei priviri înseamnă
    ~15 minute — pe orice gazdă, oricât de rar ar expedia expeditorul. Cu un
    `interval_s` de 10 minute pus de operator, pragul cade SUB o singură rundă
    normală, iar constatarea s-ar aprinde pe purtarea corectă a mecanismului.
    Aceeași podea o are deja pragul de vârstă.

    De la 23 septembrie 2026, `:stall` se scrie `ok` chiar și sub podeaua asta —
    vezi `test_a_frozen_cursor_with_a_backlog_that_does_not_grow_is_not_a_stall`
    pentru motiv. Ce testează linia de mai jos e că nicio apariție a cheii nu e
    `degraded`, nu că cheia lipsește.
    """
    db = _StallDB()
    cfg = _cfg(ship=SimpleNamespace(enabled=True, url="https://agg.invalid",
                                    interval_s=600))
    results = []
    for pending in (5, 40, 120):
        _patch_ship(monkeypatch, [_sc_lag(200, pending=pending, oldest_min=12)])
        results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None and stall.status == "ok", (
        "constatarea de înțepenire s-a aprins înainte să fi trecut trei runde de "
        "expediere — pe un interval lung, asta e funcționarea normală")


def test_the_stall_message_agrees_with_its_own_numbers(monkeypatch):
    """Textul trimis operatorului spunea „deși 1 randuri asteapta".

    Canalul ăsta e singurul prin care agentul poate spune ceva. Un mesaj care nu
    se acordă cu propriul lui număr se citește ca un mesaj pe care nu-l verifică
    nimeni, iar încrederea în canal e o proprietate de funcționare.
    """
    assert checks._numar(1, "rând", "rânduri") == "1 rând"
    assert checks._numar(3, "rând", "rânduri") == "3 rânduri"
    assert checks._numar(19, "rând", "rânduri") == "19 rânduri"
    assert checks._numar(20, "rând", "rânduri") == "20 de rânduri"
    assert checks._numar(101, "rând", "rânduri") == "101 rânduri"
    assert checks._numar(120, "rând", "rânduri") == "120 de rânduri"
    assert checks._numar(0, "rând", "rânduri") == "0 rânduri"

    db = _StallDB()
    cfg = _ship_cfg()
    results = []
    for pending in (1, 21, 21):
        _patch_ship(monkeypatch, [_sc_lag(200, pending=pending, oldest_min=30)])
        results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None, "cazul de acord nu a mai produs constatarea testată"
    assert "de la 1 rând la 21 de rânduri" in stall.detail, stall.detail
    assert "1 rânduri" not in stall.detail


def test_a_cursor_that_advances_a_little_each_run_is_never_a_stall(monkeypatch):
    """Non-regresia critică: o restanță care se scurge NU e o înțepenire.

    Miezul reparației. `updated_at` e scris necondiționat de expeditor la fiecare
    upsert, deci un detector clădit pe el ar numi înțepenit orice flux care e doar
    în urmă. Semnalul e VALOAREA cursorului: dacă avansează — chiar și cu puțin,
    chiar rămânând mereu în urmă — fluxul se mișcă și nu e blocat.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    saw_stall = False
    for cursor in (100, 101, 102, 103, 104):
        _patch_ship(monkeypatch, [_sc_lag(cursor, pending=5, oldest_min=400)])
        results = run(checks.check_ship_lag(db, cfg))
        stall = _key(results, "ship:lag:session_commands:stall")
        assert stall is not None and stall.status == "ok", (
            "cheia de înțepenire lipsește sau nu e ok pe un cursor care avansează")
        if stall.bad:
            saw_stall = True

    assert not saw_stall, (
        "un flux al cărui cursor avansează la fiecare rundă a fost numit înțepenit")
    assert _key(results, "ship:lag:session_commands").status == "degraded"


def test_another_stream_keeps_the_fifteen_minute_age_threshold(monkeypatch):
    """Harta de excepții nu are voie să slăbească restul fluxurilor.

    Pragul de 6h e DOAR pentru `session_commands`. Un alt flux în urmă cu 20 de
    minute rămâne o constatare la 15 minute — altfel ridicarea pragului pentru
    unul singur ar fi înmuiat tăcut sensibilitatea tuturor.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    for cursor in (100, 130):
        _patch_ship(monkeypatch,
                    [_sc_lag(cursor, pending=5, oldest_min=20, stream="incidents")])
        results = run(checks.check_ship_lag(db, cfg))

    r = _key(results, "ship:lag:incidents")
    assert r is not None and r.status == "degraded", (
        "20 de minute pe un flux obișnuit nu a mai fost o constatare — harta de "
        "excepții a slăbit pragul altui flux decât cel numit")
    stall = _key(results, "ship:lag:incidents:stall")
    assert stall is not None and stall.status == "ok"


def test_the_stall_counter_resets_when_the_cursor_moves_again(monkeypatch):
    """Un flux care se dezgheață nu rămâne marcat înțepenit.

    Fără reset, un flux care s-a mișcat greu o rundă-două și apoi și-a revenit ar
    fi ținut o constatare aprinsă pe o problemă care a trecut — exact felul de
    alarmă care sună degeaba. Cursorul înghețat 2 rulări, apoi se mișcă: contorul
    revine la zero, fără constatare.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    for _ in range(2):
        _patch_ship(monkeypatch, [_sc_lag(300, pending=5, oldest_min=30)])
        run(checks.check_ship_lag(db, cfg))
    assert db.store["ship:session_commands:stall"]["events_seen"] >= 1

    _patch_ship(monkeypatch, [_sc_lag(305, pending=5, oldest_min=30)])
    results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None and stall.status == "ok", (
        "un flux care a înaintat din nou e încă raportat înțepenit")
    assert db.store["ship:session_commands:stall"]["events_seen"] == 0, (
        "contorul de rulări-fără-mișcare nu a revenit la zero după ce cursorul s-a mișcat")


def test_a_registry_row_written_before_the_baseline_existed_forces_a_reset(monkeypatch):
    """Prima rulare după deploy alarma pe o creștere pe care n-o măsurase nimeni.

    Rândurile `ship:<flux>:stall` lăsate de versiunea dinainte țin doar poziția,
    fără restanța de referință. Pe un flux append-only poziția E `str(cursor)`,
    deci un asemenea rând se potrivea cu poziția de acum: contorul de priviri se
    moștenea, restanța de referință ieșea 0, iar „a crescut de la 0" e adevărat
    pentru orice restanță nenulă. Rezultatul e chiar falsul pozitiv pe care
    restanța de referință îl repară, aprins permanent pe fluxurile append-only.

    Datele sunt cele citite pe gazdă pe 28 august 2026: toate cele 12 rânduri erau
    în formatul vechi, `ship:session_commands:stall` avea `cursor = 2984543` fără
    `#`, iar prima rulare după deploy trimitea „a rămas pe loc în 6 rulări la rând,
    iar restanța a crescut în tot acest timp de la 0 rânduri la 1 rând".
    """
    db = _StallDB()
    db.store["ship:session_commands:stall"] = {"cursor": "2984543", "events_seen": 5}
    cfg = _ship_cfg()
    _patch_ship(monkeypatch, [_sc_lag(2984543, pending=1, oldest_min=30)])

    results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None and stall.status == "ok", (
        "rândul lăsat de versiunea dinainte a fost citit ca o măsurătoare proprie, "
        "iar prima rulare după deploy a alarmat pe o creștere de la un zero fabricat")
    mark = db.store["ship:session_commands:stall"]
    assert mark["events_seen"] == 0, (
        "contorul de priviri din rândul vechi a fost moștenit, deci o măsurătoare "
        "pe care detectorul n-a făcut-o rămâne în rând")
    assert mark["cursor"] == "1#2984543", (
        "restanța de referință nu a fost scrisă la reset, deci rulările următoare "
        "ar porni iar de la zero")

    # Direct pe citirea rândului, fiindcă asta e proprietatea: o valoare din care
    # nu se poate scoate restanța de referință nu e o măsurătoare, deci nu are voie
    # să se potrivească cu nimic. „Poziția ei, cu restanța 0" e o măsurătoare
    # inventată, iar pe un flux append-only e chiar poziția de acum.
    assert checks._stall_mark("2984543") is None
    assert checks._stall_mark("nu-i-numar#2984543") is None
    assert checks._stall_mark(None) is None
    assert checks._stall_mark("1#2984543") == ("2984543", 1)


def test_after_that_reset_a_backlog_that_really_grows_is_still_caught(monkeypatch):
    """Perechea: resetul nu are voie să însemne „nu mai alarmează niciodată".

    Un rând vechi îmbătrânit într-o gazdă chiar înțepenită trebuie să producă
    constatarea — doar că măsurată de la restanța pe care detectorul a văzut-o el,
    nu de la una presupusă. Aceeași poziție de pe gazdă, trei priviri, restanță
    care chiar crește.
    """
    db = _StallDB()
    db.store["ship:session_commands:stall"] = {"cursor": "2984543", "events_seen": 5}
    cfg = _ship_cfg()
    results = []
    for pending in (1, 4, 9):
        _patch_ship(monkeypatch, [_sc_lag(2984543, pending=pending, oldest_min=30)])
        results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None and stall.status == "degraded", (
        "după resetul forțat de rândul vechi, o înțepenire adevărată nu mai e prinsă")
    assert stall.facts["stall_runs"] == 3 and stall.facts["pending_at_freeze"] == 1, (
        f"numărat greșit după reset: {stall.facts}")
    assert "de la 1 rând la 9 rânduri" in stall.detail, stall.detail


def test_the_second_consecutive_look_is_not_yet_a_stall(monkeypatch):
    """Pragul de trei priviri trebuie ținut și de dedesubt, nu doar de deasupra.

    O privire e a temporizatorului de autodiagnostic, care e la 5 minute: trei
    priviri înseamnă un cursor nemișcat de ~15 minute. Aprinsă la a doua, aceeași
    alertă ar pleca după ~5 minute — adică peste o singură rundă de expediere care
    poate fi doar înceată, și atunci constatarea se aprinde pe funcționarea normală.

    De la 23 septembrie 2026, a doua privire scrie `ok` pe `:stall` (nu mai
    lipsește — vezi `test_a_frozen_cursor_with_a_backlog_that_does_not_grow_is_not_a_stall`),
    deci ce se verifică e statusul, nu prezența cheii.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    results = []
    for pending in (5, 40):
        _patch_ship(monkeypatch, [_sc_lag(200, pending=pending, oldest_min=30)])
        results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None and stall.status == "ok", (
        "constatarea de înțepenire s-a aprins la a doua privire — alerta pleacă "
        "după ~5 minute în loc de ~15")

    _patch_ship(monkeypatch, [_sc_lag(200, pending=120, oldest_min=30)])
    results = run(checks.check_ship_lag(db, cfg))
    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None and stall.facts["stall_runs"] == 3, (
        "a treia privire nu mai e constatarea de înțepenire — pragul s-a mutat")


def test_the_backlog_messages_agree_with_their_own_numbers(monkeypatch):
    """Acordul a fost aplicat doar în mesajul de înțepenire, nu și în restanță.

    Mesajele de restanță sunt cele pe care operatorul le primește de departe cel
    mai des, iar cu un singur rând spuneau „1 rânduri neexpediate". Un text care
    nu se acordă cu propriul lui număr se citește ca un text pe care nu-l verifică
    nimeni, iar canalul ăsta e singurul prin care agentul poate spune ceva.
    """
    db = _StallDB()
    cfg = _ship_cfg()

    _patch_ship(monkeypatch, [_sc_lag(100, pending=1, oldest_min=1)])
    results = run(checks.check_ship_lag(db, cfg))
    r = _key(results, "ship:lag:session_commands")
    assert r is not None and r.status == "ok", "cazul de sub prag nu mai e cel testat"
    assert "1 rând în curs de expediere" in r.detail, r.detail

    _patch_ship(monkeypatch, [_sc_lag(110, pending=1, oldest_min=420)])
    results = run(checks.check_ship_lag(db, cfg))
    r = _key(results, "ship:lag:session_commands")
    assert r is not None and r.status == "degraded", "cazul de peste prag nu mai e cel testat"
    assert "1 rând neexpediat," in r.detail, r.detail
    assert "1 rânduri" not in r.detail

    _patch_ship(monkeypatch, [_sc_lag(120, pending=21, oldest_min=420)])
    results = run(checks.check_ship_lag(db, cfg))
    r = _key(results, "ship:lag:session_commands")
    assert "21 de rânduri neexpediate," in r.detail, r.detail


# --- panoul web: cât de tare are voie să strige o pagină lentă --------------
#
# Pe 28 august 2026, la 21:24, autoverificarea a trimis „SENTINEL NU
# FUNCȚIONEAZĂ COMPLET" fiindcă pagina principală trecuse de
# `proxy_read_timeout`. În aceleași minute, măsurat pe gazdă: `/healthz` în 7 ms,
# toate unitățile active cu `NRestarts=0`, cititorul Suricata în avans, nicio
# altă intrare din `selfcheck_state` diferită de `ok`. Cauza era că pagina are
# șase interogări lente — reală, dar nu „gazda nu mai e apărată".
#
# Lanțul care face din `down` un telefon la 3 dimineața: `runner._announce`
# ridică mesajul la `critical` dacă ORICE constatare e `down`, iar
# `quiet.NEVER_MUTED_SEVERITIES` lasă `critical` să treacă peste orice mute.
# Testele de aici păzesc capătul lanțului, nu o constantă dintr-un fișier: dacă
# verdictul urcă înapoi la `down`, primul dintre ele pică.

#: Cele trei feluri în care panoul e o constatare. Numărul e verificat în test:
#: o listă golită prin editare ar face buclele să treacă uitându-se la nimic —
#: chiar tiparul „listă parametrizată ieșită goală și sărită tăcut".
_SCENARII_PANOU = ("lent", "eroare", "expirat")

#: `proxy_read_timeout` așa cum e în cod, capturat înainte ca vreun test să-l
#: coboare pentru scenariul „expirat". Fără el, ordinea scenariilor din buclă ar
#: decide rezultatul celorlalte.
_PROXY_NORMAL = checks.DASHBOARD_PROXY_TIMEOUT_S


class _Ceas:
    """`time.monotonic` scriptat, ca durata măsurată să nu ceară așteptare reală."""

    def __init__(self, *valori: float) -> None:
        self.valori = list(valori)

    def __call__(self) -> float:
        return self.valori.pop(0) if len(self.valori) > 1 else self.valori[0]


def _sonda_paginii(monkeypatch, *, secunde: float, boom: Exception | None = None):
    """Înlocuiește `page.load` și ceasul, ca sonda să „măsoare" `secunde`."""
    from sentinel.analytics import page

    async def fals(db):  # noqa: ANN001, ANN202
        if boom is not None:
            raise boom
        return {}

    monkeypatch.setattr(page, "load", fals)
    monkeypatch.setattr(checks, "DASHBOARD_PROXY_TIMEOUT_S", _PROXY_NORMAL)
    # Se înlocuiește NUMELE `time` din `checks`, nu funcția din modulul `time`:
    # `asyncio.wait_for` își ia ceasul tot de acolo, iar un ceas scriptat sub
    # bucla de evenimente face testul să măsoare altceva decât crede.
    monkeypatch.setattr(checks, "time", SimpleNamespace(monotonic=_Ceas(0.0, secunde)))


def _constatarea_panoului(monkeypatch, scenariu: str, db=None):
    """Rulează sonda panoului în scenariul numit și întoarce constatarea."""
    from sentinel.analytics import page

    tinta = _StateDB() if db is None else db
    if scenariu == "expirat":
        async def atarna(_db):  # noqa: ANN001, ANN202
            await asyncio.sleep(5)

        monkeypatch.setattr(page, "load", atarna)
        monkeypatch.setattr(checks, "DASHBOARD_PROXY_TIMEOUT_S", 0.05)
    elif scenariu == "eroare":
        _sonda_paginii(monkeypatch, secunde=checks.DASHBOARD_SLOW_S + 1,
                       boom=RuntimeError("canceling statement due to statement timeout"))
    elif scenariu == "lent":
        _sonda_paginii(monkeypatch, secunde=checks.DASHBOARD_SLOW_S + 1)
    else:  # pragma: no cover - o greșeală de scriere în test, nu o stare a gazdei
        raise AssertionError(f"scenariu necunoscut: {scenariu}")
    rezultate = run(checks.check_dashboard_latency(tinta))
    assert len(rezultate) == 1, f"scenariul „{scenariu}” nu a emis exact o cheie"
    return rezultate[0]


def _notificarea(db):
    """(severitate, text) din ultimul rând scris în `notifications`."""
    for sql, a in reversed(db.sql):
        if "INSERT INTO notifications" in sql:
            return a[0], a[-1]
    raise AssertionError("runner-ul n-a scris nicio notificare")


def test_a_slow_dashboard_never_pierces_the_operators_quiet_hours(monkeypatch):
    """O pagină lentă nu are voie să sune noaptea la operator.

    Eșecul pe care îl previne, trăit pe 28 august 2026 la 21:24, în fereastra de
    liniște 21:00-09:00: panoul era lent, iar operatorul a primit „SENTINEL NU
    FUNCȚIONEAZĂ COMPLET" — despre un agent care detecta, ingera, bloca și
    alerta perfect. Un roșu care nu e adevărat e cum ajunge operatorul să nu mai
    citească roșul următor, iar următorul poate fi chiar cel în care gazda nu mai
    e apărată.

    Se verifică LANȚUL, nu o constantă: verdictul verificării intră în
    `runner._announce`, severitatea pe care ACELA o scrie în `notifications`
    intră în `quiet.passes_anyway`. Dacă vreun verdict al panoului urcă înapoi la
    `down`, severitatea devine `critical`, `critical` e în
    `NEVER_MUTED_SEVERITIES`, și testul pică aici — nu peste trei luni, în chat.
    """
    from sentinel.selfcheck import runner
    from sentinel.telegram.quiet import NEVER_MUTED_SEVERITIES, passes_anyway

    assert len(_SCENARII_PANOU) == 3, "bucla de mai jos s-a golit prin editare"
    for scenariu in _SCENARII_PANOU:
        db = _StateDB()
        r = _constatarea_panoului(monkeypatch, scenariu, db)
        assert r.bad, (
            f"scenariul „{scenariu}” nu mai e o constatare deloc; operatorul nu "
            f"mai află nici dimineața că panoul e stricat")

        run(runner._announce(db, _cfg(), [r], []))
        severitate, text = _notificarea(db)

        assert severitate not in NEVER_MUTED_SEVERITIES, (
            f"scenariul „{scenariu}” produce severitatea „{severitate}”, care e "
            f"în `NEVER_MUTED_SEVERITIES` — deci trece peste fereastra de "
            f"liniște și îl trezește pe operator pentru o pagină web")
        assert not passes_anyway(severitate, "selfcheck"), (
            f"scenariul „{scenariu}” trece prin mute pe altă cale decât "
            f"severitatea")
        assert text.splitlines()[0].startswith(runner._EMOJI["degraded"]), (
            f"scenariul „{scenariu}” încă deschide mesajul cu titlul de pană "
            f"totală: {text.splitlines()[0]!r}")


def test_a_slow_page_and_a_page_that_never_arrived_stay_two_states(monkeypatch):
    """Dimineața, operatorul trebuie să poată deosebi „lent" de „n-a venit deloc".

    Eșecul pe care îl previne: coborârea severității topește cele trei ramuri
    într-un singur galben. Operatorul care citește la 09:00 nu mai poate spune
    dacă pagina a fost greoaie sau dacă nginx a răspuns 504 tuturor — adică nu
    mai poate spune dacă panoul a fost folosibil în timpul nopții, care e chiar
    întrebarea pe care și-o pune.

    Se verifică pe DECIZIE, nu pe prezența unui câmp: `facts["mod"]` trebuie să
    fie din vocabularul declarat, diferit pentru fiecare ramură, iar cele două
    ramuri în care operatorul n-a primit nimic trebuie să fie exact cele din
    `DASHBOARD_MODES_FAILED`.
    """
    assert len(_SCENARII_PANOU) == 3, "bucla de mai jos s-a golit prin editare"
    assert set(checks.DASHBOARD_MODES_FAILED) < set(checks.DASHBOARD_MODES), (
        "`DASHBOARD_MODES_FAILED` nu mai e o submulțime strictă a vocabularului")

    moduri: dict[str, str] = {}
    titluri: dict[str, str] = {}
    for scenariu in _SCENARII_PANOU:
        r = _constatarea_panoului(monkeypatch, scenariu)
        moduri[scenariu] = r.facts["mod"]
        titluri[scenariu] = r.title

    assert set(moduri.values()) <= set(checks.DASHBOARD_MODES), (
        f"o ramură și-a inventat un mod pe care panoul nu-l cunoaște: {moduri}")
    assert len(set(moduri.values())) == 3, (
        f"două ramuri raportează același mod, deci distincția s-a pierdut: {moduri}")
    assert len(set(titluri.values())) == 3, (
        f"două ramuri au același titlu, deci mesajul din chat nu le mai "
        f"deosebește: {titluri}")

    assert moduri["lent"] not in checks.DASHBOARD_MODES_FAILED, (
        "o pagină care s-a încărcat târziu e numărată drept pagină nelivrată")
    for scenariu in ("eroare", "expirat"):
        assert moduri[scenariu] in checks.DASHBOARD_MODES_FAILED, (
            f"scenariul „{scenariu}” nu mai e numărat drept pagină nelivrată, "
            f"deci dimineața arată la fel ca una doar lentă")


def test_a_dashboard_oscillating_around_the_threshold_speaks_once(monkeypatch):
    """O singură cauză neîntreruptă are voie la un singur mesaj.

    Eșecul pe care îl previne, măsurat pe 28 august 2026: `runner.run_and_alert`
    raportează pe SCHIMBARE de stare, iar durata încărcării e un semnal continuu
    care oscilează. Aceeași cauză nereparată a produs 6 mesaje în 7 ore. Un canal
    care repetă aceeași veste la fiecare cinci minute e un canal pe care
    operatorul îl închide, și atunci nu mai ajunge la el nici vestea următoare.

    Cealaltă jumătate, în același test: histerezisul nu are voie să înțepenească
    galbenul. O pagină care chiar și-a revenit trebuie să producă revenirea.
    """
    from sentinel.selfcheck import runner

    db = _StateDB()
    intre_praguri = (checks.DASHBOARD_RECOVER_S + checks.DASHBOARD_SLOW_S) / 2
    for durata in (checks.DASHBOARD_SLOW_S + 1, intre_praguri,
                   checks.DASHBOARD_SLOW_S + 1, intre_praguri,
                   checks.DASHBOARD_SLOW_S + 1, intre_praguri):
        _sonda_paginii(monkeypatch, secunde=durata)
        (r,) = run(checks.check_dashboard_latency(db))
        monkeypatch.setattr(runner, "run_groups", _outcome([r]))
        run(runner.run_and_alert(db, _cfg()))

    assert len(db.notifications) == 1, (
        f"șase rulări cu aceeași cauză au produs {len(db.notifications)} mesaje; "
        f"pragul n-are histerezis, deci oscilația în jurul lui devine zgomot")

    _sonda_paginii(monkeypatch, secunde=checks.DASHBOARD_RECOVER_S - 1)
    (r,) = run(checks.check_dashboard_latency(db))
    assert r.status == "ok", (
        f"pagina a coborât sub pragul de revenire și tot „{r.status}” rămâne; "
        f"histerezisul a înțepenit galbenul")
    monkeypatch.setattr(runner, "run_groups", _outcome([r]))
    run(runner.run_and_alert(db, _cfg()))
    assert len(db.notifications) == 2, "revenirea reală nu i-a fost spusă nimănui"


def test_the_hysteresis_holds_a_finding_but_never_invents_or_hides_one(monkeypatch):
    """Histerezisul are voie să întârzie o revenire, nimic mai mult.

    Eșecul pe care îl previne: un histerezis care se aplică pe partea greșită.
    Dacă ar ține și în lipsa unei constatări de dinainte, ar aprinde galben pe o
    gazdă sănătoasă; dacă ar muta pragul de intrare, o pagină chiar lentă ar
    trece drept bună și operatorul ar afla abia la 504 — adică pana din 25
    august, cu o verificare verde lângă ea.

    Și cazul „nu pot citi ce am raportat data trecută": recitirea stării poate
    eșua. Atunci se aplică pragul scris, care e verdictul măsurat — se pierde
    doar amortizarea, nu constatarea.
    """
    intre_praguri = (checks.DASHBOARD_RECOVER_S + checks.DASHBOARD_SLOW_S) / 2

    # Fără o constatare de dinainte, banda de sub prag e `ok`.
    db = _StateDB()
    _sonda_paginii(monkeypatch, secunde=intre_praguri)
    (r,) = run(checks.check_dashboard_latency(db))
    assert r.status == "ok", (
        f"o gazdă care n-a fost niciodată degradată a ieșit „{r.status}” la "
        f"{intre_praguri}s; histerezisul inventează constatări")

    # Cu una, aceeași durată se ține — și spune că se ține, nu se dă drept nouă.
    db.state["web:dashboard"] = {
        "key": "web:dashboard", "status": "degraded", "title": "x", "detail": "",
        "since": NOW, "last_alert_at": None, "stale": False}
    _sonda_paginii(monkeypatch, secunde=intre_praguri)
    (r,) = run(checks.check_dashboard_latency(db))
    assert r.status == "degraded" and r.facts["mod"] == "revine", (
        f"constatarea de dinainte nu se mai ține: {r.status}/{r.facts.get('mod')}")

    class _Oarba:
        """O bază din care starea de dinainte nu se poate citi."""

        async def fetchrow(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
            raise RuntimeError("pool epuizat")

    # Citire imposibilă: rămâne pragul scris. Nici ținut, nici ascuns.
    _sonda_paginii(monkeypatch, secunde=intre_praguri)
    (r,) = run(checks.check_dashboard_latency(_Oarba()))
    assert r.status == "ok", (
        f"o citire de stare eșuată a produs „{r.status}”; verdictul nu mai e "
        f"durata măsurată, ci o presupunere")

    # Peste prag rămâne peste prag, oricât de necitibilă e starea de dinainte.
    _sonda_paginii(monkeypatch, secunde=checks.DASHBOARD_SLOW_S + 1)
    (r,) = run(checks.check_dashboard_latency(_Oarba()))
    assert r.status == "degraded" and r.facts["mod"] == "lent", (
        f"pragul de intrare s-a mutat: {checks.DASHBOARD_SLOW_S + 1}s a ieșit "
        f"„{r.status}”")
