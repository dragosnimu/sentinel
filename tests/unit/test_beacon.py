"""Expeditorul semnalului către martorul extern.

Testul cel mai important din fișier e vectorul de referință: semnătura
calculată de Python trebuie să fie identică cu cea calculată de martorul scris
în TypeScript. Dacă cele două capete serializează diferit — o cheie nesortată,
un spațiu, un număr formatat altfel — semnătura nu se verifică NICIODATĂ, iar
eroarea arată exact ca o cheie greșită. Se pierde o zi căutând în locul
nepotrivit.

Valoarea de mai jos a fost calculată o dată cu ambele implementări și verificată
că se potrivesc. Dacă se schimbă, unul dintre capete a deviat.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from sentinel.report import beacon

# Sarcină fixă, cu forme variate: șiruri, întregi, obiect imbricat, două puncte
# în valoare. Ordinea cheilor aici e deliberat AMESTECATĂ — dacă forma canonică
# nu sortează, testul de mai jos cade.
PAYLOAD = {
    "sent_at": "2026-08-10T06:00:00+00:00",
    "max_age_s": 120,
    "interval_s": 60,
    "last_event_id": 4192883,
    "detect_cursor": 4192801,
    "incidents_open": 3,
    "blocklist_size": 17,
    "audit_head": "sha256:abc",
    "seq": 18342,
    "selfcheck": {"worst": "ok", "checks": 32, "bad": 0,
                  "ran_at": "2026-08-10T05:58:00+00:00"},
}

# Calculat cu watcher/lib/verify.ts prin Node 24 pe exact sarcina de mai sus.
GOLDEN_SECRET = "cheie-de-test"
GOLDEN_SIGNATURE = "53f00ab0778b30854428c2a68f84c3dfe65e5b58ea57f4b964ae90ddd6cec337"


def run(c):
    return asyncio.run(c)


# --- contractul între cele două limbaje ------------------------------------
def test_signature_matches_the_typescript_watcher():
    """Vectorul de referință. Dacă pică, unul dintre capete a deviat, iar
    martorul va refuza tot ce primește fără să spună de ce."""
    assert beacon.sign(PAYLOAD, GOLDEN_SECRET) == GOLDEN_SIGNATURE


def test_canonical_form_sorts_keys_and_omits_whitespace():
    body = beacon.canonical(PAYLOAD).decode()
    assert body.startswith('{"audit_head":')
    assert ", " not in body and '": ' not in body
    # Ordinea de intrare nu are voie să conteze.
    shuffled = dict(reversed(list(PAYLOAD.items())))
    assert beacon.canonical(shuffled) == beacon.canonical(PAYLOAD)


def test_a_changed_field_changes_the_signature():
    """Banal, dar e proprietatea pentru care semnăm."""
    other = {**PAYLOAD, "last_event_id": PAYLOAD["last_event_id"] + 1}
    assert beacon.sign(other, GOLDEN_SECRET) != GOLDEN_SIGNATURE


def test_diacritics_survive_the_round_trip():
    """`ensure_ascii=False` de ambele părți. Cu escape pe o parte și fără pe
    cealaltă, orice sarcină cu diacritice ar pica verificarea."""
    p = {"nota": "autentificare reușită"}
    assert "reușită" in beacon.canonical(p).decode()


# --- colectarea contoarelor -----------------------------------------------
class _DB:
    def __init__(self, vals=None, row=None, fail=()):
        self.vals, self.row, self.fail = vals or {}, row, set(fail)

    async def fetchval(self, sql, *a):
        for bad in self.fail:
            if bad in sql:
                raise RuntimeError("relația nu există")
        for k, v in self.vals.items():
            if k in sql:
                return v
        return None

    async def fetchrow(self, sql, *a):
        return self.row


def _cfg(**over):
    b = SimpleNamespace(enabled=True, url="https://exemplu/beat",
                        interval_s=60, timeout_s=10, max_age_s=120)
    for k, v in over.items():
        setattr(b, k, v)
    return SimpleNamespace(beacon=b)


def test_collect_reads_the_counters_that_must_advance():
    db = _DB(vals={"max(id) FROM raw_events": 4192883,
                   "detect:events": 4192801,
                   "FROM incidents": 3,
                   "FROM blocklist": 17,
                   "FROM audit_log": "sha256:head"},
             row={"worst_status": "ok", "checks_run": 32, "checks_bad": 0,
                  "started_at": __import__("datetime").datetime(2026, 8, 10, 5, 58)})
    out = run(beacon.collect(db, _cfg()))
    assert out["last_event_id"] == 4192883
    assert out["detect_cursor"] == 4192801
    assert out["selfcheck"]["worst"] == "ok"
    assert out["audit_head"] == "sha256:head"


def test_a_missing_table_does_not_silence_the_beacon():
    """Pe o instalare parțială sau în timpul unei migrări, o interogare
    secundară poate eșua. Un heartbeat care tace din cauza asta produce exact
    alarma falsă pe care mecanismul trebuie să nu o dea."""
    db = _DB(vals={"max(id) FROM raw_events": 99}, fail=("FROM audit_log",))
    out = run(beacon.collect(db, _cfg()))
    assert out["last_event_id"] == 99
    assert out["audit_head"] == ""


def test_collect_never_returns_none_counters():
    """Baza goală, la prima pornire. Martorul compară numere; un `None` ajuns
    acolo devine o excepție pe cealaltă mașină."""
    out = run(beacon.collect(_DB(), _cfg()))
    for key in ("last_event_id", "detect_cursor", "incidents_open", "blocklist_size"):
        assert isinstance(out[key], int)


# --- trimiterea ------------------------------------------------------------
def test_an_unreachable_watcher_is_logged_not_raised(monkeypatch):
    """Un martor indisponibil nu are voie să devină o problemă a serverului
    monitorizat. Dacă găzduirea cade, Sentinel apără serverul ca înainte."""
    class _Boom:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **kw): raise OSError("fără rețea")

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _Boom)
    db = _DB(vals={"collector_cursors": 5})
    assert run(beacon.send_once(db, _cfg(), "s")) is False


def test_the_signature_header_is_sent(monkeypatch):
    seen = {}

    class _Ok:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, content=None, headers=None):
            seen["url"], seen["headers"], seen["body"] = url, headers, content
            return SimpleNamespace(status_code=200, text="")

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _Ok)
    db = _DB(vals={"collector_cursors": 7})
    assert run(beacon.send_once(db, _cfg(), "cheie")) is True
    assert beacon.SIGNATURE_HEADER in seen["headers"]
    assert seen["headers"]["Cache-Control"] == "no-store"
    # Semnătura trimisă trebuie să verifice corpul trimis.
    import json
    assert beacon.sign(json.loads(seen["body"]), "cheie") == seen["headers"][beacon.SIGNATURE_HEADER]


def test_disabled_beacon_exits_instead_of_looping():
    """Fără martor configurat, serviciul spune o dată în jurnal și iese. Unitatea
    are Restart=on-failure tocmai ca ieșirea asta să nu devină o buclă."""
    run(beacon.run_forever(_DB(), _cfg(enabled=False)))
    run(beacon.run_forever(_DB(), _cfg(url="")))


# --- integrarea în restul sistemului --------------------------------------
def test_the_unit_exists_and_is_registered():
    from pathlib import Path
    from sentinel.constants import SYSTEMD_UNITS
    from sentinel.__main__ import SERVICES

    assert "beacon" in SERVICES
    assert "sentinel-beacon.service" in SYSTEMD_UNITS
    unit = (Path(__file__).resolve().parents[2] / "deploy" / "systemd"
            / "sentinel-beacon.service").read_text(encoding="utf-8")
    # on-failure, nu always: vezi testul de mai sus.
    assert "Restart=on-failure" in unit


def test_selfcheck_skips_the_beacon_when_it_is_not_configured():
    """Altfel autodiagnosticul ar raporta „down" o unitate oprită intenționat —
    exact clasa de alarmă falsă reparată la sursele conduse de om."""
    import asyncio as _a
    from sentinel.selfcheck import checks

    cfg = SimpleNamespace(ai=SimpleNamespace(enabled=False),
                          beacon=SimpleNamespace(enabled=False))
    results = _a.run(checks.check_units(cfg))
    assert not any("beacon" in r.key for r in results)
