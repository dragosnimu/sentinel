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

# Calculat cu aggregator/lib/verify.ts prin Node 24 pe exact sarcina de mai sus.
#
# Sarcina NU s-a extins cu `instance_id`/`instance_label` odată cu E1.4, deși
# semnalul real le poartă acum. Valoarea de mai jos e un vector de aur măsurat o
# dată cu ambele implementări; rescrisă din partea Python, ar înceta să mai
# dovedească ceva despre partea TypeScript și ar deveni o aserțiune că Python e
# egal cu el însuși. Ce dovedește vectorul — că forma canonică sortează, nu pune
# spații și tratează la fel șiruri, întregi și obiecte imbricate — nu depinde de
# ce câmpuri sunt înăuntru. Câmpurile noi sunt acoperite de testele de mai jos,
# iar contractul de octeți dintre limbaje se reia cu vector nou în E2, unde
# `canonical()` se extrage în sentinel/report/signing.py.
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
    def __init__(self, vals=None, row=None, fail=(), execute_boom=None):
        self.vals, self.row, self.fail = vals or {}, row, set(fail)
        # Câte runde au cerut un număr de secvență. O rundă care n-a trimis
        # nimic nu are voie să consume unul, iar asta se poate observa doar
        # numărând apelurile.
        self.sequence_calls = 0
        # Ce a scris runda ca urmă a rezultatului: `{nume: (cursor, mod)}`, unde
        # `mod` e „set" sau „inc". Fără el, `_record_delivery` ar fi chemat pe o
        # bază falsă care n-are `execute`, excepția ar fi înghițită de propria ei
        # gardă, iar testele ar trece verzi peste o urmă care nu se scrie —
        # exact tiparul din CLAUDE.md.
        self.markers: dict[str, tuple[str, str]] = {}
        self.execute_boom = execute_boom

    async def fetchval(self, sql, *a):
        if beacon.SEQUENCE_KEY in a:
            self.sequence_calls += 1
        for bad in self.fail:
            if bad in sql:
                raise RuntimeError("relația nu există")
        for k, v in self.vals.items():
            if k in sql:
                return v
        return None

    async def fetchrow(self, sql, *a):
        return self.row

    async def execute(self, sql, *a):
        """Un upsert simulat care CITEȘTE instrucțiunea, nu unul care o ghicește.

        Prima variantă presupunea valoarea („dacă nu e `$2`, e zero"). Măsurat cu
        o mutație care schimba chiar literalul din `VALUES`: dublul întorcea în
        continuare zero, iar aserțiunea trecea verde peste o instrucțiune care
        scria altceva. Deci se ia ramura potrivită — `VALUES` la prima scriere,
        `DO UPDATE` la a doua — și literalul din ea.
        """
        import re

        if self.execute_boom:
            raise self.execute_boom
        name = a[0]
        if name in self.markers:
            body = sql.split("DO UPDATE", 1)[1]
        else:
            body = sql.split("VALUES", 1)[1].split("ON CONFLICT", 1)[0]

        if "+ 1)::text" in body:
            self.markers[name] = (str(int(self.markers[name][0]) + 1), "inc")
            return "UPDATE 1"
        if "EXCLUDED.cursor" in body or "$2" in body:
            self.markers[name] = (str(a[1]), "set")
            return "INSERT 0 1"
        literal = re.search(r"'([^']*)'", body)
        assert literal, f"instrucțiune fără valoare de scris: {sql}"
        self.markers[name] = (literal.group(1), "set")
        return "INSERT 0 1"


@pytest.fixture(autouse=True)
def _fresh_probe_counters():
    """Contoarele de eșec sunt stare de modul, iar un proces de test rulează
    toate testele în același. Fără curățarea asta, un test care lasă sonda pe „a
    eșuat de 2 ori" schimbă pragurile din următorul, și eșecul apare la cine n-a
    greșit."""
    beacon._probe_failures.clear()
    beacon._identity_failures = 0
    beacon._canonical_failures = 0
    yield
    beacon._probe_failures.clear()
    beacon._identity_failures = 0
    beacon._canonical_failures = 0


ID_A = "0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def _identity(monkeypatch, tmp_path):
    """Gazda are o identitate în majoritatea testelor, ca în producție.

    Se repointează CONSTANTA din `sentinel.identity`, nu funcția importată în
    beacon: altfel testele ar trece și peste un cititor complet stricat, adică
    ar afirma ceva despre un dublu în loc de despre codul livrat.
    """
    import sentinel.identity as identity

    target = tmp_path / "instance_id"
    target.write_text(ID_A + "\n", encoding="utf-8")
    monkeypatch.setattr(identity, "INSTANCE_ID_PATH", target)
    return target


def _cfg(label="", **over):
    b = SimpleNamespace(enabled=True, url="https://exemplu/beat",
                        interval_s=60, timeout_s=10, max_age_s=120)
    for k, v in over.items():
        setattr(b, k, v)
    return SimpleNamespace(beacon=b, instance_label=label)


def test_collect_reads_the_counters_that_must_advance():
    db = _DB(vals={"max(id) FROM raw_events": 4192883,
                   "detect:events": 4192801,
                   "FROM incidents": 3,
                   "FROM blocklist": 17,
                   # Coloana, nu doar tabela: cu „FROM audit_log" testul ăsta
                   # trecea și peste interogarea greșită care a rulat un an.
                   "entry_hash FROM audit_log": "sha256:head"},
             row={"worst_status": "ok", "checks_run": 32, "checks_bad": 0,
                  "started_at": __import__("datetime").datetime(2026, 8, 10, 5, 58)})
    out = run(beacon.collect(db, _cfg()))
    assert out["last_event_id"] == 4192883
    assert out["detect_cursor"] == 4192801
    assert out["selfcheck"]["worst"] == "ok"
    assert out["audit_head"] == "sha256:head"


def test_audit_head_is_the_head_of_the_hash_chain():
    """Sonda a cerut un an întreg coloana `hash`, care nu există — tabela are
    `prev_hash` și `entry_hash`. Postgres refuza interogarea la fiecare rundă,
    excepția era înghițită, iar martorul primea în locul capului de lanț un șir
    gol: singurul câmp care face scump un semnal fabricat lipsea din semnal.

    Baza falsă de aici răspunde DOAR la coloana corectă, deci testul cade dacă
    se cere altceva — nu se mulțumește cu „interogarea pomenește audit_log"."""
    db = _DB(vals={"SELECT entry_hash FROM audit_log": "9f" * 32})
    out = run(beacon.collect(db, _cfg()))
    assert out["audit_head"] == "9f" * 32
    # Și capul e definit ca în scriitorul lanțului: ultima intrare după `id`.
    assert "ORDER BY id DESC LIMIT 1" in beacon.AUDIT_HEAD_SQL


def test_a_missing_table_does_not_silence_the_beacon():
    """Pe o instalare parțială sau în timpul unei migrări, o interogare
    secundară poate eșua. Un heartbeat care tace din cauza asta produce exact
    alarma falsă pe care mecanismul trebuie să nu o dea."""
    db = _DB(vals={"max(id) FROM raw_events": 99}, fail=("FROM audit_log",))
    out = run(beacon.collect(db, _cfg()))
    assert out["last_event_id"] == 99
    # Semnalul pleacă întreg: martorul compară câmpuri, iar unul lipsă e o
    # excepție pe cealaltă mașină, adică tăcere din alt motiv.
    assert {"sent_at", "last_event_id", "detect_cursor", "incidents_open",
            "blocklist_size", "audit_head", "selfcheck"} <= set(out)


def test_a_failed_audit_probe_is_not_reported_as_an_empty_log():
    """„N-am putut citi" și „nu e nimic de citit" ajung amândouă la martor ca
    valoarea câmpului `audit_head`. Dacă sunt identice, un jurnal de audit șters
    și o sondă ruptă arată exact ca o instalare proaspătă, iar martorul nu are
    de unde ști că bariera anti-falsificare lipsește din semnal."""
    broken = run(beacon.collect(_DB(fail=("FROM audit_log",)), _cfg()))
    empty = run(beacon.collect(_DB(), _cfg()))

    assert broken["audit_head"] == beacon.AUDIT_HEAD_UNAVAILABLE
    assert empty["audit_head"] == ""
    assert broken["audit_head"] != empty["audit_head"]
    # Nu se poate confunda nici cu un cap real: acela are 64 de hexazecimale.
    assert len(beacon.AUDIT_HEAD_UNAVAILABLE) != 64


def test_a_probe_that_keeps_failing_stops_looking_like_a_blip(caplog):
    """Interogarea greșită a produs un WARNING la fiecare 60 de secunde timp de
    un an și n-a fost citită ca defect, fiindcă o sondă care a clipit o dată
    arată în jurnal exact la fel. La al treilea eșec consecutiv nu mai e o
    clipire, iar linia trebuie să spună asta."""
    db = _DB(fail=("FROM audit_log",))
    with caplog.at_level("INFO", logger="sentinel.report.beacon"):
        for _ in range(3):
            run(beacon.collect(db, _cfg()))

        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(errors) == 1, [r.getMessage() for r in caplog.records]
        assert errors[0].consecutive == 3

        # Iar când sonda merge din nou, contorul repornește — altfel următorul
        # defect real nu mai atinge niciun prag și nu se anunță niciodată.
        caplog.clear()
        run(beacon.collect(_DB(vals={"SELECT entry_hash FROM audit_log": "ab" * 32}),
                           _cfg()))
        assert beacon._probe_failures.get(beacon.AUDIT_HEAD_SQL, 0) == 0
        assert any(r.getMessage() == "beacon probe works again"
                   for r in caplog.records)


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


@pytest.fixture
def no_sleeping(monkeypatch):
    """O intrare neașteptată în buclă PICĂ, nu atârnă.

    Fără asta, un beacon care intră în buclă când n-ar trebui nu produce un test
    roșu: produce `asyncio.sleep(60)` la nesfârșit. Testul nu se termină
    niciodată, `pytest-timeout` nu e instalat, deci nimic nu-l mărginește —
    suita nu spune „FAILED", nu spune nimic, și rulează până o oprește cineva.
    Măsurat: cu poarta regresată la `and`, 75 de secunde fără nicio ieșire.

    Un test care prinde bug-ul atârnând e un test pe care nimeni nu-l vede
    picând. Geamăn cu fixture-ul din tests/unit/test_shipper.py.
    """
    async def _never(seconds):
        raise AssertionError(
            f"beaconul a intrat în buclă și a cerut o pauză de {seconds}s")

    monkeypatch.setattr(beacon.asyncio, "sleep", _never)


def test_disabled_beacon_exits_instead_of_looping(monkeypatch, no_sleeping):
    """Fără martor configurat, serviciul spune o dată în jurnal și iese. Unitatea
    are Restart=on-failure tocmai ca ieșirea asta să nu devină o buclă.

    Cheia se dă dinadins, deși testul nu e despre ea: fără ea, `get_secrets()`
    citește `/etc/sentinel/secrets.env` de pe mașina care rulează testul, nu
    găsește nimic, iar poarta se închide pe `not secret` — deci testul ar fi
    trecut și peste un `enabled` și un `url` ignorate complet. Aici SINGURUL
    motiv de ieșire trebuie să fie cel pe care îl numește testul.
    """
    monkeypatch.setattr(beacon, "get_secrets",
                        lambda *a, **k: SimpleNamespace(get=lambda *_: "cheie"))
    run(beacon.run_forever(_DB(), _cfg(enabled=False)))
    run(beacon.run_forever(_DB(), _cfg(url="")))


def test_a_beacon_without_a_key_exits_rather_than_signing_with_nothing(
        monkeypatch, no_sleeping):
    """A treia condiție a porții, până acum neacoperită. Cu o cheie goală HMAC-ul
    se calculează fără să se plângă nimeni, martorul refuză cu 401 la fiecare
    semnal, iar de pe server asta arată exact ca tăcere."""
    monkeypatch.setattr(beacon, "get_secrets",
                        lambda *a, **k: SimpleNamespace(get=lambda *_: ""))
    run(beacon.run_forever(_DB(), _cfg()))


# --- cine trimite: identitatea de instalare --------------------------------
class _Recorder:
    """Client HTTP fals care ține minte DACĂ a fost chemat, nu doar cu ce.

    Distincția e tot testul pentru ramura fără identitate: „n-a trimis" e o
    afirmație despre rețea, nu despre valoarea întoarsă.
    """

    calls: list[dict] = []
    status = 200

    def __init__(self, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, content=None, headers=None):
        _Recorder.calls.append({"url": url, "body": content, "headers": headers})
        return SimpleNamespace(status_code=_Recorder.status, text="")


@pytest.fixture
def http(monkeypatch):
    import httpx

    _Recorder.calls = []
    _Recorder.status = 200
    monkeypatch.setattr(httpx, "AsyncClient", _Recorder)
    return _Recorder


def test_the_beat_says_which_installation_it_is_from():
    """Fără `instance_id`, martorul pune semnalul în găleata `default`.

    Cu două servere, ambele istorii ajung acolo: contoarele unuia par să sară
    înapoi din cauza celuilalt, „a tăcut prea mult" nu se mai poate pune despre
    niciunul, iar operatorul se uită la un panou care descrie o mașină care nu
    există. Nimic nu raportează o defecțiune.
    """
    out = run(beacon.collect(_DB(), _cfg(label="prod-web-1")))
    assert out["instance_id"] == ID_A
    assert out["instance_label"] == "prod-web-1"


def test_the_header_carries_exactly_what_the_payload_claims(http):
    """Martorul cere `payload.instance_id == antetul` și dă 401 dacă diferă.

    Un 401 nu se vede de pe server ca o eroare de configurație: se vede ca
    tăcere, iar martorul o raportează ca alarmă critică „serverul a murit"
    despre un server care funcționează. Cele două valori se iau din același loc
    tocmai ca să nu poată devia.
    """
    import json

    assert run(beacon.send_once(_DB(vals={"collector_cursors": 3}), _cfg(), "k")) is True
    sent = http.calls[0]
    assert sent["headers"][beacon.INSTANCE_HEADER] == ID_A
    assert json.loads(sent["body"])["instance_id"] == ID_A
    assert sent["headers"][beacon.INSTANCE_HEADER] == json.loads(sent["body"])["instance_id"]


def test_the_two_places_the_identity_appears_come_from_one_read(http, monkeypatch):
    """Antetul și `payload.instance_id` trebuie să fie ACELAȘI octet, nu două
    citiri care de obicei sunt de acord.

    Martorul refuză cu 401 dacă diferă, iar de pe server un 401 nu se vede ca
    eroare de configurație — se vede ca tăcere, pe care martorul o raportează
    drept „serverul a murit". Două citiri pot să nu fie de acord: o rescriere a
    fișierului între ele, sau doar o linie mutată mai târziu în alt loc. Aici
    fișierul se schimbă între citiri dinadins, ca diferența să fie observabilă
    în loc de presupusă.
    """
    import json

    import sentinel.identity as identity

    class _Shifting:
        """Un „fișier" care întoarce altceva la a doua citire, și le numără."""

        def __init__(self):
            self.reads = 0

        def read_text(self, encoding="utf-8"):
            self.reads += 1
            return (ID_A if self.reads == 1 else "f" * 32) + "\n"

    shifting = _Shifting()
    monkeypatch.setattr(identity, "INSTANCE_ID_PATH", shifting)

    assert run(beacon.send_once(_DB(vals={"collector_cursors": 3}), _cfg(), "k")) is True
    sent = http.calls[0]
    assert sent["headers"][beacon.INSTANCE_HEADER] == json.loads(sent["body"])["instance_id"]
    assert shifting.reads == 1, \
        f"identitatea s-a citit de {shifting.reads} ori pentru un singur semnal"


def test_the_label_can_never_become_the_identity():
    """Eticheta vine din `sentinel.yaml`, pe care operatorul o editează.

    Dacă ar putea ajunge vreodată în poziția de identificator, oricine editează
    fișierul ăla ar putea muta serverul în istoria altuia — exact eșecul pentru
    care identitatea e o valoare aleatoare scrisă o dată, nu o setare.
    """
    impostor = "f" * 32
    out = run(beacon.collect(_DB(), _cfg(label=impostor)))
    assert out["instance_id"] == ID_A
    assert out["instance_id"] != impostor


def test_an_empty_label_does_not_change_the_shape_of_the_beat():
    """Eticheta e cosmetică și goală e o valoare validă — martorul cade înapoi
    pe id când o primește goală.

    Cheia se trimite oricum: un semnal a cărui FORMĂ depinde de configurație are
    două forme canonice, iar forma canonică e chiar lucrul peste care se
    semnează. Depanarea unei semnături care nu se verifică e deja destul de
    grea fără ca payload-ul să difere de la o gazdă la alta.
    """
    with_label = run(beacon.collect(_DB(), _cfg(label="prod-web-1")))
    without = run(beacon.collect(_DB(), _cfg(label="")))
    assert without["instance_label"] == ""
    assert set(with_label) == set(without)


def test_a_runaway_label_cannot_inflate_every_beat():
    """Martorul taie la 64 (`MAX_LABEL` în beat/route.ts), deci tot ce trece de
    atât e octeți plătiți la fiecare rundă pentru text pe care nimeni nu-l vede.
    """
    out = run(beacon.collect(_DB(), _cfg(label="x" * 500)))
    assert len(out["instance_label"]) == beacon.MAX_LABEL


def test_the_label_is_trimmed_before_it_is_measured():
    """Spațiul de la capete e invizibil în `sentinel.yaml` și e tăiat oricum de
    martor. Netăiat aici, s-ar număra în bugetul de 64 de caractere, deci o
    etichetă cu indentare accidentală ar ajunge trunchiată pe panou dintr-un
    motiv pe care nu-l vede nimeni citind configurația."""
    out = run(beacon.collect(_DB(), _cfg(label="  prod-web-1\n")))
    assert out["instance_label"] == "prod-web-1"

    padded = run(beacon.collect(_DB(), _cfg(label=" " * 40 + "y" * 64)))
    assert padded["instance_label"] == "y" * 64


@pytest.mark.parametrize(
    "value, expected",
    [(1, "1"), (1.5, "1.5"), (True, "True"),
     (__import__("datetime").date(2026, 8, 12), "2026-08-12")],
    ids=["int", "float", "bool", "date"])
def test_a_label_that_yaml_did_not_read_as_text_cannot_kill_the_beacon(value, expected):
    """`instance_label: 01` e un ÎNTREG pentru YAML, iar `2026-08-12` e o dată.

    `_coerce` din sentinel/config.py lasă neatinse valorile adnotate `str`, deci
    tipul ajunge așa cum l-a citit YAML. Un `.strip()` peste el ridica
    AttributeError, `send_once` prinde doar `IdentityError`, iar unitatea are
    `Restart=on-failure` cu `StartLimitBurst=10` în 300 s — deci un nume de
    server scris fără ghilimele ducea unitatea în `failed` și gazda în tăcere
    permanentă față de martor. O etichetă cosmetică nu are voie să poată opri
    semnalul.
    """
    out = run(beacon.collect(_DB(), _cfg(label=value)))
    assert out["instance_label"] == expected


def test_a_label_of_the_wrong_type_still_signs_and_sends(http):
    """Și pe drumul întreg, nu doar în `collect`: dacă excepția ar apărea mai
    târziu — la serializare, la semnare — rezultatul ar fi același proces mort."""
    assert run(beacon.send_once(_DB(vals={"collector_cursors": 3}),
                                _cfg(label=20260812), "k")) is True
    assert http.calls, "semnalul nu a plecat"


def test_a_beat_without_an_identity_never_reaches_the_network(http, _identity):
    """Cazul pe care se sprijină toată faza asta.

    Fișierul lipsește (gazdă instalată înaintea pasului 27). A trimite oricum ar
    însemna găleata `default`, adică istoria acestui server amestecată cu a
    oricărei alte gazde care nu se poate citi pe sine — eșecul pe care E1 există
    ca să-l scoată, deghizat în succes. Deci semnalul nu pleacă: nu se atinge
    rețeaua deloc, iar rezultatul e `False`, nu un succes neavut.
    """
    _identity.unlink()
    assert run(beacon.send_once(_DB(vals={"collector_cursors": 3}), _cfg(), "k")) is False
    assert http.calls == [], "un semnal fără nume a plecat oricum"


def test_a_round_without_an_identity_leaves_no_trace_of_one_that_sent(http, _identity):
    """Numărul de secvență e strict crescător și persistat.

    Consumat de o rundă care n-a trimis nimic, ar arăta la martor ca o gaură în
    secvență — adică exact ca semnalele pierdute pe care mecanismul le caută.
    """
    _identity.unlink()
    db = _DB(vals={"collector_cursors": 3})
    run(beacon.send_once(db, _cfg(), "k"))
    assert db.sequence_calls == 0


def test_the_beacon_recovers_the_moment_the_identity_appears(http, _identity):
    """Fișierul se recitește la fiecare rundă, dinadins.

    Citit o singură dată la pornire, o gazdă care primește identitatea la
    `--force-step 27` ar rămâne mută până când cineva își amintește să
    repornească serviciul — iar între timp martorul o raportează moartă.
    """
    _identity.unlink()
    db = _DB(vals={"collector_cursors": 3})
    assert run(beacon.send_once(db, _cfg(), "k")) is False

    _identity.write_text(ID_A + "\n", encoding="utf-8")
    assert run(beacon.send_once(db, _cfg(), "k")) is True
    assert http.calls[0]["headers"][beacon.INSTANCE_HEADER] == ID_A


def test_a_permanently_missing_identity_stops_looking_like_a_blip(caplog, http, _identity):
    """O gazdă fără identitate nu trimite NIMIC, la nesfârșit, în tăcere.

    În jurnal, prima rundă ratată arată identic cu a o suta. La al treilea eșec
    consecutiv linia trebuie să spună că nu e o clipire — și să poarte comanda
    care repară, fiindcă altfel operatorul citește „no instance identity" și nu
    are de unde ști ce se face cu asta.
    """
    _identity.unlink()
    db = _DB(vals={"collector_cursors": 3})
    with caplog.at_level("INFO", logger="sentinel.report.beacon"):
        for _ in range(3):
            run(beacon.send_once(db, _cfg(), "k"))
        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(errors) == 1, [r.getMessage() for r in caplog.records]
        assert errors[0].consecutive == 3
        # Ambele cauze, fiindcă tratamentul diferă: un deploy obișnuit creează
        # fișierul lipsă, dar unul care există și nu e o identitate nu se
        # rescrie de nimeni — instalatorul refuză dinadins, ca să nu distrugă o
        # valoare care poate a ajuns deja la un agregator.
        assert "deploy.sh" in errors[0].action
        assert "od -c" in errors[0].action

        # Iar când identitatea apare, contorul repornește: altfel următoarea
        # dispariție reală n-ar mai atinge niciun prag și n-ar fi anunțată.
        caplog.clear()
        _identity.write_text(ID_A, encoding="utf-8")
        run(beacon.send_once(db, _cfg(), "k"))
        assert beacon._identity_failures == 0
        assert any(r.getMessage() == "beacon has an instance identity again"
                   for r in caplog.records)


def test_a_malformed_identity_file_is_refused_rather_than_sent(http, _identity):
    """O scriere trunchiată lasă în urmă o valoare scurtă.

    Două identități trunchiate se pot ciocni între ele, iar ciocnirea nu se
    raportează nicăieri — deci o valoare de altă formă e la fel de inutilizabilă
    ca una lipsă, și nu are voie să plece pe fir.
    """
    _identity.write_text(ID_A[:10], encoding="utf-8")
    assert run(beacon.send_once(_DB(vals={"collector_cursors": 3}), _cfg(), "k")) is False
    assert http.calls == []


# --- ce nu se poate semna la fel la ambele capete --------------------------
def test_a_payload_the_two_ends_would_write_differently_never_leaves(http):
    """`beacon: {interval_s: 60.0}` scris în sentinel.yaml.

    Un float ajuns în payload se scrie `60.0` de Python și `60` de JavaScript.
    Azi martorul verifică HMAC peste octeții primiți, deci ar accepta; din E2
    agregatorul recalculează forma canonică și ar refuza TOT ce vine de la gazda
    asta, cu 401 — nedistinct de o cheie greșită. Deci semnalul se oprește aici,
    unde jurnalul poate numi câmpul, nu acolo unde nu poate.
    """
    db = _DB(vals={"collector_cursors": 3})
    assert run(beacon.send_once(db, _cfg(interval_s=60.0), "k")) is False
    assert http.calls == [], "un semnal pe care celălalt capăt nu-l poate reproduce a plecat"
    # Și nu consumă un număr de secvență: o rundă care n-a trimis nimic nu are
    # voie să lase în urmă gaura pe care martorul o citește ca semnal pierdut.
    assert db.sequence_calls == 0


def test_an_unsignable_payload_does_not_stop_the_loop_and_does_not_look_like_a_blip(
        caplog, http):
    """Runda se ratează, bucla nu — și al treilea eșec o spune.

    Dacă `CanonicalError` ar urca până în `run_forever`, serviciul ar muri, iar
    `Restart=on-failure` cu `StartLimitBurst=10` l-ar opri definitiv: martorul ar
    vedea o gazdă moartă și ar suna o alarmă critică despre un server sănătos.
    Iar fără contor, prima rundă refuzată arată în jurnal exact ca a suta.
    """
    db = _DB(vals={"collector_cursors": 3})
    bad = _cfg(interval_s=60.0)
    with caplog.at_level("INFO", logger="sentinel.report.beacon"):
        for _ in range(3):
            assert run(beacon.send_once(db, bad, "k")) is False
        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(errors) == 1, [r.getMessage() for r in caplog.records]
        assert errors[0].consecutive == 3
        # Mesajul trebuie să numească CÂMPUL, altfel operatorul are un payload
        # cu douăzeci de chei și nicio indicație care dintre ele.
        assert "interval_s" in errors[0].detail
        assert "60.0" in errors[0].action

        # Iar când configurația se repară, contorul repornește — altfel
        # următoarea regresie reală n-ar mai atinge niciun prag.
        caplog.clear()
        assert run(beacon.send_once(db, _cfg(), "k")) is True
        assert beacon._canonical_failures == 0
        assert any(r.getMessage() == "beacon payload is signable again"
                   for r in caplog.records)


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


# --- plafonul martorului are pereche pe gazda asta -------------------------
def test_the_two_ends_agree_on_the_beat_freshness_ceiling(tmp_path):
    """Un `beacon.max_age_s` peste plafonul martorului e refuzat AICI, la
    încărcare, nu acolo — unde refuzul poate fi complet tăcut.

    Ce se strică pentru operator fără borna asta, măsurat pe 15 august 2026 cu
    `beacon.max_age_s: 100000` (o confuzie milisecunde/secunde e plauzibilă;
    implicitul e 120) pe o instanță NOUĂ: martorul răspunde 400, `/status` rămâne
    200 „ok" cu instanța în `no-beat` — stare care nu se numără și nu alertează
    NICIODATĂ, dinadins — iar pe gazdă `run_forever` scrie doar în jurnal. Adică
    fiecare bătaie e refuzată și nicio suprafață nu o spune.

    De ce testul citește chiar fișierul martorului: numărul din `config.py` e
    scris ca să fie același cu al lui. Scris o dată în fiecare limbaj și
    neverificat, e o intenție, nu un invariant — și exact așa a stat până azi.
    """
    import re
    from pathlib import Path

    from sentinel.config import BeaconConfig, load_config
    from sentinel.errors import ConfigError

    route = (Path(__file__).resolve().parents[2] / "aggregator" / "app" / "api"
             / "sentinel" / "beat" / "route.ts").read_text(encoding="utf-8")

    # `finditer` plus unicitate, nu `search`: `search` ia PRIMA potrivire, deci
    # un literal de aceeași formă apărut mai devreme în fișier — într-un
    # docstring care explică limita, de pildă — ar umbri constanta reală, iar
    # testul ar compara cele două capete cu un număr dintr-un comentariu.
    found = [m.group(1) for m in re.finditer(
        r"^\s*(?:export )?const MAX_AGE_CEILING_S = ([\d_]+);", route, re.MULTILINE)]
    assert len(found) == 1, (
        f"MAX_AGE_CEILING_S: {len(found)} definiții literale în beat/route.ts — "
        "cu zero, testul n-ar avea ce compara; cu două, ar compara cu prima")
    ceiling = int(found[0].replace("_", ""))

    def write(body: str) -> Path:
        path = tmp_path / "sentinel.yaml"
        path.write_text(f"telegram:\n  enabled: false\nbeacon:\n{body}",
                        encoding="utf-8")
        return path

    # Exact plafonul martorului trebuie să fie configurabil...
    assert load_config(write(f"  max_age_s: {ceiling}\n")).beacon.max_age_s == ceiling

    # ...și un pas peste el trebuie refuzat aici, unde mesajul numește câmpul.
    with pytest.raises(ConfigError, match="beacon.max_age_s"):
        load_config(write(f"  max_age_s: {ceiling + 1}\n"))
    # Zero e cealaltă margine: ar face fiecare semnal vechi din clipa în care
    # pleacă, deci martorul n-ar accepta niciodată nimic.
    with pytest.raises(ConfigError, match="beacon.max_age_s"):
        load_config(write("  max_age_s: 0\n"))

    # Și implicitul trebuie să încapă în plafon, altfel o instalare curată n-ar
    # putea trimite nimic.
    assert BeaconConfig().max_age_s <= ceiling
    assert load_config(write("  enabled: false\n")).beacon.max_age_s <= ceiling


def test_the_beacon_window_shipped_in_the_template_still_loads(tmp_path):
    """Borna nouă nu are voie să invalideze o instalare existentă.

    O `ConfigError` la încărcare oprește TOATE serviciile, nu doar beaconul —
    deci o margine adăugată peste o valoare pe care instalatorul o scrie chiar el
    ar transforma o reparație de alertare într-o pană totală la primul deploy.
    Valoarea se ia din șablonul livrat, nu se scrie din nou aici: o copie ar
    dovedi doar că testul e de acord cu el însuși.
    """
    import re
    from pathlib import Path

    from sentinel.config import load_config

    tmpl = (Path(__file__).resolve().parents[2] / "deploy" / "config"
            / "sentinel.yaml.tmpl").read_text(encoding="utf-8")
    # Secțiunea `beacon:` a șablonului, până la următoarea cheie de nivel zero.
    block = re.search(r"^beacon:\n((?:[ \t].*\n|\n)*)", tmpl, re.MULTILINE)
    assert block, "șablonul nu mai are o secțiune `beacon:` — testul nu mai citește nimic"
    values = dict(re.findall(r"^\s+(\w+):\s*(\S+)\s*$", block.group(1), re.MULTILINE))
    assert "max_age_s" in values, (
        "șablonul nu mai scrie `beacon.max_age_s` — atunci testul ăsta nu mai "
        "dovedește că valoarea livrată trece de bornă")

    path = tmp_path / "sentinel.yaml"
    path.write_text(f"telegram:\n  enabled: false\nbeacon:\n"
                    f"  max_age_s: {values['max_age_s']}\n", encoding="utf-8")
    assert load_config(path).beacon.max_age_s == int(values["max_age_s"])


# --- urma pe care o lasă rezultatul unei runde ------------------------------
def test_an_accepted_beat_leaves_a_trace_another_process_can_read(http):
    """Fără urma asta, „martorul mă primește" nu e un fapt nicăieri pe gazdă.

    Contorul din `run_forever` trăiește în proces: nu-l poate citi
    autodiagnosticul și dispare la fiecare repornire. Iar `beacon:seq` crește la
    fiecare rundă care ajunge să semneze, acceptată sau nu, deci din el nu se
    poate afla nimic despre livrare.
    """
    db = _DB(vals={"collector_cursors": 12})
    assert run(beacon.send_once(db, _cfg(), "k")) is True
    assert db.markers[beacon.DELIVERED_KEY][0] == "12", db.markers
    # Și contorul de refuzuri e adus la zero, nu șters: rândul lipsă ar face
    # „a mers din prima rundă" nedistinct de „codul care scrie urma n-a rulat".
    assert db.markers[beacon.REFUSED_KEY] == ("0", "set"), db.markers


def test_a_refused_beat_counts_up_and_an_accepted_one_zeroes_it(http):
    """Cazul pentru care există contorul: gazda trimite, martorul refuză mereu.

    Un 400 sau un 401 la fiecare bătaie nu se vede din afară — unitatea rămâne
    `active` — și, dacă instanța n-a bătut niciodată, nu se vede nici la martor:
    acolo e `no-beat`, care nu se numără și nu alertează. Contorul e singurul
    fapt din care se poate afla că refuzul se repetă.
    """
    http.status = 400
    db = _DB(vals={"collector_cursors": 3})
    for expected in ("1", "2", "3"):
        assert run(beacon.send_once(db, _cfg(), "k")) is False
        assert db.markers[beacon.REFUSED_KEY][0] == expected, db.markers
    assert beacon.DELIVERED_KEY not in db.markers, \
        "o bătaie refuzată a fost înregistrată ca livrată"

    http.status = 200
    assert run(beacon.send_once(db, _cfg(), "k")) is True
    assert db.markers[beacon.REFUSED_KEY][0] == "0"
    assert db.markers[beacon.DELIVERED_KEY][0] == "3"


def test_an_unreachable_watcher_counts_as_a_refusal_too(monkeypatch):
    """„Nu ajung la el" și „mă refuză" sunt aceeași tăcere pentru operator.

    Numărate separat, o gazdă căreia i s-a tăiat rețeaua spre martor ar rămâne
    veșnic sub prag și n-ar produce niciodată o constatare.
    """
    class _Boom:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **kw): raise OSError("fara retea")

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _Boom)
    db = _DB(vals={"collector_cursors": 5})
    assert run(beacon.send_once(db, _cfg(), "k")) is False
    assert db.markers[beacon.REFUSED_KEY][0] == "1", db.markers


def test_a_round_that_never_reached_the_network_is_not_a_refusal(http, _identity):
    """„N-am cu ce semna cine sunt" nu e „martorul m-a refuzat".

    Amestecate, contorul ar numi o cauză greșită în mesajul către operator, și
    l-ar trimite să caute o cheie greșită la martor pentru un fișier lipsă de pe
    gazda lui. Identitatea are contorul ei și verificarea ei.
    """
    _identity.unlink()
    db = _DB(vals={"collector_cursors": 3})
    assert run(beacon.send_once(db, _cfg(), "k")) is False
    assert db.markers == {}, db.markers


def test_a_trace_that_cannot_be_written_does_not_change_the_round(http, caplog):
    """Urma e un ajutor pentru autodiagnostic, nu o condiție a semnalului.

    Dacă o bază care nu răspunde ar putea face runda să pice, un defect al urmei
    ar deveni un defect al heartbeat-ului — adică fix inversul motivului pentru
    care urma există.
    """
    db = _DB(vals={"collector_cursors": 4}, execute_boom=RuntimeError("baza tace"))
    with caplog.at_level("WARNING", logger="sentinel.report.beacon"):
        assert run(beacon.send_once(db, _cfg(), "k")) is True
    assert http.calls, "semnalul nu a plecat"
    assert any("could not record" in r.getMessage() for r in caplog.records), \
        [r.getMessage() for r in caplog.records]


# ---------------------------------------------------------------------------
# Escaladarea: `beacon:delivery` în autodiagnostic
#
# Beaconul nu are cale proprie de alarmare, dinadins — o componentă care își
# raportează propria pană prin canalul pe care poate l-a rupt e chiar tiparul
# pentru care există martorul. Până pe 15 august 2026 delegarea asta ducea la
# nimic: în `selfcheck/checks.py` nu exista nicio verificare a beaconului dincolo
# de poarta pe unitate activă, iar unitatea rămâne `active` în timp ce FIECARE
# bătaie e refuzată.
# ---------------------------------------------------------------------------
class _MarkerDB:
    """Baza văzută de verificare: doar cele două urme, cu vechimea lor.

    Vechimea se calculează în SQL în codul livrat (`EXTRACT(EPOCH FROM (now() -
    updated_at))/60`), deci dublul de aici întoarce direct minutele — altfel
    testul ar depinde de ceasul mașinii pe care rulează.
    """

    def __init__(self, markers=None, boom=None):
        self.markers = markers or {}
        self.boom = boom
        self.asked: list[str] = []

    async def fetchrow(self, sql, *a):
        if self.boom:
            raise self.boom
        assert "collector_cursors" in sql, sql
        name = a[0]
        self.asked.append(name)
        found = self.markers.get(name)
        if found is None:
            return None
        cursor, minute = found
        return {"cursor": cursor, "minute": minute}


def _beacon_secrets(monkeypatch, present=True):
    from sentinel import config as config_module

    monkeypatch.setattr(config_module, "get_secrets",
                        lambda *a, **k: SimpleNamespace(has=lambda key: present))


def _delivery(db, cfg=None):
    from sentinel.selfcheck import checks

    return run(checks.check_beacon_delivery(db, cfg or _cfg()))


def _marks(delivered=None, refused=None):
    out = {}
    if delivered is not None:
        out[beacon.DELIVERED_KEY] = delivered
    if refused is not None:
        out[beacon.REFUSED_KEY] = refused
    return out


def test_a_beacon_that_is_switched_off_is_not_a_fault(monkeypatch):
    """Beaconul e oprit implicit și rămâne așa pe orice gazdă fără martor.

    `unknown` ar ține permanent titlul lui /selfcheck pe „nu tot s-a putut
    verifica", pe fiecare instalare, pentru o stare normală — iar un avertisment
    care nu se stinge niciodată e unul pe care nimeni nu-l mai citește când chiar
    apare. Se spune cu voce tare, nu prin omiterea cheii: runner-ul șterge, la o
    rulare completă, fiecare cheie pe care rularea n-a emis-o.
    """
    results = _delivery(_MarkerDB(), _cfg(enabled=False))
    assert [r.key for r in results] == ["beacon:delivery"]
    assert results[0].status == "ok"
    assert results[0].facts["configured"] is False


def test_a_beacon_that_is_on_with_nowhere_to_send_is_a_finding(monkeypatch):
    """`enabled: true` cu `url` gol e invizibil din afară: `run_forever` spune o
    dată în jurnal și iese, deci unitatea e `inactive` și arată exact ca una pe
    care nimeni n-a pornit-o. Operatorul crede că are martor."""
    results = _delivery(_MarkerDB(), _cfg(url=""))
    assert results[0].status == "degraded"
    assert "beacon.url" in results[0].detail


def test_a_beacon_that_is_on_without_a_key_is_a_finding(monkeypatch):
    """Aceeași tăcere, altă cauză. Fără `SENTINEL_BEACON_SECRET` expeditorul iese
    curat; cu una goală ar semna oricum și ar lua 401 la fiecare bătaie."""
    _beacon_secrets(monkeypatch, present=False)
    results = _delivery(_MarkerDB())
    assert results[0].status == "degraded"
    assert beacon.SECRET_NAME in results[0].detail


def test_a_beacon_that_has_reported_nothing_yet_says_so_instead_of_ok(monkeypatch):
    """Imediat după un deploy, nicio rundă n-a lăsat încă urmă.

    `ok` ar fi o afirmație pe care verificarea nu o poate susține, iar `degraded`
    ar fi o alarmă falsă la fiecare instalare — repetată la fiecare deploy, adică
    exact felul în care operatorul învață să ignore cheia. `unknown` e adevărul,
    se vede în titlu și nu sună; se stinge singur în primul interval.
    """
    _beacon_secrets(monkeypatch)
    result = _delivery(_MarkerDB())[0]
    assert result.status == "unknown"
    assert result.facts["delivered"] is False


def test_a_beacon_refused_at_every_round_is_never_reported_as_healthy(monkeypatch):
    """Proprietatea pentru care există verificarea.

    Pe o instanță care n-a bătut NICIODATĂ, refuzul e tăcut pe toate suprafețele:
    unitatea rămâne `active`, martorul ține instanța în `no-beat` — stare care nu
    se numără și nu alertează, dinadins — iar `send_once` scrie doar în jurnal.
    Măsurat pe 15 august 2026 cu `beacon.max_age_s: 100000`: beat → 400, `/status`
    → 200 „ok". Dacă asta rămâne verde și aici, nimic din tot sistemul nu spune
    că serverul nu e supravegheat.
    """
    _beacon_secrets(monkeypatch)
    result = _delivery(_MarkerDB(_marks(refused=("3", 0.5))))[0]
    assert result.status == "degraded", result.detail
    assert result.facts["refusals"] == 3
    assert result.facts["delivered"] is False
    # Mesajul trebuie să trimită omul unde se vede codul de refuz, altfel are o
    # cheie roșie și niciun mod de a afla dacă e cheia, identitatea sau payloadul.
    assert "sentinel-beacon" in result.action


def test_the_first_refused_rounds_are_not_yet_a_finding(monkeypatch):
    """O pornire în curs nu e o defecțiune. Un prag care se aprinde la prima
    rundă ratată ar fi roșu la fiecare repornire de serviciu, iar o cheie roșie
    în funcționare normală e una peste care operatorul învață să treacă.

    Dar nici `ok` nu e: nimic n-a fost acceptat vreodată, deci nu există faptul
    care ar susține afirmația. `unknown` e ce se poate spune — se vede în titlul
    lui /selfcheck, nu sună, și nu minte.
    """
    _beacon_secrets(monkeypatch)
    for count in ("1", "2"):
        result = _delivery(_MarkerDB(_marks(refused=(count, 0.1))))[0]
        assert result.status == "unknown", f"{count} refuzuri: {result.detail}"
        assert result.facts["delivered"] is False


def test_a_beacon_that_never_delivered_is_never_ok_no_matter_how_quiet(monkeypatch):
    """Starea `ok` absorbantă, măsurată pe codul livrat în runda întâi.

    „Niciodată acceptat, 2 refuzuri, ultima urmă acum un an" raporta `ok`, iar
    asta închidea chiar bucla pentru care există verificarea: unitatea rămâne
    `active` deci `check_units` tace, martorul ține instanța în `no-beat` care
    prin proiectare nu se numără și nu alarmează, iar aici era verde. Toate
    suprafețele spuneau că e bine despre un server nesupravegheat.

    Drumul care ajunge acolo nu e exotic: beaconul face o rundă-două refuzate și
    apoi încetează să mai completeze runde — proces blocat, sau `_record_delivery`
    care eșuează la nesfârșit după primele scrieri (înghite orice excepție, prin
    proiectare). Contorul mic de refuzuri nu e atunci o dovadă de sănătate, e
    chiar simptomul.

    Faptul era deja în mână și aruncat: `marker()` calculează vechimea pentru
    AMBELE chei, iar ramura asta nu se uita la a ei.
    """
    _beacon_secrets(monkeypatch)
    AN = 525_600.0
    for minute in (31.0, 24 * 60.0, AN):
        for count in ("1", "2"):
            result = _delivery(_MarkerDB(_marks(refused=(count, minute))))[0]
            assert result.status != "ok", (
                f"{count} refuzuri, urmă veche de {minute} min: „{result.title}” "
                f"raportat ca ok, deși nicio bătaie n-a fost acceptată vreodată")
            assert result.status == "degraded", f"{count}/{minute}: {result.detail}"
            assert result.facts["delivered"] is False

    # Iar sub prag ȘI proaspăt rămâne `unknown`, nu `degraded`: altfel fiecare
    # repornire de serviciu ar aprinde cheia.
    proaspat = _delivery(_MarkerDB(_marks(refused=("2", 0.5))))[0]
    assert proaspat.status == "unknown", proaspat.detail


def test_the_grace_for_a_beacon_that_never_delivered_follows_the_interval(monkeypatch):
    """Aceeași fereastră ca la restul verificării, din același motiv: cu
    `interval_s` mare, o margine fixă ar face roșu un beacon care e pur și simplu
    între două runde."""
    _beacon_secrets(monkeypatch)
    marks = _marks(refused=("2", 40.0))
    assert _delivery(_MarkerDB(marks), _cfg(interval_s=3600))[0].status == "unknown"
    assert _delivery(_MarkerDB(marks), _cfg(interval_s=60))[0].status == "degraded"


def test_a_beacon_that_is_being_accepted_is_ok(monkeypatch):
    _beacon_secrets(monkeypatch)
    result = _delivery(_MarkerDB(_marks(delivered=("41", 0.5), refused=("0", 0.5))))[0]
    assert result.status == "ok"
    assert result.facts["seq"] == "41"


def test_a_beacon_that_stopped_being_accepted_is_a_finding(monkeypatch):
    """A doua jumătate: gazda a bătut cândva, deci nu mai e cazul `no-beat`.

    Martorul ar trece instanța în `silent` și ar suna — dar numai dacă martorul
    însuși e în picioare și dacă alerta lui ajunge. Capătul monitorizat trebuie
    să știe și el, fiindcă e singurul care poate spune de ce: refuzurile de după
    ultima acceptare sunt numărate aici.
    """
    _beacon_secrets(monkeypatch)
    result = _delivery(_MarkerDB(_marks(delivered=("41", 120.0),
                                        refused=("120", 0.5))))[0]
    assert result.status == "degraded"
    assert result.facts["refusals"] == 120


def test_a_sender_that_stopped_reporting_at_all_is_not_ok(monkeypatch):
    """Contorul de refuzuri singur nu vede un proces mort: unul care nu mai
    rulează nu mai refuză nici el, deci contorul îngheață pe zero și verificarea
    ar raporta „la zi" pentru o gazdă care nu mai trimite nimic."""
    _beacon_secrets(monkeypatch)
    result = _delivery(_MarkerDB(_marks(delivered=("41", 300.0),
                                        refused=("0", 300.0))))[0]
    assert result.status == "degraded"
    assert "nu mai rulează" in result.detail


def test_the_grace_window_follows_a_long_interval(monkeypatch):
    """Cu `interval_s` mare, o fereastră fixă ar raporta defect pentru un beacon
    care e pur și simplu între două runde."""
    _beacon_secrets(monkeypatch)
    marks = _marks(delivered=("41", 40.0), refused=("0", 40.0))
    assert _delivery(_MarkerDB(marks), _cfg(interval_s=3600))[0].status == "ok"
    assert _delivery(_MarkerDB(marks), _cfg(interval_s=60))[0].status == "degraded"


def test_a_check_that_cannot_read_the_traces_says_so_instead_of_ok(monkeypatch):
    """Contopit cu „la zi", un cursor imposibil de citit devine tăcere în formă
    de sănătate — și, fiindcă runner-ul reconciliază starea după cheile emise, ar
    șterge o constatare reală și nereparată, arătând operatorului o revenire care
    nu s-a întâmplat."""
    _beacon_secrets(monkeypatch)
    result = _delivery(_MarkerDB(boom=RuntimeError("relatia nu exista")))[0]
    assert result.status == "unknown"
    assert result.key == "beacon:delivery"


def test_the_check_never_returns_an_empty_list(monkeypatch):
    """O listă goală nu e „nimic în neregulă", e „nicio cheie" — iar rularea
    completă șterge din `selfcheck_state` fiecare rând pe care nu l-a emis, deci
    verificarea ar DISPĂREA din panou în loc să se facă roșie."""
    _beacon_secrets(monkeypatch)
    cases = [
        (_MarkerDB(), _cfg(enabled=False)),
        (_MarkerDB(), _cfg(url="")),
        (_MarkerDB(), _cfg()),
        (_MarkerDB(_marks(refused=("9", 1.0))), _cfg()),
        (_MarkerDB(_marks(delivered=("1", 0.1), refused=("0", 0.1))), _cfg()),
        (_MarkerDB(_marks(delivered=("1", 999.0), refused=("0", 999.0))), _cfg()),
        (_MarkerDB(boom=RuntimeError("x")), _cfg()),
    ]
    assert len(cases) == 7, "lista a ieșit alta decât cea scrisă"
    for db, cfg in cases:
        results = _delivery(db, cfg)
        assert len(results) == 1 and results[0].key == "beacon:delivery", results


def test_the_four_verdicts_do_not_collapse_into_each_other(monkeypatch):
    """Contopită oricare pereche, unealta minte: „nu pot citi" raportat ca „la
    zi" e tăcere în formă de sănătate, iar „niciodată acceptat" raportat ca „ok"
    e chiar pana pentru care s-a scris verificarea."""
    _beacon_secrets(monkeypatch)
    off = _delivery(_MarkerDB(), _cfg(enabled=False))[0]
    live = _delivery(_MarkerDB(_marks(delivered=("7", 0.2), refused=("0", 0.2))))[0]
    never = _delivery(_MarkerDB(_marks(refused=("30", 0.2))))[0]
    unclear = _delivery(_MarkerDB(boom=RuntimeError("x")))[0]

    assert off.status == "ok" and live.status == "ok"
    assert off.detail != live.detail, "«oprit» și «primit» arată la fel"
    assert never.status == "degraded"
    assert unclear.status == "unknown"


def test_the_check_is_wired_into_the_run():
    """O verificare scrisă și neînregistrată nu rulează niciodată, iar tăcerea ei
    arată identic cu „nimic în neregulă"."""
    from sentinel.selfcheck import checks

    assert ("beacon", checks.check_beacon_delivery) in checks.CHECKS


def test_the_check_asks_only_for_what_the_runner_can_give():
    """`run_groups` injectează argumentele după NUME (`db`, `cfg`). Un parametru
    numit altfel nu se completează, apelul cade cu TypeError, iar grupul se
    raportează stricat la fiecare rulare."""
    from sentinel.selfcheck import checks

    fn = checks.check_beacon_delivery
    names = fn.__code__.co_varnames[:fn.__code__.co_argcount]
    assert set(names) <= {"db", "cfg"}, names


def test_the_check_reads_config_fields_that_exist_on_the_real_dataclass():
    """Un câmp citit de verificare și absent de pe `Config` face verificarea să
    crape la fiecare rulare — sau, cu `getattr(..., default)`, să nu ruleze
    niciodată și să treacă verde peste cod mort. Ambele s-au întâmplat aici."""
    from sentinel.config import BeaconConfig, Config

    b = Config().beacon
    assert isinstance(b, BeaconConfig)
    for attr in ("enabled", "url", "interval_s", "timeout_s", "max_age_s"):
        assert hasattr(b, attr), f"BeaconConfig nu are {attr}"
    assert b.enabled is False, "beaconul trebuie să fie oprit implicit"


def test_the_trace_names_are_not_written_a_second_time_in_the_check():
    """O verificare care întreabă de un cursor pe care nu-l scrie nimeni
    raportează „la zi" pentru totdeauna. Numele vin dintr-un singur loc."""
    import inspect

    from sentinel.selfcheck import checks

    source = inspect.getsource(checks.check_beacon_delivery)
    assert "beacon:delivered" not in source
    assert "beacon:refused" not in source
    assert beacon.DELIVERED_KEY == "beacon:delivered"
    assert beacon.REFUSED_KEY == "beacon:refused"
