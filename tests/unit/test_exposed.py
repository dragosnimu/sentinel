"""Ce ascultă pe internet, și ce anume e fiecare lucru care ascultă.

Regula asta există dintr-un eșec de utilitate, nu de corectitudine. Sentinel a
enumerat corect 21 de porturi în ascultare, la instalare, într-o listă citită o
dată. Printre ele, un panou de administrare cu drepturi de root, expus public,
cu autentificare doar prin parolă. A rămas acolo săptămâni.

Nimic nu era stricat. Pur și simplu nimeni nu a fost obligat să decidă.

Testele de mai jos păzesc două proprietăți care trag în direcții opuse: să spună
ce contează, și să tacă în rest. A doua e cea fragilă — o regulă care alertează
pe „port deschis pe care nu-l recunosc" ar produce zeci de alerte pe orice gazdă
reală și ar fi ignorată în aceeași săptămână ca lista pe care o înlocuiește.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.detect import exposed

NOW = datetime(2026, 8, 7, 18, 0, tzinfo=timezone.utc)


def run(c):
    return asyncio.run(c)


class _DB:
    """Profiluri programate; înregistrează ce s-a scris."""

    def __init__(self, seen=None, alerted=None):
        self.profiles = {exposed.DIM_SEEN: seen or {},
                         exposed.DIM_ALERTED: alerted or {}}
        self.written: list[tuple[str, str]] = []

    async def fetch(self, sql, *a):
        if "cutoff" in sql:
            return [{"cutoff": NOW - timedelta(days=a[0])}]
        rows = self.profiles.get(a[0], {})
        return [{"key": k, **v} for k, v in rows.items()]

    async def execute(self, sql, *a):
        self.written.append((a[0], a[1]))


def _row(*, last_seen=NOW, acknowledged=False, first_seen=NOW):
    return {"last_seen": last_seen, "acknowledged": acknowledged,
            "first_seen": first_seen}


def _listeners(monkeypatch, *items):
    monkeypatch.setattr(exposed, "_read_listeners", lambda: list(items))


def L(port, addr="0.0.0.0", proto="tcp"):
    return exposed.Listener(proto, addr, port, public=addr in ("0.0.0.0", "::"))


# --- ce trebuie spus -------------------------------------------------------
def test_an_admin_panel_on_all_interfaces_is_critical(monkeypatch):
    """Clasa de expunere care motiveaza regula: un panou de administrare legat pe toate interfetele."""
    _listeners(monkeypatch, L(10000))
    specs = run(exposed.exposed_services(_DB(), 0))
    assert len(specs) == 1
    s = specs[0]
    assert s.severity == "critical"
    assert "10000" in s.title
    assert "Webmin" in s.title
    assert "root" in s.summary


def test_the_alert_says_what_is_at_stake_not_just_what_is_open(monkeypatch):
    """„Portul 6379 e deschis" nu cere nimic de la cititor. „Redis pornește fără
    parolă, iar CONFIG SET permite scrierea de fișiere" îl obligă să decidă."""
    _listeners(monkeypatch, L(6379))
    s = run(exposed.exposed_services(_DB(), 0))[0]
    assert "parol" in s.summary.lower()
    assert s.evidence["severity_reason"]


def test_the_alert_admits_a_bind_is_not_proof_of_reachability(monkeypatch):
    """Firewallul providerului poate face socketul inaccesibil. De pe gazdă nu
    putem ști, iar a pretinde altfel ar transforma o observație într-o
    afirmație pe care operatorul o va găsi falsă exact o dată."""
    _listeners(monkeypatch, L(3306))
    s = run(exposed.exposed_services(_DB(), 0))[0]
    assert "nu dovedește accesibilitatea" in s.summary
    assert "nc -vz" in s.summary        # cum se verifică din afară


def test_nothing_here_is_blockable(monkeypatch):
    """Constatarea e despre configurația gazdei. O adresă sursă ar fi o
    invitație pentru decident să blocheze ceva, iar aici nu e nimic de blocat."""
    _listeners(monkeypatch, L(27017))
    s = run(exposed.exposed_services(_DB(), 0))[0]
    assert s.src_ip is None
    assert s.actor_key == "host"


# --- ce trebuie să tacă ----------------------------------------------------
def test_loopback_is_not_exposure(monkeypatch):
    """127.0.0.1 e exact unde ar trebui să fie o bază de date."""
    _listeners(monkeypatch, L(5432, "127.0.0.1"), L(6379, "::1", "tcp6"))
    assert run(exposed.exposed_services(_DB(), 0)) == []


def test_an_unrecognised_port_says_nothing(monkeypatch):
    """Proprietatea cea mai fragilă din fișier.

    O regulă care alertează pe „port deschis pe care nu-l recunosc" produce
    zeci de alerte pe orice gazdă reală. Ar fi ignorată în aceeași săptămână ca
    lista pe care o înlocuiește, si atunci regula n-ar fi rezolvat nimic — doar
    ar fi mutat zgomotul.
    """
    _listeners(monkeypatch, L(47821), L(31337), L(8899))
    assert run(exposed.exposed_services(_DB(), 0)) == []


def test_one_incident_per_port_not_per_address_family(monkeypatch):
    """Același serviciu ascultă pe IPv4 și IPv6. Operatorul repară serviciul."""
    _listeners(monkeypatch, L(10000), L(10000, "::", "tcp6"))
    specs = run(exposed.exposed_services(_DB(), 0))
    assert len(specs) == 1
    assert len(specs[0].evidence["bindings"]) == 2


def test_an_acknowledged_exposure_never_alerts_again(monkeypatch):
    """„Știu, e al meu" e o decizie umană, iar ea se respectă la nesfârșit."""
    _listeners(monkeypatch, L(10000))
    db = _DB(seen={"tcp/10000": _row(acknowledged=True)})
    assert run(exposed.exposed_services(db, 0)) == []


def test_a_standing_exposure_is_not_reported_every_pass(monkeypatch):
    """O expunere e o stare, nu un eveniment. Raportată la fiecare trecere a
    motorului, ar produce mii de detecții pe zi pentru un singur fapt."""
    _listeners(monkeypatch, L(10000))
    db = _DB(seen={"tcp/10000": _row()},
             alerted={"tcp/10000": _row(last_seen=NOW - timedelta(days=1))})
    assert run(exposed.exposed_services(db, 0)) == []


def test_but_it_is_repeated_once_the_nag_interval_passes(monkeypatch):
    """Tăcerea permanentă e cum a fost uitat panoul de administrare.

    O alertă unică, la instalare, e exact ce a eșuat. Reamintirea trebuie să
    existe, doar rară.
    """
    _listeners(monkeypatch, L(10000))
    old = NOW - timedelta(days=exposed.RENAG_DAYS + 1)
    db = _DB(seen={"tcp/10000": _row(last_seen=old)},
             alerted={"tcp/10000": _row(last_seen=old)})
    specs = run(exposed.exposed_services(db, 0))
    assert len(specs) == 1
    assert "Persistă de la" in specs[0].summary


def test_the_first_sighting_is_named_as_such(monkeypatch):
    _listeners(monkeypatch, L(2375))
    s = run(exposed.exposed_services(_DB(), 0))[0]
    assert "Prima observare" in s.summary


def test_observations_are_recorded_even_when_no_alert_is_emitted(monkeypatch):
    """Altfel o expunere confirmată ar arăta ca nouă la fiecare repornire, iar
    intervalul de reamintire nu s-ar mai închide niciodată."""
    _listeners(monkeypatch, L(10000))
    db = _DB(seen={"tcp/10000": _row(acknowledged=True)})
    run(exposed.exposed_services(db, 0))
    assert (exposed.DIM_SEEN, "tcp/10000") in db.written


# --- catalogul -------------------------------------------------------------
VALID = {"info", "low", "medium", "high", "critical"}


@pytest.mark.parametrize("port,klass", sorted(exposed.CATALOGUE.items()))
def test_every_catalogue_entry_is_complete(port, klass):
    """Fiecare intrare trebuie să poată răspunde la „ce e" și „de ce contează".

    O intrare fără al doilea răspuns produce o alertă care spune doar că un port
    e deschis — adică exact raportarea pe care regula asta o înlocuiește.
    """
    assert klass.severity in VALID
    assert klass.name.strip()
    assert len(klass.why) > 20, f"portul {port} nu explică miza"


def test_the_catalogue_does_not_claim_generic_ports():
    """8080, 8443, 3000, 9000 găzduiesc orice. O clasificare greșită într-o
    alertă critică e mai rea decât absența ei."""
    for port in (80, 443, 3000, 8000, 8080, 8443, 9000):
        assert port not in exposed.CATALOGUE, f"portul {port} e prea generic pentru o afirmație"


def test_sentinels_own_dashboard_port_is_not_flagged():
    """Singura expunere pe care operatorul a configurat-o explicit, cu TOTP.

    Nu e un caz special în cod — e o consecință a faptului că portul e prea
    generic ca să fie în catalog. Testul o fixează, ca nimeni să nu adauge 8443
    „pentru completitudine" și să transforme propriul panou într-o alertă
    critică permanentă.
    """
    from sentinel.config import Config
    assert Config().web.port not in exposed.CATALOGUE


# --- decodarea adreselor ---------------------------------------------------
@pytest.mark.parametrize("hex_addr,expected", [
    ("00000000", "0.0.0.0"),
    ("0100007F", "127.0.0.1"),
    ("0201A8C0", "192.168.1.2"),
])
def test_ipv4_is_decoded_little_endian(hex_addr, expected):
    """Nucleul le scrie little-endian. Citite big-endian, 127.0.0.1 devine
    2.0.0.127 — o adresă publică plauzibilă, deci o greșeală care nu se vede."""
    assert exposed._ipv4(hex_addr) == expected


@pytest.mark.parametrize("hex_addr,expected", [
    ("0" * 32, "::"),
    ("00000000000000000000000001000000", "::1"),
])
def test_ipv6_is_decoded_in_little_endian_groups(hex_addr, expected):
    assert exposed._ipv6(hex_addr) == expected


def test_an_unreadable_proc_is_not_an_alert(monkeypatch):
    """O gazdă pe care /proc nu se poate citi e o gazdă unde verificarea nu
    funcționează — nu una fără expuneri. Zero rezultate, nicio afirmație."""
    monkeypatch.setattr(exposed, "PROC_TCP", ("/nu/exista", ))
    assert exposed._read_listeners() == []


# --- marcajul operatorului -------------------------------------------------
#
# `behaviour_profiles.acknowledged` a existat de la migratia 0018, cu un
# comentariu care ii descria rostul, era citit de doua reguli — si nu il scria
# nimic. Alerta promitea „daca e intentionat, marcheaza-l", iar promisiunea
# n-avea acoperire in cod. O functionalitate pe jumatate construita se citeste
# ca intreg pana in ziua in care cineva chiar incearca sa o foloseasca.

class _AckDB:
    def __init__(self, existing=("tcp/10000",)):
        self.existing = set(existing)
        self.updated: list[tuple] = []
        self.deleted: list[tuple] = []

    async def fetch(self, sql, *a):
        if "UPDATE behaviour_profiles" in sql:
            self.updated.append(a)
            return [{"key": a[1]}] if a[1] in self.existing else []
        return [{"key": k, "first_seen": NOW, "last_seen": NOW, "acknowledged": False}
                for k in sorted(self.existing)]

    async def execute(self, sql, *a):
        if "DELETE" in sql:
            self.deleted.append(a)


def test_acknowledging_marks_the_profile():
    db = _AckDB()
    assert run(exposed.acknowledge(db, "tcp/10000")) is True
    dim, key, on = db.updated[0]
    assert (dim, key, on) == (exposed.DIM_SEEN, "tcp/10000", True)


def test_acknowledging_something_never_seen_reports_failure():
    """Altfel o greșeală de tastare ar arăta ca o expunere făcută să tacă."""
    db = _AckDB()
    assert run(exposed.acknowledge(db, "tcp/9999")) is False


def test_acknowledging_clears_the_nag_timer():
    """Ca o de-marcare ulterioară să raporteze imediat, nu peste încă șapte zile.

    Fără asta, cineva care își schimbă părerea ar rămâne cu o săptămână de
    tăcere pe care nu a cerut-o.
    """
    db = _AckDB()
    run(exposed.acknowledge(db, "tcp/10000"))
    assert db.deleted and db.deleted[0][0] == exposed.DIM_ALERTED


def test_acknowledgement_is_reversible():
    db = _AckDB()
    run(exposed.acknowledge(db, "tcp/10000", on=False))
    assert db.updated[0][2] is False
    # De-marcarea NU șterge cronometrul: n-are ce, alerta trebuie să revină.
    assert not db.deleted


def test_listing_names_the_service_not_just_the_port():
    """Scopul întregii funcționalități, într-o singură aserțiune."""
    db = _AckDB()
    rows = run(exposed.list_exposures(db))
    assert rows[0]["port"] == 10000
    assert "Webmin" in rows[0]["service"]
    assert rows[0]["severity"] == "critical"


def test_listing_does_not_invent_a_class_for_unknown_ports():
    db = _AckDB(existing=("tcp/47821",))
    rows = run(exposed.list_exposures(db))
    assert rows[0]["service"] == "neclasificat"
    assert rows[0]["severity"] == "info"


def test_the_commands_the_alert_promises_actually_exist():
    """Textul alertei spune „marchează-l și nu mai revine".

    Dacă comanda nu există, propoziția aia e o minciună livrată pe telefonul
    operatorului exact în momentul în care are încredere maximă în ea.
    """
    from sentinel.telegram import bot
    assert hasattr(bot, "cmd_ack_exposure")
    assert hasattr(bot, "cmd_exposures")
    src = __import__("inspect").getsource(bot)
    assert '"stiu"' in src and '"expuneri"' in src
