"""Contractul de semnare dintre Python și TypeScript.

Tot ce e aici apără o singură proprietate: **pentru orice payload pe care
`canonical()` îl acceptă, cele două capete produc aceiași octeți**. Când
proprietatea se rupe, martorul refuză fiecare semnal cu 401 — adică exact ce s-ar
vedea la o cheie greșită — iar operatorul caută o zi în locul nepotrivit, timp în
care nimic nu ajunge la martor și nimeni nu știe că tăcerea e a lui.

Jumătatea din TypeScript e în `aggregator/tests/canonical.test.ts`. Amândouă citesc
`tests/fixtures/canonical-corpus.json` și se compară cu ȘIRURILE de acolo, nu una
cu cealaltă: două implementări care se verifică reciproc pot deriva împreună.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sentinel.report import beacon, signing
from sentinel.report.signing import CanonicalError, canonical, sign

# ---------------------------------------------------------------------------
# Vectorul de aur al MUTĂRII.
#
# Măsurat cu `json.dumps(sort_keys=True, separators=(",", ":"),
# ensure_ascii=False)` din beacon.py:95-107, ÎNAINTE ca funcția să se mute în
# signing.py și înainte ca implementarea să se schimbe. Nu se rescrie din partea
# Python: rescris, ar înceta să dovedească ceva despre mutare și ar deveni o
# aserțiune că Python e egal cu el însuși.
# ---------------------------------------------------------------------------
GOLDEN_SECRET = "cheie-de-test-0123456789abcdef"

GOLDEN_PAYLOAD = {
    "instance_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    "instance_label": "Server producție",
    "seq": 4471,
    "sent_at": "2026-08-12T09:15:04.512345+00:00",
    "max_age_s": 120,
    "interval_s": 60,
    "last_event_id": 918273,
    "detect_cursor": 918200,
    "incidents_open": 2,
    "blocklist_size": 37,
    "audit_head": "3f9c1d0e6b2a48f7c5e0d1a2b3c4d5e60718293a4b5c6d7e8f90a1b2c3d4e5f6",
    "selfcheck": {"worst": "ok", "checks": 33, "bad": 0,
                  "ran_at": "2026-08-12T09:14:31+00:00"},
}

GOLDEN_CANONICAL = (
    '{"audit_head":"3f9c1d0e6b2a48f7c5e0d1a2b3c4d5e60718293a4b5c6d7e8f90a1b2c3d4e5f6",'
    '"blocklist_size":37,"detect_cursor":918200,"incidents_open":2,'
    '"instance_id":"a1b2c3d4e5f60718293a4b5c6d7e8f90",'
    '"instance_label":"Server producție","interval_s":60,"last_event_id":918273,'
    '"max_age_s":120,'
    '"selfcheck":{"bad":0,"checks":33,"ran_at":"2026-08-12T09:14:31+00:00","worst":"ok"},'
    '"sent_at":"2026-08-12T09:15:04.512345+00:00","seq":4471}'
)

GOLDEN_HMAC = "98d34da11517dcf63e8eb9f10efee4f619fce0405250c6ab6488a2c294eb731f"

CORPUS_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "canonical-corpus.json"
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
ACCEPTED = [c for c in CORPUS["cases"] if c["expect"] == "accept"]
REJECTED = [c for c in CORPUS["cases"] if c["expect"] == "reject"]


def _id(case: dict) -> str:
    return case["name"]


# --- mutarea din beacon.py -------------------------------------------------
def test_the_golden_vector_survived_the_move():
    """Vectorul măsurat înainte de mutare.

    Eșecul pe care îl previne: forma canonică se rescrie „echivalent", octeții
    se schimbă cu unul, iar semnalul se semnează cu o valoare pe care martorul
    nu o poate reproduce. Simptomul e 401 la fiecare rundă, nedistinct de o cheie
    greșită.
    """
    assert canonical(GOLDEN_PAYLOAD).decode("utf-8") == GOLDEN_CANONICAL
    assert sign(GOLDEN_PAYLOAD, GOLDEN_SECRET) == GOLDEN_HMAC


def test_beacon_reexports_the_one_definition():
    """Un singur `canonical` în tot depozitul.

    Eșecul pe care îl previne: mutarea lasă o copie în beacon.py, cineva o repară
    pe una dintre ele, iar heartbeat-ul și expeditorul de loturi din E2 semnează
    două forme diferite ale aceluiași lucru.
    """
    assert beacon.canonical is signing.canonical
    assert beacon.sign is signing.sign
    assert beacon.CanonicalError is signing.CanonicalError


def test_key_order_of_the_input_does_not_matter():
    """Aceleași câmpuri în altă ordine dau aceiași octeți.

    Eșecul pe care îl previne: `collect()` capătă un câmp nou pus în altă
    poziție, iar semnătura se schimbă fără ca datele să se schimbe.
    """
    shuffled = dict(reversed(list(GOLDEN_PAYLOAD.items())))
    assert canonical(shuffled) == canonical(GOLDEN_PAYLOAD)


def test_a_changed_field_changes_the_signature():
    """Banal, dar e chiar proprietatea pentru care semnăm."""
    other = {**GOLDEN_PAYLOAD, "last_event_id": GOLDEN_PAYLOAD["last_event_id"] + 1}
    assert sign(other, GOLDEN_SECRET) != GOLDEN_HMAC


# --- corpusul comun --------------------------------------------------------
# Corpusul, caz cu caz. Lista e ÎNTREAGĂ și e duplicată la celălalt capăt
# (`aggregator/tests/canonical.test.ts`) dinadins: fixtura e generată, deci un prag
# de tipul „cel puțin zece" lasă loc să dispară tăcut cazuri, iar ștergerea unui
# caz șterge exact acoperirea pe care o aducea. Prima versiune a testului ăstuia
# avea praguri cu două cazuri sub realitate, și cu ele se puteau șterge
# `escape-uri`, `astral-si-separatori` și `surogat-neimperecheat` — adică TOATĂ
# acoperirea tabelului de escape C0/DEL și a lui U+2028/U+2029 — după care o
# schimbare a hexa-ului de escape la AMBELE capete trecea verde.
#
# Un caz nou se adaugă aici cu mâna. Costul ăsta e scopul.
EXPECTED_ACCEPTED = [
    "beat-real", "chei-intregi", "chei-intregi-imbricate", "chei-mixte-ascii",
    "diacritice", "sir-gol-si-null", "obiect-gol-si-tablou-gol",
    "intreg-mare-exact", "booleeni", "escape-uri", "astral-si-separatori",
    "chei-la-marginea-ascii", "adancime-la-limita", "imbricare-adanca",
]
EXPECTED_REJECTED = [
    "cheie-non-ascii", "cheie-diacritic", "cheie-control", "cheie-del",
    "cheie-sub-limita", "adancime-peste-limita", "float-fractionar",
    "float-exponent", "intreg-peste-limita", "surogat-neimperecheat",
]


def test_the_corpus_contains_exactly_the_cases_it_is_supposed_to():
    """Un corpus din care se poate șterge un caz nu apără cazul acela.

    Eșecul pe care îl previne, măsurat: ștergerea a trei cazuri și schimbarea
    hexa-ului de escape la ambele capete trecea verde la ambele suite — adică
    exact deriva comună despre care restul fișierului spune că e imposibilă.
    Și o listă parametrizată ieșită goală trece verde fără să verifice nimic;
    s-a întâmplat deja aici și a costat o pană.
    """
    assert [c["name"] for c in ACCEPTED] == EXPECTED_ACCEPTED
    assert [c["name"] for c in REJECTED] == EXPECTED_REJECTED
    assert len(CORPUS["cases"]) == len(EXPECTED_ACCEPTED) + len(EXPECTED_REJECTED)


# ---------------------------------------------------------------------------
# Ce ESTE fiecare caz, nu doar cum îl cheamă.
#
# A treia oară când același tipar se mută cu un nivel mai jos, deci merită scris
# de ce arată așa. Întâi a fost un prag `len(CORPUS) >= 20` care lăsa ștergibile
# exact cazurile care contau. Apoi praguri `>= 10`/`>= 6` peste 12/7, cu același
# efect. Reparate cu lista de nume — după care se puteau goli PAYLOAD-urile:
# `escape-uri` devenit `{"raw":"nimic special"}`, `astral-si-separatori` devenit
# `{"emoji":"a"}`, fixtura regenerată cinstit, nume și număr neatinse, ambele
# suite verzi. Și atunci aceeași mutație de hexa la ambele capete trecea din nou.
#
# Fixtura e GENERATĂ, deci orice s-ar fixa în ea se poate regenera. Singurul
# lucru care nu se poate regenera e o afirmație despre ce trebuie să conțină, ca
# aici. Fiecare caz își declară proprietatea pentru care există; un payload golit
# n-o mai satisface.
#
# Geamănul e `CASE_PROPERTIES` din `aggregator/tests/canonical.test.ts`.
# ---------------------------------------------------------------------------
def _depth(value: Any) -> int:
    """Câte containere sunt imbricate, numărând rădăcina."""
    if isinstance(value, dict):
        return 1 + max((_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(v) for v in value), default=0)
    return 0


def _walk(value: Any):
    yield value
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v)


def _keys(payload: Any) -> list[str]:
    out: list[str] = []
    if isinstance(payload, dict):
        for k, v in payload.items():
            out.append(k)
            out.extend(_keys(v))
    elif isinstance(payload, list):
        for v in payload:
            out.extend(_keys(v))
    return out


def _strings(payload: Any) -> list[str]:
    return [v for v in _walk(payload) if isinstance(v, str)]


def _numbers(payload: Any) -> list[Any]:
    return [v for v in _walk(payload)
            if isinstance(v, (int, float)) and not isinstance(v, bool)]


def _in_order(text: str, *needles: str) -> None:
    positions = []
    for n in needles:
        i = text.find(n)
        assert i >= 0, f"{n!r} lipsește din {text!r}"
        positions.append(i)
    assert positions == sorted(positions), f"ordinea {needles} e greșită în {text!r}"


CASE_PROPERTIES: dict[str, Any] = {
    # --- acceptate: proprietatea se citește din octeții ÎNREGISTRAȚI ---------
    "beat-real": lambda c: (
        [_assert_in(c["canonical"], f'"{f}":') for f in (
            "audit_head", "blocklist_size", "detect_cursor", "incidents_open",
            "instance_id", "instance_label", "interval_s", "last_event_id",
            "max_age_s", "selfcheck", "sent_at", "seq")],
        _assert(c["canonical"].startswith('{"audit_head":'), "cheile nu sunt sortate")),

    "chei-intregi": lambda c: (
        # DIVERGENȚA 1: ordinea punctelor de cod, nu cea numerică.
        _in_order(c["canonical"], '"1":', '"10":', '"2":', '"20":', '"3":'),
        _assert(len(c["payload"]) == 5, "cazul are nevoie de cheile care se reașază")),

    "chei-intregi-imbricate": lambda c: (
        # DIVERGENȚA 2: aceeași cauză SUB rădăcină, unde o sortare de suprafață
        # n-o vede. Ambele containere imbricate trebuie să rămână.
        _assert_in(c["canonical"], '{"10":1,"2":2}'),
        _assert_in(c["canonical"], '[{"100":1,"20":2}]')),

    "chei-mixte-ascii": lambda c: _in_order(
        c["canonical"], '" ":', '"0":', '"A":', '"Z":', '"_x":', '"a":', '"z.y":', '"z_y":'),

    "diacritice": lambda c: (
        # `ensure_ascii=False` la ambele capete: diacriticele ies BRUTE.
        [_assert_in(c["canonical"], ch) for ch in "ăâîșțĂÂÎȘȚ"],
        _assert("\\u" not in c["canonical"], "un diacritic a fost escapat")),

    "sir-gol-si-null": lambda c: (
        _assert_in(c["canonical"], ':null'),
        _assert_in(c["canonical"], '"":'),          # cheie goală
        _assert_in(c["canonical"], '"instance_label":""')),

    "obiect-gol-si-tablou-gol": lambda c: (
        _assert_in(c["canonical"], '{}'),
        _assert_in(c["canonical"], '[]'),
        _assert_in(c["canonical"], '[[],{}]')),

    "intreg-mare-exact": lambda c: (
        _assert_in(c["canonical"], str(signing.MAX_SAFE_INT)),
        _assert_in(c["canonical"], "-" + str(signing.MAX_SAFE_INT)),
        _assert(signing.MAX_SAFE_INT in _numbers(c["payload"]), "limita a dispărut")),

    "booleeni": lambda c: (
        # În Python `bool` E `int`: `true` și `1` trebuie amândouă în caz, altfel
        # un emitent care scrie `1` pentru `True` trece.
        _assert_in(c["canonical"], ':true'),
        _assert_in(c["canonical"], ':false'),
        _assert_in(c["canonical"], '"unu":1'),
        _assert_in(c["canonical"], '"zero":0')),

    "escape-uri": lambda c: (
        # Tabelul de escape C0/DEL, singura lui acoperire din tot depozitul.
        [_assert_in(c["canonical"], e) for e in (
            "\\u0000", "\\u0001", "\\u001f",        # hexa MINUSCULĂ, patru cifre
            "\\t", "\\n", "\\r", "\\b", "\\f",      # scurtăturile
            '\\"', "\\\\")],
        # DEL nu se escapează — se scrie brut. Cealaltă jumătate a regulii.
        _assert_in(c["canonical"], chr(0x7F)),
        _assert("\\u007f" not in c["canonical"], "DEL a fost escapat")),

    "astral-si-separatori": lambda c: (
        # U+2028/U+2029 sunt exact ce conține textul din jurnalele web, și
        # singurul lor loc din corpus. Toate ies BRUTE.
        [_assert_in(c["canonical"], chr(cp))
         for cp in (0x1F600, 0x2028, 0x2029, 0xE000, 0xFFFD)],
        _assert("\\u" not in c["canonical"], "ceva peste 0x20 a fost escapat")),

    "chei-la-marginea-ascii": lambda c: (
        _assert(chr(0x20) in c["payload"], "marginea de jos (0x20) a dispărut"),
        _assert(chr(0x7E) in c["payload"], "marginea de sus (0x7E) a dispărut"),
        _assert(c["canonical"].startswith('{" ":'), "spațiul nu mai e prima cheie")),

    "adancime-la-limita": lambda c: (
        _assert(_depth(c["payload"]) == signing.MAX_DEPTH,
                f"adâncimea e {_depth(c['payload'])}, nu {signing.MAX_DEPTH}"),
        # Ambele ramuri ale verificării: obiect ȘI tablou.
        _assert_in(c["canonical"], "["),
        _assert_in(c["canonical"], "{")),

    "imbricare-adanca": lambda c: (
        _assert_in(c["canonical"], '"audit_log":['),
        _assert(_depth(c["payload"]) >= 4, "structura s-a aplatizat")),

    # --- refuzate: proprietatea se citește din PAYLOAD ----------------------
    "cheie-non-ascii": lambda c: (
        _assert(any(ord(ch) > 0x7F for k in _keys(c["payload"]) for ch in k),
                "nicio cheie non-ASCII"),
        # DIVERGENȚA 4 cere una PESTE BMP: acolo diferă unitățile UTF-16 de
        # punctele de cod.
        _assert(any(ord(ch) > 0xFFFF for k in _keys(c["payload"]) for ch in k),
                "nicio cheie peste BMP — cazul nu mai acoperă divergența 4")),

    "cheie-diacritic": lambda c: _assert(
        any(0x7F < ord(ch) < 0x2000 for k in _keys(c["payload"]) for ch in k),
        "nicio cheie cu diacritic"),

    "cheie-control": lambda c: _assert(
        any(ord(ch) < 0x20 for k in _keys(c["payload"]) for ch in k),
        "nicio cheie cu un control C0"),

    "cheie-del": lambda c: _assert(
        any(chr(0x7F) in k for k in _keys(c["payload"])),
        "marginea de sus (DEL) a dispărut din caz"),

    "cheie-sub-limita": lambda c: _assert(
        any(chr(0x1F) in k for k in _keys(c["payload"])),
        "marginea de jos (0x1F) a dispărut din caz"),

    "adancime-peste-limita": lambda c: _assert(
        _depth(c["payload"]) == signing.MAX_DEPTH + 1,
        f"adâncimea e {_depth(c['payload'])}, nu {signing.MAX_DEPTH + 1}"),

    "float-fractionar": lambda c: _assert(
        any(isinstance(v, float) and not v.is_integer() for v in _numbers(c["payload"])),
        "niciun float cu parte fracționară"),

    "float-exponent": lambda c: _assert(
        any(isinstance(v, float) and "e" in repr(v) for v in _numbers(c["payload"])),
        "niciun float scris cu exponent — DIVERGENȚA 3 nu mai e acoperită"),

    "intreg-peste-limita": lambda c: _assert(
        any(isinstance(v, int) and abs(v) > signing.MAX_SAFE_INT
            for v in _numbers(c["payload"])),
        "niciun întreg peste limita exactă"),

    "surogat-neimperecheat": lambda c: _assert(
        any(0xD800 <= ord(ch) <= 0xDFFF for s in _strings(c["payload"]) for ch in s),
        "niciun surogat neîmperecheat"),
}


def _assert(condition: bool, message: str) -> None:
    assert condition, message


def _assert_in(haystack: str, needle: str) -> None:
    assert needle in haystack, f"{needle!r} lipsește"


def test_every_corpus_case_declares_what_it_is_for():
    """Un caz fără proprietate declarată e un caz care se poate goli.

    Eșecul pe care îl previne: cineva adaugă un caz și nu spune ce apără, sau
    scoate proprietatea unuia existent. Fixtura fiind generată, ce e ÎN ea se
    poate regenera oricând; ce nu se poate regenera e afirmația de aici.
    """
    assert set(CASE_PROPERTIES) == {c["name"] for c in CORPUS["cases"]}


@pytest.mark.parametrize("case", CORPUS["cases"], ids=_id)
def test_a_corpus_case_still_carries_the_property_it_exists_for(case):
    """Măsurat: `escape-uri` golit la `{"raw":"nimic special"}` și
    `astral-si-separatori` la `{"emoji":"a"}`, cu `canonical`/`hmac` regenerate
    cinstit și cu numele și numărul neatinse, treceau ambele suite — după care
    aceeași schimbare de hexa la AMBELE emitente trecea și ea.

    Aserțiunile de aici sunt despre ce ESTE cazul, nu despre cum îl cheamă.
    """
    CASE_PROPERTIES[case["name"]](case)


@pytest.mark.parametrize("case", ACCEPTED, ids=_id)
def test_accepted_corpus_case_produces_the_recorded_bytes(case):
    """Octeții și semnătura pe care le verifică și partea TypeScript.

    Eșecul pe care îl previne: unul dintre capete deviază singur. Fiindcă
    amândouă se compară cu șirurile din fixtură, o derivă comună cere schimbare
    de cod la ambele ȘI regenerarea fixturii.
    """
    assert canonical(case["payload"]).decode("utf-8") == case["canonical"], case["why"]
    assert sign(case["payload"], CORPUS["secret"]) == case["hmac"]


@pytest.mark.parametrize("case", REJECTED, ids=_id)
def test_rejected_corpus_case_is_refused_at_the_sender(case):
    """Un payload în afara contractului se oprește AICI, nu la celălalt capăt.

    Eșecul pe care îl previne: expeditorul semnează ceva ce receptorul nu poate
    reproduce, iar operatorul vede un 401 fără cauză în loc de un câmp numit în
    jurnal.
    """
    with pytest.raises(CanonicalError):
        canonical(case["payload"])


@pytest.mark.parametrize("case", ACCEPTED, ids=_id)
def test_accepted_cases_match_the_old_serialiser_byte_for_byte(case):
    """Emitentul propriu scrie exact ce scria `json.dumps` pe ce e în contract.

    Eșecul pe care îl previne: E2.1 rescrie forma canonică și schimbă tăcut
    octeții pentru payload-urile care merg azi. Ar rupe vectorii de aur din
    `tests/unit/test_beacon.py` și, mai rău, ar face ca un beacon actualizat și
    un martor neactualizat să nu se mai potrivească nicăieri altundeva decât în
    producție.
    """
    old = json.dumps(case["payload"], sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False)
    assert canonical(case["payload"]).decode("utf-8") == old, case["why"]


# ---------------------------------------------------------------------------
# Cazurile pe care JSON NU le poate purta identic în ambele limbaje.
#
# Scrise nativ, fiindcă un fișier JSON le-ar schimba pe drum: `60.0` devine `60`
# la `JSON.parse`, `NaN` nu e JSON, iar tuplul nu există în JavaScript. Geamănul
# din TypeScript are propria listă, cu aceleași nume.
# ---------------------------------------------------------------------------
def test_a_float_that_looks_like_an_integer_is_refused():
    """`beacon: {interval_s: 60.0}` în sentinel.yaml.

    Singura cale prin care un payload real ieșea din contract: `json.dumps`
    scrie `60.0`, `JSON.stringify` scrie `60`. Refuzul e aici ca plasă; cauza e
    închisă în `_coerce` din sentinel/config.py. Nu se convertește tăcut la
    `int`, fiindcă atunci contractul ar depinde de o conversie pe care celălalt
    capăt nu o face.
    """
    with pytest.raises(CanonicalError, match="float"):
        canonical({"interval_s": 60.0})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nan_and_infinity_are_refused(value):
    """`json.dumps` le scrie ca `NaN`/`Infinity`, care nu sunt JSON valid.

    Eșecul pe care îl previne: un contor calculat printr-o împărțire ajunge în
    semnal, `JSON.parse` la celălalt capăt aruncă, iar martorul refuză fiecare
    semnal cu o eroare de parsare pe care nimeni nu o leagă de câmpul acela.
    """
    with pytest.raises(CanonicalError):
        canonical({"n": value})


def test_a_bool_is_written_as_true_not_as_one():
    """În Python `bool` E `int`.

    Eșecul pe care îl previne: verificarea de interval pentru întregi prinde
    `True` înaintea verificării de bool și scrie `1`, iar celălalt capăt scrie
    `true` — semnătura nu se mai verifică pentru orice semnal cu un fanion în el.
    """
    assert canonical({"enabled": True, "off": False}).decode() == \
        '{"enabled":true,"off":false}'


@pytest.mark.parametrize("value", [(1, 2), {1, 2}, b"abc", object()])
def test_types_without_a_twin_are_refused(value):
    """Tuplu, mulțime, octeți, obiect oarecare.

    `json.dumps` ar serializa tăcut tuplul ca tablou și ar arunca pe restul.
    Eșecul pe care îl previne: un câmp adăugat ca tuplu merge luni de zile, apoi
    cineva îl citește înapoi din JSON ca listă și forma canonică se schimbă.
    """
    with pytest.raises(CanonicalError):
        canonical({"x": value})


def test_a_non_string_key_is_refused():
    """`json.dumps({1: "a"})` scrie `{"1": "a"}` — o conversie tăcută.

    Eșecul pe care îl previne: un dicționar indexat pe `int` (un id de instanță,
    un cod de severitate) se serializează diferit de cum îl citește oricine
    înapoi, iar cheia nu mai e cheia.
    """
    with pytest.raises(CanonicalError, match="cheie"):
        canonical({1: "a"})


def test_the_top_level_must_be_an_object():
    """Semnăm payload-uri, nu valori.

    Eșecul pe care îl previne: un apelant trimite o listă de rânduri direct, iar
    protocolul din E2 — care cere `instance_id` în corp ca să nu poți raporta în
    numele altcuiva — nu mai are unde să-l pună.
    """
    for bad in ([1, 2], "text", 5, None):
        with pytest.raises(CanonicalError):
            canonical(bad)


def _nest(n: int):
    """`n` containere imbricate, cel din afară mereu obiect.

    Alternează obiect/tablou ca să treacă prin ambele ramuri ale verificării de
    adâncime. Rădăcina rămâne obiect, altfel refuzul ar veni din altă regulă și
    n-ar mai spune nimic despre limită.
    """
    v: object = 1
    for i in range(n):
        v = {"a": v} if (i == n - 1 or i % 2 == 1) else [v]
    return v


def test_the_depth_limit_is_pinned_at_the_boundary_not_near_it():
    """Exact `MAX_DEPTH` trece, exact `MAX_DEPTH + 1` nu.

    Eșecul pe care îl previne, măsurat: `depth >= MAX_DEPTH` schimbat în
    `depth > MAX_DEPTH` doar în Python. Cele două capete se despart cu exact un
    nivel — Python acceptă 33, TypeScript refuză 33 — iar un test care încearcă
    34 și 31 nu vede nimic. Într-un modul al cărui scop E identitatea de octeți,
    o limită nefixată e chiar eșecul pe care modulul îl previne, cu un nivel mai
    sus.

    Și motivul pentru care limita există: fluxurile din E2 duc blob-uri JSON
    influențate de atacator, iar o recursie nemărginită într-o primitivă de
    semnare oprește serviciul care există tocmai ca să raporteze că serviciile
    trăiesc.
    """
    canonical(_nest(signing.MAX_DEPTH))
    with pytest.raises(CanonicalError, match="imbricare"):
        canonical(_nest(signing.MAX_DEPTH + 1))


def test_the_key_range_is_pinned_at_both_boundaries():
    """0x20 și 0x7E trec, 0x1F și 0x7F nu.

    Eșecul pe care îl previne, măsurat: `_KEY_MAX = 0x7F` în loc de `0x7E`, doar
    în Python. Python acceptă atunci o cheie cu DEL în ea și o semnează,
    TypeScript o refuză, iar dezacordul apare abia pe câmpul care o folosește.
    """
    assert canonical({" ": 1}) == b'{" ":1}'
    assert canonical({"~": 1}) == b'{"~":1}'
    for bad in (chr(0x1F), chr(0x7F), chr(0x00)):
        with pytest.raises(CanonicalError, match="cheia"):
            canonical({f"a{bad}b": 1})


def test_the_error_names_the_field():
    """Mesajul trebuie să spună CARE câmp, nu doar că a fost unul.

    Eșecul pe care îl previne: jurnalul spune „payload invalid" pentru un semnal
    cu douăzeci de câmpuri, iar operatorul le încearcă pe rând.
    """
    with pytest.raises(CanonicalError) as exc:
        canonical({"selfcheck": {"rows": [{"ratio": 0.5}]}})
    assert "$.selfcheck.rows[0].ratio" in str(exc.value)
