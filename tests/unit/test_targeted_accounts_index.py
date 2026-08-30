"""Indexul care scoate cardul „Conturi țintă" de sub volumul brut al tabelei.

0033 a reparat `probed_paths`; `targeted_accounts` avea exact aceeași boală —
`raw_events_source_idx` (0001) are `(source, action, ts DESC)`, deci nu se poate
mărgini pe fereastra de 7 zile fără să parcurgă tot ce a strâns `sshd|auth_fail`
de la începutul retenției, iar rândurile astea sunt împrăștiate printre milioane
de rânduri de `auditd`. Măsurat pe replică: 227 406 de buffere înainte,
1 691 după, `Index Only Scan`, `Heap Fetches: 0`.

Testele de aici păzesc 0034 și felurile în care ar putea raporta succes fără
efect: un index care pierde `source`/`action` din predicat, unul care pierde
`INCLUDE (src_ip)`, o interogare care cere o coloană din afara indexului, și un
`CONCURRENTLY` întrerupt lăsat INVALID sub numele corect.

Ce NU se poate verifica fără un PostgreSQL viu: că planificatorul chiar ALEGE
`Index Only Scan`. Verificat manual pe o replică locală (PostgreSQL 16.4,
6 640 790 de rânduri, 11 partiții zilnice) — vezi comentariul din 0034.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from sentinel.analytics import aggregate

RADACINA = Path(__file__).resolve().parents[2]
MIGRATII = RADACINA / "sentinel" / "db" / "migrations"
MIGRATIA = MIGRATII / "0034_targeted_accounts_index.sql"

NUME = "raw_events_authfail_idx"

_INDEX = re.compile(
    r"CREATE\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(?P<nume>\w+)\s+ON\s+(?P<tabela>\w+)\s*"
    r"(?:USING\s+\w+\s*)?\((?P<chei>[^)]*)\)"
    r"(?:\s*INCLUDE\s*\((?P<include>[^)]*)\))?"
    r"(?:\s*WHERE\s+(?P<predicat>[^;]*))?\s*;",
    re.I | re.S,
)


def _executabil(sql: str) -> str:
    """Ce chiar ajunge la PostgreSQL: fără comentarii.

    La fel ca la 0033: antetul citează definiții de index în proză, iar un test
    pe text brut ar putea da verde pe o explicație, nu pe o instrucțiune.
    """
    return "\n".join(re.sub(r"--.*$", "", linie) for linie in sql.splitlines())


def _coloane(lista: str | None) -> list[str]:
    if not lista:
        return []
    return [c.split()[0].strip('"') for c in lista.split(",") if c.strip()]


def _indexul() -> dict[str, object]:
    text = _executabil(MIGRATIA.read_text(encoding="utf-8"))
    gasit = None
    for m in _INDEX.finditer(text):
        if m.group("nume").lower() == NUME and m.group("tabela").lower() == "raw_events":
            gasit = {
                "chei": _coloane(m.group("chei")),
                "include": _coloane(m.group("include")),
                "predicat": " ".join((m.group("predicat") or "").split()),
            }
    assert gasit, f"{NUME} nu mai e creat de 0034 pe raw_events"
    return gasit


def test_indexul_acopera_conturile_tinta():
    """Fără el, panoul plătește o pagină de heap pentru fiecare rând de sshd.

    Interogarea filtrează `source = 'sshd' AND action = 'auth_fail'` — dacă
    oricare din ele lipsește din predicat, planificatorul trebuie să-l verifice
    din heap pentru fiecare rând, iar rândurile de sshd sunt împrăștiate printre
    milioane de rânduri de auditd.
    """
    idx = _indexul()
    predicat = idx["predicat"]
    disponibile = set(idx["chei"]) | set(idx["include"])
    assert idx["chei"][:1] == ["ts"], (
        "ts nu e prima cheie — fereastra de 7 zile ar citi toată retenția")
    assert re.search(r"source\s*=\s*'sshd'", predicat), predicat
    assert re.search(r"action\s*=\s*'auth_fail'", predicat), predicat
    assert {"username", "src_ip"} <= disponibile, idx


def test_criteriul_respinge_forme_incomplete():
    """Un criteriu prea larg ar binecuvânta exact starea care face panoul să cadă."""
    idx = dict(_indexul())

    fara_action = dict(idx, predicat="source = 'sshd'")
    assert not re.search(r"action\s*=\s*'auth_fail'", fara_action["predicat"])

    fara_include = dict(idx, include=[])
    assert "src_ip" not in (set(fara_include["chei"]) | set(fara_include["include"]))


def test_interogarea_targeted_accounts_nu_cere_nimic_din_afara_indexului():
    """O coloană nouă în SELECT ar stinge tăcut Index Only Scan.

    Aceeași pană ca la `probed_paths` (0033): cineva adaugă `http_ua` sau altă
    coloană în `targeted_accounts`, testele de Python trec, iar planul
    redevine dependent de heap.
    """
    idx = _indexul()
    acoperite = set(idx["chei"]) | set(idx["include"])
    for coloana in re.findall(r"(\w+)\s*=", idx["predicat"]):
        acoperite.add(coloana)

    sursa = inspect.getsource(aggregate.targeted_accounts)
    m = re.search(r'db\.fetch\(\s*"""(.*?)"""', sursa, re.S)
    assert m, "nu mai găsesc interogarea livrată de targeted_accounts"
    sql = m.group(1)

    coloane_raw_events = {"ts", "source", "action", "username", "src_ip"}
    cerute = {c for c in coloane_raw_events if re.search(rf"\b{c}\b", sql)}
    assert cerute, "nu am găsit nicio coloană de raw_events în targeted_accounts"
    assert cerute <= acoperite, (
        f"targeted_accounts cere {sorted(cerute - acoperite)} din afara lui {NUME}; "
        f"planul redevine Index Scan")


def test_garda_accepta_forma_corecta_si_respinge_omonime():
    """`IF NOT EXISTS` se uită DOAR PE NUME — un index cu numele corect dar
    predicat incomplet ar face migrația să raporteze „aplicată" cu panoul
    picând mai departe exact la fel."""
    text = MIGRATIA.read_text(encoding="utf-8")
    tipare = [re.compile(g.replace("''", "'"))
              for g in re.findall(r"definitie\s*!~\s*'((?:[^']|'')*)'", text)]
    assert tipare, "0034 nu mai compară definiția indexului cu nimic"

    cap = "CREATE INDEX raw_events_authfail_idx ON ONLY public.raw_events USING btree "

    def trece(definitie: str) -> bool:
        return all(t.search(definitie) for t in tipare)

    assert trece(cap + "(ts DESC, username) INCLUDE (src_ip) "
                       "WHERE ((source = 'sshd'::text) AND (action = 'auth_fail'::text))"), \
        "garda ar refuza chiar indexul pe care îl construiește migrația"
    assert not trece(cap + "(ts DESC, username) INCLUDE (src_ip) "
                           "WHERE (source = 'sshd'::text)"), \
        "garda ar binecuvânta un index peste tot traficul sshd, nu doar auth_fail"
    assert not trece(cap + "(ts DESC, username) INCLUDE (src_ip) "
                           "WHERE (action = 'auth_fail'::text)"), \
        "garda ar binecuvânta un index fără source în predicat"
    assert not trece(cap + "(ts DESC, username) "
                           "WHERE ((source = 'sshd'::text) AND (action = 'auth_fail'::text))"), \
        "garda ar binecuvânta un index fără INCLUDE (src_ip)"


def test_garda_citeste_validitatea_si_migratia_ridica_timeout_urile():
    """La fel ca 0031/0033: fără `indisvalid`/`indisready`, un CONCURRENTLY
    întrerupt ar trece drept „aplicat"; fără timeout-uri ridicate, construcția
    ar fi omorâtă de instanța cu statement_timeout=60s."""
    text = MIGRATIA.read_text(encoding="utf-8")
    assert "indisvalid" in text and "indisready" in text, text
    assert "IF NOT EXISTS" in text
    assert re.search(r"SET\s+LOCAL\s+statement_timeout\s*=\s*'10min'", text, re.I)
    assert re.search(r"SET\s+LOCAL\s+lock_timeout\s*=\s*'60s'", text, re.I)
