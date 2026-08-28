"""Indexul care scoate `max(ts)` pe sesiune din parcurgerea întregii tabele.

Pe 28 august 2026 panoul a picat de șase ori în șapte ore cu «datele paginii au
eșuat după 46,1 s: canceling statement due to statement timeout». Cea mai lentă
instrucțiune a zilei — 37 856 ms — era măturătoarea de sesiuni din
`close_stale_sessions`, al cărei `(SELECT max(ts) FROM session_commands WHERE
session_id = ...)` nu avea niciun index cu `session_id` în față, deci cobora prin
`session_commands_ts_idx` peste comenzile TUTUROR sesiunilor: 2 983 178 de
rânduri, 661 MB, la fiecare zece secunde.

Testele de aici păzesc reparația (0031) și cele două feluri în care ea ar putea
raporta succes fără să aibă efect: un index construit pe alte coloane, și o
migrație omorâtă de `statement_timeout` înainte să apuce să-l construiască.

Ce NU se poate verifica fără un PostgreSQL viu: că planificatorul ALEGE indexul.
Aia se citește cu `EXPLAIN` pe gazdă, după migrație.
"""

from __future__ import annotations

import re
from pathlib import Path

RADACINA = Path(__file__).resolve().parents[2]
MIGRATII = RADACINA / "sentinel" / "db" / "migrations"
MIGRATIA = MIGRATII / "0031_session_last_activity.sql"
TUNING = RADACINA / "deploy" / "postgres" / "sentinel-tuning.conf"

_INDEX = re.compile(
    r"CREATE\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(?P<nume>\w+)\s+ON\s+(?P<tabela>\w+)\s*"
    r"(?:USING\s+\w+\s*)?\((?P<coloane>[^)]*)\)",
    re.I | re.S,
)


def _executabil(sql: str) -> str:
    """Ce chiar ajunge la PostgreSQL: fără comentarii și fără șiruri.

    Șirurile se scot fiindcă mesajele de eroare din migrații CITEAZĂ SQL — 0031
    numește `CREATE INDEX CONCURRENTLY` în textul unei excepții, ca operatorul să
    știe ce s-a întâmplat. Un test care ar căuta tiparul în text brut ar da roșu
    pe o explicație, nu pe o instrucțiune.
    """
    fara_comentarii = "\n".join(
        re.sub(r"--.*$", "", linie) for linie in sql.splitlines())
    return re.sub(r"'(?:[^']|'')*'", "''", fara_comentarii)


def _coloane(lista: str) -> list[str]:
    """Numele coloanelor dintr-o listă de index, fără DESC/ASC/opclass."""
    return [c.split()[0].strip('"') for c in lista.split(",") if c.strip()]


def _rezolva(coloane: list[str]) -> bool:
    """Servește indexul ăsta un `max(ts)` filtrat pe UNA din sesiuni?

    Doar dacă `session_id` e prima coloană — pe ea se filtrează cu egalitate,
    iar un B-tree se poate mărgini doar pe prefix — și `ts` e imediat după ea,
    ca marginea intervalului să fie chiar prima intrare citită.
    """
    return coloane[:2] == ["session_id", "ts"]


def _indecsi(tabela: str) -> dict[str, list[str]]:
    gasiti: dict[str, list[str]] = {}
    for f in sorted(MIGRATII.glob("*.sql")):
        for m in _INDEX.finditer(_executabil(f.read_text(encoding="utf-8"))):
            if m.group("tabela").lower() == tabela:
                gasiti[m.group("nume").lower()] = _coloane(m.group("coloane"))
    return gasiti


def _secunde(valoare: str) -> float:
    """`'10min'`, `'60s'`, `2000` → secunde. Ridică dacă nu înțelege unitatea."""
    m = re.fullmatch(r"'?\s*(\d+)\s*(ms|s|min|h)?\s*'?", valoare.strip(), re.I)
    assert m, f"nu pot citi durata {valoare!r}"
    n = int(m.group(1))
    return n * {None: 1, "ms": 0.001, "s": 1, "min": 60, "h": 3600}[
        (m.group(2) or "").lower() or None]


def _din_tuning(nume: str) -> float:
    m = re.search(rf"^\s*{nume}\s*=\s*(\S+)", TUNING.read_text(encoding="utf-8"), re.M)
    assert m, f"{nume} nu mai e în {TUNING.name}; testul ar păzi o valoare inventată"
    return _secunde(m.group(1))


def _set_local(nume: str) -> tuple[str, float]:
    """Perechea (cuvântul de domeniu, secunde) pentru un `SET ... = ...` din 0031."""
    m = re.search(rf"^\s*SET\s+(LOCAL\s+|SESSION\s+)?{nume}\s*=\s*(\S+?);",
                  MIGRATIA.read_text(encoding="utf-8"), re.M | re.I)
    assert m, (
        f"0031 nu mai ridică {nume}. Instanța îl are din "
        f"deploy/postgres/sentinel-tuning.conf, iar migrate.py nu-l schimbă.")
    return (m.group(1) or "").strip().upper(), _secunde(m.group(2))


# ---------------------------------------------------------------------------
# Indexul
# ---------------------------------------------------------------------------
def test_parserul_de_indecsi_chiar_vede_tabela():
    """Fără asta, toate testele de mai jos ar trece pe o listă goală.

    E eșecul numit în CLAUDE.md: o listă parametrizată ieșită goală și sărită
    tăcut. Dacă regexul încetează să potrivească — altă formă de `CREATE INDEX`,
    alt fișier — vreau să pice AICI, nu să declar verde pe nimic.
    """
    indecsi = _indecsi("session_commands")
    assert indecsi.get("session_commands_ts_idx") == ["ts"], indecsi
    assert indecsi.get("session_commands_session_idx") == ["session_id", "id"], indecsi
    assert indecsi.get("session_commands_user_idx") == ["username", "ts"], indecsi


def test_exista_index_cu_session_id_in_fata_si_ts_dupa():
    """Fără el, panoul moare în `statement_timeout` și operatorul primește 🔴.

    `max(ts)` filtrat pe o sesiune poate fi luat dintr-o singură coborâre doar
    dacă `session_id` e PRIMA coloană a unui index și `ts` urmează imediat. Cu
    orice altă ordine, planificatorul cade pe `session_commands_ts_idx (ts DESC)`
    și parcurge comenzile tuturor sesiunilor — pe gazdă, 2 983 178 de rânduri /
    661 MB, de două ori per sesiune, la fiecare zece secunde. Măsurat: 22 072 –
    37 856 ms per instrucțiune, șase căderi de panou în șapte ore.
    """
    indecsi = _indecsi("session_commands")
    potriviti = [n for n, col in indecsi.items() if _rezolva(col)]
    assert potriviti, (
        "niciun index pe session_commands nu începe cu (session_id, ts). "
        f"Ce există: {indecsi}"
    )


def test_criteriul_nu_accepta_indecsii_care_nu_rezolva():
    """Criteriul lărgit ar face testul de mai sus să treacă pe indexul greșit.

    `session_commands_session_idx (session_id, id)` are deja `session_id` prima.
    Un criteriu care s-ar uita doar la prima coloană ar fi declarat verde ÎNAINTE
    de reparație, adică fix pe starea care a picat panoul de șase ori. Iar
    `(session_id, id)` chiar nu rezolvă: `id` e ordinea INSERT-ului, `ts` e
    ordinea faptei, iar docstring-ul din `sentinel/db/repo/logins.py` spune de ce
    nu coincid — înregistrările nu sosesc în ordine, orfanele se leagă mai
    târziu. `ts` nici măcar nu e în indexul ăla, deci `max(ts)` ar cere un acces
    la heap pentru fiecare rând al sesiunii; pentru sesiunea de deploy din 0028,
    cu 558 079 de comenzi, mai rău decât defectul.
    """
    assert _rezolva(["session_id", "ts"])
    assert not _rezolva(["session_id", "id"]), "criteriul acceptă indexul de dinainte"
    assert not _rezolva(["ts", "session_id"]), "criteriul acceptă ordinea inversă"
    assert not _rezolva(["session_id"]), "criteriul acceptă un index fără ts"
    assert not _rezolva(_indecsi("session_commands")["session_commands_session_idx"])


def test_nicio_migratie_nu_construieste_index_concurrently():
    """`CREATE INDEX CONCURRENTLY` într-o migrație oprește schema pe loc.

    `sentinel/db/migrate.py` aplică fiecare fișier într-o singură tranzacție, iar
    PostgreSQL refuză `CONCURRENTLY` acolo (25001). Migrația ar pica, s-ar derula
    înapoi, iar toate migrațiile de după ea n-ar mai fi aplicate niciodată — pe
    fiecare gazdă, nu doar pe cea pe care s-a scris.
    """
    vinovate = [
        f.name for f in sorted(MIGRATII.glob("*.sql"))
        if re.search(r"CREATE\s+INDEX\s+CONCURRENTLY",
                     _executabil(f.read_text(encoding="utf-8")), re.I)
    ]
    assert not vinovate, vinovate


# ---------------------------------------------------------------------------
# Timeout-urile: migrația trebuie să apuce să construiască indexul
# ---------------------------------------------------------------------------
def test_statement_timeout_ridicat_peste_cel_al_instantei():
    """Altfel construcția e omorâtă la 60 s și schema se oprește la 0031.

    `deploy/postgres/sentinel-tuning.conf` pune `statement_timeout` pe toată
    instanța, iar `migrate.py` se conectează fără să-l schimbe. Un `CREATE INDEX`
    pe 661 MB cu `maintenance_work_mem = 64MB` sortează trei milioane de rânduri
    pe disc; dacă depășește, PostgreSQL îl anulează, tranzacția se derulează
    înapoi și operatorul rămâne cu «migration failed», fără index și cu panoul
    care pică în continuare.

    Mărginit, nu zero: dacă durează zece minute, ingestia stă blocată zece
    minute, și e mai bine să se retragă.
    """
    domeniu, migratie = _set_local("statement_timeout")
    instanta = _din_tuning("statement_timeout")
    assert migratie > instanta, (
        f"0031 pune statement_timeout = {migratie}s, instanța are {instanta}s")
    assert migratie > 0, "statement_timeout = 0 lasă construcția fără nicio margine"
    assert domeniu == "LOCAL", (
        "fără LOCAL valoarea rămâne pe conexiune și după migrație — următoarea "
        "interogare a runner-ului ar rula fără plasa de siguranță a instanței")


def test_lock_timeout_ridicat_dar_marginit():
    """Prea mic, migrația pică degeaba; zero, ingestia se oprește definitiv.

    `CREATE INDEX` cere `SHARE`, care intră în conflict cu `ROW EXCLUSIVE` al
    INSERT-urilor de ingestie. Cu `lock_timeout` de 10 s, un lot de ingestie
    perfect normal e de ajuns ca migrația să se retragă. Cu `lock_timeout = 0`,
    construcția stă la coadă oricât, iar fiecare INSERT care sosește se așază în
    spatele ei — adică ingestia se oprește, și nu din cauza unui atac.
    """
    domeniu, migratie = _set_local("lock_timeout")
    instanta = _din_tuning("lock_timeout")
    assert migratie > instanta, (
        f"0031 pune lock_timeout = {migratie}s, instanța are {instanta}s")
    assert migratie > 0, "lock_timeout = 0 înseamnă așteptare nemărginită la coadă"
    assert domeniu == "LOCAL"


# ---------------------------------------------------------------------------
# Garda: ce a rămas în catalog, nu ce s-a cerut
# ---------------------------------------------------------------------------
def _regex_garzii() -> str:
    text = MIGRATIA.read_text(encoding="utf-8")
    m = re.search(r"definitie\s*!~\s*'([^']*)'", text)
    assert m, "0031 nu mai compară definiția indexului cu nimic"
    return m.group(1)


def test_garda_accepta_indexul_corect_si_respinge_omonimele():
    """Garda decide pe definiția din catalog; dacă decide greșit, e mai rea decât lipsa ei.

    `CREATE INDEX IF NOT EXISTS` se potrivește DOAR PE NUME. Un index cu numele
    ăsta pe alte coloane — sau rămas de la o încercare cu altă ordine — ar face
    migrația să raporteze «aplicată» în timp ce planificatorul rămâne pe
    `session_commands_ts_idx` și panoul pică mai departe. Invers, o gardă prea
    strictă ar refuza un index construit corect și ar rupe fiecare instalare.

    Se verifică amândouă direcțiile, pe forma reală a lui `pg_get_indexdef`.
    """
    tipar = re.compile(_regex_garzii())
    cap = ("CREATE INDEX session_commands_session_ts_idx "
           "ON public.session_commands USING btree ")

    assert tipar.search(cap + "(session_id, ts DESC)"), \
        "garda ar refuza chiar indexul pe care îl construiește migrația"
    assert not tipar.search(cap + "(session_id, id)"), \
        "garda ar binecuvânta exact indexul care nu rezolvă defectul"
    assert not tipar.search(cap + "(ts DESC, session_id)"), \
        "garda ar binecuvânta ordinea inversă, adică defectul măsurat"
    assert not tipar.search(cap + "(session_id)"), \
        "garda ar binecuvânta un index fără ts"


def test_garda_citeste_si_validitatea_indexului():
    """Un `CONCURRENTLY` întrerupt lasă un index INVALID cu numele corect.

    Există în catalog, e scris la fiecare INSERT, și nu e folosit de nimeni. Fără
    `indisvalid`/`indisready`, migrația ar fi înregistrată ca aplicată, iar
    panoul ar continua să pice cu `schema_version` spunând că reparația a plecat.

    Aserțiunea e pe PREZENȚA celor două coloane în gardă — că blocul chiar ridică
    excepția se poate dovedi doar pe un PostgreSQL viu.
    """
    executabil = _executabil(MIGRATIA.read_text(encoding="utf-8"))
    assert "indisvalid" in executabil and "indisready" in executabil, executabil
    assert "IF NOT EXISTS" in executabil, (
        "fără IF NOT EXISTS, un index creat de mână înainte de migrație o face "
        "să pice cu «relation already exists» și oprește schema acolo")
