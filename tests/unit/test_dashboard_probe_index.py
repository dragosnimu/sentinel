"""Indexul care scoate panoul „Căi sondate" de sub volumul brut al tabelei.

Pe 29–30 august 2026 panoul principal cădea de 2–6 ori pe oră, în fiecare oră,
cu «datele paginii au eșuat după 47,0 s: canceling statement due to statement
timeout». Cauza e forma din migrația 0030, netratată până la capăt: rândurile
utile sunt împrăștiate printre 3,8 milioane de rânduri de `auditd`, câte una la
~15, deci orice interogare care mai are nevoie de o coloană din HEAP plătește o
pagină pe rând, iar costul ei crește cu volumul brut al partiției.

`raw_events_notfound_idx` din 0030 era parțial doar pe `http_status = 404`.
Amândouă interogările care îl foloseau filtrează însă și `source = 'nginx'`, iar
`source` nu era nici cheie, nici `INCLUDE`, nici implicat de predicat — deci
PostgreSQL îl citea din heap pentru fiecare rând. Măsurat pe o replică a formei
de pe gazdă: `Index Scan` cu `Filter: (source = 'nginx')`, 53 375 de accese la
buffere pentru 55 674 de rânduri. Cu `source` mutat în predicat: `Index Only
Scan`, `Heap Fetches: 0`, 501 de buffere.

Testele de aici păzesc reparația (0033) și felurile în care ea ar putea raporta
succes fără efect: un index care pierde `source` din predicat, unul care pierde
`INCLUDE (src_ip)`, o interogare care începe să ceară o coloană din afara
indexului, și un index vechi lăsat în urmă sub alt nume.

Ce NU se poate verifica fără un PostgreSQL viu: că planificatorul chiar ALEGE
`Index Only Scan`. Aia se citește cu `EXPLAIN` pe gazdă, după migrație.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from sentinel.analytics import aggregate, insights

RADACINA = Path(__file__).resolve().parents[2]
MIGRATII = RADACINA / "sentinel" / "db" / "migrations"
MIGRATIA = MIGRATII / "0033_probe_index_source.sql"
CORE = MIGRATII / "0001_core.sql"
TUNING = RADACINA / "deploy" / "postgres" / "sentinel-tuning.conf"

#: Indexul pe care îl construiește 0033 și pe care îl caută restul fișierului.
NUME = "raw_events_probes_idx"


def _executabil(sql: str) -> str:
    """Ce chiar ajunge la PostgreSQL: fără comentarii.

    Antetul lui 0033 CITEAZĂ definiția indexului vechi, ca operatorul să vadă
    diferența. Un test care ar căuta tipare în textul brut ar da roșu pe o
    explicație în loc de pe o instrucțiune — sau, mai rău, verde: predicatul
    corect apare și el în proză.
    """
    return "\n".join(re.sub(r"--.*$", "", linie) for linie in sql.splitlines())


# ---------------------------------------------------------------------------
# Ce spune migrația
# ---------------------------------------------------------------------------
_INDEX = re.compile(
    r"CREATE\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(?P<nume>\w+)\s+ON\s+(?P<tabela>\w+)\s*"
    r"(?:USING\s+\w+\s*)?\((?P<chei>[^)]*)\)"
    r"(?:\s*INCLUDE\s*\((?P<include>[^)]*)\))?"
    r"(?:\s*WHERE\s+(?P<predicat>[^;]*))?\s*;",
    re.I | re.S,
)


def _coloane(lista: str | None) -> list[str]:
    """Numele coloanelor dintr-o listă de index, fără DESC/ASC/opclass."""
    if not lista:
        return []
    return [c.split()[0].strip('"') for c in lista.split(",") if c.strip()]


def _indecsi_pe_raw_events() -> dict[str, dict[str, object]]:
    """Toți indecșii pe `raw_events` declarați de migrații, cu forma lor."""
    gasiti: dict[str, dict[str, object]] = {}
    for f in sorted(MIGRATII.glob("*.sql")):
        text = _executabil(f.read_text(encoding="utf-8"))
        for m in _INDEX.finditer(text):
            if m.group("tabela").lower() != "raw_events":
                continue
            gasiti[m.group("nume").lower()] = {
                "chei": _coloane(m.group("chei")),
                "include": _coloane(m.group("include")),
                "predicat": " ".join((m.group("predicat") or "").split()),
                "fisier": f.name,
            }
        for m in re.finditer(r"DROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?(\w+)\s*;", text, re.I):
            gasiti.pop(m.group(1).lower(), None)
    return gasiti


def _coloane_raw_events() -> set[str]:
    """Coloanele reale ale lui `raw_events`, citite din 0001.

    Luate din schemă, nu scrise de mână: dacă tabela capătă o coloană nouă,
    verificarea de acoperire de mai jos o vede fără să fie actualizată aici.
    """
    text = CORE.read_text(encoding="utf-8")
    corp = re.search(r"CREATE TABLE raw_events \((.*?)\n\) PARTITION BY", text, re.S)
    assert corp, "nu mai găsesc definiția lui raw_events în 0001_core.sql"
    nume: set[str] = set()
    for linie in corp.group(1).splitlines():
        linie = re.sub(r"--.*$", "", linie).strip()
        m = re.match(r"^([a-z_][a-z0-9_]*)\s+[a-z]", linie)
        if m and m.group(1).upper() not in {"PRIMARY", "FOREIGN", "UNIQUE", "CHECK"}:
            nume.add(m.group(1))
    return nume


def test_parserul_chiar_vede_indecsii_lui_raw_events():
    """Fără asta, tot fișierul ar trece pe un dicționar gol.

    E eșecul numit în CLAUDE.md: o listă parametrizată ieșită goală și sărită
    tăcut. Dacă regexul încetează să potrivească — altă formă de `CREATE
    INDEX`, alt fișier — vreau să pice AICI, nu să declar verde pe nimic.
    """
    indecsi = _indecsi_pe_raw_events()
    assert indecsi["raw_events_source_idx"]["chei"] == ["source", "action", "ts"], indecsi
    assert indecsi["raw_events_hostile_idx"]["chei"] == ["ts"], indecsi
    assert indecsi["raw_events_hostile_idx"]["include"] == [
        "src_ip", "source", "geo_country", "geo_asn", "geo_as_org"], indecsi
    assert "action IN ('auth_fail', 'alert')" in str(
        indecsi["raw_events_hostile_idx"]["predicat"]), indecsi


def test_coloanele_lui_raw_events_se_citesc_din_schema():
    """Aceeași plasă, pentru celălalt parser: o listă goală ar face testul de
    acoperire să treacă pe orice interogare, inclusiv pe una care cere `raw`."""
    coloane = _coloane_raw_events()
    for asteptata in ("ts", "source", "http_path", "http_status", "src_ip", "raw", "username"):
        assert asteptata in coloane, coloane
    assert "PRIMARY" not in coloane and "raw_events" not in coloane


# ---------------------------------------------------------------------------
# Indexul: forma care face Index Only Scan posibil
# ---------------------------------------------------------------------------
def _acopera_sondarile(idx: dict[str, object]) -> bool:
    """Poate indexul ăsta răspunde la «căi sondate» fără să atingă heap-ul?

    Trei condiții, fiecare dintr-un motiv separat:

    * `source` ȘI `http_status` în predicat — sunt cele două filtre cu
      egalitate ale interogării. Ce e implicat de predicat nu mai e cerut din
      heap; ce nu e implicat, da. 0030 avea doar `http_status`, și exact
      `source` era coloana care trimitea planul înapoi în heap.
    * `ts` prima cheie — fereastra e un INTERVAL, iar un B-tree se poate
      mărgini la o porțiune contiguă doar pe prefix. Cu `ts` mai încolo,
      retenția de 30 de zile s-ar citi întreagă pentru o întrebare de 7.
    * `http_path` și `src_ip` prezente, oriunde (cheie sau `INCLUDE`) — sunt
      exact ce întoarce interogarea. Lipsind, planul redevine `Index Scan`.
    """
    predicat = str(idx["predicat"])
    chei = list(idx["chei"])  # type: ignore[arg-type]
    disponibile = set(chei) | set(idx["include"])  # type: ignore[arg-type]
    return (
        re.search(r"source\s*=\s*'nginx'", predicat) is not None
        and re.search(r"http_status\s*=\s*404", predicat) is not None
        and chei[:1] == ["ts"]
        and {"http_path", "src_ip"} <= disponibile
    )


def test_exista_index_care_acopera_sondarile_404():
    """Fără el, panoul moare în `statement_timeout` și operatorul primește 🟡.

    Interogarea citește 404-urile nginx din 7 zile. Dacă `source` nu e în
    predicatul indexului, PostgreSQL trebuie să-l ia din heap pentru fiecare
    rând, iar rândurile de nginx sunt împrăștiate printre milioane de rânduri de
    `auditd` — una pe pagină. Măsurat pe replică: 53 375 de buffere în loc de
    501, și un cost care crește cu volumul brut al partiției, nu cu numărul de
    sondări.
    """
    indecsi = _indecsi_pe_raw_events()
    potriviti = [n for n, idx in indecsi.items() if _acopera_sondarile(idx)]
    assert potriviti, (
        "niciun index pe raw_events nu acoperă interogarea de sondări. "
        f"Ce există: {indecsi}"
    )


def test_criteriul_respinge_exact_indexul_din_0030():
    """Un criteriu prea larg ar fi declarat verde chiar starea care a picat.

    `raw_events_notfound_idx` din 0030 avea aceleași coloane și același
    `INCLUDE`; îi lipsea doar `source` din predicat. Un criteriu care s-ar uita
    numai la coloane l-ar fi binecuvântat — adică ar fi spus „reparat" despre
    fix configurația care făcea panoul să cadă de trei ori pe oră.
    """
    bun = {"chei": ["ts", "http_path"], "include": ["src_ip"],
           "predicat": "source = 'nginx' AND http_status = 404"}
    assert _acopera_sondarile(bun)

    ca_in_0030 = dict(bun, predicat="http_status = 404")
    assert not _acopera_sondarile(ca_in_0030), "criteriul acceptă indexul de dinainte"

    fara_include = dict(bun, include=[])
    assert not _acopera_sondarile(fara_include), "criteriul acceptă un index fără src_ip"

    fara_cale = dict(bun, chei=["ts"])
    assert not _acopera_sondarile(fara_cale), "criteriul acceptă un index fără http_path"

    ts_al_doilea = dict(bun, chei=["http_path", "ts"])
    assert not _acopera_sondarile(ts_al_doilea), (
        "criteriul acceptă un index care nu se poate mărgini pe fereastra de timp")

    fara_404 = dict(bun, predicat="source = 'nginx'")
    assert not _acopera_sondarile(fara_404), (
        "criteriul acceptă un index peste TOATE cererile nginx, nu doar 404-urile")


# ---------------------------------------------------------------------------
# Interogările: ce cer ele trebuie să încapă în ce dă indexul
# ---------------------------------------------------------------------------
def _coloane_cerute(sql: str) -> set[str]:
    """Coloanele lui `raw_events` care apar în interogarea asta."""
    return {c for c in _coloane_raw_events() if re.search(rf"\b{c}\b", sql)}


def _sql_livrat(functie) -> str:
    """Interogarea pe care funcția asta o dă chiar driverului.

    NU `inspect.getsource` întreg: corpul lui `_probe_campaign_insights`
    conține și Python — un câmp numit `action=` al lui `Insight` — iar o
    căutare de cuvinte peste tot fișierul l-ar citi drept coloana `action` a lui
    `raw_events` și ar da roșu pe ceva ce nu ajunge niciodată la PostgreSQL.
    """
    sursa = inspect.getsource(functie)
    m = re.search(r'db\.fetch\(\s*"""(.*?)"""', sursa, re.S)
    assert m, f"nu mai găsesc interogarea livrată de {functie.__name__}"
    return m.group(1)


def _indexul_sondarilor() -> dict[str, object]:
    idx = _indecsi_pe_raw_events().get(NUME)
    assert idx, f"{NUME} nu mai e creat de nicio migrație"
    return idx


def test_interogarile_de_sondari_nu_cer_nimic_din_afara_indexului():
    """O coloană în plus în SELECT stinge tăcut `Index Only Scan`.

    Asta e felul în care reparația se poate pierde fără ca nimeni să atingă
    migrația: cineva adaugă `http_ua` sau `geo_country` în panoul de sondări,
    testele trec, iar planul redevine `Index Scan` cu o pagină de heap pe rând.
    Panoul începe iar să cadă, și nimic nu leagă cauza de schimbare.

    Se verifică AMÂNDOI consumatorii, fiindcă ei citesc aceleași rânduri:
    `aggregate.probed_paths` (panoul) și `insights._probe_campaign_insights`
    (cardul „Campanie activă împotriva ...").
    """
    idx = _indexul_sondarilor()
    acoperite = set(idx["chei"]) | set(idx["include"])  # type: ignore[arg-type]
    # Ce e implicat de predicat nu se mai cere din heap — de-asta `source` și
    # `http_status` sunt tot atât de „acoperite" ca o coloană din INCLUDE.
    for coloana in re.findall(r"(\w+)\s*=", str(idx["predicat"])):
        acoperite.add(coloana)

    for functie in (aggregate.probed_paths, insights._probe_campaign_insights):
        cerute = _coloane_cerute(_sql_livrat(functie))
        assert cerute, f"nu am găsit nicio coloană de raw_events în {functie.__name__}"
        assert cerute <= acoperite, (
            f"{functie.__name__} cere {sorted(cerute - acoperite)} din afara lui {NUME}; "
            f"planul redevine Index Scan și panoul plătește o pagină de heap pe rând")


def test_criteriul_de_acoperire_vede_o_coloana_in_plus():
    """Verificarea de mai sus trebuie să pice pe cazul pe care îl păzește.

    Fără proba asta, `cerute <= acoperite` ar putea trece fiindcă `_coloane_cerute`
    nu găsește nimic — exact aserțiunea pe prezența unui nume în loc de pe
    decizia luată din el, pe care CLAUDE.md o numește.
    """
    acoperite = {"ts", "http_path", "src_ip", "source", "http_status"}
    ca_azi = _coloane_cerute(_sql_livrat(aggregate.probed_paths))
    assert ca_azi == acoperite, ca_azi
    cu_agent = _coloane_cerute("SELECT http_path, http_ua FROM raw_events WHERE ts > x")
    assert not cu_agent <= acoperite
    assert cu_agent - acoperite == {"http_ua"}


# ---------------------------------------------------------------------------
# Indexul vechi: șters, și ștergerea verificată pe efect
# ---------------------------------------------------------------------------
def test_indexul_din_0030_nu_mai_ramane_in_urma():
    """Doi indecși peste aceleași rânduri înseamnă scriere dublă la fiecare 404.

    `raw_events_notfound_idx` indexează exact aceleași rânduri ca cel nou și îi
    servește pe aceiași consumatori, doar mai prost. Lăsat pe loc, n-ar aduce
    niciun plan mai bun, dar s-ar scrie la fiecare cerere 404 care intră — chiar
    regula pe care o scrie 0030: „un index care nu schimbă nimic dar se scrie la
    fiecare INSERT e cost curat".
    """
    assert "raw_events_notfound_idx" not in _indecsi_pe_raw_events()


def test_stergerea_indexului_vechi_isi_verifica_efectul():
    """`DROP INDEX IF EXISTS` întoarce succes și când n-a șters nimic.

    Dacă indexul vechi a fost redenumit — de mână, sau de o restaurare — el
    rămâne pe loc și continuă să fie scris, iar migrația raportează „aplicată".
    E tiparul din CLAUDE.md: cod de ieșire zero luat drept dovadă de efect. 0033
    citește catalogul după ștergere și refuză dacă a mai rămas vreun index
    parțial pe 404 în afară de cel nou.
    """
    executabil = _executabil(MIGRATIA.read_text(encoding="utf-8"))
    assert re.search(r"DROP\s+INDEX\s+IF\s+EXISTS\s+raw_events_notfound_idx", executabil), \
        "0033 nu mai șterge indexul din 0030"
    dupa_stergere = executabil.split("DROP INDEX IF EXISTS raw_events_notfound_idx", 1)[1]
    assert "http_status = 404" in dupa_stergere and "RAISE EXCEPTION" in dupa_stergere, (
        "după DROP nu se mai citește catalogul, deci un index vechi redenumit ar "
        "trece neobservat")


# ---------------------------------------------------------------------------
# Garda pe definiția din catalog
# ---------------------------------------------------------------------------
def _regexuri_garzii() -> list[str]:
    text = MIGRATIA.read_text(encoding="utf-8")
    gasite = re.findall(r"definitie\s*!~\s*'((?:[^']|'')*)'", text)
    assert gasite, "0033 nu mai compară definiția indexului cu nimic"
    return [g.replace("''", "'") for g in gasite]


def test_garda_accepta_indexul_corect_si_respinge_omonimele():
    """`IF NOT EXISTS` se potrivește DOAR PE NUME.

    Un index cu numele corect dar cu predicatul lui 0030 ar face migrația să
    raporteze „aplicată" în timp ce panoul continuă să cadă exact la fel. Invers,
    o gardă prea strictă ar refuza indexul pe care chiar îl construiește
    migrația și ar rupe fiecare instalare nouă. Se verifică amândouă direcțiile,
    pe forma reală a lui `pg_get_indexdef`.
    """
    tipare = [re.compile(r) for r in _regexuri_garzii()]
    cap = "CREATE INDEX raw_events_probes_idx ON ONLY public.raw_events USING btree "

    def trece(definitie: str) -> bool:
        return all(t.search(definitie) for t in tipare)

    assert trece(cap + "(ts DESC, http_path) INCLUDE (src_ip) "
                       "WHERE ((source = 'nginx'::text) AND (http_status = 404))"), \
        "garda ar refuza chiar indexul pe care îl construiește migrația"
    assert not trece(cap + "(ts DESC, http_path) INCLUDE (src_ip) "
                           "WHERE (http_status = 404)"), \
        "garda ar binecuvânta exact predicatul din 0030, adică defectul măsurat"
    assert not trece(cap + "(ts DESC, http_path) "
                           "WHERE ((source = 'nginx'::text) AND (http_status = 404))"), \
        "garda ar binecuvânta un index fără INCLUDE (src_ip)"
    assert not trece(cap + "(ts DESC, http_path) INCLUDE (src_ip) "
                           "WHERE (source = 'nginx'::text)"), \
        "garda ar binecuvânta un index peste toate cererile nginx"


def test_garda_citeste_si_validitatea_indexului():
    """Un `CONCURRENTLY` întrerupt lasă un index INVALID cu numele corect.

    Există în catalog, e scris la fiecare INSERT, și nu-l folosește nimeni. Fără
    `indisvalid`/`indisready`, migrația s-ar înregistra ca aplicată, iar panoul
    ar continua să cadă cu `schema_version` spunând că reparația a plecat.

    Aserțiunea e pe PREZENȚA celor două coloane în gardă — că blocul chiar ridică
    excepția se dovedește doar pe un PostgreSQL viu.
    """
    executabil = _executabil(MIGRATIA.read_text(encoding="utf-8"))
    assert "indisvalid" in executabil and "indisready" in executabil, executabil
    assert "IF NOT EXISTS" in executabil, (
        "fără IF NOT EXISTS, un index creat de mână înainte de migrație o face să "
        "pice cu «relation already exists» și oprește schema acolo")


# ---------------------------------------------------------------------------
# Timeout-urile: migrația trebuie să apuce să construiască indexul
# ---------------------------------------------------------------------------
def _secunde(valoare: str) -> float:
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
    m = re.search(rf"^\s*SET\s+(LOCAL\s+|SESSION\s+)?{nume}\s*=\s*(\S+?);",
                  MIGRATIA.read_text(encoding="utf-8"), re.M | re.I)
    assert m, (
        f"0033 nu ridică {nume}. Instanța îl are din "
        f"deploy/postgres/sentinel-tuning.conf, iar migrate.py nu-l schimbă.")
    return (m.group(1) or "").strip().upper(), _secunde(m.group(2))


def test_0033_ridica_timeoutele_ca_0031():
    """Altfel construcția e omorâtă la 60 s și schema se oprește la 0033.

    `CREATE INDEX` pe o tabelă partiționată de câțiva GB, cu
    `maintenance_work_mem = 64MB` și un disc împărțit cu ingestia, Suricata și
    nginx, poate trece de `statement_timeout`-ul instanței. Dacă trece, migrația
    e anulată și derulată înapoi, iar operatorul rămâne fără index și cu panoul
    care cade mai departe — plus toate migrațiile de după ea neaplicate.

    `lock_timeout` urcă din motivul opus: cât timp construcția stă la coadă după
    lacătul `SHARE`, fiecare INSERT care sosește se așază în spatele ei. Prea
    mic, migrația pică dintr-un lot de ingestie normal; zero, coada crește la
    nesfârșit. Mărginit, deci.

    `LOCAL` fiindcă valoarea trebuie să moară odată cu tranzacția: rămasă pe
    conexiune, următoarea interogare a runner-ului ar rula fără plasa instanței.
    """
    for nume in ("statement_timeout", "lock_timeout"):
        domeniu, migratie = _set_local(nume)
        instanta = _din_tuning(nume)
        assert migratie > instanta, (
            f"0033 pune {nume} = {migratie}s, instanța are {instanta}s")
        assert migratie > 0, f"{nume} = 0 lasă migrația fără nicio margine"
        assert domeniu == "LOCAL", f"{nume} fără LOCAL rămâne agățat de conexiune"
