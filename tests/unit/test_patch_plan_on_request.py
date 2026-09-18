"""Garda de duplicat pentru un plan cerut manual, și eticheta de origine.

Eșecul pe care îl previne fișierul ăsta: operatorul cere un plan pentru o
vulnerabilitate care are deja unul viu, iar sistemul plătește un al doilea apel
Opus și lasă DOUĂ planuri vii pentru aceeași vulnerabilitate, fiecare cu propriul
set de butoane de aprobare. `planner.generate_for_kev` are garda asta scrisă în
`NOT EXISTS`; `planner.generate` nu are niciuna — e treaba apelantului, spune
docstring-ul lui — iar până acum singurul apelant era `generate_for_kev`.

Ce se verifică AICI și nu în `test_telegram_plan_request.py`: că cele două
interogări — cea care alege ce se redactează automat și cea care refuză o cerere
manuală — spun același lucru despre fiecare status pe care baza îl acceptă. Sunt
rulate amândouă, pe SQLite, peste aceleași rânduri. O aserțiune pe textul SQL ar
fi trecut și peste o listă divergentă scrisă identic în două locuri.
"""
from __future__ import annotations

import asyncio
import re
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.db.repo import patches as repo
from sentinel.patch import planner

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION = REPO_ROOT / "sentinel" / "db" / "migrations" / "0004_patch.sql"


def run(c):
    return asyncio.run(c)


def _toate_statusurile_de_plan() -> tuple[str, ...]:
    """Statusurile pe care baza le acceptă pentru `patch_plans`, citite din
    CHECK-ul migrației.

    Citite, nu scrise aici: un status nou adăugat în schemă trebuie să apară în
    testul de mai jos și să fie clasificat explicit — viu sau mort — nu să intre
    tăcut în niciuna dintre liste.
    """
    sql = MIGRATION.read_text(encoding="utf-8")
    start = sql.index("CREATE TABLE patch_plans")
    m = re.search(r"CHECK \(status IN \((.*?)\)\)", sql[start:], re.S)
    assert m, "nu am mai găsit CHECK-ul de status al lui patch_plans în 0004_patch.sql"
    return tuple(re.findall(r"'([a-z_]+)'", m.group(1)))


STATUSURI = _toate_statusurile_de_plan()

# Statusurile VII, scrise ca literali AICI — nu citite din constanta testată.
#
# Runda 2 a arătat de ce: și lista parametrizată, și `_cauta` de mai jos își
# luau cazurile din `repo.LIVE_PLAN_STATUSES`, deci cazul „viu" era adevărat
# prin construcție. Constanta putea fi îngustată la `("validated",)` — sau doar
# golită de `applying` — și toate cele 147 de teste ale celor două fișiere
# rămâneau verzi, iar suita întreagă la fel. Cu lista îngustată, garda manuală
# nu mai vede un plan care se APLICĂ chiar acum, `NOT EXISTS`-ul lui
# `generate_for_kev` nu-l mai vede nici el, și findingul ajunge cu două planuri
# vii și două seturi de butoane concurente.
#
# Fiecare intrare își spune motivul, ca ștergerea uneia să nu arate ca o
# curățenie.
VII: tuple[tuple[str, str], ...] = (
    ("validated",
     "planul așteaptă chiar acum decizia operatorului, cu butoanele lui pe "
     "telefon; un al doilea plan ar face butoanele primului tăcut inutile"),
    ("approved",
     "cineva a apăsat deja «Aplică» și a confirmat; redactarea unui duplicat "
     "peste el înseamnă două planuri aprobate pentru aceeași vulnerabilitate"),
    ("applying",
     "planul RULEAZĂ pe mașină în clipa asta — un al doilea plan pentru "
     "același pachet ar fi scris peste o aplicare în curs"),
    ("applied",
     "patch-ul a fost aplicat; findingul se închide la scanarea următoare, iar "
     "până atunci un plan nou ar repara ceva deja reparat"),
    ("scheduled",
     "planul e programat și așteaptă fereastra lui; încă e al cuiva"),
)

MOARTE = tuple(s for s in STATUSURI if s not in {v for v, _ in VII})


class _CaptureDB:
    """Reține interogarea și argumentele; nu întoarce nimic.

    Cu `None`/`[]` ca răspuns, nici `live_plan_for_finding`, nici
    `generate_for_kev` nu ajung mai departe, deci SQL-ul real poate fi luat fără
    să fie simulat nimic altceva.
    """

    def __init__(self) -> None:
        self.sql: str | None = None
        self.args: tuple = ()

    async def fetchrow(self, sql, *a):
        self.sql, self.args = sql, a
        return None

    async def fetch(self, sql, *a):
        self.sql, self.args = sql, a
        return []


def _sql_repo() -> str:
    db = _CaptureDB()
    run(repo.live_plan_for_finding(db, 7))
    assert db.args[0] == 7, "interogarea nu primește id-ul findingului cerut"
    assert list(db.args[1]) == list(repo.LIVE_PLAN_STATUSES), (
        "lista de statusuri nu mai ajunge ca parametru — testul ar verifica "
        "altceva decât rulează codul")
    return db.sql


#: Ecosistemul pe care familia gazdei de test îl poate atinge. Luat din
#: `planner.OS_PACKAGE_ECOSYSTEM`, nu scris de mână: dacă tabela aia s-ar
#: schimba, interogarea ar filtra pe altceva decât inserează testul, iar
#: rândul ar dispărea din rezultat — adică testul ar deveni verde din motivul
#: greșit (niciun rând găsit arată la fel ca „plan viu care blochează").
ECOSISTEM = planner.OS_PACKAGE_ECOSYSTEM["rhel"]


def _sql_planner() -> str:
    db = _CaptureDB()
    run(planner.generate_for_kev(db, cfg=_cfg(), api_key="sk-test", limit=3))
    return db.sql


def _tradu_repo(sql: str) -> str:
    """Traduce STRICT ce SQLite nu poate rula: comparațiile pe array PostgreSQL.

    `$1 = ANY(finding_ids)` devine egalitate pe o coloană scalară `finding_id` —
    un plan generat pentru un finding are exact un element în array
    (`planner.generate` cheamă `store_plan` cu `finding_ids=[finding_id]`), deci
    pentru decizia testată e echivalent. `status = ANY($2::text[])` devine
    `status = ?`, iar `_cauta` de mai jos rulează interogarea o dată pentru
    FIECARE status din listă și adună rezultatele — reuniunea peste mulțime e
    chiar ce înseamnă `= ANY(mulțime)`. Legarea statusului RÂNDULUI, în loc de
    statusurile CERUTE, ar fi făcut din test o tautologie: orice rând s-ar fi
    potrivit cu el însuși.

    Refuză zgomotos dacă tiparele lipsesc — o schimbare a interogării trebuie să
    strice testul cu un mesaj clar, nu să-l lase să potrivească pe nimic.
    """
    for ac in ("$1 = ANY(finding_ids)", "status = ANY($2::text[])"):
        assert ac in sql, f"tipar PostgreSQL neașteptat, actualizează traducătorul: {sql!r}"
    return (sql.replace("$1 = ANY(finding_ids)", "? = finding_id")
               .replace("status = ANY($2::text[])", "status = ?"))


def _tradu_planner(sql: str) -> str:
    needle = "f.id = ANY(p.finding_ids)"
    assert needle in sql, f"tipar PostgreSQL neașteptat: {sql!r}"
    # `$1` e ecosistemul, `$2` limita. Poarta de ecosistem e în SQL fiindcă pe
    # gazda reală toate findingurile KEV de sus sunt din ecosisteme pe care
    # gazda nu le poate atinge, deci o filtrare de după `LIMIT` n-ar mai
    # genera niciodată nimic. Aserțiunea ține traducătorul onest: dacă filtrul
    # dispare din interogare, testul o spune, nu potrivește pe altceva.
    assert "lower(trim(f.ecosystem)) = $1" in sql, (
        f"filtrul de ecosistem a dispărut din interogare: {sql!r}")
    return (sql.replace(needle, "f.id = p.finding_id")
               .replace("$1", "?").replace("$2", "?"))


def _cauta(conn: sqlite3.Connection, finding_id: int) -> list:
    """Ce găsește garda de duplicat pentru un finding — interogarea REALă,
    rulată o dată pentru fiecare status din `LIVE_PLAN_STATUSES`."""
    sql = _tradu_repo(_sql_repo())
    gasite: list = []
    for live in repo.LIVE_PLAN_STATUSES:
        gasite += list(conn.execute(sql, (finding_id, live)))
    return gasite


def _conn(status: str, *, origine: str = "ai_manual",
          creat: str = "2026-09-15") -> sqlite3.Connection:
    """Un finding KEV deschis, cu fix, și un singur plan pentru el, în `status`.

    `generated_by` e o coloană în plus față de `_PLAN_COLS` (care e lista de
    coloane CITITE, nu schema): `expire_stale_plans` decide pe ea, deci fără ea
    interogarea aia n-ar putea fi rulată aici deloc.
    """
    conn = sqlite3.connect(":memory:")
    coloane = [c.strip() for c in repo._PLAN_COLS.replace("\n", " ").split(",") if c.strip()]
    assert "status" in coloane and "created_at" in coloane, coloane
    conn.execute(f"CREATE TABLE patch_plans ({', '.join(coloane)}, "
                 "generated_by TEXT, finding_id INTEGER)")
    conn.execute("CREATE TABLE findings (id INTEGER, status TEXT, kev INTEGER, "
                 "fixed_version TEXT, priority INTEGER, ecosystem TEXT)")
    conn.execute("INSERT INTO findings VALUES (7, 'open', 1, '1.2.3', 5, ?)",
                 (ECOSISTEM,))
    conn.execute("INSERT INTO patch_plans (id, status, created_at, generated_by, "
                 "finding_id) VALUES (99, ?, ?, ?, 7)", (status, creat, origine))
    return conn


def test_fiecare_stare_vie_e_numita_pe_fata():
    """Aserțiunea care mușcă la ÎNGUSTARE, nu doar la lărgire.

    Fără ea, scoaterea unui singur status din `LIVE_PLAN_STATUSES` — `applying`
    e cazul care doare — trecea neobservată prin toată suita: garda de duplicat
    nu mai vedea planul care se aplică în clipa aia, `generate_for_kev` nu-l
    vedea nici el, iar operatorul primea un al doilea plan viu pentru aceeași
    vulnerabilitate, cu un set de butoane care se contrazic cu primul.
    """
    vii = {v for v, _ in VII}
    for status, de_ce in VII:
        assert status in repo.LIVE_PLAN_STATUSES, (
            f"{status!r} a dispărut din LIVE_PLAN_STATUSES — {de_ce}")
    assert set(repo.LIVE_PLAN_STATUSES) == vii, (
        "LIVE_PLAN_STATUSES nu mai e mulțimea numită în testul ăsta: "
        f"în plus {set(repo.LIVE_PLAN_STATUSES) - vii}, "
        f"lipsă {vii - set(repo.LIVE_PLAN_STATUSES)}. Orice schimbare a ei "
        "trebuie argumentată aici, pe status, nu strecurată.")


def test_lista_de_statusuri_nu_e_goala_si_are_amandoua_taberele():
    """Aserțiunea care ține testele parametrizate de mai jos să nu treacă verde
    pe o listă goală — tiparul „listă parametrizată ieșită goală și sărită
    tăcut" din CLAUDE.md."""
    assert len(STATUSURI) >= 8, STATUSURI
    assert set(repo.LIVE_PLAN_STATUSES) < set(STATUSURI), (
        "un status din LIVE_PLAN_STATUSES nu e acceptat de baza de date")
    assert MOARTE, "niciun status mort — garda ar bloca orice cerere, la infinit"
    # Numite pe față. `MOARTE` se calculează din CHECK-ul bazei minus lista
    # LITERALĂ `VII`, deci o stare moartă mutată în `LIVE_PLAN_STATUSES` rămâne
    # în parametrizarea de mai jos și PICĂ acolo, în loc să dispară din ea.
    # Numele de aici sunt a doua plasă, pentru cazul invers. `expired` e cazul care a costat
    # deja o rundă (Funcționalitatea 08), `failed` și `rejected_invalid` sunt
    # singurele stări în care se află planurile gazdei azi.
    for mort in ("expired", "failed", "rejected_invalid", "rejected"):
        assert mort in MOARTE, (
            f"{mort!r} a ajuns printre statusurile vii: findingul lui n-ar mai "
            "primi niciodată un plan nou, nici automat, nici la cerere")


@pytest.mark.parametrize("status", [v for v, _ in VII])
def test_un_plan_viu_e_vazut_de_amandoua_interogarile(status):
    """Dacă cererea manuală și planner-ul automat n-ar fi de acord ce înseamnă
    „findingul ăsta are deja un plan", una dintre ele ar plăti un apel Opus
    pentru un duplicat pe care cealaltă îl credea blocat — iar diferența s-ar fi
    văzut abia pe factura de la model.

    Cazurile vin din lista LITERALĂ `VII`, nu din constanta verificată: altfel
    un status scos din `LIVE_PLAN_STATUSES` ar fi DISPĂRUT din parametrizare în
    loc să pice testul — exact tiparul „listă parametrizată ieșită goală și
    sărită tăcut" din CLAUDE.md, în varianta lui parțială."""
    conn = _conn(status)

    gasit = _cauta(conn, 7)
    assert len(gasit) == 1, (
        f"cererea manuală nu vede planul în starea {status!r}, deci ar redacta "
        "un al doilea peste el")

    ramase = {r[0] for r in conn.execute(_tradu_planner(_sql_planner()),
                                         (ECOSISTEM, 3))}
    assert ramase == set(), (
        f"planner-ul automat ar redacta încă un plan peste unul în starea {status!r}")


@pytest.mark.parametrize("status", MOARTE)
def test_un_plan_mort_nu_blocheaza_nici_cererea_nici_redactarea(status):
    """Reversul, și partea care a costat deja o rundă: un plan `expired`,
    `failed` sau `rejected_invalid` înseamnă că findingul a rămas FĂRĂ plan
    utilizabil. Dacă ar bloca, findingul n-ar mai primi niciodată unul —
    regresia respinsă la runda 2 a Funcționalității 08, acum pe amândouă căile.

    Pe gazda de producție, toate cele 4 planuri existente sunt `rejected_invalid`
    sau `failed` (măsurat pe 15 septembrie 2026), deci exact cazul ăsta e cel pe
    care operatorul îl întâlnește azi.
    """
    conn = _conn(status)

    gasit = _cauta(conn, 7)
    assert gasit == [], (
        f"un plan în starea {status!r} blochează cererea manuală, deși findingul "
        "a rămas fără plan utilizabil")

    ramase = {r[0] for r in conn.execute(_tradu_planner(_sql_planner()),
                                         (ECOSISTEM, 3))}
    assert ramase == {7}


# --- îmbătrânirea planului cerut manual -------------------------------------
#
# Garda de mai sus e utilă doar dacă planul viu chiar MOARE cândva. Până pe 15
# septembrie 2026 `expire_stale_plans` n-avea niciun apelant, iar `/planifica`
# tocmai începuse să scrie planuri `ai_manual` — adică un plan cerut și
# neatins bloca findingul lui pentru totdeauna, iar singura scăpare a
# operatorului era butonul „Respinge".
def _sql_expirare() -> str:
    db = _CaptureDB()
    n = run(repo.expire_stale_plans(db))
    assert n == 0, "fără rânduri întoarse, expirarea n-are ce raporta"
    assert db.args == (repo.PLAN_TTL_HOURS,), db.args
    return db.sql


def _tradu_expirare(sql: str) -> str:
    """Traduce STRICT ce SQLite nu are: intervalul calculat de PostgreSQL și
    `IS DISTINCT FROM` (SQLite scrie același lucru `IS NOT`). Refuză zgomotos
    dacă tiparele nu mai există — o interogare schimbată trebuie să strice
    testul cu un mesaj clar, nu să potrivească pe nimic."""
    for ac in ("now() - make_interval(hours => $1)",
               "generated_by IS DISTINCT FROM 'ai'"):
        assert ac in sql, f"tipar PostgreSQL neașteptat, actualizează traducătorul: {sql!r}"
    return (sql.replace("now() - make_interval(hours => $1)", "?")
               .replace("IS DISTINCT FROM", "IS NOT"))


def _unde(sql: str) -> str:
    """Tot ce e după `WHERE`, fără `RETURNING` — clauza reală, nu una rescrisă
    de test."""
    return _tradu_expirare(sql).split("WHERE", 1)[1].split("RETURNING")[0].strip()


VECHI = "2026-09-01T00:00:00+00:00"
PROASPAT = "2026-09-14T00:00:00+00:00"
PRAG = "2026-09-12T00:00:00+00:00"   # „acum minus PLAN_TTL_HOURS"


def test_expirarea_ia_planurile_cerute_de_om_si_le_lasa_pe_ale_ferestrei():
    """EXECUTAT peste SQLite, pe rânduri concrete, nu citit ca text.

    Cele două jumătăți ale deciziei, amândouă cu preț:

    * un plan `ai_manual` (sau unul vechi, fără etichetă) care depășește cele
      72h TREBUIE să moară — altfel findingul lui nu mai primește niciodată alt
      plan, iar `/patch` îi oferă butoane pe versiuni de pachet vechi de luni;
    * un plan `ai` NU are voie să moară aici — are alt ciclu, de 30 de zile
      (`expire_stale_window_candidates`), fiindcă exercițiul de restaurare
      rulează lunar și fereastra săptămânal. Cu 72h peste el, fiecare plan
      automat ar fi mort înainte ca fereastra să apuce să se uite la el, adică
      Funcționalitatea 08 ar deveni inertă fără ca nimic să pice.
    """
    unde = _unde(_sql_expirare())

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE patch_plans (id INTEGER, status TEXT, "
                 "generated_by TEXT, created_at TEXT)")
    conn.executemany("INSERT INTO patch_plans VALUES (?,?,?,?)", [
        (1, "validated", "ai_manual", VECHI),      # cerut de om, vechi -> expiră
        (2, "validated", "ai_manual", PROASPAT),   # cerut de om, proaspăt -> rămâne
        (3, "validated", "ai", VECHI),             # al ferestrei -> rămâne
        (4, "rejected", "ai_manual", VECHI),       # deja mort -> neatins
        (5, "validated", None, VECHI),             # fără etichetă (rând vechi) -> expiră
        (6, "approved", "ai_manual", VECHI),       # aprobat și neaplicat -> expiră
    ])
    conn.execute(f"UPDATE patch_plans SET status = 'expired' WHERE {unde}", (PRAG,))

    assert dict(conn.execute("SELECT id, status FROM patch_plans")) == {
        1: "expired", 2: "validated", 3: "validated",
        4: "rejected", 5: "expired", 6: "expired"}


def test_dupa_expirare_findingul_poate_primi_din_nou_un_plan():
    """Capătul care contează pentru operator: expirarea trebuie să DEBLOCHEZE
    cererea următoare, nu doar să schimbe un cuvânt în bază. Rulate una după
    alta, pe aceleași rânduri: interogarea de expirare, apoi chiar garda de
    duplicat a lui `/planifica`."""
    conn = _conn("validated", origine="ai_manual", creat=VECHI)

    assert len(_cauta(conn, 7)) == 1, "planul viu trebuie să blocheze ÎNAINTE de expirare"

    conn.execute(f"UPDATE patch_plans SET status = 'expired' "
                 f"WHERE {_unde(_sql_expirare())}", (PRAG,))

    assert _cauta(conn, 7) == [], (
        "planul expirat blochează în continuare cererea manuală — findingul "
        "rămâne fără plan și fără cale să ceară altul")
    ramase = {r[0] for r in conn.execute(_tradu_planner(_sql_planner()),
                                         (ECOSISTEM, 3))}
    assert ramase == {7}, "nici planner-ul automat nu mai are voie să-l creadă blocat"


def test_garda_se_uita_la_findingul_cerut_nu_la_oricare():
    """Un fals care întoarce rândul lui indiferent de argument ar fi trecut peste
    o gardă care citește planul ALTUI finding. Aici interogarea reală e rulată cu
    un id care nu are niciun plan."""
    conn = _conn("validated")
    assert _cauta(conn, 8) == []


# --- eticheta de origine ----------------------------------------------------
def _planner_simulat(monkeypatch, capturat: list):
    """Tot ce e în jurul apelului la model, înlocuit — apelul însuși inclusiv.
    Rămâne de verificat exact ce se scrie în `patch_plans.generated_by`."""
    async def _context(db, finding_id):
        return {"id": finding_id, "cve": "CVE-2026-0001", "package": "curl",
                "fixed_version": "8.0.1-2", "protected": False, "asset_id": 1,
                "severity": "high", "priority": 60}

    async def _allowed(db, cfg):
        return True, ""

    async def _record(*a, **kw):
        return None

    async def _call(api_key, **kw):
        return SimpleNamespace(
            ok=True, error=None, tool_input={"schema_version": 1},
            usage=SimpleNamespace(input_tokens=1, output_tokens=1, cached_tokens=0))

    async def _store_plan(db, **kw):
        capturat.append(kw)
        return 42

    monkeypatch.setattr(planner, "_context", _context)
    monkeypatch.setattr(planner.budget, "allowed", _allowed)
    monkeypatch.setattr(planner.budget, "record", _record)
    monkeypatch.setattr(planner, "call_structured", _call)
    monkeypatch.setattr(planner, "validate_plan",
                        lambda plan, **kw: SimpleNamespace(valid=True, errors=[]))
    monkeypatch.setattr(planner, "plan_hash", lambda plan: "h" * 8)
    monkeypatch.setattr(planner.repo, "store_plan", _store_plan)


def test_planul_automat_ramane_etichetat_ai(monkeypatch):
    """Eticheta `'ai'` e ce ține planurile nesupravegheate în afara canalului
    rapid de aprobare până când fereastra săptămânală le dovedește eligibile
    (0043_patch_window.sql). Dacă un parametru nou ar fi schimbat implicitul,
    fiecare plan KEV ar ajunge cu butoane pe telefon în 15 secunde, ocolind
    poarta."""
    capturat: list = []
    _planner_simulat(monkeypatch, capturat)

    class _DB(_CaptureDB):
        async def fetch(self, sql, *a):
            return [{"id": 7, "ecosystem": ECOSISTEM}]

    run(planner.generate_for_kev(_DB(), cfg=_cfg(), api_key="sk-test", limit=1))

    assert len(capturat) == 1
    assert capturat[0]["generated_by"] == "ai"


def test_planul_cerut_de_operator_e_etichetat_altfel(monkeypatch):
    """Etichetat tot `'ai'`, planul pe care operatorul tocmai l-a primit cu
    butoane ar mai primi, 15 secunde mai târziu, și anunțul „fereastra nu l-a
    eliberat" de la `_push_window_gated_notices` — o contrazicere pe telefon."""
    capturat: list = []
    _planner_simulat(monkeypatch, capturat)

    run(planner.generate(_CaptureDB(), _cfg(), "sk-test", 7, generated_by="ai_manual"))

    assert len(capturat) == 1
    assert capturat[0]["generated_by"] == "ai_manual"


def _cfg():
    from sentinel.config import Config

    return Config()


# --- cel mai recent, nu primul inserat --------------------------------------
def test_cel_mai_recent_plan_viu_e_cel_intors():
    """Docstring-ul lui `live_plan_for_finding` spune „Cel mai RECENT, dacă
    cumva sunt mai multe: e cel către care trimitem operatorul" — nu un
    detaliu incidental, e decizia. EXECUTAT peste SQLite, cu `ORDER BY
    created_at DESC` real din sursă: un `ASC` scris din greșeală ar rămâne
    verde pe cele 224 de teste țintite ale acestui fișier și ar pica DOAR
    aici — trimițând operatorul la un plan mai vechi, poate deja respins, în
    loc de cel de pe ecran."""
    sql = _tradu_repo(_sql_repo())
    conn = sqlite3.connect(":memory:")
    coloane = [c.strip() for c in repo._PLAN_COLS.replace("\n", " ").split(",") if c.strip()]
    conn.execute(f"CREATE TABLE patch_plans ({', '.join(coloane)}, finding_id INTEGER)")
    # Inserate în ordinea INVERSĂ vechimii — planul cel mai VECHI e inserat
    # ultimul — ca un test care doar citește primul rând găsit de SQLite (fără
    # ORDER BY, ordinea de inserare) să nu treacă din întâmplare.
    conn.executemany(
        "INSERT INTO patch_plans (id, status, created_at, finding_id) "
        "VALUES (?, ?, ?, ?)",
        [(20, "validated", "2026-09-15T00:00:00+00:00", 7),   # cel mai recent
         (10, "validated", "2026-09-01T00:00:00+00:00", 7)])  # mai vechi

    rand = conn.execute(sql, (7, "validated")).fetchone()
    assert rand is not None
    assert rand[0] == 20, (
        f"a fost întors planul #{rand[0]}, nu cel mai recent (#20) — "
        "`ORDER BY created_at DESC` nu mai e ce rulează interogarea")
