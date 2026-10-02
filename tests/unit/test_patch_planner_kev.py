"""`sentinel/patch/planner.py:generate_for_kev` — ce statusuri de plan contează
drept „findingul are deja unul viu" cât timp se decide dacă merită cerut un
plan nou modelului.

Runda 3 a `sentinel/patch/window.py` (secțiunea „Îmbătrânirea candidaților")
depinde ÎN ÎNTREGIME ca `expired` să NU fie în lista asta: dacă ar fi,
`expire_stale_window_candidates` ar marca planul `expired` în bază, dar
`generate_for_kev` tot l-ar considera „plan viu" pentru finding-ul lui — deci
finding-ul KEV ar rămâne fără plan proaspăt PENTRU TOTDEAUNA, exact regresia
respinsă la runda 2. Nimic nu pinează asta până acum: niciun test nu execută
subinterogarea `NOT EXISTS` peste rânduri concrete.
"""
from __future__ import annotations

import asyncio
import re
import sqlite3

from sentinel.patch import planner


def run(c):
    return asyncio.run(c)


def _cfg():
    """Config-ul real, cu familia gazdei de test.

    `generate_for_kev` citește `cfg.platform.family` ÎNAINTE de interogare, ca
    să știe ce ecosistem poate atinge gazda; `cfg=None` nu mai e o simulare
    validă a niciunui apelant.
    """
    from sentinel.config import Config

    cfg = Config()
    cfg.platform.family = "rhel"
    return cfg


#: Vezi `_cfg`: ecosistemul citit din aceeași tabelă pe care o citește codul,
#: ca rândurile inserate aici să treacă chiar filtrul care rulează.
ECOSISTEM = planner.OS_PACKAGE_ECOSYSTEM["rhel"]


class _FetchDB:
    """Doar `fetch`: cu `fetch_rows=[]`, `generate_for_kev` nu ajunge
    niciodată la apelul modelului (bucla peste rânduri e goală), deci
    interogarea poate fi capturată fără nimic altceva simulat."""

    def __init__(self, *, fetch_rows=None):
        self.fetch_rows = fetch_rows if fetch_rows is not None else []
        self.fetch_sql: str | None = None
        self.fetch_args: tuple = ()

    async def fetch(self, sql, *a):
        self.fetch_sql = sql
        self.fetch_args = a
        return self.fetch_rows


def _translate(sql: str) -> str:
    """Traduce STRICT ce SQLite nu poate rula din interogarea reală:
    `f.id = ANY(p.finding_ids)` e o comparație pe array PostgreSQL, sintaxă pe
    care sqlite3 n-o parsează deloc. În acest cod, un plan AI are exact un
    singur finding (`planner.generate` cheamă `store_plan` cu
    `finding_ids=[finding_id]`), deci egalitatea scalară pe o coloană
    `finding_id` singulară din tabela de test e echivalentă pentru decizia
    testată — care STATUSuri blochează redactarea, nu forma array-ului.

    Refuză zgomotos dacă tiparul așteptat lipsește: o schimbare viitoare a
    interogării trebuie să strice testul ăsta cu un mesaj clar, nu cu o
    potrivire tăcută pe nimic (vezi docstring-ul modulului
    `test_patch_window_repo.py` — aceeași grijă, runda 2, acolo pentru o
    tautologie SQL, aici pentru un traducător care ar putea deveni orb)."""
    needle = "f.id = ANY(p.finding_ids)"
    if needle not in sql:
        raise AssertionError(
            f"tipar PostgreSQL neașteptat în interogare — actualizează "
            f"traducătorul: {sql!r}")
    # `$1` e ecosistemul gazdei, `$2` limita. Filtrul de ecosistem trebuie să
    # RĂMÂNĂ în interogare: fără el, bucla automată cere din nou planuri
    # pentru findinguri npm/alpine/go pe care gazda nu le poate atinge, iar
    # cele trei sloturi se consumă pe rânduri imposibile.
    if "lower(trim(f.ecosystem)) = $1" not in sql:
        raise AssertionError(
            f"filtrul de ecosistem a dispărut din interogare: {sql!r}")
    # Predicatul „reparația e instalată, dar nu rulează” (`pending_reboot_sql`):
    # singura sintaxă PostgreSQL în plus e calea jsonb. O traducere MECANICĂ a
    # textului real (nu un predicat rescris aici), ca rândurile fără `raw` sau cu
    # alt verdict să treacă prin exact ce rulează codul. Refuză zgomotos dacă
    # predicatul lipsește: fără el, bucla ar redacta iar planurile fără rost.
    if "#>> '{fix_state,state}'" not in sql:
        raise AssertionError(
            f"predicatul `pending_reboot_sql` a dispărut din interogare: {sql!r}")
    sql = re.sub(r"(\w+\.raw) #>> '\{([^}]*)\}'",
                 lambda m: f"json_extract({m.group(1)}, '$.{m.group(2).replace(',', '.')}')",
                 sql)
    return (sql.replace(needle, "f.id = p.finding_id")
               .replace("$1", "?").replace("$2", "?"))


def test_expired_plans_do_not_block_a_fresh_kev_plan():
    """EXECUTAT peste SQLite, pe subinterogarea `NOT EXISTS` reală: un finding
    KEV cu un singur plan, `status = 'expired'`, trebuie să rămână selectabil
    — dacă `'expired'` ar intra vreodată în lista de excludere de lângă
    `'validated','approved','applying','applied','scheduled'`, finding-ul ar
    dispărea din rezultat și n-ar mai primi niciodată un plan nou."""
    db = _FetchDB(fetch_rows=[])
    run(planner.generate_for_kev(db, cfg=_cfg(), api_key="sk-test", limit=3))
    sql = _translate(db.fetch_sql)

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE findings (id INTEGER, status TEXT, kev INTEGER, "
                 "fixed_version TEXT, priority INTEGER, ecosystem TEXT, raw TEXT, "
                 "risk_score REAL)")
    conn.execute("CREATE TABLE patch_plans (finding_id INTEGER, status TEXT)")
    conn.execute("INSERT INTO findings (id, status, kev, fixed_version, priority, "
                 "ecosystem) VALUES (1, 'open', 1, '1.2.3', 5, ?)",
                 (ECOSISTEM,))
    conn.execute("INSERT INTO patch_plans VALUES (1, 'expired')")

    matched = {r[0] for r in conn.execute(sql, (ECOSISTEM, 3))}
    assert matched == {1}, (
        "un plan 'expired' a blocat generarea unui plan nou pentru același "
        "finding — regresia respinsă la runda 2 a Funcționalității 08")


def test_a_genuinely_live_plan_still_blocks_a_duplicate():
    """Reversul testului de mai sus: un plan `validated` pentru același
    finding TREBUIE să blocheze o redactare nouă — altfel traducerea ar fi
    slăbit interogarea în loc s-o păstreze, iar `generate_for_kev` ar cere
    modelului planuri duplicate pentru un finding care are deja unul viu."""
    db = _FetchDB(fetch_rows=[])
    run(planner.generate_for_kev(db, cfg=_cfg(), api_key="sk-test", limit=3))
    sql = _translate(db.fetch_sql)

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE findings (id INTEGER, status TEXT, kev INTEGER, "
                 "fixed_version TEXT, priority INTEGER, ecosystem TEXT, raw TEXT, "
                 "risk_score REAL)")
    conn.execute("CREATE TABLE patch_plans (finding_id INTEGER, status TEXT)")
    conn.execute("INSERT INTO findings (id, status, kev, fixed_version, priority, "
                 "ecosystem) VALUES (1, 'open', 1, '1.2.3', 5, ?)",
                 (ECOSISTEM,))
    conn.execute("INSERT INTO patch_plans VALUES (1, 'validated')")

    matched = {r[0] for r in conn.execute(sql, (ECOSISTEM, 3))}
    assert matched == set(), matched


# ---------------------------------------------------------------------------
# Poarta de ecosistem — bucla automată nu o avea
# ---------------------------------------------------------------------------
# `/planifica` trecea prin `unplannable_reason` de la început; `generate_for_kev`
# nu. Pe gazda Debian (măsurat 15 septembrie 2026) 407 din 857 de findinguri
# deschise cu fix NU sunt pachete ale gazdei, iar toate primele 12 după
# prioritate sunt din categoria aia — deci bucla cheltuia cele trei sloturi pe
# findinguri npm/alpine/go, câte două apeluri Opus fiecare, toate terminate în
# `rejected_invalid`. Sau, mai rău: un plan `apt-get` plauzibil pentru un pachet
# dintr-o imagine de container, care validează și pică abia la dry-run.
def test_un_finding_din_alt_ecosistem_nu_ajunge_niciodata_la_model(monkeypatch):
    """Dacă rândul trece totuși de filtrul SQL (o interogare slăbită, o
    coloană cu majuscule), poarta din cod trebuie să-l oprească ÎNAINTE de
    apelul la model — și să spună de ce, nu să-l sară tăcut."""
    chemari: list = []

    async def _nu_trebuie_chemat(db, cfg, api_key, finding_id, **kw):
        chemari.append(finding_id)
        return 1, "validated"

    monkeypatch.setattr(planner, "generate", _nu_trebuie_chemat)

    db = _FetchDB(fetch_rows=[{"id": 11, "ecosystem": "npm"}])
    rezultate = run(planner.generate_for_kev(db, cfg=_cfg(), api_key="sk-test", limit=3))

    assert chemari == [], "s-a cerut un plan pentru un finding npm pe o gazdă rpm"
    assert len(rezultate) == 1
    plan_id, motiv = rezultate[0]
    assert plan_id is None
    assert "npm" in motiv, motiv


def test_o_familie_necunoscuta_nu_interogheaza_si_nu_ghiceste(monkeypatch):
    """„Nu știu" și „probabil rpm" sunt lucruri diferite. Cu o familie pe care
    `OS_PACKAGE_ECOSYSTEM` n-o cunoaște, nu se poate ști ce pachete poate
    atinge gazda, deci nu se cere niciun plan — nici măcar nu se interoghează
    baza, fiindcă n-ar exista cu ce filtra."""
    chemari: list = []

    async def _nu_trebuie_chemat(db, cfg, api_key, finding_id, **kw):
        chemari.append(finding_id)
        return 1, "validated"

    monkeypatch.setattr(planner, "generate", _nu_trebuie_chemat)

    cfg = _cfg()
    cfg.platform.family = "alpine"
    db = _FetchDB(fetch_rows=[{"id": 11, "ecosystem": "rpm"}])

    assert run(planner.generate_for_kev(db, cfg=cfg, api_key="sk-test", limit=3)) == []
    assert db.fetch_sql is None, "s-a interogat baza fără să se știe ce se caută"
    assert chemari == []


def test_findingul_potrivit_familiei_ajunge_la_model(monkeypatch):
    """Reversul celor două de mai sus, fără de care poarta ar putea refuza
    tot și testele ar rămâne verzi: un finding `rpm` pe o gazdă `rhel`
    TREBUIE să primească un plan, altfel bucla automată nu mai face nimic
    niciodată."""
    chemari: list = []

    async def _generate(db, cfg, api_key, finding_id, **kw):
        chemari.append(finding_id)
        return 42, "validated"

    monkeypatch.setattr(planner, "generate", _generate)

    db = _FetchDB(fetch_rows=[{"id": 11, "ecosystem": ECOSISTEM}])
    rezultate = run(planner.generate_for_kev(db, cfg=_cfg(), api_key="sk-test", limit=3))

    assert chemari == [11]
    assert rezultate == [(42, "validated")]


# ---------------------------------------------------------------------------
# Departajarea în interiorul unei benzi
# ---------------------------------------------------------------------------
def test_kev_urile_cu_aceeasi_banda_se_aleg_dupa_risk_score_apoi_dupa_id():
    """EXECUTAT peste SQLite, pe interogarea reală. `priority` e banda
    semaforului, iar un KEV poate fi verde (SSVC: activ + neautomatizabil +
    impact parțial = Track): verdele stă aproape tot la `priority` 0. Fără
    `risk_score` în `ORDER BY`, `LIMIT 3` alege dintre ele după ordinea
    fizică a rândurilor, iar planul cerut modelului (două apeluri Opus) merge
    la un KEV oarecare în loc de cel mai probabil să fie atacat.

    Limită declarată: SQLite pune NULL ultimul la DESC, Postgres îl pune
    PRIMUL; `NULLS LAST` nu poate fi falsificat aici, ci în
    `tests/integration/test_risk_intel_pg.py`, pe un Postgres real."""
    db = _FetchDB(fetch_rows=[])
    run(planner.generate_for_kev(db, cfg=_cfg(), api_key="sk-test", limit=3))
    sql = _translate(db.fetch_sql)

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE findings (id INTEGER, status TEXT, kev INTEGER, "
                 "fixed_version TEXT, priority INTEGER, ecosystem TEXT, raw TEXT, "
                 "risk_score REAL)")
    conn.execute("CREATE TABLE patch_plans (finding_id INTEGER, status TEXT)")
    # (id, priority, risk_score), inserate într-o ordine fizică care nu e cea
    # corectă pe nicio cheie, ca să nu iasă bună din întâmplare (5 înaintea lui 2
    # la risk_score egal: doar `id` le pune în ordine).
    rows = [(6, 40, 0.01), (5, 0, 0.90), (3, 0, None), (4, 0, 0.50), (2, 0, 0.90),
            (1, 0, 0.10)]
    conn.executemany("INSERT INTO findings (id, status, kev, fixed_version, priority, "
                     "ecosystem, risk_score) VALUES (?, 'open', 1, '1.2.3', ?, ?, ?)",
                     [(i, p, ECOSISTEM, s) for i, p, s in rows])

    chosen = [r[0] for r in conn.execute(sql, (ECOSISTEM, 5))]
    assert chosen == [6, 2, 5, 4, 1], (
        "ordinea trebuie să fie banda (priority), apoi risk_score, apoi id; "
        f"s-a ales {chosen}")
    assert [r[0] for r in conn.execute(sql, (ECOSISTEM, 3))] == [6, 2, 5]
