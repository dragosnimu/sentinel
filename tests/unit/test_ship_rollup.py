"""Fluxul de agregate: filigran pe `updated_at`, și de ce nu pe `bucket`.

Eșecul pe care îl previne, măsurat pe gazda reală pe 24 august 2026 — aceeași
oră, cele două capete:

    interval   server                 agregator
    04:00      6 rânduri, 1385 ev     5 rânduri,   60 ev
    05:00      6 rânduri,  977 ev     5 rânduri,   22 ev

Rândurile existau la ambele capete. Erau VECHI. `maintenance_service` scrie
agregatul pentru fereastra SCURSĂ — raportul lui spune „12 rânduri pe 0,9h" —
deci ora 04:00 e scrisă o dată la 04:56 și COMPLETATĂ la 05:56. Cursorul mergea
strict pe `bucket`, deci pleca versiunea parțială, iar cursorul trecea dincolo
pentru totdeauna.

Un grafic desenat peste valorile alea ar fi arătat perfect normal și ar fi fost
de douăzeci de ori mai mic decât realitatea. Nimic nu s-ar fi plâns.

Prima versiune a modulului scria pe față presupunerea pe care se sprijinea:
„dacă serverul ar recalcula vreodată un interval DUPĂ ce a fost expediat,
schimbarea aia n-ar mai pleca — mentenanța își încheie intervalele înainte de a
trece mai departe". Era falsă. Scrisă, măcar s-a putut găsi.

A doua proprietate, păstrată: intervalul ÎN CURS nu pleacă. Un contor orar
trimis la jumătatea orei lui s-ar citi pe grafic ca o cădere de trafic care nu
s-a întâmplat.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.report import shipper
from sentinel.report.shipper import ROLLUP, STREAMS, Stream

NOW = datetime(2026, 8, 21, 14, 37, tzinfo=timezone.utc)
HOUR = NOW.replace(minute=0, second=0, microsecond=0)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

ROLLUPS = [s for s in STREAMS if s.cursor_kind == ROLLUP]


def run(coro):
    return asyncio.run(coro)


def _bucket(offset_h: int, source: str = "nginx", *, scris: datetime | None = None,
            n: int = 10):
    """Un rând de agregat.

    `scris` e `updated_at` — CÂND a fost calculat ultima oară, care nu e același
    lucru cu intervalul pe care îl descrie. Implicit: la sfârșitul intervalului.
    """
    interval = HOUR - timedelta(hours=offset_h)
    return {"bucket": interval, "asset_id": 1, "source": source, "action": "req",
            "n": n, "uniq_src": 3, "bytes_in": 100, "bytes_out": 200,
            "p95_latency_ms": 7,
            "updated_at": scris if scris is not None else interval + timedelta(hours=1)}


def _cere_lant(randuri, coloana: str, lant: str, valoare) -> None:
    """Cele DOUĂ reguli de tip pe care le-a încălcat, pe rând, aceeași linie.

    Pe 24 august 2026, aceeași idee a fost respinsă de două ori în producție:

      1. **Postgres**, la compilare: `(updated_at, bucket) > ($1::timestamptz,
         $2::text)` — «operator does not exist: timestamp with time zone > text».
         `bucket` e un moment, deci n-are cum să fie comparat cu un text.
      2. **asyncpg**, la legarea parametrilor: `$2::timestamptz` primind valoarea
         din `collector_cursors.cursor`, care e stocată ca TEXT — «invalid input
         for query argument $2 … expected a datetime».

    Cele două cer lucruri opuse de la aceeași poziție, iar răspunsul e lanțul
    `$2::text::timestamptz`: parametrul SOSEȘTE text, comparația se face pe
    momente.

    Dublul a lăsat ambele să treacă fiindcă modela doar FORMA instrucțiunii și
    compara apoi valorile în Python, unde un `datetime` și un `str` se compară
    fără să se plângă. Aici se cer amândouă capetele lanțului:

      * capătul din DREAPTA — tipul în care intră comparația — trebuie să fie
        tipul coloanei;
      * capătul din STÂNGA — tipul pe care îl cere driverul de la apelant —
        trebuie să fie tipul valorii chiar trimise.
    """
    pasi = lant.split("::")
    if randuri:
        proba = randuri[0][coloana]
        cerut = "timestamptz" if isinstance(proba, datetime) else "text"
        assert pasi[-1] == cerut, (
            f"coloana {coloana} poartă un {type(proba).__name__}, dar comparația "
            f"se face în {pasi[-1]}. Postgres refuză asta cu «operator does not "
            f"exist», iar fluxul tace până citește cineva jurnalul")
    if valoare is not _NECUNOSCUT:
        primit = "timestamptz" if isinstance(valoare, datetime) else "text"
        assert pasi[0] == primit, (
            f"parametrul sosește ca {type(valoare).__name__}, dar castul cere "
            f"{pasi[0]}. asyncpg deduce tipul din cast și refuză valoarea cu "
            f"«invalid input for query argument»")


_NECUNOSCUT = object()


class _DB:
    def __init__(self, rows, cursor_at=None, cursor_key="", trigger=True):
        self.rows = list(rows)
        self.at = cursor_at
        self.key = cursor_key
        self.trigger = trigger
        self.seeded = False
        self.sql: list[str] = []

    async def fetchval(self, sql, *a):
        self.sql.append(sql)
        if "FROM pg_trigger" in sql:
            # Un catalog PostgreSQL nu se modelează într-un dicționar, deci
            # condițiile care nu se pot juca se CER ca text — altfel o sondă din
            # care s-a pierdut „activ" sau „BEFORE UPDATE" ar răspunde tot „da".
            for cerut in ("to_regclass($1)", "NOT tgisinternal",
                          "to_regproc('set_updated_at')", "(tgtype & 19) = 19"):
                assert cerut in sql, f"sonda de trigger nu mai cere {cerut}: {sql}"
            return 1 if self.trigger else 0
        if "EXTRACT(EPOCH FROM ($1::timestamptz - now()))" in sql:
            # Ceasul e la zi: testele de aici sunt despre filigran, iar derapajul
            # de ceas are testele lui. Un `None` ar fi „nu s-a putut citi".
            return 0.0
        if "to_timestamp(0)" in sql:
            return EPOCH
        if sql.startswith("SELECT cursor_at FROM collector_cursors"):
            return self.at
        if sql.startswith("SELECT cursor FROM collector_cursors"):
            return self.key
        raise AssertionError(f"fetchval nerecunoscut: {sql}")

    async def execute(self, sql, *a):
        self.sql.append(sql)
        # Ce se SEAMĂNĂ în `cursor` trebuie să fie castabil la tipul cheii: e
        # valoarea cu care se compară prima rundă. Semănat ca șir gol — cum era
        # până pe 24 august —, `''::timestamptz` cade cu «invalid input syntax»,
        # iar fluxul nu pleacă niciodată de la prima rundă.
        cast = re.search(r"VALUES \(\$1, \$2::([\w:]+)::text,", sql)
        assert cast, f"cursorul nu se seamănă cu o valoare tipată: {sql}"
        _cere_lant(self.rows, "bucket", cast.group(1), a[1])
        self.at = a[1]
        self.key = str(a[1])
        self.seeded = True
        return "INSERT 0 1"

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        if len(a) == 2:
            return await self.fetch_group(sql, *a)
        cursor_at, cursor_key, limit = a
        # Coloanele se CITESC din instrucțiune, nu se fixează aici. Un dublu care
        # ar filtra pe `updated_at` scris de mână ar continua să dea răspunsul
        # corect și după ce fluxul a fost mutat înapoi pe `bucket` — adică exact
        # bug-ul de reparat ar trece testele. S-a întâmplat: falsificarea din 24
        # august a picat alte două teste, nu pe cel scris pentru el.
        pereche = re.search(
            r"WHERE \((\w+), (\w+)\) > \(\$1::([\w:]+), \$2::([\w:]+)\)", sql)
        assert pereche, f"instrucțiunea nu compară o pereche tipată: {sql}"
        tcol, kcol = pereche.group(1), pereche.group(2)
        _cere_lant(self.rows, tcol, pereche.group(3), a[0])
        _cere_lant(self.rows, kcol, pereche.group(4), a[1])
        margine = re.search(r"AND (\w+) < date_trunc\('(\w+)'", sql)

        def _trecut(r):
            if margine is None:
                return True
            unitate = margine.group(2)
            assert unitate == "hour", f"unitate netestată: {unitate}"
            return r[margine.group(1)] < HOUR

        picked = sorted(
            (r for r in self.rows
             if (r[tcol], str(r[kcol])) > (cursor_at, cursor_key) and _trecut(r)),
            key=lambda r: (r[tcol], str(r[kcol])))
        return picked[:limit]

    async def fetch_group(self, sql, *a):
        # Aceeași regulă de tipuri ca la citirea obișnuită. Ramura asta se atinge
        # doar când un grup depășește plafonul, deci un cast greșit aici ar sta
        # ascuns luni de zile și ar cădea exact în ziua în care contează.
        pereche = re.search(
            r"WHERE (\w+) = \$1::([\w:]+) AND (\w+) = \$2::([\w:]+)", sql)
        assert pereche, f"recitirea grupului nu compară două coloane tipate: {sql}"
        moment, cheie = a
        _cere_lant(self.rows, pereche.group(1), pereche.group(2), moment)
        _cere_lant(self.rows, pereche.group(3), pereche.group(4), cheie)
        return [r for r in self.rows
                if r["updated_at"] == moment and str(r["bucket"]) == str(cheie)]

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        if sql.startswith("SELECT cursor, cursor_at FROM collector_cursors"):
            if self.at is None:
                return None
            return {"cursor": self.key, "cursor_at": self.at}
        if "count(*) AS pending" in sql:
            # Restanța se numără cu ACEEAȘI clauză cu care se și expediază —
            # perechea, și marginea de sus. Numărată peste intervalul în curs, ar
            # arăta permanent unu, iar operatorul ar învăța să ignore alarma.
            pereche = re.search(
                r"\((\w+), (\w+)\) > \(\$1::([\w:]+), \$2::([\w:]+)\)", sql)
            assert pereche, f"restanța nu se numără pe perechea tipată: {sql}"
            assert "date_trunc(" in sql, sql
            moment, cheie = a
            _cere_lant(self.rows, pereche.group(1), pereche.group(3), moment)
            _cere_lant(self.rows, pereche.group(2), pereche.group(4), cheie)
            restanta = [r for r in self.rows
                        if (r["updated_at"], str(r["bucket"])) > (moment, cheie)
                        and r["bucket"] < HOUR]
            cel_mai_vechi = min((r["bucket"] for r in restanta), default=None)
            return {"pending": len(restanta),
                    "oldest_min": None if cel_mai_vechi is None else
                    (NOW - (cel_mai_vechi + timedelta(hours=1))).total_seconds() / 60}
        if "INSERT INTO collector_cursors" in sql and "RETURNING cursor_at" in sql:
            # Se scrie CE SCRIE INSTRUCȚIUNEA, nu ce ar fi corect: dublul care
            # aplică singur monotonia o face proprietatea LUI, iar SQL-ul din
            # care garda a fost scoasă ar trece testul.
            #
            # Marcajul e chiar COMPARAȚIA, nu forma `CASE`: un `CASE WHEN true`
            # păstrează forma și pierde proprietatea, iar prima versiune a
            # dublului îl declara monoton — falsificarea a scăpat.
            monoton = ("(collector_cursors.cursor_at, "
                       "collector_cursors.cursor::timestamptz) "
                       "< ($2::timestamptz, $3::text::timestamptz)") in sql
            _cere_lant(self.rows, "updated_at", "timestamptz", a[1])
            _cere_lant(self.rows, "bucket", "text::timestamptz", a[2])
            moment, cheie = a[1], a[2]
            if self.at is None or not monoton or (self.at, self.key) < (moment, cheie):
                self.at, self.key = moment, cheie
            return {"cursor_at": self.at, "cursor": self.key}
        raise AssertionError(f"fetchrow nerecunoscut: {sql}")


def _cfg(rows: int = 2000):
    from types import SimpleNamespace
    return SimpleNamespace(ship=SimpleNamespace(max_rows_per_batch=rows))


def test_there_is_a_rollup_stream_at_all() -> None:
    """Garda listei parametrizate: fără ea, testele de mai jos ar fi decorative."""
    assert [s.name for s in ROLLUPS] == ["event_rollup_1h"], ROLLUPS


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_a_recomputed_interval_is_shipped_AGAIN(stream: Stream) -> None:
    """Defectul din 24 august, în forma lui exactă.

    Ora 04:00 pleacă parțială la 04:56, e completată la 05:56, iar cursorul e
    deja dincolo de ea. Pe `bucket` n-ar mai pleca niciodată; pe `updated_at`,
    pleacă.
    """
    interval = HOUR - timedelta(hours=10)
    recalculat = _bucket(10, n=1385, scris=interval + timedelta(hours=2))
    db = _DB([recalculat],
             cursor_at=interval + timedelta(hours=1),
             cursor_key=str(interval))

    batch = run(shipper.collect_stream(db, _cfg(), stream))
    assert len(batch.rows) == 1, (
        "intervalul recalculat n-a mai plecat; panoul rămâne cu valoarea "
        "parțială, de douăzeci de ori mai mică, și nimic nu se plânge")
    assert batch.rows[0]["n"] == 1385


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_the_interval_in_progress_is_never_shipped(stream: Stream) -> None:
    """Ora în curs rămâne pe server până se încheie.

    Un contor orar trimis la jumătatea orei lui arată pe grafic ca o cădere de
    trafic care nu s-a întâmplat.
    """
    db = _DB([_bucket(0, scris=NOW), _bucket(1)])
    batch = run(shipper.collect_stream(db, _cfg(), stream))
    assert len(batch.rows) == 1, (
        f"{len(batch.rows)} rânduri; ora în curs n-are ce căuta în lot")


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_nothing_new_means_zero_rows_shipped(stream: Stream) -> None:
    """Proprietatea care dovedește că nu există buclă de retrimitere."""
    scris = HOUR
    db = _DB([_bucket(1, scris=scris)], cursor_at=scris,
             cursor_key=str(HOUR - timedelta(hours=1)))
    batch = run(shipper.collect_stream(db, _cfg(), stream))
    assert batch.rows == [], f"s-au retrimis rânduri deja expediate: {batch.rows}"


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_no_source_of_an_hour_is_dropped_at_the_batch_edge(stream: Stream) -> None:
    """Perechea `(updated_at, bucket)` NU e unică, iar asta e o capcană.

    Mentenanța scrie TOATE sursele unei ore în aceeași tranzacție, deci `nginx`,
    `sshd` și `auditd` împart și momentul, și intervalul. Tăiat la mijlocul unui
    asemenea grup, cursorul ar trece dincolo de el, iar sursele rămase n-ar mai
    pleca NICIODATĂ — un panou cu o oră în care lipsesc două surse din trei,
    fără nimic care să se plângă.

    Aici grupul e mai mare decât plafonul, deci nu e loc de retragere: retras,
    lotul ar fi gol, cursorul n-ar avansa și runda următoare ar citi exact
    aceleași rânduri — flux oprit pe loc. Deci grupul pleacă întreg, peste plafon.
    """
    scris = HOUR
    randuri = [_bucket(1, source=s, scris=scris) for s in ("nginx", "sshd", "auditd")]
    db = _DB(randuri)

    lot = run(shipper.collect_stream(db, _cfg(rows=2), stream))
    assert sorted(r["source"] for r in lot.rows) == ["auditd", "nginx", "sshd"], (
        "o sursă a orei s-a pierdut la marginea lotului")


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_a_group_cut_by_the_limit_is_deferred_not_lost(stream: Stream) -> None:
    """Cazul obișnuit al aceleiași capcane: marginea cade ÎN interiorul ultimului
    grup, dar înaintea lui mai există un grup întreg.

    Atunci lotul se retrage la ultima graniță de grup, iar grupul tăiat pleacă
    runda următoare — întreg. Prețul e o rundă de întârziere; alternativa e
    pierdere definitivă și tăcută.
    """
    devreme = HOUR - timedelta(hours=2)
    grup_a = [_bucket(3, source="nginx", scris=devreme)]
    grup_b = [_bucket(2, source=s, scris=HOUR) for s in ("nginx", "sshd", "auditd")]
    db = _DB(grup_a + grup_b)

    lot1 = run(shipper.collect_stream(db, _cfg(rows=2), stream))
    assert len(lot1.rows) == 1 and lot1.full is True, (
        f"lotul nu s-a retras la granița de grup: {lot1.rows}")
    run(shipper._advance_rollup(db, stream, lot1.position, len(lot1.rows)))

    lot2 = run(shipper.collect_stream(db, _cfg(rows=2), stream))
    assert sorted(r["source"] for r in lot2.rows) == ["auditd", "nginx", "sshd"], (
        f"grupul amânat n-a plecat întreg în runda următoare: {lot2.rows}")


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_a_quiet_stream_returns_an_empty_batch_not_none(stream: Stream) -> None:
    """`None` strecurat în listă oprește runda pentru TOATE fluxurile."""
    db = _DB([], cursor_at=EPOCH)
    batch = run(shipper.collect_stream(db, _cfg(), stream))
    assert batch is not None and batch.rows == []
    assert batch.stall == ""


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_the_watermark_is_the_largest_INTERVAL_in_the_batch(stream: Stream) -> None:
    """Filigranul e ce recalculează receptorul din conținutul lotului.

    Nu poziția locală: pe `updated_at`, ultimul rând citit și intervalul cel mai
    mare nu sunt același lucru — un interval vechi recalculat acum vine ULTIMUL
    în ordinea citirii și e cel mai MIC ca interval.
    """
    db = _DB([_bucket(3, scris=HOUR), _bucket(2, scris=HOUR)])
    batch = run(shipper.collect_stream(db, _cfg(), stream))
    assert batch.watermark == (HOUR - timedelta(hours=2)).isoformat()
    assert isinstance(batch.watermark, str)


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_the_first_round_starts_at_the_beginning_of_time(stream: Stream) -> None:
    """Fără cursor, se pleacă de la zero — nu de la un prag.

    Un contor orar are prin construcție puține rânduri, iar istoricul lui e chiar
    ce vrea panoul. Un prag ar tăia tăcut lunile de dinainte, iar simptomul ar fi
    un grafic care începe brusc.
    """
    db = _DB([_bucket(500), _bucket(1)])
    batch = run(shipper.collect_stream(db, _cfg(), stream))
    assert len(batch.rows) == 2, "istoricul de dinainte de prima rundă a fost tăiat"
    assert db.seeded, "cursorul nu a fost semănat, deci nu s-ar fi persistat nimic"


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_a_full_batch_says_there_is_more(stream: Stream) -> None:
    """Lotul plin trebuie să ceară altă rundă, altfel restanța se scurge încet."""
    db = _DB([_bucket(h, scris=HOUR - timedelta(hours=h - 1)) for h in range(1, 6)])
    batch = run(shipper.collect_stream(db, _cfg(rows=2), stream))
    assert len(batch.rows) == 2 and batch.full is True


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_the_cursor_moves_forward_only(stream: Stream) -> None:
    """Un lot reluat, sau un ceas care a sărit, nu are voie să tragă cursorul
    înapoi — atunci fiecare rundă ar retrimite aceleași ore, la nesfârșit."""
    db = _DB([], cursor_at=HOUR, cursor_key=str(HOUR))
    vechi = HOUR - timedelta(hours=9)
    written = run(shipper._advance_rollup(db, stream, (vechi, str(vechi)), 3))
    assert written[0] == HOUR, "cursorul a fost tras înapoi de un lot vechi"


def test_a_rollup_stream_must_declare_a_text_watermark() -> None:
    """Un filigran de interval scris ca număr cade la import, nu în producție."""
    with pytest.raises(ValueError, match="watermark_kind"):
        Stream(name="inventat", table="event_rollup_1h",
               columns=("bucket", "updated_at", "n"), time_column="updated_at",
               key_column="bucket", cursor_kind=ROLLUP, watermark_kind="int")


def test_a_rollup_stream_must_carry_its_time_column() -> None:
    """Fără coloana de timp în `columns`, filigranul nu se poate citi din rând."""
    with pytest.raises(ValueError, match="updated_at"):
        Stream(name="inventat", table="event_rollup_1h",
               columns=("bucket", "n"), time_column="updated_at",
               key_column="bucket", cursor_kind=ROLLUP, watermark_kind="text")


def test_an_unknown_rollup_unit_is_refused_at_declaration() -> None:
    """Unitatea ajunge în TEXTUL instrucțiunii, deci nu poate fi liberă."""
    from sentinel.report.shipper import ROLLUP_UNITS

    with pytest.raises(ValueError, match="rollup_unit"):
        Stream(name="inventat", table="event_rollup_1h",
               columns=("bucket", "updated_at", "n"), time_column="updated_at",
               key_column="bucket", cursor_kind=ROLLUP, watermark_kind="text",
               rollup_unit="hour'); DROP TABLE scans; --")

    for unit in ROLLUP_UNITS:
        Stream(name=f"probă-{unit}", table="event_rollup_1h",
               columns=("bucket", "updated_at", "n"), time_column="updated_at",
               key_column="bucket", cursor_kind=ROLLUP, watermark_kind="text",
               rollup_unit=unit)


def test_every_shipped_moment_carries_an_explicit_utc_offset() -> None:
    """Faptul pe care se sprijină filigranul de text al receptorului.

    Două momente scrise cu fusuri diferite pot fi EGALE și să sorteze diferit,
    iar filigranul se compară pe octeți la ambele capete.
    """
    from sentinel.report.shipper import encode_value

    momente = [datetime(2026, 8, 21, 14, tzinfo=timezone.utc), EPOCH, HOUR]
    scrise = [encode_value(m, "probă") for m in momente]
    for text in scrise:
        assert text.endswith("+00:00"), (
            f"{text!r} nu poartă fus UTC explicit; comparat pe octeți cu altul "
            f"scris în alt fus, ordinea nu mai e cea cronologică")
    assert sorted(scrise) == [encode_value(m, "probă") for m in sorted(momente)]


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_without_the_trigger_the_stream_refuses_to_ship(stream: Stream) -> None:
    """Poarta pusă pe 24 august, împreună cu mutarea filigranului pe `updated_at`.

    Fără triggerul din 0025, `updated_at` nu se mai mișcă atunci când mentenanța
    completează un interval. Interogarea ar întoarce corect zero rânduri, iar
    zero rânduri arată IDENTIC cu «nimic nu s-a schimbat» — adică defectul de
    zece ori mai mic s-ar întoarce tăcut, cu migrația prezentă pe disc.

    Un fișier de migrație pe disc nu e dovadă că nucleul l-a acceptat.
    """
    db = _DB([_bucket(1)], trigger=False)
    with pytest.raises(shipper.ShipTriggerError, match="set_updated_at"):
        run(shipper.collect_stream(db, _cfg(), stream))


@pytest.mark.parametrize("stream", ROLLUPS, ids=lambda s: s.name)
def test_the_lag_report_probes_the_trigger_instead_of_assuming_it(stream: Stream) -> None:
    """`_rollup_lag` afirma `updated_at_trigger=True`, cu un comentariu care
    explica de ce fluxul nu depinde de niciun trigger. De la 0025 depinde.

    O afirmație care a fost adevărată o dată e cel mai bun ascunziș pentru una
    care nu mai e.
    """
    # CU rânduri, nu pe gol: dublul își cere tipurile din rândurile pe care le
    # are, iar pe o fixtură goală n-are ce cere — deci o instrucțiune cu tipul
    # greșit ar trece pe aici fără să se plângă. S-a întâmplat: falsificarea din
    # 24 august a mutat restanța înapoi pe `::text` și n-a picat nimic.
    randuri = [_bucket(1)]
    fara = _DB(randuri, cursor_at=HOUR, cursor_key=str(HOUR), trigger=False)
    assert run(shipper._rollup_lag(fara, stream)).updated_at_trigger is False

    cu = _DB(randuri, cursor_at=HOUR, cursor_key=str(HOUR), trigger=True)
    raport = run(shipper._rollup_lag(cu, stream))
    assert raport.updated_at_trigger is True
    assert raport.pending == 0, "restanța numărată peste rânduri deja expediate"
