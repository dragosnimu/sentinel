"""Mentenanța: retenție, agregate, garda de disc.

Primul test din fișier nu verifică logica, ci existența. Serviciul acesta a
lipsit complet dintr-un build livrat: unitatea systemd exista, timerul rula din
oră în oră, comanda era listată în CLI — și modulul nu. A eșuat tăcut săptămâni,
iar retenția partițiilor nu a rulat niciodată.

Nimic nu lega cele două liste. Acum le leagă un test.
"""
from __future__ import annotations

import asyncio
import importlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sentinel.services import maintenance_service as ms

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


def run(c):
    return asyncio.run(c)


# --- fiecare serviciu declarat trebuie să existe --------------------------
def test_every_declared_service_has_a_module():
    """`sentinel <x>` promite un modul. Dacă lipsește, unitatea eșuează din oră
    în oră cu `No module named` și nimeni nu se uită la un oneshot."""
    from sentinel.__main__ import SERVICES
    missing = []
    for name in SERVICES:
        try:
            importlib.import_module(f"sentinel.services.{name}_service")
        except ImportError as exc:
            missing.append(f"{name} ({exc})")
    assert not missing, "servicii declarate fără modul: " + ", ".join(missing)


def test_every_service_module_has_a_main():
    """`_run_service` cheamă `module.main`. Un modul fără el eșuează la fel de
    tăcut ca unul absent, doar un pas mai târziu."""
    from sentinel.__main__ import SERVICES
    for name in SERVICES:
        mod = importlib.import_module(f"sentinel.services.{name}_service")
        assert callable(getattr(mod, "main", None)), f"{name}_service nu are main()"


# --- dublura de stub ------------------------------------------------------
class _DB:
    """Înregistrează SQL-ul și întoarce valori programate, pe potrivire de text."""

    def __init__(self, vals=None, rows=None):
        self.vals = vals or {}
        self.rows = rows or {}
        self.sql: list[str] = []

    def _match(self, table, sql):
        for k, v in table.items():
            if k in sql:
                return v
        return None

    async def fetchval(self, sql, *a):
        self.sql.append(sql)
        v = self._match(self.vals, sql)
        return v() if callable(v) else v

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        return self._match(self.rows, sql) or []

    async def execute(self, sql, *a):
        self.sql.append(sql)
        self.last_args = a
        return "INSERT 0 1"


def _cfg(**over):
    r = SimpleNamespace(raw_events_days=30, rollup_1m_days=90, rollup_1h_days=400,
                        health_samples_days=30, disk_guard_free_pct=15)
    for k, v in over.items():
        setattr(r, k, v)
    return SimpleNamespace(retention=r,
                           patch=SimpleNamespace(retention_count=10, retention_days=30))


# --- ordinea pașilor ------------------------------------------------------
def test_rollups_run_before_retention():
    """Ordinea e corectitudine, nu stil.

    Retenția înaintea agregatelor ar arunca exact rândurile pe care agregatele
    trebuiau să le rezume, iar gaura din grafic ar apărea abia peste săptămâni,
    când partiția e demult ștearsă."""
    src = ms.run.__code__.co_consts
    order = [c for c in src if isinstance(c, str)
             and c in ("rollup_events", "retention_partitions", "partitions")]
    assert order.index("partitions") < order.index("rollup_events") < \
           order.index("retention_partitions")


def test_a_failing_step_does_not_stop_the_others():
    """Reîmprospătarea intelligence-ului are nevoie de rețea; retenția, nu.
    În aceeași încercare, o cădere de DNS ar deveni, peste câteva săptămâni, un
    disc plin."""
    rep = ms.Report()

    async def boom():
        raise RuntimeError("fără rețea")

    async def fine():
        return "ok", {}

    run(ms._step(rep, "intel", boom()))
    run(ms._step(rep, "retention", fine()))
    assert [s.name for s in rep.failed] == ["intel"]
    assert rep.steps[1].ok


# --- recuperarea după o pauză --------------------------------------------
def test_rollup_resumes_from_the_watermark_not_the_last_hour():
    """Un serviciu care nu a rulat trei zile trebuie să recupereze, nu să lase
    o gaură permanentă exact în perioada în care ceva era stricat."""
    old = NOW - timedelta(days=3)
    db = _DB(vals={"max(bucket)": old, "sentinel_rollup_events": 4321})
    detail, facts = run(ms.rollup_events(db))
    # Plafonat la MAX_CATCHUP_HOURS, nu la o oră.
    assert facts["event_rollup_1m"]["hours"] == pytest.approx(ms.MAX_CATCHUP_HOURS, abs=0.2)
    assert facts["event_rollup_1m"]["remaining_hours"] > 0, \
        "recuperarea plafonată trebuie să raporteze cât a rămas"


def test_rollup_on_a_fresh_database_does_not_scan_all_of_history():
    """Fără agregate, watermark-ul e o podea, nu începutul timpului. Unitatea are
    TimeoutStartSec=900; o rulare care încearcă o lună e omorâtă la mijloc."""
    db = _DB(vals={"max(bucket)": None, "sentinel_rollup_events": 10})
    _, facts = run(ms.rollup_events(db))
    assert facts["event_rollup_1h"]["hours"] <= ms.MAX_CATCHUP_HOURS


# --- retenția -------------------------------------------------------------
def test_retention_uses_the_configured_days_per_table():
    calls = []

    class DB(_DB):
        async def fetch(self, sql, *a):
            calls.append(a)
            return []

    run(ms.drop_partitions(DB(), _cfg(raw_events_days=14, health_samples_days=7)))
    assert ("raw_events", 14) in calls
    assert ("health_samples", 7) in calls
    assert ("capacity_samples", 7) in calls


def test_rollup_trim_reports_the_real_count():
    """A raportat cândva multipli de mărimea tranșei fiindcă citea `RETURNING 1`
    cu fetchval. O cifră inventată într-un jurnal de mentenanță e mai rea decât
    niciuna: pare o măsurătoare."""
    seq = iter([137, 0, 42, 0])
    db = _DB(vals={"DELETE FROM": lambda: next(seq)})
    _, facts = run(ms.trim_rollups(db, _cfg()))
    assert facts["trimmed"]["event_rollup_1m"] == 137
    assert facts["trimmed"]["event_rollup_1h"] == 42


# --- golirea partiției DEFAULT -------------------------------------------
def test_default_drain_is_capped_and_says_what_is_left():
    """Rândurile blocate în DEFAULT sunt invizibile pentru retenție, iar mutarea
    unei zile e o tranzacție care nu se poate întrerupe. Plafonat pe rulare — dar
    o golire plafonată care tace arată identic cu una completă."""
    from datetime import date as _d
    days = [{"day": _d(2026, 7, d), "rows_in_default": 1000 * d} for d in range(20, 30)]

    class DB(_DB):
        def __init__(self):
            super().__init__()
            self.created = []

        async def fetch(self, sql, *a):
            return days if a[0] == "raw_events" else []

        async def fetchval(self, sql, *a):
            self.created.append(a)
            return "part"

    db = DB()
    detail, facts = run(ms.drain_default(db))
    assert len(db.created) == ms.MAX_DRAIN_DAYS
    assert facts["days_remaining"] == len(days) - ms.MAX_DRAIN_DAYS
    assert "rămase" in detail


def test_default_drain_is_quiet_when_nothing_is_stranded():
    detail, facts = run(ms.drain_default(_DB()))
    assert facts["days_remaining"] == 0
    assert facts["moved"] == {}


def test_the_drain_runs_before_retention():
    """Retenția nu vede rândurile din DEFAULT. Dacă ar rula prima, ziua abia
    mutată ar aștepta încă o oră ca să fie luată în calcul — și pe un disc care
    se umple, ora aia contează."""
    order = [c for c in ms.run.__code__.co_consts if isinstance(c, str)]
    assert order.index("drain_default") < order.index("retention_partitions")


# --- bug-urile SQL prinse la prima rulare reală ---------------------------
def test_the_rollup_functions_do_not_shadow_a_column_name():
    """`DECLARE n integer` se ciocnea cu coloana `n` din event_rollup_1m, iar
    PL/pgSQL refuza `SET n = EXCLUDED.n` ca ambiguu. Nu a fost prins niciodată
    fiindcă nimic nu apela funcția: SQL care se aplică fără eroare nu e SQL care
    funcționează."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"
    sql = (root / "0017_partition_fixes.sql").read_text(encoding="utf-8")
    assert "DECLARE\n    rows_written integer;" in sql
    # Coloanele tabelei nu au voie să apară ca nume de variabilă declarată.
    for col in ("n", "uniq_src", "bytes_in", "bytes_out", "bucket"):
        assert f"    {col} integer;" not in sql, f"variabila `{col}` umbrește o coloană"


def test_partition_creation_handles_rows_already_in_default():
    """Rândurile ajung în DEFAULT când partiția zilei lipsește, iar apoi Postgres
    refuză să creeze acea partiție. Blocajul se auto-întreține: DEFAULT crește și
    nu e atins de retenție."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"
    sql = (root / "0017_partition_fixes.sql").read_text(encoding="utf-8")
    assert "sentinel_create_partition" in sql
    assert "ATTACH PARTITION" in sql, "fără ATTACH, rândurile blocate rămân blocate"
    assert "DELETE FROM %I WHERE" in sql, "rândurile trebuie mutate, nu doar numărate"
    # CHECK-ul dinainte de ATTACH e ce face validarea instantanee în loc de o
    # scanare completă a tabelei.
    assert "ADD CONSTRAINT" in sql and "CHECK" in sql


def test_the_partition_key_is_read_from_the_catalog():
    """Toate trei tabelele partiționează pe `ts` azi. Scris în cod, ar minți
    tăcut în ziua în care una nu o mai face."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"
    sql = (root / "0017_partition_fixes.sql").read_text(encoding="utf-8")
    assert "pg_partitioned_table" in sql
    # int2vector nu se indexează ca un array obișnuit; trecerea prin text scoate
    # întrebarea din discuție.
    assert "string_to_array(pt.partattrs::text" in sql


# --- garda de disc --------------------------------------------------------
def test_disk_guard_is_quiet_above_the_threshold(monkeypatch):
    monkeypatch.setattr(ms.shutil, "disk_usage",
                        lambda p: SimpleNamespace(total=100, used=40, free=60))
    db = _DB(vals={"SHOW data_directory": "/var/lib/pgsql"})
    detail, facts = run(ms.disk_guard(db, _cfg()))
    assert facts["free_pct"] == 60.0
    assert "emergency" not in facts
    assert not any("notifications" in s for s in db.sql)


def test_disk_guard_shortens_retention_and_says_so(monkeypatch):
    """Pierderea de istoric e acceptabilă; pierderea tăcută, nu. Operatorul
    trebuie să afle că are mai puține date decât crede."""
    monkeypatch.setattr(ms.shutil, "disk_usage",
                        lambda p: SimpleNamespace(total=100, used=95, free=5))
    db = _DB(vals={"SHOW data_directory": "/var/lib/pgsql",
                   "sentinel_emergency_retention": 6})
    detail, facts = run(ms.disk_guard(db, _cfg(raw_events_days=30)))
    assert facts["emergency"] is True
    assert facts["target_days"] == 7          # max(7, 30 // 4)
    assert facts["dropped"] == 6
    assert any("notifications" in s for s in db.sql), "trebuie să alerteze"
    assert db.last_args[0] == "critical"


def test_disk_guard_never_shortens_below_a_week(monkeypatch):
    """Sub o săptămână, o pană de weekend plus o zi de investigație nu mai are
    niciun eveniment de citit."""
    monkeypatch.setattr(ms.shutil, "disk_usage",
                        lambda p: SimpleNamespace(total=100, used=98, free=2))
    db = _DB(vals={"SHOW data_directory": "/x", "sentinel_emergency_retention": 1})
    _, facts = run(ms.disk_guard(db, _cfg(raw_events_days=8)))
    assert facts["target_days"] == 7


def test_disk_guard_falls_back_when_the_data_directory_is_unreadable(monkeypatch):
    """`SHOW data_directory` cere superuser. Rolul `sentinel` nu e, deci
    întrebarea e refuzată — și asta nu are voie să oprească garda."""
    seen = []

    def usage(p):
        seen.append(p)
        return SimpleNamespace(total=100, used=10, free=90)

    monkeypatch.setattr(ms.shutil, "disk_usage", usage)

    class DB(_DB):
        async def fetchval(self, sql, *a):
            if "data_directory" in sql:
                raise RuntimeError("permission denied")
            return 0

    run(ms.disk_guard(DB(), _cfg()))
    assert seen == ["/var/lib/sentinel"]


# --- unitatea systemd corespunde cu ce face serviciul ---------------------
def test_the_unit_can_write_where_the_service_writes():
    """Serviciul curăță punctele de restaurare, deci unitatea trebuie să poată
    scrie în directorul de backup. `ProtectSystem=strict` fără calea potrivită
    face pasul să eșueze doar în producție, niciodată în teste."""
    from pathlib import Path
    unit = (Path(__file__).resolve().parents[2] / "deploy" / "systemd" /
            "sentinel-maintenance.service").read_text(encoding="utf-8")
    rw = next(l for l in unit.splitlines() if l.startswith("ReadWritePaths="))
    assert "/var/backups/sentinel" in rw
    assert "Type=oneshot" in unit
