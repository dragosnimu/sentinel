"""Scriitorul oglinzii: singurul cod care pune identitatea în baza de date.

Ce se strică dacă e greșit nu se vede de nicăieri. Un scriitor care nu scrie
lasă `check_instance_identity` fără termenul de comparație, deci o bază
restaurată pe o mașină clonată nu mai e observată de nimeni — două servere
raportează sub o singură identitate și cifrele din panou încetează să însemne ce
spun, fără nicio eroare undeva. Un scriitor care scrie PREA mult e mai rău: dacă
suprascrie un rând diferit, șterge chiar dovada.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from sentinel.db import identity_mirror
from sentinel.db.identity_mirror import mirror_instance_id

ID_A = "0123456789abcdef0123456789abcdef"
ID_B = "fedcba9876543210fedcba9876543210"


def run(c):
    return asyncio.run(c)


@pytest.fixture(autouse=True)
def _identity(monkeypatch, tmp_path) -> Path:
    """Se repointează CONSTANTA din `sentinel.identity`, nu funcția importată în
    scriitor: altfel testele ar trece și peste un cititor complet stricat."""
    import sentinel.identity as identity

    target = tmp_path / "instance_id"
    target.write_text(ID_A + "\n", encoding="utf-8")
    monkeypatch.setattr(identity, "INSTANCE_ID_PATH", target)
    return target


class _Conn:
    """Conexiune falsă care ține minte ce s-a executat, nu doar ce s-a întors.

    `writes` e lista de instrucțiuni care ATING date. Ramura de conflict se
    verifică pe ea: „nu a suprascris" e o afirmație despre ce s-a executat, iar
    o aserțiune pe valoarea întoarsă ar trece și peste un UPDATE.
    """

    def __init__(self, existing: str | None = None, boom: Exception | None = None):
        self.existing = existing
        self.boom = boom
        self.writes: list[tuple[str, tuple]] = []

    async def fetchval(self, sql, *args):
        self.writes.append((sql, args))
        if self.boom is not None:
            raise self.boom
        if "INSERT INTO instance_identity" in sql:
            if self.existing is not None:
                return None            # ON CONFLICT DO NOTHING → niciun rând
            self.existing = args[0]
            return args[0]
        if "SELECT instance_id FROM instance_identity" in sql:
            return self.existing
        raise AssertionError(f"interogare neașteptată: {sql}")

    async def execute(self, sql, *args):
        self.writes.append((sql, args))
        return "INSERT 0 1"

    # --- ce s-a întâmplat, exprimat cum se citește într-o aserțiune ---------
    @property
    def marker(self) -> str | None:
        for sql, args in self.writes:
            if "collector_cursors" in sql and args[0] == identity_mirror.MIRROR_MARKER:
                return args[1]
        return None

    @property
    def touched_identity(self) -> list[str]:
        return [sql for sql, _ in self.writes if "instance_identity" in sql]


def test_a_fresh_host_gets_its_mirror_written():
    """Cazul normal. Dacă nu merge, tot restul fișierului nu apără nimic."""
    conn = _Conn(existing=None)
    assert run(mirror_instance_id(conn)) == identity_mirror.WRITTEN
    assert conn.existing == ID_A


def test_running_it_twice_changes_nothing():
    """`sentinel migrate` rulează la FIECARE instalare, și se rulează și de mână.

    Un scriitor care nu e idempotent ar fi eșuat pe cheia primară la a doua
    rulare, iar `install.sh` face `die` dacă migrarea întoarce non-zero — adică
    a doua instalare pe orice gazdă ar fi picat, în pasul cu numele „migrate",
    pentru un motiv care n-are nimic de-a face cu migrațiile.
    """
    conn = _Conn(existing=None)
    assert run(mirror_instance_id(conn)) == identity_mirror.WRITTEN
    assert run(mirror_instance_id(conn)) == identity_mirror.MATCHED
    assert conn.existing == ID_A


def test_a_different_id_in_the_database_is_never_overwritten(caplog):
    """Constatarea pentru care există toată tabela.

    Baza spune A, fișierul spune B: o copie de siguranță luată pe un server și
    restaurată pe clona altuia. A „repara" asta scriind ar șterge exact dovada,
    iar cele două servere ar continua să raporteze sub o identitate, în tăcere.
    Deci rândul nu se atinge, și operatorul află.
    """
    conn = _Conn(existing=ID_B)
    with caplog.at_level("ERROR", logger="sentinel.db.identity_mirror"):
        assert run(mirror_instance_id(conn)) == identity_mirror.CONFLICT
    assert conn.existing == ID_B, "oglinda a fost suprascrisă"
    assert not any("UPDATE" in sql.upper() for sql in conn.touched_identity)
    assert any(r.levelname == "ERROR" for r in caplog.records), \
        "nepotrivirea nu ajunge nicăieri"


def test_a_conflict_does_not_leak_the_whole_identity(caplog):
    """Mesajul ajunge în jurnal și pe ecranul instalatorului. Prefixele sunt
    de-ajuns ca să se vadă că sunt două lucruri diferite; valoarea întreagă nu
    are ce căuta acolo, mai ales că una dintre ele e a ALTUI server."""
    conn = _Conn(existing=ID_B)
    with caplog.at_level("ERROR", logger="sentinel.db.identity_mirror"):
        run(mirror_instance_id(conn))
    text = " ".join(r.getMessage() + str(getattr(r, "file", "")) +
                    str(getattr(r, "db", "")) for r in caplog.records)
    assert ID_A not in text and ID_B not in text
    assert ID_A[:8] in text and ID_B[:8] in text


def test_an_unreadable_identity_file_records_the_attempt(_identity):
    """Gazda instalată înaintea pasului 27: fișierul nu există încă.

    Fără urma încercării, `check_instance_identity` nu poate deosebi asta de „nu
    a rulat nimic încă", și le raportează pe amândouă `ok` — tăcere în formă de
    sănătate.
    """
    _identity.unlink()
    conn = _Conn(existing=None)
    assert run(mirror_instance_id(conn)) == identity_mirror.UNREADABLE
    assert conn.marker == identity_mirror.UNREADABLE
    assert conn.touched_identity == [], "s-a scris ceva fără să se știe ce"


def test_a_failing_insert_records_the_attempt_too():
    """Tabela lipsă, drepturi lipsă, disc plin.

    Urma trebuie scrisă mai ales AICI: „scriitorul a rulat și rândul tot nu e
    acolo" e singurul lucru care transformă absența rândului dintr-o etapă
    normală într-o constatare.
    """
    conn = _Conn(boom=RuntimeError('relation "instance_identity" does not exist'))
    assert run(mirror_instance_id(conn)) == identity_mirror.FAILED
    assert conn.marker == identity_mirror.FAILED


def test_the_writer_never_raises_into_the_migration_runner():
    """`install.sh` face `die` dacă `sentinel migrate` întoarce non-zero.

    Un diagnostic care oprește instalări e o pană mai mare decât lucrul
    diagnosticat: gazda rămâne cu codul vechi și cu tot ce venea în aceeași
    livrare.
    """
    class _Dead:
        async def fetchval(self, sql, *a):
            raise RuntimeError("baza nu răspunde")

        async def execute(self, sql, *a):
            raise RuntimeError("baza nu răspunde")

    assert run(mirror_instance_id(_Dead())) == identity_mirror.FAILED


def test_every_outcome_is_a_distinct_word():
    """Vocabularul e un contract cu `check_instance_identity`, care îl tipărește
    operatorului. Două rezultate cu același șir ar face imposibil de spus, dintr-o
    urmă, care dintre ele s-a întâmplat."""
    outcomes = [identity_mirror.WRITTEN, identity_mirror.MATCHED,
                identity_mirror.CONFLICT, identity_mirror.UNREADABLE,
                identity_mirror.FAILED]
    assert len(set(outcomes)) == len(outcomes) == 5


# ---------------------------------------------------------------------------
# Legătura cu runner-ul de migrații
# ---------------------------------------------------------------------------
def _apply_source():
    """Nodul AST al lui `_apply` din runner-ul de migrații.

    Se verifică pe SURSĂ fiindcă apelul real cere PostgreSQL, iar suita nu are
    unul. Ce se poate afirma astfel e limitat și e spus în fiecare test care
    folosește funcția asta: unde e apelul, nu că a avut efect.
    """
    import ast

    from sentinel.db import migrate

    tree = ast.parse(Path(migrate.__file__).read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.AsyncFunctionDef) and n.name == "_apply")


def _mirror_calls(node) -> int:
    import ast

    return sum(1 for n in ast.walk(node)
               if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id == "mirror_instance_id")


def test_the_writer_is_called_on_the_path_that_applied_migrations():
    """Cele două ieșiri ale runner-ului sunt drumuri DIFERITE, și fiecare are
    nevoie de apel.

    O primă versiune a testului ăstuia cerea doar ca numele să apară undeva în
    `_apply` — și trecea verde peste ștergerea apelului de pe drumul care CHIAR
    aplică migrații, fiindcă celălalt drum îl mai avea. Adică exact aserțiunea pe
    prezența unui nume în loc de pe decizia luată din el, din CLAUDE.md. Aici se
    numără apelurile din afara ramurii „nimic de aplicat".

    Ce se strică dacă lipsește: pe o instalare NOUĂ — singura pe care 0022 chiar
    are ceva de aplicat — oglinda nu se scrie niciodată, iar
    `check_instance_identity` raportează „nu e scrisă încă" pe veci.
    """
    import ast

    apply_fn = _apply_source()
    total = _mirror_calls(apply_fn)
    branch = next(n for n in ast.walk(apply_fn)
                  if isinstance(n, ast.If) and isinstance(n.test, ast.UnaryOp)
                  and isinstance(n.test.op, ast.Not)
                  and isinstance(n.test.operand, ast.Name)
                  and n.test.operand.id == "pending")
    assert total - _mirror_calls(branch) >= 1, \
        "singurul apel e în ramura „nimic de aplicat”; drumul care migrează nu-l are"


def test_the_mirror_is_written_on_a_host_with_nothing_left_to_migrate():
    """Pe orice gazdă deja instalată, 0022 e demult aplicată.

    Acolo `_apply` iese prin ramura „schema up to date" — care e SINGURA atinsă
    la o reinstalare. Un apel pus doar după bucla de migrații ar fi însemnat că
    oglinda nu se scrie niciodată exact pe gazdele pentru care a fost scrisă, iar
    verificarea ar fi rămas pe „oglinda nu e scrisă încă" la nesfârșit.
    """
    import ast

    apply_fn = _apply_source()
    # Ramura „nimic de aplicat" e `if not pending:` — se cere apelul ÎNĂUNTRUL ei.
    branch = next(n for n in ast.walk(apply_fn)
                  if isinstance(n, ast.If) and isinstance(n.test, ast.UnaryOp)
                  and isinstance(n.test.op, ast.Not)
                  and isinstance(n.test.operand, ast.Name)
                  and n.test.operand.id == "pending")
    assert _mirror_calls(branch) >= 1


class _MigrateConn:
    """Conexiunea pe care o vede `_apply`, cu tot SQL-ul înregistrat.

    `applied` decide dacă mai există migrații de aplicat. Cazul care contează e
    „niciuna" — adică fiecare gazdă deja instalată.
    """

    def __init__(self, applied: list):
        self.applied = applied
        self.sql: list[str] = []

    async def execute(self, sql, *args):
        self.sql.append(sql)
        return "OK"

    async def fetch(self, sql, *args):
        self.sql.append(sql)
        return list(self.applied)

    async def fetchval(self, sql, *args):
        self.sql.append(sql)
        return None

    async def close(self):
        pass

    @property
    def writes(self) -> list[str]:
        """Doar instrucțiunile care ATING date, nu cele care le citesc."""
        return [s for s in self.sql
                if "instance_identity" in s or "collector_cursors" in s]


def _up_to_date_rows():
    """Ce ar întoarce `schema_version` pe o gazdă cu tot ce e pe disc aplicat."""
    from sentinel.db.migrate import discover

    return [{"version": m.version, "name": m.name, "checksum": m.checksum}
            for m in discover()]


def _run_apply(monkeypatch, dry_run: bool, applied: list) -> _MigrateConn:
    import asyncpg

    from sentinel.db import migrate

    conn = _MigrateConn(applied)

    async def _connect(dsn, timeout=None):
        return conn

    monkeypatch.setattr(asyncpg, "connect", _connect)
    assert run(migrate._apply("postgres://nu-se-conectează", dry_run)) == 0
    return conn


def test_a_dry_run_writes_nothing_on_a_host_with_nothing_to_migrate(monkeypatch):
    """`--dry-run` e comanda pe care o rulează cineva care vrea să AFLE ce s-ar
    întâmpla, de obicei înainte să se hotărască dacă atinge gazda.

    Pe ORICE gazdă deja instalată nu e nimic de aplicat, deci ordinea celor două
    ramuri din `_apply` decide totul: cu `if not pending` înaintea lui
    `if dry_run`, o rulare „de probă" scrie rândul oglinzii și urma
    scriitorului. Testul se uită la SQL-ul emis, nu la forma sursei — o
    aserțiune pe conținutul ramurilor trece verde peste exact schimbarea asta
    de ordine, fiindcă ramurile rămân neatinse.
    """
    conn = _run_apply(monkeypatch, dry_run=True, applied=_up_to_date_rows())
    assert conn.writes == [], conn.writes


def test_a_dry_run_writes_nothing_when_migrations_are_pending(monkeypatch):
    """Cealaltă jumătate a aceleiași comenzi: pe o gazdă nouă `--dry-run`
    listează ce s-ar aplica și tot nu are voie să scrie."""
    conn = _run_apply(monkeypatch, dry_run=True, applied=[])
    assert conn.writes == [], conn.writes
    assert not any("INSERT INTO schema_version" in s for s in conn.sql)


def test_a_real_run_on_an_up_to_date_host_does_write_the_mirror(monkeypatch):
    """Garda gărzii.

    Fără ea, testele de mai sus ar trece și peste un `_apply` care nu scrie
    NICIODATĂ oglinda — adică peste eșecul opus, în care `check_instance_identity`
    rămâne pe „nu e scrisă încă" pe fiecare gazdă din producție.
    """
    conn = _run_apply(monkeypatch, dry_run=False, applied=_up_to_date_rows())
    assert any("INSERT INTO instance_identity" in s for s in conn.writes), conn.writes
    assert any("collector_cursors" in s for s in conn.writes), conn.writes
