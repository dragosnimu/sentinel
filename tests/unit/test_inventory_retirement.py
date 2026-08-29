"""Retragerea unui activ scos din `inventory.yaml`, în `scan/inventory.py:sync`.

Panele pe care le previn testele de aici, fiecare în ce se strică pentru
operator:

  * **Roșu permanent peste ceva care nu mai există.** Pe 29 august 2026 panoul
    arăta `Servicii: 🟢 10 · 🔴 4` de optsprezece zile. Cele patru — `n8n`,
    `n8n-traefik`, `qdrant`, `webmin` — nu erau picate, erau dezinstalate;
    `n8n` singur strânsese 30 237 de sonde reușite din 78 739. `sync` făcea doar
    `upsert`, deci scoaterea lor din fișier n-avea niciun efect. Patru rânduri
    roșii care nu se pot stinge antrenează exact obiceiul de a nu mai citi
    roșul.
  * **Toată monitorizarea oprită de un fișier gol.** `load` întoarce deliberat
    o listă goală pentru un fișier lipsă, și tot o listă goală pentru unul
    trunchiat de o editare eșuată. O retragere care se ia după listă ar stinge
    fiecare sondă de pe gazdă, în tăcere, exact când nimeni nu se uită. Ăsta e
    testul care contează cel mai mult.
  * **Istoric tăiat de o ștergere.** `findings`, `outages` și
    `availability_rollup` atârnă de `assets` cu `ON DELETE CASCADE`, `incidents`
    și `scans` cu `ON DELETE SET NULL`, iar `health_samples` fără nicio cheie
    străină. Un `DELETE` ar lua sau ar orfaniza chiar dosarul pe care îl vrei
    după ce ai scos ceva de pe server, dacă acel ceva a fost atacat cât timp a
    existat.
  * **Un activ scos din greșeală care nu se mai poate întoarce.** Re-adăugarea
    în fișier trebuie să-l facă activ la loc, cu ACELAȘI `id` — altfel istoricul
    rămâne agățat de un rând pe care nu-l mai citește nimeni.
  * **O a doua rulare care mută iar `retired_at`.** `sync` rulează la fiecare
    trecere a serviciului de sănătate. Dacă a doua trecere ar rescrie momentul
    retragerii, „retras de 18 zile" ar fi mereu „retras acum" și n-ar mai spune
    nimic.

Dublul de mai jos ȚINE RÂNDURI și își citește regulile din CHIAR TEXTUL
instrucțiunilor pe care i le dă codul: lista de coloane a `INSERT`-ului,
atribuirile din `DO UPDATE SET`, predicatele din `WHERE`. Un dublu care își
face singur regulile probează dublul — iar aici tocmai despre ce anume
potrivesc regulile e vorba.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.db.repo import assets as assets_repo
from sentinel.scan import inventory

T0 = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


class FakeDB:
    """Rânduri în memorie, cu SQL-ul real ca singură sursă a regulilor."""

    def __init__(self) -> None:
        self.rows: list[dict] = []
        self.statements: list[str] = []
        self._next_id = 1
        self.clock = T0

    # -- ce se citește din SQL -------------------------------------------
    @staticmethod
    def _insert_columns(sql: str) -> list[str]:
        m = re.search(r"INSERT INTO assets\s*\((.*?)\)\s*VALUES", sql, re.S)
        assert m, f"nu găsesc lista de coloane a INSERT-ului:\n{sql}"
        return [c.strip() for c in m.group(1).split(",")]

    @staticmethod
    def _update_assignments(sql: str) -> list[tuple[str, str]]:
        m = re.search(r"DO UPDATE SET(.*?)RETURNING", sql, re.S)
        assert m, f"nu găsesc corpul DO UPDATE SET:\n{sql}"
        pairs = []
        for part in m.group(1).split(","):
            col, sep, expr = part.partition("=")
            assert sep, f"atribuire nerecunoscută: {part!r}"
            pairs.append((col.strip(), expr.strip()))
        return pairs

    def _apply(self, row: dict, col: str, expr: str, incoming: dict) -> None:
        if expr.startswith("EXCLUDED."):
            row[col] = incoming[expr.split(".", 1)[1]]
        elif expr == "now()":
            row[col] = self.clock
        elif expr.upper() == "NULL":
            row[col] = None
        else:
            raise AssertionError(f"expresie nerecunoscută în DO UPDATE SET: {expr!r}")

    # -- interfața Database ----------------------------------------------
    async def fetchval(self, sql: str, *args):
        self.statements.append(sql)
        assert "INSERT INTO assets" in sql, f"fetchval neașteptat:\n{sql}"
        columns = self._insert_columns(sql)
        assert len(columns) == len(args), (
            f"{len(columns)} coloane în INSERT, {len(args)} argumente")
        incoming = dict(zip(columns, args))

        existing = next((r for r in self.rows if r["name"] == incoming["name"]), None)
        if existing is None:
            row = dict(incoming)
            row["id"] = self._next_id
            self._next_id += 1
            row["first_seen"] = self.clock
            row["last_seen"] = self.clock
            row["retired_at"] = None
            self.rows.append(row)
            return row["id"]

        for col, expr in self._update_assignments(sql):
            self._apply(existing, col, expr, incoming)
        return existing["id"]

    async def fetch(self, sql: str, *args):
        self.statements.append(sql)
        if "UPDATE assets" in sql:
            assert "SET retired_at = now()" in sql, sql
            # Fără el, a doua trecere ar rescrie momentul retragerii.
            assert "retired_at IS NULL" in sql, (
                "UPDATE-ul de retragere nu se mărginește la rândurile încă active")
            assert "name <> ALL($1::text[])" in sql, sql
            keep = set(args[0])
            hit = [r for r in self.rows
                   if r["retired_at"] is None and r["name"] not in keep]
            for r in hit:
                r["retired_at"] = self.clock
            return [{"name": r["name"]} for r in hit]

        if "FROM assets" in sql:
            rows = list(self.rows)
            if "retired_at IS NULL" in sql:
                rows = [r for r in rows if r["retired_at"] is None]
            if "NOT protected" in sql:
                rows = [r for r in rows if not r["protected"]]
            rows.sort(key=lambda r: (-r["criticality"], r["name"]))
            return [dict(r) for r in rows]

        raise AssertionError(f"instrucțiune nerecunoscută:\n{sql}")

    async def fetchrow(self, sql: str, *args):
        self.statements.append(sql)
        assert "FROM assets WHERE name" in sql, sql
        rows = [r for r in self.rows if r["name"] == args[0]]
        if "retired_at IS NULL" in sql:
            rows = [r for r in rows if r["retired_at"] is None]
        return dict(rows[0]) if rows else None


def write(tmp_path: Path, names, *, protected=(), text: str | None = None) -> Path:
    p = tmp_path / "inventory.yaml"
    if text is not None:
        p.write_text(text, encoding="utf-8")
        return p
    lines = ["assets:"]
    for n in names:
        lines += [f"  - name: {n}", "    kind: service", "    port: 22"]
        if n in protected:
            lines.append("    protected: true")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def active_names(db: FakeDB) -> set[str]:
    return {a.name for a in run(assets_repo.list_all(db))}


def all_names(db: FakeDB) -> set[str]:
    return {a.name for a in run(assets_repo.list_all(db, include_retired=True))}


def populated(tmp_path: Path,
              names=("n8n", "qdrant", "sshd", "webmin")) -> tuple[FakeDB, Path]:
    db = FakeDB()
    path = write(tmp_path, names)
    run(inventory.sync(db, path))
    assert active_names(db) == set(names), "pregătirea testului nu a populat nimic"
    return db, path


# --- retragerea propriu-zisă ----------------------------------------------
def test_asset_removed_from_the_file_stops_being_probed(tmp_path):
    """Patru servicii dezinstalate rămâneau roșii pentru totdeauna pe panou.

    `probe_all`, pagina Servicii și `/status` de pe Telegram trec toate prin
    `assets_repo.list_all`. Dacă un activ scos din `inventory.yaml` rămâne
    acolo, sonda continuă să-l încerce, eșecul se înregistrează, iar operatorul
    citește un roșu care nu se poate stinge prin nimic din ce ar putea el face.
    """
    db, _ = populated(tmp_path)

    run(inventory.sync(db, write(tmp_path, ["sshd"])))

    assert active_names(db) == {"sshd"}


def test_retiring_keeps_the_row_and_its_id(tmp_path):
    """O ștergere ar lua constatările și panele activului, sau le-ar orfaniza.

    `findings`, `outages` și `availability_rollup` cad în cascadă; `incidents`
    și `scans` rămân cu `asset_id` NULL; `health_samples` n-are cheie străină și
    ar rămâne pur și simplu în urmă. Toate se leagă prin `id`, deci rândul
    trebuie să rămână, cu același `id`.
    """
    db, _ = populated(tmp_path)
    inainte = {r["name"]: r["id"] for r in db.rows}

    rezultat = run(inventory.sync(db, write(tmp_path, ["sshd"])))

    assert rezultat["retired"] == 3
    assert all_names(db) == {"n8n", "qdrant", "sshd", "webmin"}
    assert {r["name"]: r["id"] for r in db.rows} == inainte
    assert not any("DELETE" in s.upper() for s in db.statements), \
        "sincronizarea a emis un DELETE"
    retrase = {a.name: a.retired_at
               for a in run(assets_repo.list_all(db, include_retired=True))}
    assert retrase["sshd"] is None
    assert retrase["n8n"] == T0


def test_a_protected_asset_is_retired_like_any_other(tmp_path):
    """Altfel tocmai rândurile la care ține operatorul nu se pot stinge niciodată.

    `protected` înseamnă „niciun plan de patch automat nu-l atinge" — atât, și
    e aplicat în `patch/validator.py`. Dacă ar însemna în plus „rândul ăsta e
    permanent", un serviciu protejat scos de pe gazdă ar rămâne roșu pe panou
    pentru totdeauna, fără nicio cale de ieșire.
    """
    db = FakeDB()
    run(inventory.sync(db, write(tmp_path, ["sshd", "webmin"], protected=("webmin",))))
    assert any(r["name"] == "webmin" and r["protected"] for r in db.rows)

    run(inventory.sync(db, write(tmp_path, ["sshd"])))

    assert active_names(db) == {"sshd"}


# --- fișierul gol: testul care contează cel mai mult -----------------------
@pytest.mark.parametrize(
    "eticheta,continut",
    [
        ("fișier lipsă", None),
        ("fișier gol", ""),
        ("doar comentarii", "# nimic aici\n"),
        ("assets: listă goală", "assets: []\n"),
        ("assets: null", "assets:\n"),
        ("fără cheia assets", "allowlist: []\ndiscovered: []\n"),
    ],
)
def test_an_empty_inventory_retires_nothing(tmp_path, eticheta, continut):
    """Un fișier trunchiat ar stinge fiecare sondă de pe gazdă, în tăcere.

    `load` întoarce o listă goală pentru o instalare nouă — deliberat, e o stare
    validă — și exact aceeași listă goală pentru un fișier golit de o editare
    eșuată sau de un disc plin. Din `sync` cele două nu se pot deosebi. Dacă
    retragerea s-ar lua după listă, o gazdă cu paisprezece active ar rămâne cu
    zero, panoul ar arăta o pagină goală, iar o pagină goală arată identic cu
    „totul e în regulă".
    """
    db, _ = populated(tmp_path)
    if continut is None:
        gol = tmp_path / "lipsa.yaml"
        assert not gol.exists()
    else:
        gol = write(tmp_path, [], text=continut)

    rezultat = run(inventory.sync(db, gol))

    assert active_names(db) == {"n8n", "qdrant", "sshd", "webmin"}, eticheta
    assert rezultat["retired"] == 0
    # „N-am avut ce retrage" și „n-am putut ști ce să retrag" sunt fapte
    # diferite; un raport care le confundă e un raport care minte.
    assert rezultat["retire_skipped"] == 1, eticheta


def test_an_unparseable_inventory_retires_nothing(tmp_path):
    """Un YAML stricat nu are voie să treacă drept „inventarul e gol acum".

    `health_service` prinde excepția și continuă să sondeze ce are deja. Dacă
    `sync` ar înghiți eroarea și ar merge mai departe cu o listă goală, o
    greșeală de indentare ar opri monitorizarea gazdei.
    """
    db, _ = populated(tmp_path)
    stricat = tmp_path / "inventory.yaml"
    stricat.write_text("assets: [unu\n  - doi:\n", encoding="utf-8")

    with pytest.raises(Exception):
        run(inventory.sync(db, stricat))

    assert active_names(db) == {"n8n", "qdrant", "sshd", "webmin"}


def test_retire_missing_refuses_an_empty_keep_list():
    """Instrucțiunea care ar putea retrage tot își poartă singură paza.

    Paza din `sync` acoperă drumul de azi. Următorul apelant — o comandă de
    mână, un script de întreținere — n-o moștenește, iar `keep` gol înseamnă
    acolo „retrage fiecare activ de pe gazdă".
    """
    db = FakeDB()
    with pytest.raises(ValueError, match="empty keep list"):
        run(assets_repo.retire_missing(db, []))
    assert db.statements == [], "a ajuns totuși un UPDATE la bază"


# --- întoarcerea și idempotența -------------------------------------------
def test_a_retired_asset_returns_active_with_its_history(tmp_path):
    """Un activ scos din greșeală trebuie să se întoarcă, nu să înceapă de la zero.

    Dacă re-adăugarea l-ar lăsa retras, retragerea ar fi ireversibilă din
    fișier. Dacă ar face un rând NOU, incidentele și constatările lui ar rămâne
    agățate de vechiul `id`, adică de un rând pe care nu-l mai citește nimeni.
    """
    db, _ = populated(tmp_path)
    id_initial = {r["name"]: r["id"] for r in db.rows}["qdrant"]
    prima_vedere = {r["name"]: r["first_seen"] for r in db.rows}["qdrant"]

    run(inventory.sync(db, write(tmp_path, ["sshd"])))
    assert "qdrant" not in active_names(db)

    db.clock = T0 + timedelta(days=3)
    rezultat = run(inventory.sync(db, write(tmp_path, ["sshd", "qdrant"])))

    assert "qdrant" in active_names(db)
    assert rezultat["retired"] == 0
    revenit = next(r for r in db.rows if r["name"] == "qdrant")
    assert revenit["id"] == id_initial
    assert revenit["first_seen"] == prima_vedere
    assert revenit["retired_at"] is None


def test_sync_is_idempotent_and_does_not_move_retired_at(tmp_path):
    """„Retras de 18 zile" trebuie să rămână 18 zile, nu să devină mereu „acum".

    `sync` rulează la fiecare trecere a serviciului de sănătate. Dacă a doua
    trecere ar reretrage rândurile deja retrase, momentul retragerii s-ar muta
    la fiecare minut și n-ar mai putea răspunde la „de când".
    """
    db, _ = populated(tmp_path)
    ramase = write(tmp_path, ["sshd"])
    prima = run(inventory.sync(db, ramase))
    instantaneu = [dict(r) for r in db.rows]

    db.clock = T0 + timedelta(days=18)
    a_doua = run(inventory.sync(db, ramase))

    assert prima["retired"] == 3 and a_doua["retired"] == 0
    assert a_doua["retire_skipped"] == 0
    assert {r["name"]: r["retired_at"] for r in db.rows} == \
        {r["name"]: r["retired_at"] for r in instantaneu}
    assert active_names(db) == {"sshd"}


def test_list_all_hides_retired_from_every_consumer(tmp_path):
    """Sonda, pagina Servicii și `/status` citesc toate din aceeași interogare.

    Dacă filtrul ar fi opțional în loc de implicit, ar fi trei locuri în care
    să fie uitat, iar unul uitat înseamnă că activul retras rămâne numărat sau
    sondat. `include_retired=True` rămâne pentru istoric.
    """
    db, _ = populated(tmp_path)
    run(inventory.sync(db, write(tmp_path, ["sshd"])))

    implicit = run(assets_repo.list_all(db))
    cu_istoric = run(assets_repo.list_all(db, include_retired=True))

    assert [a.name for a in implicit] == ["sshd"]
    assert sorted(a.name for a in cu_istoric) == ["n8n", "qdrant", "sshd", "webmin"]
    assert {a.name for a in cu_istoric if a.retired_at is not None} == \
        {"n8n", "qdrant", "webmin"}
