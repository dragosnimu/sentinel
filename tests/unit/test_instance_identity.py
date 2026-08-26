"""Identitatea instalării: cine e serverul ăsta, și ce se strică dacă nu se știe.

Un panou extern care adună mai multe instalări le deosebește după o singură
valoare. Toate eșecurile de mai jos au aceeași formă și niciunul nu ridică vreo
excepție undeva: două servere care raportează aceeași identitate se contopesc
într-o istorie, un server care raportează două se rupe în două jumătăți, iar un
server care nu-și poate citi identitatea aterizează într-o găleată comună cu
toate celelalte care nu și-o pot citi.

Fișierul `/etc/sentinel/instance_id` e autoritatea; rândul din
`instance_identity` e oglinda. Nepotrivirea dintre ele e constatarea — simptomul
unui backup restaurat pe o mașină clonată.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.config import Config
from sentinel.db import identity_mirror
from sentinel.errors import SentinelError
from sentinel.identity import IdentityError, read_instance_id
from sentinel.selfcheck import checks

ID_A = "0123456789abcdef0123456789abcdef"
ID_B = "fedcba9876543210fedcba9876543210"
WHEN = datetime(2026, 8, 12, 9, 0, tzinfo=timezone.utc)


def run(c):
    return asyncio.run(c)


class _DB:
    """Doar `fetchrow`, fiindcă doar asta cere verificarea.

    Interogările se deosebesc după TABELĂ, nu se răspunde la fel la orice: cu un
    singur răspuns pentru toate, rândul oglinzii ar fi întors și ca urmă a
    scriitorului, iar testul ar trece peste o verificare care confundă exact
    cele două lucruri pe care e scrisă să le deosebească.

    `boom`/`marker_boom` ridică, ca ramurile „nu pot citi" să fie exercitate.
    """

    def __init__(self, row=None, boom: Exception | None = None,
                 marker=None, marker_boom: Exception | None = None):
        self._row, self._boom = row, boom
        self._marker, self._marker_boom = marker, marker_boom

    async def fetchrow(self, sql, *a):
        if "collector_cursors" in sql:
            if self._marker_boom is not None:
                raise self._marker_boom
            return self._marker
        if self._boom is not None:
            raise self._boom
        return self._row


def _write(tmp_path: Path, content: str) -> Path:
    target = tmp_path / "instance_id"
    target.write_text(content, encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# Cititorul
# ---------------------------------------------------------------------------
def test_a_well_formed_file_is_read_verbatim(tmp_path):
    """Cazul normal. Dacă se strică, tot restul fișierului ăstuia e teatru."""
    assert read_instance_id(_write(tmp_path, ID_A + "\n")) == ID_A


def test_a_missing_file_raises_instead_of_returning_nothing(tmp_path):
    """Un „" întors în loc de eroare nu e o identitate absentă, e una
    plauzibilă: fiecare gazdă care nu-și poate citi fișierul ar raporta sub
    aceeași identitate goală, adică exact eșecul de identitate duplicată, atins
    din cealaltă parte."""
    with pytest.raises(IdentityError) as exc:
        read_instance_id(tmp_path / "nu-exista")
    # Mesajul trebuie să spună ce se face, nu doar ce lipsește — și trebuie să
    # spună ce e adevărat ACUM. Până la E1.4 identitatea se scria în pasul 27 și
    # mesajul trimitea la `--force-step 27`; apelul e de atunci necondiționat în
    # install.sh, deci orice deploy creează fișierul, iar pasul 27 pe deasupra
    # rescrie secrets.env dintr-un stdin pe care nimeni nu l-a cerut. Sfatul
    # vechi ar fi funcționat din întâmplare și ar fi contrazis docs/OPERARE.md
    # §12 — o unealtă care își contrazice manualul e la fel de inutilizabilă ca
    # doi cititori ai aceluiași fișier care nu sunt de acord, adică exact ce
    # argumentează o pagină din sentinel/identity.py.
    assert "./scripts/deploy.sh" in str(exc.value)
    assert "--force-step 27" not in str(exc.value)


def test_a_truncated_write_is_refused(tmp_path):
    """Un disc plin lasă în urmă o valoare scurtă. Două identități trunchiate se
    pot ciocni între ele, iar o ciocnire nu se raportează nicăieri — deci forma
    se verifică, nu se presupune."""
    with pytest.raises(IdentityError):
        read_instance_id(_write(tmp_path, ID_A[:12]))


def test_an_empty_file_is_refused(tmp_path):
    with pytest.raises(IdentityError):
        read_instance_id(_write(tmp_path, "\n"))


def test_the_content_of_a_malformed_file_is_never_echoed(tmp_path):
    """Mesajul ajunge pe Telegram și în jurnal. Un fișier de altă formă e un
    fișier al cărui conținut nu l-a garantat nimeni — poate fi un secret lipit
    din greșeală acolo. Se spune lungimea, nu valoarea."""
    # Nu ceva în formă de cheie: `tests/security/test_repo_is_sanitised.py`
    # caută în tot arborele șiruri în formă de secret, iar o fixtură care
    # seamănă cu o cheie e exact la fel de mult o problemă ca una adevărată —
    # nimeni care triază constatarea aia nu poate spune din grep care e care.
    junk = "aici-a-lipit-cineva-altceva-din-gresala"
    with pytest.raises(IdentityError) as exc:
        read_instance_id(_write(tmp_path, junk))
    assert junk not in str(exc.value)
    assert str(len(junk)) in str(exc.value)


def test_binary_content_is_an_error_not_a_crash(tmp_path):
    """`read_text` pe octeți nevalizi ridică `UnicodeDecodeError`, care NU e
    `OSError`. Neprins, ar ieși din verificare ca excepție nespecificată, grupul
    s-ar marca eșuat și rularea ar deveni incompletă — adică o rulare care nu
    mai curăță nicio constatare veche, din cauza unui fișier stricat."""
    target = tmp_path / "instance_id"
    target.write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(IdentityError):
        read_instance_id(target)


@pytest.mark.skipif(os.name == "nt", reason="modurile POSIX nu se aplică pe Windows")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root citește orice, deci proba nu ar dovedi nimic")
def test_an_unreadable_file_is_an_error_not_an_empty_id(tmp_path):
    """Fișierul e 0640 root:sentinel. Un proces care nu e în grupul `sentinel`
    nu citește nimic — și „n-am voie să mă uit" nu are voie să arate ca „nu
    există identitate"."""
    target = _write(tmp_path, ID_A)
    target.chmod(0o000)
    try:
        with pytest.raises(IdentityError):
            read_instance_id(target)
    finally:
        target.chmod(0o600)


def test_an_uppercase_id_is_refused(tmp_path):
    """PostgreSQL respinge majusculele; cititorul nu are voie să le accepte.

    Măsurat pe gazdă, PostgreSQL 16.14, cu CHECK-ul din 0022:

            label      | sql_accepts
        ---------------+-------------
         good-32-lower | t
         uppercase     | f

    Dacă aici s-ar strecura un `re.I` — sau un `.lower()` pe valoarea citită —
    scriitorul oglinzii din E1.4 ar citi o identitate cu majuscule, `INSERT` ar
    cădea pe constrângere, rândul nu ar apărea niciodată, iar
    `check_instance_identity` ar raporta „oglinda nu e scrisă încă" pentru
    totdeauna. Nimic nu se aprinde roșu; serverul pur și simplu nu ajunge în
    panou.
    """
    with pytest.raises(IdentityError):
        read_instance_id(_write(tmp_path, ID_A.upper()))


def test_the_pattern_is_anchored_the_way_postgres_anchors():
    """`$` nu înseamnă același lucru în cele două motoare.

    În PostgreSQL `$` e SFÂRȘITUL ȘIRULUI. În Python, `$` se potrivește și chiar
    înaintea unui `\\n` final, deci `re.match(r"^[0-9a-f]{32}$", "…\\n")`
    reușește pe o valoare pe care `INSERT` o refuză. Tăierea marginilor ascunde
    asta azi — și exact de-asta merită prins aici: dacă tăierea se schimbă
    vreodată, potrivirea trebuie să rămână cea a bazei de date.
    """
    import ast

    from sentinel.identity import _INSTANCE_ID_RE

    trailing = ID_A + "\n"
    assert _INSTANCE_ID_RE.match(trailing) is not None, \
        "presupunerea din care pornește testul nu mai e adevărată"
    assert _INSTANCE_ID_RE.fullmatch(trailing) is None
    assert _INSTANCE_ID_RE.fullmatch(ID_A) is not None

    # Și locul de apel — aserțiune pe COD, dinadins, cu motivul scris aici ca
    # să nu fie luată drept lene.
    #
    # Azi niciun conținut de fișier nu poate deosebi `match` de `fullmatch`:
    # tăierea marginilor scoate singurul `\n` final care le-ar despărți, deci nu
    # există intrare care să facă un test de comportament să pice. Alegerea
    # rămâne totuși încărcată — e singurul lucru care ține potrivirea din Python
    # egală cu cea a bazei de date dacă tăierea se schimbă vreodată — iar o
    # decizie fără nicio gardă e o decizie care se pierde la prima refactorizare.
    source = Path(sys.modules["sentinel.identity"].__file__).read_text(encoding="utf-8")
    used = {
        node.func.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "_INSTANCE_ID_RE"
    }
    assert used == {"fullmatch"}, \
        f"tiparul se aplică prin {used or 'nimic'}; `match` acceptă „…\\n" \
        f"\" pe care PostgreSQL îl respinge"


def test_only_ascii_whitespace_is_trimmed(tmp_path):
    """`str.strip()` fără argument taie și NBSP; `[[:space:]]` din bash nu.

    Divergența nu strică nimic în tăcere, dar produce ceva la fel de coroziv: un
    fișier pe care instalatorul îl refuză zgomotos la fiecare rulare și pe care
    agentul îl citește fără să clipească. Operatorul nu are cum să afle care
    dintre cele două are dreptate, iar avertismentul care nu se stinge e cel pe
    care îl ignoră data viitoare.
    """
    assert read_instance_id(_write(tmp_path, "  " + ID_A + "\t\r\n")) == ID_A
    with pytest.raises(IdentityError):
        read_instance_id(_write(tmp_path, "\xa0" + ID_A + "\xa0"))


def test_the_error_is_a_sentinel_error():
    """Ca un apelant care prinde `SentinelError` (beaconul, în E1.4) să nu
    trebuiască să știe de tipul ăsta anume ca să nu cadă."""
    assert issubclass(IdentityError, SentinelError)


# ---------------------------------------------------------------------------
# Verificarea
# ---------------------------------------------------------------------------
def _point_at(monkeypatch, path: Path) -> None:
    """Se repointează constanta modulului, nu funcția.

    Dacă s-ar înlocui `checks.read_instance_id` cu o funcție de test, testele de
    mai jos ar trece și peste un cititor complet stricat — aserțiune pe un dublu,
    nu pe cod livrat.
    """
    import sentinel.identity as identity

    monkeypatch.setattr(identity, "INSTANCE_ID_PATH", path)


def test_agreement_is_ok(monkeypatch, tmp_path):
    """Cazul verde, ca restul să însemne ceva."""
    _point_at(monkeypatch, _write(tmp_path, ID_A))
    results = run(checks.check_instance_identity(
        _DB(row={"instance_id": ID_A, "first_seen": WHEN})))
    assert [r.key for r in results] == ["identity:instance"]
    assert results[0].status == "ok"
    assert results[0].facts["mirrored"] is True


def test_a_mismatch_is_the_finding(monkeypatch, tmp_path):
    """Constatarea pentru care există tot fișierul ăsta.

    Un backup al bazei luat pe serverul A, restaurat pe o clonă a lui B: baza
    poartă identitatea lui A, fișierul o poartă pe a lui B. Fără comparație,
    cele două servere își amestecă istoriile într-un panou comun și nimic nu
    raportează o defecțiune — cifrele doar încetează să însemne ce spun.
    """
    _point_at(monkeypatch, _write(tmp_path, ID_B))
    results = run(checks.check_instance_identity(
        _DB(row={"instance_id": ID_A, "first_seen": WHEN})))
    assert len(results) == 1
    assert results[0].bad, "nepotrivirea nu ajunge la operator"
    assert results[0].facts == {"file": ID_B, "db": ID_A}


def test_a_mismatch_is_not_reported_as_total_failure(monkeypatch, tmp_path):
    """`down` produce „🔴 SENTINEL NU FUNCȚIONEAZĂ COMPLET".

    Pe gazda asta nu s-a oprit nimic: se colectează, se detectează, se blochează.
    Titlul ăla trebuie să însemne un singur lucru — nu se mai uită nimeni la
    server — iar folosit pentru altceva îl golește de sens exact când contează.
    """
    _point_at(monkeypatch, _write(tmp_path, ID_B))
    results = run(checks.check_instance_identity(
        _DB(row={"instance_id": ID_A, "first_seen": WHEN})))
    assert results[0].status == "degraded"


def test_an_unreadable_file_is_unknown_and_never_ok(monkeypatch, tmp_path):
    """„Nu se știe" și „e bine" sunt stări diferite.

    Fără fișier nu există comparație, deci verificarea nu s-a uitat. Un `ok`
    aici ar declara identitatea sănătoasă fără s-o fi văzut niciodată — un
    instrument de monitorizare care minte în felul cel mai comod.
    """
    _point_at(monkeypatch, tmp_path / "nu-exista")
    results = run(checks.check_instance_identity(
        _DB(row={"instance_id": ID_A, "first_seen": WHEN})))
    assert results[0].status == "unknown"
    assert not results[0].bad


def test_the_check_and_its_manual_prescribe_the_same_cure(monkeypatch, tmp_path):
    """Verificarea tipărește o comandă; `docs/OPERARE.md §12` descrie același
    simptom. Dacă cele două nu spun același lucru, operatorul nu are cum să afle
    care are dreptate — și pe drumul greșit plătește o rescriere a lui
    `secrets.env` și o citire de stdin pentru nimic.

    Cele două cauze cer tratamente DIFERITE, deci acțiunea trebuie să le
    numească pe amândouă: fișierul lipsă îl creează orice deploy, iar unul care
    există dar nu e o identitate nu se rescrie de nimeni, dinadins.
    """
    _point_at(monkeypatch, tmp_path / "nu-exista")
    action = run(checks.check_instance_identity(_DB(row=None)))[0].action

    assert "./scripts/deploy.sh" in action
    assert "--force-step 27" not in action, \
        "verificarea trimite la un pas care nu mai e cel care scrie identitatea"
    assert "od -c" in action, "cazul fișierului corupt nu are tratament"

    manual = (Path(__file__).resolve().parents[2] / "docs" / "OPERARE.md"
              ).read_text(encoding="utf-8")
    section = manual.split("## 12. Identitatea instalării", 1)
    assert len(section) == 2, "secțiunea §12 a dispărut din OPERARE.md"
    assert "un deploy obișnuit îl creează" in section[1]


def test_an_unreadable_file_still_emits_its_key(monkeypatch, tmp_path):
    """Runner-ul reconciliază `selfcheck_state` după cheile pe care rularea le-a
    emis: o cheie lipsă e tratată ca o constatare retrasă și rândul se șterge.

    Deci o ieșire tăcută aici ar șterge o nepotrivire adevărată și nereparată,
    iar operatorului i s-ar spune că nu se mai raportează — exact pana de 26 de
    ore din 0021, cu semnul schimbat.
    """
    _point_at(monkeypatch, tmp_path / "nu-exista")
    results = run(checks.check_instance_identity(_DB(row=None)))
    assert [r.key for r in results] == ["identity:instance"]


def test_a_missing_mirror_table_is_unknown_not_a_crashed_group(monkeypatch, tmp_path):
    """Cod nou, migrații neaplicate: `instance_identity` nu există încă.

    Lăsată să iasă, excepția marchează grupul ca eșuat, rularea devine
    incompletă și NIMIC nu se mai reconciliază în runda aia — o migrație
    neaplicată ar îngheța toată curățarea de stare, nu doar verificarea asta.
    """
    _point_at(monkeypatch, _write(tmp_path, ID_A))
    results = run(checks.check_instance_identity(
        _DB(boom=RuntimeError('relation "instance_identity" does not exist'))))
    assert [r.key for r in results] == ["identity:instance"]
    assert results[0].status == "unknown"
    assert not results[0].bad


def test_a_fresh_install_without_a_mirror_row_is_not_a_fault(monkeypatch, tmp_path):
    """Fișierul există și e valid, oglinda nu s-a scris încă.

    E starea normală a unei instalări noi. `down` ar suna alarma pe fiecare
    server nou; `unknown` ar ține titlul lui /selfcheck permanent pe „nu tot s-a
    putut verifica", iar un avertisment care nu se stinge niciodată e unul pe
    care nimeni nu-l mai citește când chiar apare. Verificarea s-a uitat la
    ambele capete și afirmația ei — cele două nu se contrazic — e adevărată.
    """
    _point_at(monkeypatch, _write(tmp_path, ID_A))
    results = run(checks.check_instance_identity(_DB(row=None)))
    assert results[0].status == "ok"
    assert not results[0].bad
    assert results[0].facts["mirrored"] is False
    # Și se spune, ca „ok" să nu fie confundat cu „oglinda e verificată".
    assert "nu e scrisă încă" in results[0].detail


def test_a_broken_mirror_writer_is_not_reported_as_a_fresh_install(monkeypatch, tmp_path):
    """Aceeași absență, două înțelesuri — și numai unul e în regulă.

    De când scriitorul există (`sentinel migrate`), „rândul lipsește" înseamnă
    ori „scriitorul n-a rulat încă", ori „a rulat și n-a reușit". Raportate
    amândouă `ok`, al doilea caz e tăcut pentru totdeauna: oglinda nu se mai
    scrie niciodată, iar nepotrivirea pe care ea o păzește — o bază restaurată
    pe o mașină clonată — nu mai poate fi observată de nimeni. Verificarea ar
    afișa verde peste un mecanism care nu mai există.
    """
    _point_at(monkeypatch, _write(tmp_path, ID_A))
    results = run(checks.check_instance_identity(
        _DB(row=None, marker={"cursor": "failed", "updated_at": WHEN})))
    assert results[0].bad, "un scriitor stricat trece drept instalare proaspătă"
    assert results[0].facts["writer_ran"] is True
    assert results[0].facts["outcome"] == "failed"
    # Rezultatul înregistrat ajunge în text: fără el, operatorul vede „nu s-a
    # scris" și nu are de unde ști dacă e vina fișierului, a tabelei sau a
    # drepturilor.
    assert "failed" in results[0].detail


def test_a_mirror_that_was_never_attempted_is_not_a_fault(monkeypatch, tmp_path):
    """Fereastra dintre copierea codului și `sentinel migrate`.

    E starea normală a fiecărei instalări în primele secunde. `degraded` aici ar
    suna o alarmă la fiecare instalare nouă, iar o alarmă care apare de fiecare
    dată e una pe care operatorul o filtrează — inclusiv în ziua în care e
    adevărată.
    """
    _point_at(monkeypatch, _write(tmp_path, ID_A))
    results = run(checks.check_instance_identity(_DB(row=None, marker=None)))
    assert results[0].status == "ok"
    assert not results[0].bad
    assert results[0].facts == {"mirrored": False, "writer_ran": False}


def test_an_unreadable_writer_trace_is_unknown_not_ok(monkeypatch, tmp_path):
    """Fără urmă, cele două înțelesuri de mai sus nu se pot despărți.

    A ghici ar însemna să alegem între o alarmă falsă permanentă și o tăcere
    falsă permanentă. „Nu știu" e a treia stare și e singura adevărată.
    """
    _point_at(monkeypatch, _write(tmp_path, ID_A))
    results = run(checks.check_instance_identity(
        _DB(row=None, marker_boom=RuntimeError('relation "collector_cursors" does not exist'))))
    assert [r.key for r in results] == ["identity:instance"]
    assert results[0].status == "unknown"
    assert not results[0].bad


def test_the_writer_trace_is_read_under_the_name_the_writer_writes(monkeypatch, tmp_path):
    """Numele urmei e un contract între două fișiere.

    Scris cu o literă în plus într-unul dintre ele, verificarea nu găsește
    niciodată urma, orice scriitor perfect funcțional arată ca „n-a rulat
    niciodată", și ramura de defect devine cod mort — clasa de bug pentru care
    există jumătate din comentariile din depozitul ăsta.
    """
    seen: list = []

    class _Spy(_DB):
        async def fetchrow(self, sql, *a):
            if "collector_cursors" in sql:
                seen.append(a)
            return await super().fetchrow(sql, *a)

    _point_at(monkeypatch, _write(tmp_path, ID_A))
    run(checks.check_instance_identity(_Spy(row=None, marker=None)))
    assert seen == [(identity_mirror.MIRROR_MARKER,)], seen


def test_the_check_never_falls_silent(monkeypatch, tmp_path):
    """Fiecare cale posibilă emite exact o cheie.

    Regula din docstring-ul lui `checks.py`: „n-am emis cheia asta" înseamnă
    „verificarea a privit și n-a avut ce raporta", niciodată „n-a putut privi".
    """
    good = tmp_path / "bun"
    good.mkdir()
    junk = tmp_path / "gunoi"
    junk.mkdir()

    cases = [
        (tmp_path / "lipsa", _DB(row=None)),
        (_write(junk, "nu-e-o-identitate"), _DB(row=None)),
        (_write(good, ID_A), _DB(row={"instance_id": ID_B, "first_seen": WHEN})),
        (_write(good, ID_A), _DB(row={"instance_id": ID_A, "first_seen": WHEN})),
        (_write(good, ID_A), _DB(boom=RuntimeError("nope"))),
        (_write(good, ID_A), _DB(row=None, marker={"cursor": "failed", "updated_at": WHEN})),
        (_write(good, ID_A), _DB(row=None, marker_boom=RuntimeError("nope"))),
    ]
    assert len(cases) == 7, "lista de cazuri s-a golit — un test parametrizat gol trece"
    for path, db in cases:
        _point_at(monkeypatch, path)
        results = run(checks.check_instance_identity(db))
        assert [r.key for r in results] == ["identity:instance"], path


def test_the_check_is_wired_into_the_run():
    """O verificare scrisă și neînregistrată nu rulează niciodată, iar tăcerea ei
    arată identic cu „nimic în neregulă"."""
    assert ("identity", checks.check_instance_identity) in checks.CHECKS


def test_the_check_asks_only_for_what_the_runner_can_give():
    """`run_groups` injectează argumente după NUME (`db`, `cfg`). Un parametru
    numit altfel nu se completează, apelul cade cu TypeError, iar grupul se
    raportează stricat la fiecare rulare."""
    fn = checks.check_instance_identity
    names = fn.__code__.co_varnames[:fn.__code__.co_argcount]
    assert set(names) <= {"db", "cfg"}, names


# ---------------------------------------------------------------------------
# Eticheta cosmetică
# ---------------------------------------------------------------------------
def test_instance_label_exists_and_defaults_to_empty():
    """Adăugată în șablon fără să existe pe dataclass, `_build` ridică
    `ConfigError` la pornire și fiecare serviciu refuză să pornească — o linie
    de configurație care oprește tot agentul."""
    assert Config().instance_label == ""


def test_the_identity_never_falls_back_to_configuration():
    """Cosmetic înseamnă cosmetic.

    Dacă identitatea ar putea veni vreodată dintr-o valoare din `sentinel.yaml`,
    oricine poate edita fișierul ăla poate muta un server în istoria altuia —
    fix eșecul pe care valoarea aleatoare îl evită. Garda e cuplarea: modulul de
    identitate nu are voie să știe de configurație deloc, fiindcă asta e tot ce
    i-ar trebui ca să ia eticheta drept identificator.
    """
    import ast

    import sentinel.identity as identity

    source = Path(sys.modules["sentinel.identity"].__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    # Importurile din AST, nu un `in` peste text: comentariile modulului chiar
    # vorbesc despre `sentinel.config`, și un test care pică pe o explicație e
    # un test care se șterge.
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    assert "sentinel.config" not in imported, imported

    body = source.split('"""', 2)[-1]
    assert "instance_label" not in body
    assert not hasattr(identity, "get_config")
