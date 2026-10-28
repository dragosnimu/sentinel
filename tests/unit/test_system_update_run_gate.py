"""`_run` nu pornește nimic care nu e o interogare de citire — oricine l-ar chema.

Eșecul pe care fișierul ăsta îl previne: `/update` PROPUNE planuri, iar aplicarea trece prin două
atingeri, PIN și o semnătură făcută pe stația operatorului. `_run` e o funcție care pornește procese
ca utilizatorul `sentinel` (în grupul `docker`, deci root prin soclu). O gardă pe AST care verifică
ORTOGRAFIA apelanților (`_run(["rpm", "-q", ...])` într-un fișier) a fost ocolită în patru feluri
măsurate, toate cu suita verde: un alias (`_apply = _run`), un apel din alt modul, un apel din
`bot.py`, și un `sh -c '... dnf -y update ...'` adăugat ÎN interiorul lui `_run`. Niciuna nu
schimba un nume pe care garda îl citește. De aceea limita trăiește în `_run`, la execuție, și aici se
verifică ce face, nu cum arată codul care o cheamă.

Ce NU se poate verifica de aici: că `rpm` de pe o gazdă reală nu execută nimic cu flag-urile din
lista albă — asta s-a măsurat pe RPM 4.16 (doar `--eval` execută `%(...)`) și nu rulează în suită.
"""
from __future__ import annotations

import asyncio
import re
import sys

import pytest

from sentinel.patch import system_update as su
from tests.unit import _system_update_support as sup


def run(c):
    return asyncio.run(c)


class _Proc:
    def __init__(self, code: int, out: str, err: str) -> None:
        self.returncode = code
        self._out, self._err = out.encode(), err.encode()

    async def communicate(self):
        return self._out, self._err


class Spawns:
    """Ia locul lui `asyncio.create_subprocess_exec` și notează fiecare încercare de a porni ceva.
    Fără `host`, orice pornire pică cu `OSError` — dar chiar și așa rămâne în `calls`, deci un
    test care cere «nimic nu a pornit» vede pornirea, nu doar rezultatul ei."""

    def __init__(self, host: sup.FakeHost | None = None) -> None:
        self.host = host
        self.calls: list[tuple[tuple[str, ...], dict]] = []

    async def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.host is None:
            raise OSError("mock: niciun proces nu are voie să pornească aici")
        code, out, err = await self.host(list(args))
        return _Proc(code, out, err)


def _spawns(monkeypatch, host: sup.FakeHost | None = None) -> Spawns:
    spawns = Spawns(host)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawns)
    return spawns


class _LyingStr(str):
    """Un `str` care minte despre ce începe cu `-`: poarta nu are voie să se încreadă în metodele lui."""

    def startswith(self, *args, **kwargs):
        return False


class _List(list):
    """O subclasă de `list`: poarta și procesul ar putea vedea conținut diferit."""


#: Fiecare formă prin care o aplicare sau o scriere ar putea trece pe aici. Primele trei sunt
#: exemplele verificatorului; restul sunt flag-urile `rpm` care execută sau schimbă gazda.
REFUSED = {
    "dnf update": ["dnf", "-y", "update"],
    "sh wrapper": ["sh", "-c", "dnf -y update"],
    "rpm eval macro": ["rpm", "--eval", "%(dnf -y update)"],
    "rpm -q eval": ["rpm", "-q", "--eval", "%(echo X)"],
    "rpm -q -E": ["rpm", "-q", "-E", "%(echo X)"],
    "macro in qf": ["rpm", "-q", "--qf", "%(echo X)", "bash"],
    "lua in qf": ["rpm", "-q", "--qf", "%{lua:os.execute('x')}", "bash"],
    "lua spaced": ["rpm", "-q", "--qf", "%{ LUA : os.execute('x') }", "bash"],
    "macro in a name": ["rpm", "-q", "a%(id)"],
    "define": ["rpm", "-q", "--define", "x %(id)"],
    "define short": ["rpm", "-q", "-D", "x 1", "bash"],
    "macros file": ["rpm", "-q", "--macros", "/tmp/m", "bash"],
    "rcfile": ["rpm", "-q", "--rcfile", "/tmp/r", "bash"],
    "pipe": ["rpm", "-q", "--pipe", "sh", "bash"],
    "install": ["rpm", "-i", "x.rpm"],
    "erase": ["rpm", "-e", "kernel"],
    "cluster -qa": ["rpm", "-qa"],
    "flag with equals": ["rpm", "-q", "--qf=%{NAME}", "bash"],
    "mode not first": ["rpm", "--qf", "%{NAME}", "-q"],
    "mode missing": ["rpm"],
    "dpkg list files": ["dpkg-query", "-L", "bash"],
    "dpkg odd flag": ["dpkg-query", "-W", "-f", "x", "--eval"],
    "path to rpm": ["/tmp/rpm", "-q", "bash"],
    "empty": [],
    "string not list": "rpm -q bash",
    "tuple not list": ("rpm", "-q", "bash"),
    "non-string word": ["rpm", "-q", None],
    "bytes word": ["rpm", "-q", b"bash"],
    "str subclass lying about startswith": ["rpm", "-q", _LyingStr("--eval")],
    "list subclass": _List(["rpm", "-q", "bash"]),
}


@pytest.mark.parametrize("argv", list(REFUSED.values()), ids=list(REFUSED))
def test_run_refuses_anything_that_is_not_a_read_query_and_starts_nothing(monkeypatch, argv):
    """`_run(["dnf", "-y", "update"])` ar fi o aplicare fără nicio semnătură, făcută de contul care
    are soclul `docker`. Refuzul trebuie să vină ÎNAINTE de proces: `create_subprocess_exec`
    nemaichemat, nu un cod de ieșire. Un cod de eroare ar putea fi confundat cu «programul lipsește»
    (127), iar un proces deja pornit ar fi rulat comanda înainte să afle cineva că n-ar fi trebuit."""
    spawns = _spawns(monkeypatch)
    with pytest.raises(su.RefusedCommand):
        run(su._run(argv))
    assert spawns.calls == [], f"a pornit ceva: {spawns.calls}"


def test_the_refusal_check_can_see_a_start_when_there_is_one(monkeypatch):
    """Martorul pozitiv al testului de mai sus: `Spawns` înregistrează o pornire când `_run` chiar
    pornește ceva. Fără el, `calls == []` ar fi adevărat și cu un recorder stricat."""
    spawns = _spawns(monkeypatch, sup.FakeHost())
    code, _out, _err = run(su._run(["rpm", "-q", "--qf", su._RPM_QF, "bash"]))
    assert len(spawns.calls) == 1 and isinstance(code, int)


def test_the_refusal_is_not_an_exit_code_and_does_not_look_like_a_missing_program(monkeypatch):
    """127 înseamnă «binarul lipsește» și e starea unei gazde; refuzarea unui argv e o greșeală de
    programare. Dacă ar fi un cod, `read_host` ar raporta «nu pot citi starea pachetelor», adică ar
    pune pe seama gazdei un bug de cod. Nu moștenește nici excepțiile pe care `except`-urile de pe
    cale le transformă în mesaje de gazdă (`OSError`, `ValueError`, `LookupError`, `TimeoutError`)."""
    _spawns(monkeypatch)
    with pytest.raises(su.RefusedCommand) as info:
        run(su._run(["dnf", "-y", "update"]))
    assert "dnf" in str(info.value)
    assert not issubclass(su.RefusedCommand, (OSError, ValueError, LookupError, TimeoutError,
                                              asyncio.TimeoutError, KeyError))
    assert issubclass(su.RefusedCommand, Exception) and not issubclass(su.RefusedCommand, RuntimeError), \
        "trebuie prinsă de `except Exception`, nu de `BaseException` (un handler Telegram mort tace)"


def test_the_queries_the_module_really_makes_pass_through_unchanged_and_without_a_wrapper(monkeypatch):
    """Interogările de azi (`rpm -q --qf`, `rpm -q --whatprovides`, `dpkg-query -W -f`) trebuie să
    treacă de poartă ca atare. Și procesul trebuie să primească EXACT argv-ul verificat: un `sh -c`
    pus în interiorul lui `_run` (cu `dnf -y update` înăuntru) ar schimba `args[0]` și `args[:2]`,
    iar poarta de la intrare ar fi verificat un argv, iar gazda ar fi rulat altul."""
    spawns = _spawns(monkeypatch, sup.FakeHost())
    names = ["httpd", "openssh"]
    host = run(su.read_host("rhel", names))
    assert host.error is None and set(names) <= set(host.installed) and host.installonly
    want = [("rpm", "-q", "--qf", su._RPM_QF, *names),
            ("rpm", "-q", "--whatprovides", *su._INSTALLONLY_PROVIDES, "rpm", "--qf", "%{NAME}\\n")]
    assert [a for a, _ in spawns.calls] == want
    for _, kwargs in spawns.calls:
        assert set(kwargs) == {"stdout", "stderr", "env"}, kwargs

    spawns = _spawns(monkeypatch, sup.FakeHost(dpkg_out="openssl\t3.0.2-0\tamd64\topenssl\tii \n"))
    host = run(su.read_host("debian", ["openssl"]))
    assert host.error is None and "openssl" in host.installed
    assert [a for a, _ in spawns.calls] == [("dpkg-query", "-W", "-f", su._DPKG_QF, "openssl")]


def test_an_unlisted_flag_is_refused_until_the_gate_is_widened_on_purpose(monkeypatch):
    """Prețul unei liste albe, spus pe față: un flag de citire pe care azi nu-l folosește nimeni e
    refuzat până când lista îl numește (`--queryformat` e sinonimul lui `--qf` și e refuzat azi). Aici,
    cu un flag inventat, ca testul să nu devină fals în ziua în care `--queryformat` e adăugat cu
    adevărat. Lărgirea o face `widen_gate` (împachetează poarta, vizibil în test), iar martorul pozitiv
    arată că argv-ul era altfel în regulă: refuzul de la început era al flagului, nu al altui cuvânt."""
    spawns = _spawns(monkeypatch, sup.FakeHost())
    argv = ["rpm", "-q", "--flag-inventat-de-test", su._RPM_QF, "bash"]
    with pytest.raises(su.RefusedCommand):
        run(su._run(argv))
    assert spawns.calls == []
    sup.widen_gate(monkeypatch, flags={**su.READ_ONLY_FLAGS,
                                       "rpm": (*su.READ_ONLY_FLAGS["rpm"], "--flag-inventat-de-test")})
    run(su._run(argv))
    assert len(spawns.calls) == 1


def test_a_program_with_a_mode_and_no_flag_list_is_refused_not_a_key_error(monkeypatch):
    """Cineva adaugă un program în `READ_ONLY_MODE` și uită `READ_ONLY_FLAGS`. Garda din `tests/security/`
    o prinde în CI, dar poarta e și ultima linie la execuție: fără refuzul ei, `flags[prog]` dă `KeyError`,
    care în jurnal și în mesajul de pe Telegram arată ca un defect al lui `/update` («KeyError: 'xyz'»),
    nu ca ce este — două tabele care nu se potrivesc. Tot nu pornește nimic; diferența e excepția, care
    trebuie să fie `RefusedCommand` și să numească programul. Martorul pozitiv: cu lista de flag-uri
    adăugată, ACELAȘI argv pornește, deci refuzul vine din lipsa listei, nu din altceva."""
    spawns = _spawns(monkeypatch, sup.FakeHost())
    argv = ["program-de-control", "-q", "bash"]
    sup.widen_gate(monkeypatch, modes={**su.READ_ONLY_MODE, "program-de-control": "-q"})
    with pytest.raises(su.RefusedCommand) as info:
        run(su._run(argv))
    assert "program-de-control" in str(info.value)
    assert spawns.calls == [], f"a pornit ceva: {spawns.calls}"
    sup.widen_gate(monkeypatch, flags={**su.READ_ONLY_FLAGS, "program-de-control": ("-q",)})
    run(su._run(argv))
    assert [a for a, _ in spawns.calls] == [tuple(argv)]


_WIDE_FLAGS = {"rpm": ("-q", "--qf", "--whatprovides", "--flag-inventat"), "dpkg-query": ("-W", "-f")}

#: Fiecare formă prin care parametrii limitei se rescriau din ALT fișier cu o simplă atribuire pe
#: numele din modul (măsurat de verificator pe `e6e9768`: trei linii în `bot.py` lăsau garda pe AST la
#: 71 verzi, iar la execuție `rpm -q --flag-inventat bash` pornea). Fiecare caz: atribuirile care
#: ar lărgi poarta, argv-ul interzis pe care l-ar lăsa să treacă, și cum se lărgește poarta LEGITIM
#: (martorul pozitiv: argv-ul e bine format, deci refuzul vine doar din listă).
FROM_OUTSIDE = {
    "flag list replaced": (
        [("READ_ONLY_FLAGS", _WIDE_FLAGS)],
        ["rpm", "-q", "--flag-inventat", "bash"], dict(flags=_WIDE_FLAGS)),
    "program and mode added": (
        [("READ_ONLY_MODE", {"rpm": "-q", "dpkg-query": "-W", "dnf": "-y"}),
         ("READ_ONLY_FLAGS", {**_WIDE_FLAGS, "dnf": ("-y",)})],
        ["dnf", "-y", "update"], dict(modes={"rpm": "-q", "dnf": "-y"}, flags={"dnf": ("-y",)})),
    "macro pattern disabled": (
        [("_MACRO_EXEC", re.compile(r"(?!)"))],
        ["rpm", "-q", "--qf", "%(echo X)", "bash"], dict(macro_exec=re.compile(r"(?!)"))),
}


@pytest.mark.parametrize("label", list(FROM_OUTSIDE))
def test_assigning_to_the_module_names_from_outside_does_not_change_what_the_gate_refuses(monkeypatch, label):
    """Operatorul nu vede un `system_update.READ_ONLY_FLAGS = {...}` pus în `bot.py` sau în `patch_flow`:
    garda pe AST citea atribuirea LITERALĂ din `system_update.py`, nu starea de la rulare, iar poarta
    citea globalele modulului la fiecare apel. Rezultatul: `rpm -q --flag-inventat bash` (sau
    `dnf -y update`) pornea ca utilizatorul `sentinel`, din grupul `docker`, cu suita verde. Poarta
    își leagă acum lista la definire: atribuirea ia efect pe NUME (verificat mai jos, ca testul să
    nu treacă pe gol) și nu schimbă nimic din ce se refuză."""
    assignments, argv, widen = FROM_OUTSIDE[label]
    spawns = _spawns(monkeypatch)
    for name, value in assignments:
        monkeypatch.setattr(su, name, value)
        assert getattr(su, name) is value, "atribuirea n-a ajuns pe modul: testul nu probează nimic"
    with pytest.raises(su.RefusedCommand):
        run(su._run(argv))
    assert spawns.calls == [], f"a pornit ceva după o atribuire din afară: {spawns.calls}"
    # martorul pozitiv: același argv trece când poarta e lărgită pe calea vizibilă a testelor
    sup.widen_gate(monkeypatch, **widen)
    run(su._run(argv))
    assert len(spawns.calls) == 1


def test_a_provides_list_rewritten_from_outside_is_still_stopped_by_the_gate(monkeypatch):
    """`_INSTALLONLY_PROVIDES` e citită de `read_host` când construiește argv-ul; un fișier care o
    înlocuiește cu un flag, împreună cu lista de flag-uri, făcea ca `rpm -q --whatprovides` să primească
    un cuvânt pe care nu l-a aprobat nimeni. Primul argv (numele pachetelor) e legitim și pornește;
    al doilea trebuie să ridice `RefusedCommand`, iar flagul inventat să nu ajungă la niciun proces."""
    spawns = _spawns(monkeypatch, sup.FakeHost())
    monkeypatch.setattr(su, "_INSTALLONLY_PROVIDES", ("--flag-inventat", "installonlypkg(kernel)"))
    monkeypatch.setattr(su, "READ_ONLY_FLAGS", _WIDE_FLAGS)
    with pytest.raises(su.RefusedCommand):
        run(su.read_host("rhel", ["httpd"]))
    started = [a for a, _ in spawns.calls]
    assert len(started) == 1 and "--whatprovides" not in started[0], started
    assert all("--flag-inventat" not in a for a in started), started


def test_the_listed_constants_cannot_be_edited_in_place():
    """`system_update.READ_ONLY_MODE["dnf"] = "-y"` e o linie, iar un dicționar legat la definire ca
    parametru implicit ar fi rămas mutabil prin numele lui. Vederile nu se pot scrie, iar valorile din
    `READ_ONLY_FLAGS` sunt tuple: nicio formă de editare pe loc nu lărgește poarta."""
    def item_assign():
        su.READ_ONLY_MODE["dnf"] = "-y"

    def flags_item_assign():
        su.READ_ONLY_FLAGS["dnf"] = ("-y",)

    def flags_augment():
        su.READ_ONLY_FLAGS["rpm"] += ("--eval",)

    def flags_update():
        su.READ_ONLY_FLAGS.update({"dnf": ("-y",)})

    def mode_pop():
        su.READ_ONLY_MODE.pop("rpm")

    def rpm_tuple_append():
        su.READ_ONLY_FLAGS["rpm"].append("--eval")

    for attempt in (item_assign, flags_item_assign, flags_augment, flags_update, mode_pop, rpm_tuple_append):
        with pytest.raises((TypeError, AttributeError)):
            attempt()
    assert "dnf" not in su.READ_ONLY_MODE and "--eval" not in su.READ_ONLY_FLAGS["rpm"]


def test_a_refusal_inside_read_host_is_raised_not_turned_into_a_host_error(monkeypatch):
    """Dacă formatul `--qf` ar deveni o macro care rulează cod, `read_host` n-are voie să întoarcă
    `HostRead(error="rpm a ieșit cu 127")` — operatorul ar căuta o problemă pe gazdă. Ridică, iar
    cele trei `except Exception` de pe cale (`select` în `/update`, `select` în privirea de
    ansamblu, `reconcile` după rulare) o pun în mesaj cu numele tipului."""
    spawns = _spawns(monkeypatch)
    monkeypatch.setattr(su, "_RPM_QF", "%(echo X)")
    with pytest.raises(su.RefusedCommand):
        run(su.read_host("rhel", ["bash"]))
    with pytest.raises(su.RefusedCommand):
        run(su.select(sup.FakeDB(), sup.cfg()))
    plan = {"update": {"packages": [{"name": "httpd", "before": "1-1", "target": "1-2"}]}}
    with pytest.raises(su.RefusedCommand):
        run(su.reconcile(plan, "rhel"))
    assert spawns.calls == []


def test_the_machinery_tests_may_start_python_only_after_widening_the_list_on_purpose(monkeypatch):
    """Testele din `test_system_update_edges` care pornesc procese de-adevăratelea (cod de ieșire,
    127, timeout) rulează `sys.executable`. Fără lărgirea explicită a listei (`sup.allow_own_programs`),
    interpretorul e refuzat ca orice alt program; cu ea, trece — deci lărgirea e vizibilă în test, nu
    o ușă lăsată deschisă în cod."""
    spawns = _spawns(monkeypatch)
    with pytest.raises(su.RefusedCommand):
        run(su._run([sys.executable, "-c", "print('x')"]))
    assert spawns.calls == []
    sup.allow_own_programs(monkeypatch)
    code, _out, _err = run(su._run([sys.executable, "-c", "print('x')"]))
    assert code == 127 and len(spawns.calls) == 1   # `Spawns` fără gazdă dă OSError: a ajuns la pornire
