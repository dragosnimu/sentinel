"""Marginile planificatorului de update: ce se întâmplă când datele nu sunt cele obișnuite.

Aceeași regulă ca în `test_system_update_plan`: fiecare test spune în docstring ce se strică
pentru operator. Dubla de gazdă și de bază e cea din `_system_update_support`.
"""
from __future__ import annotations

import asyncio
import sys

import pytest

from sentinel.patch import system_update as su
from tests.unit import _system_update_support as sup


def run(c):
    return asyncio.run(c)


def _row(i, package, fixed="2-1.el9", **over):
    row = dict(id=i, package=package, cve=None, severity="high", kev=False, priority=50,
               fixed_version=fixed, ecosystem="rpm", asset_id=None, asset_name=None,
               asset_protected=False, fix_pending_reboot=False)
    row.update(over)
    return row


def _select(monkeypatch, rows, rpm_lines, *, host=None, family="rhel"):
    host = host or sup.FakeHost("\n".join(rpm_lines) + "\n")
    sup.install(monkeypatch, host)
    return run(su.select(sup.FakeDB(rows), sup.cfg(family)))


def _planned(sel):
    return [[p.name for p in lot.packages] for lot in sel.lots]


def _held(sel):
    return {n: h for h in sel.held for n in h.packages}


# ---------------------------------------------------------------------------
# Ordinea și lotizarea
# ---------------------------------------------------------------------------
def test_an_invalid_group_does_not_split_the_valid_ones_around_it(monkeypatch):
    """Un grup pe care validatorul îl respinge (un nume cu `nft`) stă între două grupuri bune. Dacă
    ar fi tratat doar la sfârșit, împachetarea l-ar lua drept sfârșit de lot și cele două bune ar
    ajunge în loturi separate — adică o ceremonie de semnare în plus pe stația operatorului."""
    rows = [_row(1, "aaa", priority=99), _row(2, "nftables", priority=70), _row(3, "zzz", priority=50)]
    rpm = [sup.rpm_line("aaa", "1-1.el9"), sup.rpm_line("nftables", "1-1.el9"), sup.rpm_line("zzz", "1-1.el9")]
    sel = _select(monkeypatch, rows, rpm)
    assert _planned(sel) == [["aaa", "zzz"]], _planned(sel)
    assert _held(sel)["nftables"].code == "validator"


def test_exploited_vulnerabilities_come_first(monkeypatch):
    """Un KEV (exploatat activ) nu așteaptă în lotul doi după pachete cu prioritate mai mare dar
    neexploatate. Lotul pe care operatorul îl vede primul trebuie să-l conțină."""
    rows = [_row(i, f"p{i:02d}-extra", priority=90) for i in range(30)]
    rows.append(_row(99, "zz-exploited", kev=True, priority=1))
    rpm = [sup.rpm_line(r["package"], "1-1.el9") for r in rows]
    sel = _select(monkeypatch, rows, rpm)
    assert len(sel.lots) > 1
    assert "zz-exploited" in _planned(sel)[0]


# ---------------------------------------------------------------------------
# Motivele de reținere pe care le dă fiecare ramură
# ---------------------------------------------------------------------------
def test_a_protected_asset_is_never_planned(monkeypatch):
    """Un asset marcat protejat nu primește niciun plan automat: validatorul îl respinge oricum
    (`protected_asset`), dar un plan construit și apoi respins ar irosi o ceremonie."""
    rows = [_row(1, "locked", asset_id=3, asset_name="web", asset_protected=True), _row(2, "free")]
    sel = _select(monkeypatch, rows, [sup.rpm_line("locked", "1-1.el9"), sup.rpm_line("free", "1-1.el9")])
    assert _held(sel)["locked"].code == "protected_asset"
    assert _planned(sel) == [["free"]]


def test_two_installed_versions_of_an_ordinary_package_are_not_guessed_between(monkeypatch):
    """La un pachet obișnuit cu două versiuni instalate deodată, rollback-ul ar trebui fixat pe
    una dintre ele, iar `pkg_version equals` verifică doar cea mai nouă: nu se alege, se reține
    familia."""
    rpm = [sup.rpm_line("dup", "1-1.el9"), sup.rpm_line("dup", "1-2.el9"), sup.rpm_line("dup-lib", "1-1.el9",
           srpm="dup-1-1.el9.src.rpm")]
    rows = [_row(1, "dup", fixed="1-9.el9"), _row(2, "dup-lib", fixed="1-9.el9")]
    sel = _select(monkeypatch, rows, rpm)
    held = _held(sel)
    assert held["dup"].code == "multiple_versions" and "dup-lib" in held
    assert not sel.lots


def test_the_asset_of_the_findings_becomes_the_target_of_the_plan(monkeypatch):
    """Dacă toate constatările lotului stau pe același asset, planul îl numește (și se leagă de el
    în bază); altfel pachetele sunt ale gazdei, nu ale unui asset."""
    rows = [_row(1, "aaa", asset_id=3, asset_name="web"), _row(2, "bbb", asset_id=3, asset_name="web")]
    rpm = [sup.rpm_line("aaa", "1-1.el9"), sup.rpm_line("bbb", "1-1.el9")]
    lot = _select(monkeypatch, rows, rpm).lots[0]
    assert lot.asset_id == 3 and lot.plan["target"]["asset_id"] == 3 and lot.plan["target"]["asset_name"] == "web"

    mixed = [_row(1, "aaa", asset_id=3, asset_name="web"), _row(2, "bbb", asset_id=4, asset_name="db")]
    lot2 = _select(monkeypatch, mixed, rpm).lots[0]
    assert lot2.asset_id is None and lot2.plan["target"]["asset_id"] == 0
    assert lot2.plan["target"]["asset_name"] == "host"


def test_an_unknown_platform_family_proposes_nothing(monkeypatch):
    """«Probabil rpm» nu e un răspuns: pentru o familie pe care nu o cunoaște, planificatorul nu
    construiește comenzi."""
    sup.install(monkeypatch, sup.FakeHost())
    sel = run(su.select(sup.FakeDB(), sup.cfg("arch")))
    assert sel.error and "arch" in sel.error and not sel.lots


def test_a_cve_that_is_not_a_cve_never_reaches_the_plan(monkeypatch):
    """Planul poartă CVE-ul reprezentant al lotului; un id de aviz (RHSA/ALSA) în câmpul `cve`
    ar fi respins de validator și ar scoate pachetul din răspuns fără niciun motiv bun."""
    rows = [_row(1, "aaa", cve="ALSA-2026:0001")]
    sel = _select(monkeypatch, rows, [sup.rpm_line("aaa", "1-1.el9")])
    assert sel.lots and sel.lots[0].plan["vulnerabilities"][0]["cve"] is None


# ---------------------------------------------------------------------------
# Configurația dnf și citirea gazdei
# ---------------------------------------------------------------------------
def test_a_dnf_conf_that_redefines_installonly_is_not_trusted(monkeypatch, tmp_path):
    """Dacă `dnf.conf` are propria listă `installonlypkgs`, dnf tratează alte pachete ca
    install-only decât cele pe care le citesc eu din `rpm`. «Nu știu ce e install-only» nu devine
    «nimic nu e»."""
    conf = tmp_path / "dnf.conf"
    conf.write_text("[main]\ninstallonly_limit=3\ninstallonlypkgs=kernel mykernel\n", encoding="utf-8")
    monkeypatch.setattr(su, "_DNF_CONF_PATHS", (str(conf),))
    assert "installonlypkgs" in su._dnf_conf_override()

    conf.write_text("[main]\n# installonlypkgs=kernel\ninstallonly_limit=3\n", encoding="utf-8")
    assert su._dnf_conf_override() is None, "un rând comentat nu e o redefinire"
    monkeypatch.setattr(su, "_DNF_CONF_PATHS", (str(tmp_path / "nu-exista.conf"),))
    assert su._dnf_conf_override() is None, "un fișier absent nu spune nimic"
    monkeypatch.setattr(su, "_DNF_CONF_PATHS", (str(tmp_path),))
    assert "nu se poate citi" in su._dnf_conf_override(), "un fișier ilizibil NU e «nu spune nimic»"


def _select_with_real_dnf_conf(monkeypatch, conf_path):
    """`select` cu `_dnf_conf_override` REAL, arătând spre `conf_path`. `sup.install` îl
    înlocuiește cu un stub care întoarce `None`, deci orice test făcut cu el e orb la ștergerea
    consultării din `read_host`."""
    real = su._dnf_conf_override
    sup.install(monkeypatch, sup.FakeHost())
    monkeypatch.setattr(su, "_dnf_conf_override", real)
    monkeypatch.setattr(su, "_DNF_CONF_PATHS", (str(conf_path),))
    return run(su.select(sup.FakeDB(), sup.cfg()))


def test_select_refuses_to_plan_on_a_host_whose_dnf_conf_redefines_installonly(monkeypatch, tmp_path):
    """Pe o gazdă cu `installonlypkgs=` în `dnf.conf`, dnf are altă listă de pachete install-only
    decât cea pe care o citesc din `rpm`. Dacă `read_host` n-ar consulta fișierul, `select` ar
    propune loturi pentru pachete pe care dnf le tratează altfel (adaugă lângă cel nou în loc să
    înlocuiască, deci revenirea n-ar restaura nimic) — fără nicio eroare. Controalele pozitive:
    aceeași gazdă cu fișierul curat, comentat sau absent propune loturi."""
    conf = tmp_path / "dnf.conf"
    conf.write_text("[main]\ninstallonlypkgs=kernel mykernel\n", encoding="utf-8")
    sel = _select_with_real_dnf_conf(monkeypatch, conf)
    assert sel.error and "installonlypkgs" in sel.error and not sel.lots, sel

    # Ilizibil (aici: un director în locul fișierului) nu e «nu spune nimic».
    sel = _select_with_real_dnf_conf(monkeypatch, tmp_path)
    assert sel.error and "nu se poate citi" in sel.error and not sel.lots, sel

    conf.write_text("[main]\n# installonlypkgs=kernel\ninstallonly_limit=3\n", encoding="utf-8")
    for path in (conf, tmp_path / "nu-exista.conf"):
        sel = _select_with_real_dnf_conf(monkeypatch, path)
        assert sel.error is None and sel.lots, (path.name, sel.error)


@pytest.mark.parametrize("name", ["expat\n", "expat\n--root=/x", " expat", "expat ", "", "-a", "a" * 129])
def test_a_package_name_must_match_whole_not_up_to_a_trailing_newline(name, monkeypatch):
    """`$` potrivește și înaintea unui rând nou de la coadă, deci un `match` ar fi acceptat
    «expat\n». Azi nu e atins (argumentele Telegram sunt tăiate la spații, numele din bază sunt
    curățate), dar e la un apelant distanță: numele ajunge în argv-ul lui `rpm`, care îl citește ca
    nume și ce urmează. Trei locuri folosesc regula: argumentul comenzii, citirea gazdei, clasificarea."""
    assert su.is_package_name(name) is False
    host = sup.FakeHost(sup.rpm_line("expat", "2.5.0-1.el9") + "\n")
    sup.install(monkeypatch, host)
    run(su.read_host("rhel", [name, "expat"]))
    assert all(name not in argv for argv in host.argvs), host.argvs
    cand = su.Candidate(package=name, fixed="2-1", finding_ids=[1], kev=False, priority=1,
                        severity="high", rep_id=1, rep_cve=None, asset_id=None, asset_name=None,
                        protected=False)
    sel = su.Selection()
    su.classify(su.CandidateSet(candidates=[cand]), su.HostRead(), "rhel", sel)
    assert [h.code for h in sel.held] == ["bad_name"]


def test_a_plain_package_name_is_still_a_package_name():
    """Controlul pozitiv al testului de mai sus: o regulă care ar refuza orice ar trece de el."""
    assert all(su.is_package_name(n) for n in ("expat", "libstdc++", "python3.9", "perl-URI", "a_b"))


def test_the_install_only_query_needs_its_positive_control_on_its_own(monkeypatch):
    """Ieșirea fără controlul pozitiv (`rpm`), dar cu codul și numărul de «no package provides»
    în acord, arată exact ca un `rpm` care a răspuns «nimic nu e install-only» — și e o pană
    tăcută. Doar controlul le deosebește."""
    silent = ("no package provides installonlypkg(vm)\nno package provides multiversion(kernel)\n"
              "no package provides installonlypkg(kernel)\nno package provides installonlypkg(kernel-module)\n")
    host = sup.FakeHost(provides=silent, provides_code=4)
    sup.install(monkeypatch, host)
    sel = run(su.select(sup.FakeDB(), sup.cfg()))
    assert sel.error and "controlul pozitiv" in sel.error
    assert not sel.lots


# ---------------------------------------------------------------------------
# Procesul care citește
# ---------------------------------------------------------------------------
def test_run_reports_exit_code_and_both_streams(monkeypatch):
    sup.allow_own_programs(monkeypatch)
    code, out, err = run(su._run([sys.executable, "-c",
                                  "import sys; print('a'); print('b', file=sys.stderr); sys.exit(3)"]))
    assert (code, out.strip(), err.strip()) == (3, "a", "b")


def test_run_says_127_for_a_missing_program_and_124_for_a_timeout(monkeypatch):
    """Un program lipsă și un `rpm` agățat nu sunt «niciun pachet». Aceleași coduri ca shell-ul,
    ca eroarea să se citească. Poarta de la intrare (`_require_read_only`) refuză ambele programe de
    aici; testul le trece pe lista albă, vizibil, ca să probeze mașinăria de pornire."""
    sup.allow_own_programs(monkeypatch)
    code, _out, err = run(su._run(["definitely-not-a-program-xyz", "-q"]))
    assert code == 127 and "nu poate fi pornit" in err
    code, _out, err = run(su._run([sys.executable, "-c", "import time; time.sleep(30)"], limit_s=1))
    assert code == 124 and err == "timeout"


@pytest.mark.parametrize("srpm,expected", [
    ("kernel-5.14.0-687.53.1.el9_8.src.rpm", "kernel"),
    ("perl-URI-5.09-3.el9.src.rpm", "perl-URI"),
    ("zabbix-6.4.21-release1.el9.src.rpm", "zabbix"),
    ("(none)", "fallback"),
    ("", "fallback"),
    ("not-an-srpm", "fallback"),
])
def test_the_source_of_a_package_is_its_srpm_name_without_version(srpm, expected):
    """Familia (ce se mișcă împreună) se citește din SRPM, fără versiune: aceeași sursă în două
    versiuni (nucleele instalate în paralel) trebuie să cadă în același grup."""
    assert su._srpm_source(srpm, "fallback") == expected


def test_the_last_finished_update_plan_is_asked_for_by_origin_and_by_ending():
    """Doar planurile de update, și doar cele încheiate (aplicat/eșuat/revenit): un plan respins
    de operator sau expirat nu e un eșec, iar unul deschis nu s-a încheiat."""
    db = sup.FakeDB(last_finished=[{"id": 4, "status": "failed"}])
    assert run(su.last_finished_update_plan(db)) == (4, "failed")
    sql, args = db.calls[-1]
    assert args[0] == "update" and set(args[1]) == {"applied", "failed", "rolled_back"}
    assert run(su.last_finished_update_plan(sup.FakeDB())) is None


def test_a_row_the_host_family_cannot_touch_is_reported_not_dropped(monkeypatch):
    """Un rând al scanerului de pachete cu alt ecosistem (npm sub `dnf`: nu se întâmplă azi, dar
    tabelele se schimbă) nu poate primi un plan `dnf`. Nu dispare: apare ca reținut, cu motivul
    din `planner.unplannable_reason`."""
    rows = [_row(1, "aaa"), _row(2, "left-pad", ecosystem="npm")]
    sel = _select(monkeypatch, rows, [sup.rpm_line("aaa", "1-1.el9")])
    assert _planned(sel) == [["aaa"]]
    assert _held(sel)["left-pad"].code == "foreign"


def test_the_web_page_does_not_call_a_deterministic_plan_ai_generated(monkeypatch):
    """`patch.html` scrie `plan.generated_by`, cu «ai» ca implicit. Un plan la care niciun model n-a
    pus mâna nu trebuie să poarte eticheta asta; iar cheia, exclusă din hash, nu schimbă ce se
    aprobă."""
    lot = _select(monkeypatch, [_row(1, "aaa")], [sup.rpm_line("aaa", "1-1.el9")]).lots[0]
    assert lot.plan["generated_by"] == "update"
    without = {k: v for k, v in lot.plan.items() if k != "generated_by"}
    assert su.plan_hash(lot.plan) == su.plan_hash(without)
