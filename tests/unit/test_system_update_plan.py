"""Planurile de update se construiesc în cod, trec de același validator, și încap în aprobare.

Fiecare test își spune în docstring ce se strică pentru operator dacă pică. Ce NU se poate
verifica de aici, și niciun test nu se preface că acoperă:

  * că `dnf update <pachete>` chiar se termină cu bine pe o gazdă — nu există `dnf` în suită, iar
    pe producție nicio aplicare reală n-a ajuns vreodată la `applied` (1 `aborted`, 1
    `rollback_failed`, ambele din 5 oct 2026);
  * că versiunea veche mai e în oglindă, deci că `dnf downgrade` ar merge;
  * forma exactă a ieșirii lui `rpm` pe o gazdă anume: dublura reproduce formele măsurate (vezi
    `_system_update_support`), nu le dovedește.
"""
from __future__ import annotations

import asyncio
import random

import pytest

import policy  # executor/policy.py — vezi tests/conftest.py
from sentinel.constants import REBOOT_REQUIRED_PACKAGES
from sentinel.patch import approval
from sentinel.patch import system_update as su
from sentinel.patch.validator import validate_plan
from tests.unit import _system_update_support as sup


def run(c):
    return asyncio.run(c)


def _select(monkeypatch, *, db=None, host=None, only=None, family="rhel"):
    host = host or sup.FakeHost()
    sup.install(monkeypatch, host)
    return run(su.select(db or sup.FakeDB(), sup.cfg(family), only=only))


def _planned(sel) -> set[str]:
    return {p.name for lot in sel.lots for p in lot.packages}


def _held(sel) -> dict[str, su.Held]:
    return {name: h for h in sel.held for name in h.packages}


# ---------------------------------------------------------------------------
# Forma producției
# ---------------------------------------------------------------------------
def test_a_production_shaped_host_yields_valid_lots_and_holds_what_it_must(monkeypatch):
    """Pe gazda reală, 33 de pachete cu constatări: 8 de nucleu, 3 openssh, 8 zabbix, restul
    obișnuite. Operatorul trebuie să primească loturi pe care validatorul le acceptă, FĂRĂ
    nucleu, FĂRĂ sshd și FĂRĂ pachetul care ar coborî o serie — și să vadă de ce lipsesc."""
    sel = _select(monkeypatch)

    assert sel.error is None
    held = _held(sel)
    assert {"kernel", "kernel-core", "kernel-modules", "kernel-headers", "kernel-tools"} <= set(held)
    assert {"openssh", "openssh-server", "openssh-clients"} <= set(held)
    assert {"zabbix-server", "zabbix-web"} <= set(held)
    assert held["kernel"].code == "install_only"
    assert held["openssh-server"].code == "manual_only"
    assert held["zabbix-web"].code == "epoch_changed"

    planned = _planned(sel)
    assert planned == {"httpd", "httpd-core", "httpd-tools", "httpd-filesystem", "mod_lua", "expat",
                       "libgs", "ca-certificates", "perl-URI", "bubblewrap", "librsvg2", "libaom",
                       "environment-modules", "emacs-filesystem"}
    assert not planned & set(held), "un pachet e și planificat, și reținut"
    for lot in sel.lots:
        assert validate_plan(lot.plan, platform_family="rhel").valid, lot.number


def test_a_lot_is_one_transaction_with_a_pinned_way_back(monkeypatch):
    """Un pas `dnf update` pentru tot lotul, nu unul pe pachet: runnerul rulează TOT rollback-ul
    când pică ORICE pas de apply, deci pașii pe pachet ar fi făcut `downgrade` și pe pachete
    neatinse — «ROLLBACK-UL A EȘUAT» pe o mașină sănătoasă."""
    sel = _select(monkeypatch)
    for lot in sel.lots:
        plan = lot.plan
        assert len(plan["apply"]) == 1 and len(plan["rollback"]) == 1
        names = [p.name for p in lot.packages]
        assert plan["apply"][0]["argv"] == ["dnf", "-y", "update", *sorted(names)]
        pins = plan["rollback"][0]["argv"]
        assert pins[:3] == ["dnf", "-y", "downgrade"]
        by_name = {p["check"]["name"]: p["check"]["equals"]
                   for p in plan["preflight"] if p["check"]["kind"] == "pkg_version"}
        assert sorted(pins[3:]) == sorted(f"{n}-{v}" for n, v in by_name.items())
        assert plan["risk"]["reversible"] is True


# ---------------------------------------------------------------------------
# Lotul se măsoară, nu se presupune
# ---------------------------------------------------------------------------
def _many_singletons(n: int):
    rows, rpm = [], []
    for i in range(n):
        name = f"pkg{i:03d}-extra"
        rows.append(dict(id=9000 + i, package=name, cve=None, severity="medium", kev=False,
                         priority=10, fixed_version="2.0-1.el9", ecosystem="rpm", asset_id=None,
                         asset_name=None, asset_protected=False, fix_pending_reboot=False))
        rpm.append(sup.rpm_line(name, "1.0-1.el9", srpm=f"{name}-1.0-1.el9.src.rpm"))
    return rows, "\n".join(rpm) + "\n"


def test_every_lot_fits_the_signing_request_and_none_could_take_one_more(monkeypatch):
    """Cererea de semnat are cel mult un mesaj Telegram. Un lot care n-ar încăpea ar fi refuzat
    abia la cerere — după trei atingeri și PIN. Și un lot MAI MIC decât trebuie ar însemna
    semnături în plus: fiecare lot e o ceremonie pe stația operatorului."""
    rows, rpm = _many_singletons(60)
    sel = _select(monkeypatch, db=sup.FakeDB(rows), host=sup.FakeHost(rpm))
    assert len(sel.lots) > 1, "60 de pachete într-un singur plan: plafonul nu se aplică"
    limit = approval.MAX_REQUEST_CHARS - su.REQUEST_MARGIN_CHARS
    assert _planned(sel) == {r["package"] for r in rows}

    def request_len(plan):
        flat = approval.flatten(plan, "rhel")
        return len(approval.build_request(su.plan_hash(plan), "0" * 64, "0" * 32, flat.steps))

    for lot in sel.lots:
        assert request_len(lot.plan) <= limit, f"lotul {lot.number} nu încape în cererea de semnat"
    # Maximalitate: adăugând primul pachet al lotului următor, lotul curent NU mai încape.
    for lot, nxt in zip(sel.lots, sel.lots[1:], strict=False):
        grown = su.build_plan(lot.packages + nxt.packages[:1], family="rhel", scope="system",
                              number=1, total=1, asset_id=None, asset_name=None)
        ok, _why = su.fits(grown, "rhel")
        assert not ok, f"lotul {lot.number} s-a oprit prea devreme: mai încape un pachet"


def test_the_timeout_budget_is_a_limit_too(monkeypatch):
    """Planul declară timeouturi care trebuie să încapă în fereastra de aprobare, apply ȘI
    rollback. Dacă bugetul nu s-ar aplica, validatorul ar respinge lotul întreg (`run_budget_exceeded`)
    abia la ultima verificare, iar operatorul n-ar primi nimic."""
    monkeypatch.setattr(approval, "RUN_BUDGET_S", 1500)   # apply + rollback = 1500: nicio verificare nu mai încape
    rows, rpm = _many_singletons(4)
    sel = _select(monkeypatch, db=sup.FakeDB(rows), host=sup.FakeHost(rpm))
    assert not sel.lots, "un lot a trecut deși timeouturile lui nu încap în buget"
    assert sel.held and all("timeout" in h.reason.lower() for h in sel.held), [h.reason for h in sel.held]


def _plan_pkg(name: str, *, priority_group: str | None = None) -> su.PlanPkg:
    return su.PlanPkg(name=name, before="1.0-1.el9", target="2.0-1.el9", finding_ids=[1], findings=1,
                      kev=False, cve=None, rep_id=1, severity="high", reboot=False)


def _request_len(n: int) -> int:
    plan = su.build_plan([_plan_pkg(f"pkg{i:03d}-extra") for i in range(n)], family="rhel",
                         scope="system", number=1, total=1, asset_id=None, asset_name=None)
    flat = approval.flatten(plan, "rhel")
    return len(approval.build_request(su.plan_hash(plan), "0" * 64, "0" * 32, flat.steps))


def test_a_source_group_is_never_split_across_lots(monkeypatch):
    """`httpd` cere `httpd-core` de aceeași versiune: `dnf` le trage împreună oricum. Un lot care
    l-ar numi pe unul singur ar actualiza pe ascuns celelalte, fără verificare și fără rollback.

    Plafonul e ales ca un lot să încapă exact 6 pachete, iar trei pachete singure cu prioritate
    mai mare vin ÎNAINTEA familiei httpd (5): o împachetare pe pachete ar umple lotul 1 cu trei
    singure și primele trei din httpd; una pe familii mută tot httpd în lotul 2."""
    monkeypatch.setattr(approval, "MAX_REQUEST_CHARS", _request_len(6) + su.REQUEST_MARGIN_CHARS)
    singles = [dict(id=9800 + i, package=f"first{i}-extra", cve=None, severity="high", kev=False,
                    priority=99, fixed_version="2-1.el9", ecosystem="rpm", asset_id=None,
                    asset_name=None, asset_protected=False, fix_pending_reboot=False) for i in range(3)]
    rpm = sup.rpm_query_output([sup.rpm_line(r["package"], "1-1.el9") for r in singles])
    rows = [r for r in sup.finding_rows() if r["package"].startswith(("httpd", "mod_lua"))]
    sel = _select(monkeypatch, db=sup.FakeDB(singles + rows), host=sup.FakeHost(rpm))
    httpd = {"httpd", "httpd-core", "httpd-tools", "httpd-filesystem", "mod_lua"}
    where = {name: lot.number for lot in sel.lots for name in (p.name for p in lot.packages)}
    assert httpd <= set(where), (sorted(where), [(h.code, h.packages) for h in sel.held])
    assert len({where[n] for n in httpd}) == 1, where
    assert len(sel.lots) == 2, [(lt.number, [p.name for p in lt.packages]) for lt in sel.lots]


def test_a_group_too_big_for_any_plan_is_held_not_cut(monkeypatch):
    """Un grup care singur nu încape într-un plan se REȚINE cu motivul, nu se taie: tăiat, ar
    lăsa jumătate din familie pe versiunea veche."""
    monkeypatch.setattr(approval, "MAX_REQUEST_CHARS", 900)
    sel = _select(monkeypatch)
    held = _held(sel)
    assert "httpd" in held and held["httpd"].code == "too_big"
    assert "httpd" not in _planned(sel)


# ---------------------------------------------------------------------------
# Ce se reține
# ---------------------------------------------------------------------------
def test_the_executor_would_accept_every_command_of_every_plan(monkeypatch):
    """Un plan pe care validatorul îl binecuvântează și executorul îl refuză moare la pasul 1 —
    exact cazul `--only-upgrade` din 18 sep 2026. Fiecare argv înregistrat, pe fiecare familie,
    trece prin `policy.check_argv` și nu e refuzat de `sandbox_refusal`."""
    sel = _select(monkeypatch)
    assert sel.lots
    for lot in sel.lots:
        flat = approval.flatten(lot.plan, "rhel")
        assert flat.steps
        for argv in flat.steps:
            policy.check_argv(list(argv))
            assert policy.sandbox_refusal(list(argv)) is None, argv
        for item in lot.plan["backup"]:
            policy.check_argv(list(item["restore_argv"]))


def test_install_only_is_read_from_the_host_not_from_a_name(monkeypatch):
    """Pe producție `kernel-headers` și `kernel-tools` NU sunt install-only, iar `kernel-core` e.
    O regulă pe prefixul «kernel» ar fi reținut greșit unele; una care nu știe nimic despre
    nucleu ar fi planificat unul fără cale de întoarcere. Un pachet cu alt nume, dar cu
    furnizarea `installonlypkg`, trebuie reținut."""
    extra_rows = [dict(id=9100, package="mykernel", cve=None, severity="high", kev=False,
                       priority=1, fixed_version="2.0-1.el9", ecosystem="rpm", asset_id=None,
                       asset_name=None, asset_protected=False, fix_pending_reboot=False)]
    rpm = sup.rpm_query_output([sup.rpm_line("mykernel", "1.0-1.el9")])
    prov = sup.WHATPROVIDES_OUTPUT.replace("rpm\n", "mykernel\nrpm\n")
    sel = _select(monkeypatch, db=sup.FakeDB(sup.finding_rows() + extra_rows),
                  host=sup.FakeHost(rpm, provides=prov))
    assert _held(sel)["mykernel"].code == "install_only"

    # `kernel-tools` singur, fără niciun membru install-only reținut în familia lui: se planifică.
    only_tools = [r for r in sup.finding_rows(kernel=False)] + [
        dict(id=9200, package="kernel-tools", cve=None, severity="high", kev=False, priority=1,
             fixed_version=sup.KERNEL_FIXED, ecosystem="rpm", asset_id=None, asset_name=None,
             asset_protected=False, fix_pending_reboot=False)]
    rpm2 = sup.rpm_query_output([sup.rpm_line("kernel-tools", "5.14.0-100.3.el9",
                                              srpm="kernel-tools-src-5.14.0-100.3.el9.src.rpm")],
                                kernel=False)
    sel2 = _select(monkeypatch, db=sup.FakeDB(only_tools), host=sup.FakeHost(rpm2))
    assert "kernel-tools" in _planned(sel2), _held(sel2).get("kernel-tools")


def test_a_group_with_a_held_member_is_held_whole(monkeypatch):
    """`kernel-tools` fără `kernel` e un nucleu pe jumătate, iar `openssh` fără `openssh-server`
    nu există (serverul cere clientul de aceeași versiune): membrii obișnuiți ai unui grup cu un
    membru reținut se rețin cu el, altfel `dnf` l-ar trage pe cel reținut fără să-l numească."""
    sel = _select(monkeypatch)
    for member in ("kernel-headers", "kernel-tools", "openssh", "openssh-clients", "zabbix-server"):
        assert member in _held(sel), member
        assert member not in _planned(sel), member


def test_an_epoch_change_is_never_planned_as_an_ordinary_update(monkeypatch):
    """Măsurat pe producție: `zabbix-web` e instalat ca 6.4.x (fără epoch), iar reparația din
    bază e `1:6.0.x`. `dnf update` ar urca epoch-ul, adică ar muta pachetul pe seria 6.0 — o
    COBORÂRE de versiune majoră — iar post_verification (`at_least 1:6.0.x`) ar spune «verificat»."""
    sel = _select(monkeypatch)
    h = _held(sel)["zabbix-web"]
    assert h.code == "epoch_changed" and "epoch" in h.reason
    assert "zabbix-web" not in _planned(sel)


def test_a_validator_rejection_holds_that_group_and_keeps_the_rest(monkeypatch):
    """Dacă validatorul respinge o formă corectă de update (aici: un nume de pachet care conține
    `nft`, interzis în orice argv), grupul respins se REȚINE cu mesajul LUI — constatare de
    raportat, nu un motiv de a-l modifica — iar restul răspunsului rămâne."""
    row = dict(id=9300, package="nftables", cve=None, severity="high", kev=False, priority=99,
               fixed_version="1.0-2.el9", ecosystem="rpm", asset_id=None, asset_name=None,
               asset_protected=False, fix_pending_reboot=False)
    rpm = sup.rpm_query_output([sup.rpm_line("nftables", "1.0-1.el9")])
    sel = _select(monkeypatch, db=sup.FakeDB(sup.finding_rows() + [row]), host=sup.FakeHost(rpm))
    h = _held(sel)["nftables"]
    assert h.code == "validator" and "nft" in h.reason, h.reason
    assert "nftables" not in _planned(sel)
    assert "expat" in _planned(sel), "un grup respins a golit tot răspunsul"


def test_a_fix_already_on_disk_is_reported_not_planned(monkeypatch):
    """Reparația e pe disc (scanarea n-a rulat încă): un plan ar rula `dnf update` fără nimic de
    instalat. Răspunsul e «instalat», iar pentru un pachet care cere repornire — «așteaptă
    repornire»; niciodată «actualizat»."""
    rows = sup.finding_rows(kernel=False)
    rows.append(dict(id=9400, package="glibc", cve=None, severity="high", kev=False, priority=1,
                     fixed_version="2.34-2.el9", ecosystem="rpm", asset_id=None, asset_name=None,
                     asset_protected=False, fix_pending_reboot=False))
    rows.append(dict(id=9401, package="bash", cve=None, severity="high", kev=False, priority=1,
                     fixed_version="5.1-1.el9", ecosystem="rpm", asset_id=None, asset_name=None,
                     asset_protected=False, fix_pending_reboot=False))
    rpm = sup.rpm_query_output([sup.rpm_line("glibc", "2.34-3.el9"), sup.rpm_line("bash", "5.1-1.el9")],
                               kernel=False)
    sel = _select(monkeypatch, db=sup.FakeDB(rows), host=sup.FakeHost(rpm))
    already = {a[0]: a for a in sel.already}
    assert already["glibc"][2] is True, "glibc cere repornire: trebuie să spună «așteaptă repornire»"
    assert already["bash"][2] is False
    assert {"glibc", "bash"}.isdisjoint(_planned(sel))


def test_a_scanner_verdict_of_pending_reboot_is_never_planned():
    """Cele 491 de CVE-uri de nucleu din 29 sep cereau o REPORNIRE: pachetul era instalat, doar
    nu rula. Un plan pentru ele ar rula un `dnf update` fără nimic de instalat."""
    rows = sup.finding_rows(kernel=False, per_package=1)
    for r in rows:
        if r["package"] == "expat":
            r["fix_pending_reboot"] = True
    cands = run(su.load_candidates(sup.FakeDB(rows), "rhel"))
    assert "expat" in cands.pending_reboot
    assert "expat" not in {c.package for c in cands.candidates}


# ---------------------------------------------------------------------------
# „Nu știu" nu devine „e bine"
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("host", [
    sup.FakeHost("garbage line without tabs\n"),
    sup.FakeHost(sup.rpm_query_output(), rpm_code=5),
    sup.FakeHost(sup.rpm_query_output(), provides="kernel-core\n"),
    sup.FakeHost("", rpm_code=0),
])
def test_unreadable_host_state_proposes_nothing(monkeypatch, host):
    """Dacă `rpm` nu răspunde cum trebuie (linie ilizibilă, cod care nu corespunde cu ce a
    raportat, control pozitiv lipsă, ieșire goală pentru nume cerute), planificatorul spune că nu
    poate ști și NU propune nimic — nu «niciun pachet instalat», nu «nimic install-only»."""
    sel = _select(monkeypatch, host=host)
    assert sel.error and not sel.lots, sel
    assert "nu pot" in sel.error


def test_rpm_exit_code_is_the_count_of_missing_names_not_a_failure(monkeypatch):
    """Măsurat pe producție: `rpm -q a b c` iese cu NUMĂRUL argumentelor eșuate, deci cod 2 e
    normal când două nume lipsesc. O verificare «cod 0 sau 1» ar fi luat gazda sănătoasă drept
    stricată, iar una «orice cod e bun» ar fi luat un `rpm` căzut drept «nu e instalat»."""
    gone = "package ghost-one is not installed\npackage ghost-two is not installed\n"
    rows = sup.finding_rows(kernel=False) + [
        dict(id=9500 + i, package=f"ghost-{n}", cve=None, severity="high", kev=False, priority=1,
             fixed_version="2-1.el9", ecosystem="rpm", asset_id=None, asset_name=None,
             asset_protected=False, fix_pending_reboot=False)
        for i, n in enumerate(("one", "two"))]
    rpm = sup.rpm_query_output(kernel=False) + gone
    sel = _select(monkeypatch, db=sup.FakeDB(rows), host=sup.FakeHost(rpm))
    assert sel.error is None
    assert _held(sel)["ghost-one"].code == "not_installed"
    # Același text, dar codul spune că a eșuat altceva: nu se mai crede nimic din ieșire.
    sel2 = _select(monkeypatch, db=sup.FakeDB(rows), host=sup.FakeHost(rpm, rpm_code=1))
    assert sel2.error and not sel2.lots


def test_a_name_that_looks_like_a_flag_never_reaches_rpm(monkeypatch):
    """Numele pachetelor vin de la un scaner. Unul care începe cu `-` ar fi citit de `rpm` ca
    flag (`rpm -q -a` listează tot). Nu ajunge în argv; ajunge în răspuns, ca «nume neacceptat»."""
    rows = sup.finding_rows(kernel=False) + [
        dict(id=9600, package="-a", cve=None, severity="high", kev=False, priority=1,
             fixed_version="2-1.el9", ecosystem="rpm", asset_id=None, asset_name=None,
             asset_protected=False, fix_pending_reboot=False)]
    host = sup.FakeHost(sup.rpm_query_output(kernel=False))
    sel = _select(monkeypatch, db=sup.FakeDB(rows), host=host)
    assert all("-a" not in argv for argv in host.argvs), host.argvs
    assert _held(sel)["-a"].code == "bad_name"


# ---------------------------------------------------------------------------
# Determinism și ce poartă planul
# ---------------------------------------------------------------------------
def test_the_same_facts_give_the_same_plan_whatever_order_they_arrive_in(monkeypatch):
    """Un plan e legat de aprobare prin hash. Dacă ordinea în care răspunde baza de date ar
    schimba octeții, un buton trimis ieri n-ar mai potrivi planul de azi fără ca ceva să se fi
    schimbat — și un test ar putea trece azi și pica mâine."""
    a = _select(monkeypatch)
    rows = sup.finding_rows()
    random.Random(7).shuffle(rows)
    b = _select(monkeypatch, db=sup.FakeDB(rows))
    assert [su.plan_hash(lt.plan) for lt in a.lots] == [su.plan_hash(lt.plan) for lt in b.lots]


def test_the_reboot_flag_is_the_validators_rule_for_every_listed_package(monkeypatch):
    """Validatorul cere `requires_reboot: true` pentru orice pachet din REBOOT_REQUIRED_PACKAGES.
    Dacă planul de aici ar spune altceva, validatorul l-ar respinge — sau, mai rău, dacă regula
    de aici ar fi mai îngustă, un plan cu glibc ar ajunge la operator fără avertisment."""
    for prefix in REBOOT_REQUIRED_PACKAGES:
        name = f"{prefix}-libs"
        rows = [dict(id=9700, package=name, cve=None, severity="high", kev=False, priority=1,
                     fixed_version="2-2.el9", ecosystem="rpm", asset_id=None, asset_name=None,
                     asset_protected=False, fix_pending_reboot=False)]
        rpm = sup.rpm_line(name, "2-1.el9") + "\n"
        sel = _select(monkeypatch, db=sup.FakeDB(rows), host=sup.FakeHost(rpm))
        assert sel.lots, (name, [h.reason for h in sel.held])
        plan = sel.lots[0].plan
        assert plan["risk"]["requires_reboot"] is True, name
        assert plan["risk"]["level"] == "high" and plan["risk"]["blast_radius"] == "host-wide"
        assert plan["update"]["packages"][0]["reboot"] is True
        assert validate_plan(plan, platform_family="rhel").valid


def test_an_ordinary_lot_does_not_claim_a_reboot(monkeypatch):
    """Un «necesită repornire» pe fiecare plan ar învăța operatorul să-l ignore."""
    sel = _select(monkeypatch)
    for lot in sel.lots:
        assert lot.plan["risk"]["requires_reboot"] is False


def test_the_plan_carries_the_findings_it_addresses(monkeypatch):
    """`finding_ids` e ce leagă planul de constatări: de el depind `retire_moot_plans` (planul
    dispare când toate sunt rezolvate) și refuzul de a face un al doilea plan pentru aceleași."""
    sel = _select(monkeypatch)
    ids = {r["id"] for r in sup.finding_rows() if r["package"] in _planned(sel)}
    assert {i for lot in sel.lots for i in lot.finding_ids} == ids


# ---------------------------------------------------------------------------
# Un pachet într-un plan deschis nu primește al doilea
# ---------------------------------------------------------------------------
def test_a_package_in_an_open_plan_is_not_offered_again(monkeypatch):
    sel = _select(monkeypatch, db=sup.FakeDB(
        covering=[{"id": 5, "status": "validated", "finding_ids": [r["id"] for r in sup.finding_rows()
                                                                    if r["package"] == "expat"]}]))
    assert ("expat", 5, "validated") in sel.covered
    assert "expat" not in _planned(sel)


HTTPD_FAMILY = {"httpd", "httpd-core", "httpd-tools", "httpd-filesystem", "mod_lua"}


def _plan_covering(package: str, plan_id: int = 5, status: str = "validated") -> dict:
    return {"id": plan_id, "status": status,
            "finding_ids": [r["id"] for r in sup.finding_rows() if r["package"] == package]}


def _argv_names(sel) -> set[str]:
    """Tot ce numește comanda de apply a fiecărui lot, fără steguri."""
    return {a.split("=")[0] for lot in sel.lots for a in lot.plan["apply"][0]["argv"]
            if not a.startswith("-") and a not in ("dnf", "update", "apt-get", "install")}


def test_a_sibling_covered_by_another_open_plan_holds_its_whole_family(monkeypatch):
    """`httpd` cere `httpd-core` de aceeași versiune, deci `dnf update httpd ...` îl mută și pe
    el. Dacă `httpd-core` e deja în planul #5, scos din lot în tăcere, tranzacția celorlalte patru
    ar muta un pachet fără pin de pregătire, fără pin de revenire și fără verificare — exact
    «actualizarea pe ascuns» pe care familia indivizibilă există s-o prevină. Familia se reține
    ÎNTREAGĂ, cu planul care o acoperă numit, iar niciun lot nu mai atinge niciun httpd."""
    sel = _select(monkeypatch, db=sup.FakeDB(covering=[_plan_covering("httpd-core")]))

    assert ("httpd-core", 5, "validated") in sel.covered
    assert not HTTPD_FAMILY & _planned(sel), _planned(sel)
    assert not any(n.startswith(("httpd", "mod_lua")) for n in _argv_names(sel)), _argv_names(sel)
    held = _held(sel)
    assert HTTPD_FAMILY <= set(held), "familia nu e reținută întreagă"
    h = held["httpd"]
    assert h.code == "covered" and set(h.packages) == HTTPD_FAMILY
    assert "#5" in h.reason and "validated" in h.reason, h.reason
    assert "expat" in _planned(sel), "un grup acoperit a golit tot răspunsul"


def test_asking_for_one_package_of_a_covered_family_still_says_why_and_names_the_plan(monkeypatch):
    """`/update httpd` cu `httpd-core` în planul #5: dacă răspunsul ar propune celelalte patru, ar
    muta `httpd-core` nenumit; dacă ar tăcea despre #5, operatorul n-ar ști încotro să meargă.
    Răspunsul: niciun lot, familia întreagă reținută, rândul «acoperit» păstrat. La fel când
    pachetul cerut e chiar cel acoperit."""
    for asked in ("httpd", "httpd-core", "mod_lua"):
        sel = _select(monkeypatch, db=sup.FakeDB(covering=[_plan_covering("httpd-core")]), only=asked)
        assert not sel.lots, (asked, _planned(sel))
        assert [h.code for h in sel.held] == ["covered"], (asked, sel.held)
        assert set(sel.held[0].packages) == HTTPD_FAMILY, asked
        assert sel.covered == [("httpd-core", 5, "validated")], (asked, sel.covered)


def test_a_covered_package_with_nothing_to_move_does_not_hold_its_family(monkeypatch):
    """Contrastul care păstrează regula cinstită: ce contează e dacă `dnf` ar MUTA pachetul. Un
    `httpd-core` acoperit dar aflat deja la versiunea care repară nu are nimic de instalat, iar
    unul neinstalat nu are ce fi mutat — familia rămasă se planifică, iar el rămâne vizibil ca
    acoperit. Reținerea familiei pentru un pachet pe care nimeni nu-l atinge ar ascunde patru
    reparații fără niciun câștig."""
    stock = sup.rpm_query_output(kernel=True)
    fixed = stock.replace(
        sup.rpm_line("httpd-core", "2.4.50-1.el9", srpm="httpd-2.4.50-1.el9.src.rpm"),
        sup.rpm_line("httpd-core", "2.4.50-2.el9", srpm="httpd-2.4.50-1.el9.src.rpm"))
    assert fixed != stock, "fixture-ul n-a schimbat nimic"
    sel = _select(monkeypatch, db=sup.FakeDB(covering=[_plan_covering("httpd-core")]),
                  host=sup.FakeHost(fixed))
    assert ("httpd-core", 5, "validated") in sel.covered
    assert HTTPD_FAMILY - {"httpd-core"} <= _planned(sel)

    lines = [ln for ln in sup.rpm_query_output(kernel=True).splitlines()
             if not ln.startswith("httpd-core" + chr(9))]
    gone = chr(10).join(lines) + chr(10) + "package httpd-core is not installed" + chr(10)
    sel = _select(monkeypatch, db=sup.FakeDB(covering=[_plan_covering("httpd-core")]),
                  host=sup.FakeHost(gone))
    assert sel.error is None
    assert ("httpd-core", 5, "validated") in sel.covered
    assert HTTPD_FAMILY - {"httpd-core"} <= _planned(sel)


def test_a_protected_sibling_holds_its_whole_family(monkeypatch):
    """Același mecanism ca la planul acoperit: un `httpd-core` pe un asset protejat nu poate fi
    numit într-un plan, dar `dnf update httpd` îl mută oricum. Fără reținerea familiei, un
    asset marcat «nu atinge» ar fi actualizat de o tranzacție care nu-l menționează."""
    rows = sup.finding_rows()
    for r in rows:
        if r["package"] == "httpd-core":
            r["asset_protected"] = True
    sel = _select(monkeypatch, db=sup.FakeDB(rows))
    assert not HTTPD_FAMILY & _planned(sel)
    assert set(_held(sel)["httpd"].packages) == HTTPD_FAMILY
    assert _held(sel)["httpd"].code == "protected_asset"


def test_classify_takes_the_covering_plans_as_an_argument_and_touches_no_database(monkeypatch):
    """`classify` promite că e pură în raport cu rețeaua și baza. Planurile care acoperă vin ca
    argument: o funcție care ar interoga singură ar face grupurile dependente de ora la care
    se apelează, iar testele ei ar cere o bază."""
    sup.install(monkeypatch, sup.FakeHost())
    db = sup.FakeDB()
    cands = run(su.load_candidates(db, "rhel"))
    host = run(su.read_host("rhel", [c.package for c in cands.candidates]))
    ids = [r["id"] for r in sup.finding_rows() if r["package"] == "httpd-core"]
    sel = su.Selection()
    groups = su.classify(cands, host, "rhel", sel, {ids[0]: (5, "approved")})
    assert not any(m.cand.package.startswith("httpd") for ms in groups.values() for m in ms)
    assert ("httpd-core", 5, "approved") in sel.covered
    assert "covered" in {h.code for h in sel.held}
    seen = [sql for sql, _ in db.calls]
    assert not any("patch_plans" in q for q in seen), "classify a interogat planurile"


def test_an_applied_plan_does_not_block_a_new_one(monkeypatch):
    """`applied` nu e în statusurile care blochează: un plan aplicat a cărui constatare a rămas
    deschisă n-a avut efect, iar nimic nu expiră un plan `applied` — blocarea ar face constatarea
    neplanificabilă pentru totdeauna."""
    db = sup.FakeDB()
    _select(monkeypatch, db=db)
    statuses = [a for sql, args in db.calls if "finding_ids &&" in sql for a in args[0]]
    assert statuses and "applied" not in statuses
    assert set(statuses) == {"validated", "approved", "scheduled", "applying"}


def test_only_narrows_to_the_group_of_that_package(monkeypatch):
    """`/update expat` propune expat și ce se mișcă cu el, nu tot sistemul; iar pentru un pachet
    din grup, tot grupul — fiindcă dnf l-ar trage oricum."""
    sel = _select(monkeypatch, only="expat")
    assert _planned(sel) == {"expat"}
    assert sel.lots[0].plan["update"]["scope"] == "package"
    sel2 = _select(monkeypatch, only="httpd-core")
    assert _planned(sel2) == {"httpd", "httpd-core", "httpd-tools", "httpd-filesystem", "mod_lua"}


def test_only_a_held_package_answers_with_why(monkeypatch):
    sel = _select(monkeypatch, only="kernel-core")
    assert not sel.lots
    assert [h.code for h in sel.held] == ["install_only"]
    assert "expat" not in {n for h in sel.held for n in h.packages}


# ---------------------------------------------------------------------------
# Debian
# ---------------------------------------------------------------------------
DEB_OUT = ("openssl\t3.0.13-0ubuntu3.16\tamd64\topenssl\tii \n"
           "libc6\t2.39-0ubuntu8.9\tamd64\tglibc\tii \n"
           "curl\t8.5.0-2ubuntu10.5\tamd64\tcurl\tii \n"
           "linux-image-generic\t6.8.0.100.100\tamd64\tlinux-meta\tii \n")


def _deb_rows():
    def row(i, pkg, fixed):
        return dict(id=i, package=pkg, cve=None, severity="medium", kev=False, priority=1,
                    fixed_version=fixed, ecosystem="deb", asset_id=None, asset_name=None,
                    asset_protected=False, fix_pending_reboot=False)
    return [row(1, "openssl", "3.0.13-0ubuntu3.17"), row(2, "libc6", "2.39-0ubuntu8.10"),
            row(3, "curl", "8.5.0-2ubuntu10.6"), row(4, "linux-image-generic", "6.8.0.101.101")]


def test_a_debian_lot_is_pinned_forward_and_back_and_validates(monkeypatch):
    """Pe Debian, `apt` n-are `downgrade`: singura revenire e `install pachet=versiune`, iar
    `--allow-downgrades` fără `=versiune` e refuzat de executor. Nucleul (`linux-*`) se instalează
    în paralel, deci se reține ca pe rhel. `rpm_state` nu există pe Debian: backup-ul e registrul dpkg."""
    host = sup.FakeHost(dpkg_out=DEB_OUT, dpkg_code=0)
    sel = _select(monkeypatch, db=sup.FakeDB(_deb_rows()), host=host, family="debian")
    assert sel.error is None, sel.error
    assert _held(sel)["linux-image-generic"].code == "install_only"
    assert _planned(sel) == {"openssl", "libc6", "curl"}
    plan = sel.lots[0].plan
    assert plan["apply"][0]["argv"] == [
        "apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "install",
        "curl=8.5.0-2ubuntu10.6", "libc6=2.39-0ubuntu8.10", "openssl=3.0.13-0ubuntu3.17"]
    assert plan["rollback"][0]["argv"] == [
        "apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "install", "--allow-downgrades",
        "curl=8.5.0-2ubuntu10.5", "libc6=2.39-0ubuntu8.9", "openssl=3.0.13-0ubuntu3.16"]
    assert [b["kind"] for b in plan["backup"]] == ["path"]
    assert validate_plan(plan, platform_family="debian").valid
    for argv in approval.flatten(plan, "debian").steps:
        policy.check_argv(list(argv))
        assert policy.sandbox_refusal(list(argv)) is None


def test_a_debian_name_the_host_does_not_know_is_a_missing_package_not_an_error(monkeypatch):
    """`dpkg-query` iese cu 1 și scrie pe stderr «no packages found matching X» pentru un nume
    necunoscut: asta e «nu e instalat», nu o pană."""
    host = sup.FakeHost(dpkg_out=DEB_OUT.replace("curl\t8.5.0-2ubuntu10.5\tamd64\tcurl\tii \n", ""),
                        dpkg_err="dpkg-query: no packages found matching curl\n", dpkg_code=1)
    sel = _select(monkeypatch, db=sup.FakeDB(_deb_rows()), host=host, family="debian")
    assert sel.error is None
    assert _held(sel)["curl"].code == "not_installed"
    # Cod 1 FĂRĂ un singur nume negăsit nu e «lipsă»: e o pană.
    host2 = sup.FakeHost(dpkg_out=DEB_OUT, dpkg_err="", dpkg_code=1)
    assert _select(monkeypatch, db=sup.FakeDB(_deb_rows()), host=host2, family="debian").error


#: Forma măsurată pe gazda n8n (Ubuntu 24.04): un nucleu dezinstalat al cărui fișier de configurare a
#: rămas — `dpkg-query -W` îl tipărește totuși, cu coloana de stare `rc`, iar `un` e un pachet
#: cunoscut dar niciodată instalat. Versiunile din rânduri sunt inventate.
DEB_REMOVED = ("linux-image-6.8.0-100-generic\t6.8.0-100.100\tamd64\tlinux-signed\trc \n"
               "oldlib\t1.0-1\tamd64\toldlib\tun \n")


def test_a_debian_package_that_is_not_installed_is_not_an_instance():
    """`dpkg-query -W` listează și pachetele dezinstalate cu configurația rămasă (`rc`) sau doar
    cunoscute (`un`). Numărate drept instalate, ar primi un `apt-get install pachet=versiune`
    peste ceva ce nu e pe gazdă — sau, mai rău, ar fi judecate «deja la versiunea care repară»."""
    installed, missing, error = su.parse_dpkg_query(DEB_OUT + DEB_REMOVED, "")
    assert error is None
    assert set(installed) == {"openssl", "libc6", "curl", "linux-image-generic"}
    assert missing == {"linux-image-6.8.0-100-generic", "oldlib"}


def test_a_removed_debian_kernel_is_reported_as_not_installed_not_held_as_a_kernel(monkeypatch):
    """Pe producția n8n există un `linux-image-...-generic` în starea `rc`. Dacă `select` l-ar socoti
    instalat, operatorul ar citi «install-only (nucleu)» despre un pachet care nu e pe disc — sau
    un `oldlib` `un` ar intra într-un plan. Spus corect: «nu e instalat», iar restul se planifică."""
    def row(i, pkg, fixed):
        return dict(id=i, package=pkg, cve=None, severity="medium", kev=False, priority=1,
                    fixed_version=fixed, ecosystem="deb", asset_id=None, asset_name=None,
                    asset_protected=False, fix_pending_reboot=False)
    rows = [*_deb_rows(), row(5, "linux-image-6.8.0-100-generic", "6.8.0-101.101"),
            row(6, "oldlib", "1.0-2")]
    host = sup.FakeHost(dpkg_out=DEB_OUT + DEB_REMOVED, dpkg_code=0)
    sel = _select(monkeypatch, db=sup.FakeDB(rows), host=host, family="debian")
    assert sel.error is None, sel.error
    held = _held(sel)
    assert held["linux-image-6.8.0-100-generic"].code == "not_installed"
    assert held["oldlib"].code == "not_installed"
    assert _planned(sel) == {"openssl", "libc6", "curl"}


# ---------------------------------------------------------------------------
# Stocarea
# ---------------------------------------------------------------------------
def test_store_lot_writes_the_plan_and_marks_it_notified_before_anything_is_sent(monkeypatch):
    """Planul de update e `generated_by <> 'ai'`, deci `unnotified_plans` îl oferă la fiecare 15
    secunde cât `notified_at` e NULL. Scris fără marcaj, bucla de push l-ar trimite a doua oară,
    cu alt set de butoane, în timp ce comanda trimite primul mesaj."""
    sel = _select(monkeypatch)
    order: list[tuple[str, dict]] = []

    async def store_plan(db, **kw):
        order.append(("store", kw))
        return 77

    async def mark(db, plan_id):
        order.append(("mark", {"id": plan_id}))

    monkeypatch.setattr(su.repo, "store_plan", store_plan)
    monkeypatch.setattr(su.repo, "mark_plan_notified", mark)
    plan_id = run(su.store_lot(object(), sel.lots[0]))

    assert plan_id == 77
    assert [k for k, _ in order] == ["store", "mark"] and order[1][1] == {"id": 77}
    kw = order[0][1]
    assert kw["generated_by"] == "update" and kw["model"] is None and kw["status"] == "validated"
    assert kw["finding_ids"] == sel.lots[0].finding_ids and kw["plan_hash"] == su.plan_hash(kw["plan"])


# ---------------------------------------------------------------------------
# După rulare
# ---------------------------------------------------------------------------
def _plan_for_reconcile(monkeypatch):
    return _select(monkeypatch).lots[0].plan


def test_reconcile_reads_the_host_and_uses_the_newest_instance(monkeypatch):
    """Starea unui pachet după rulare se citește de pe gazdă (`rpm`), nu din codul de ieșire al
    executorului. La un pachet cu mai multe instanțe contează cea mai nouă: dacă s-ar citi prima,
    un pachet corect instalat ar apărea ca «neschimbat»."""
    plan = _plan_for_reconcile(monkeypatch)
    meta = {p["name"]: p for p in plan["update"]["packages"]}
    names = sorted(meta)
    lines = []
    for i, name in enumerate(names):
        lines.append(sup.rpm_line(name, meta[name]["before"]))        # instanța veche, prima
        if i != 1:
            lines.append(sup.rpm_line(name, meta[name]["target"]))    # cea nouă; la al doilea lipsește
    sup.install(monkeypatch, sup.FakeHost("\n".join(lines) + "\n"))
    states, error = run(su.reconcile(plan, "rhel"))
    assert error is None
    by = {s.name: s for s in states}
    assert by[names[0]].state == su.STATE_TARGET and by[names[0]].now == meta[names[0]]["target"]
    assert by[names[1]].state == su.STATE_UNCHANGED


def test_reconcile_says_unread_not_unchanged_when_the_host_cannot_be_read(monkeypatch):
    plan = _plan_for_reconcile(monkeypatch)
    sup.install(monkeypatch, sup.FakeHost("not a package line\n"))
    states, error = run(su.reconcile(plan, "rhel"))
    assert states == [] and error


def test_one_garbled_line_spoils_the_answer_even_when_the_package_has_a_good_line():
    """Un `rpm -q` cu o linie ruptă la un pachet care MAI ARE o linie bună (nucleele se instalează
    în paralel) nu e un răspuns incomplet pe care să-l treacem cu vederea. Sărită în tăcere, linia
    ruptă — de obicei cea mai nouă instanță — face ca „cea mai nouă" să fie alta, iar planul spune
    «neschimbat» sau «reparația nu e pe disc» despre un pachet care o are. Verificarea „fiecare nume
    cerut a primit un răspuns" NU o prinde: numele a primit un răspuns, cel bun. Doar parserul o
    prinde."""
    good = sup.rpm_line("kernel-core", "5.14.0-100.1.el9", srpm="kernel-5.14.0-100.1.el9.src.rpm")
    garbled = "kernel-core\t(none):5.14.0-100.9.el9\tx86_64"      # tăiat: lipsește SOURCERPM
    installed, missing, error = su.parse_rpm_query(good + "\n" + garbled + "\n")
    assert error and "linia 2" in error
    assert installed == {} and missing == set(), "o parte din răspuns nu se folosește"
    # Control pozitiv: aceleași două linii, a doua întreagă, se parsează.
    whole = sup.rpm_line("kernel-core", "5.14.0-100.9.el9", srpm="kernel-5.14.0-100.9.el9.src.rpm")
    installed, _missing, error = su.parse_rpm_query(good + "\n" + whole + "\n")
    assert error is None and len(installed["kernel-core"]) == 2


def test_select_will_not_guess_the_newest_kernel_when_one_instance_line_is_garbled(monkeypatch):
    """Același defect, prin `select`: a treia instanță de nucleu vine ruptă. Fără eroare, nucleul
    ar fi judecat după primele două (mai vechi decât reparația), și răspunsul ar fi un motiv
    de reținere fals în loc de «nu pot citi starea»."""
    out = sup.rpm_query_output().splitlines()
    idx = max(i for i, ln in enumerate(out) if ln.startswith("kernel-core\t"))
    out[idx] = out[idx].rsplit("\t", 1)[0]                        # a treia instanță, fără SOURCERPM
    sel = _select(monkeypatch, host=sup.FakeHost("\n".join(out) + "\n"))
    assert sel.error and "linia" in sel.error and "nu pot" in sel.error, sel.error
    assert not sel.lots and not sel.held and not sel.already


def test_reconcile_will_not_call_a_package_unchanged_from_a_partly_garbled_answer(monkeypatch):
    """După rulare, «neschimbat» îi spune operatorului că nu e nimic de restaurat. Dacă instanța
    nouă a unui pachet vine ruptă și e sărită, rămâne doar cea veche — adică exact «neschimbat»,
    despre un pachet pe care tranzacția l-a instalat."""
    plan = _plan_for_reconcile(monkeypatch)
    meta = plan["update"]["packages"][0]
    lines = [sup.rpm_line(p["name"], p["target"]) for p in plan["update"]["packages"][1:]]
    lines += [sup.rpm_line(meta["name"], meta["before"]),
              f"{meta['name']}\t(none):{meta['target']}\tx86_64"]       # instanța nouă, ruptă
    sup.install(monkeypatch, sup.FakeHost("\n".join(lines) + "\n"))
    states, error = run(su.reconcile(plan, "rhel"))
    assert error and states == []


def test_detections_during_groups_by_rule_and_names_the_processes():
    """Un update își declanșează detectorii (`unit_change`: rpm scrie fișiere de unitate). Nu se
    suprimă nimic — se atribuie, ca operatorul să vadă că alerta coincide cu tranzacția."""
    import datetime as dt
    t = dt.datetime(2026, 10, 26, 10, 0, tzinfo=dt.timezone.utc)
    db = sup.FakeDB(execution={"started_at": t, "finished_at": t + dt.timedelta(minutes=3)},
                    detections=[
                        {"rule_id": "intrusion.persistence.unit_change", "severity": "critical",
                         "evidence": {"processes": ["/usr/bin/python3.9"]}},
                        {"rule_id": "intrusion.persistence.unit_change", "severity": "critical",
                         "evidence": '{"processes": ["/usr/bin/rpm"]}'},
                        {"rule_id": "intrusion.module_load", "severity": "critical", "evidence": {}}])
    got = run(su.detections_during(db, 5))
    by = {d["rule_id"]: d for d in got}
    assert by["intrusion.persistence.unit_change"]["count"] == 2
    assert by["intrusion.persistence.unit_change"]["processes"] == ["/usr/bin/python3.9", "/usr/bin/rpm"]
    assert by["intrusion.module_load"]["count"] == 1
    sql, args = [c for c in db.calls if "FROM detections" in c[0]][0]
    assert args == (t, t + dt.timedelta(minutes=3)), "fereastra nu e cea a execuției"


def test_no_detections_and_no_window_to_look_in_are_not_the_same_answer():
    """`[]` și «n-am avut unde să caut» arătau la fel în mesajul de după rulare: nimic. Pentru un
    operator care se uită după urma tranzacției în alerte, tăcerea înseamnă «curat» — și e
    adevărată doar în primul caz. Un rând de execuție lipsă sau fără oră de început nu e
    «nicio detecție»: se ridică, iar apelantul spune că n-a putut citi."""
    import datetime as dt
    t = dt.datetime(2026, 10, 26, 10, 0, tzinfo=dt.timezone.utc)
    # Control pozitiv: fereastră reală, nicio detecție -> listă goală, fără eroare.
    looked = sup.FakeDB(execution={"started_at": t, "finished_at": t + dt.timedelta(minutes=3)})
    assert run(su.detections_during(looked, 5)) == []
    assert [c for c in looked.calls if "FROM detections" in c[0]], "n-a căutat deloc"

    missing = sup.FakeDB(execution=None)
    with pytest.raises(su.NoExecutionWindow, match="#5"):
        run(su.detections_during(missing, 5))
    unstarted = sup.FakeDB(execution={"started_at": None, "finished_at": None})
    with pytest.raises(su.NoExecutionWindow, match="#5"):
        run(su.detections_during(unstarted, 5))
    assert not [c for c in missing.calls + unstarted.calls if "FROM detections" in c[0]], \
        "a căutat într-o fereastră inventată"


def test_category_counts_use_the_same_classification_as_the_vulnerability_page():
    """Categoria o hotărăște scanerul, prin `subject.describe` — nu o a doua hartă. «Containerele»
    nu sunt pachetele gazdei, și nu trebuie numărate ca actualizabile."""
    db = sup.FakeDB(scanners=[{"scanner": "dnf", "n": 347, "with_fix": 347},
                              {"scanner": "trivy_image", "n": 2536, "with_fix": 1679},
                              {"scanner": "trivy_fs", "n": 140, "with_fix": 140}])
    got = {c.kind: c for c in run(su.category_counts(db))}
    assert (got["os"].open_total, got["os"].with_fix) == (347, 347)
    assert (got["container"].open_total, got["container"].with_fix) == (2536, 1679)
    assert (got["app"].open_total, got["app"].with_fix) == (140, 140)
    assert "unknown" not in got, "«necunoscut» apare doar când are rânduri"


def test_reading_the_state_back_does_not_depend_on_the_install_only_query(monkeypatch):
    """După o rulare, versiunile pachetelor contează cel mai mult. Dacă a doua interogare
    («ce e install-only») ar putea ascunde starea, o pană la ea ar lăsa operatorul fără singurul
    lucru pe care voia să-l vadă."""
    plan = _plan_for_reconcile(monkeypatch)
    lines = [sup.rpm_line(p["name"], p["target"]) for p in plan["update"]["packages"]]
    sup.install(monkeypatch, sup.FakeHost("\n".join(lines) + "\n", provides="nimic util\n"))
    states, error = run(su.reconcile(plan, "rhel"))
    assert error is None and {s.state for s in states} == {su.STATE_TARGET}


def test_fits_refuses_a_plan_whose_timeouts_do_not_fit_the_approval_window(monkeypatch):
    """`approval.challenge` refuză un plan ale cărui timeouturi depășesc fereastra — după trei
    atingeri și PIN. Validatorul are aceeași regulă; `fits` o are și ea, ca lotul să nu depindă de
    ce face validatorul într-o zi cu o regulă mai slabă."""
    plan = su.build_plan([_plan_pkg("one"), _plan_pkg("two")], family="rhel", scope="system", number=1,
                         total=1, asset_id=None, asset_name=None)
    assert su.fits(plan, "rhel") == (True, None)
    monkeypatch.setattr(approval, "RUN_BUDGET_S", 100)
    ok, why = su.fits(plan, "rhel")
    assert not ok and "timeouturile" in why
