"""Ce anume cere Sentinel nucleului să înregistreze.

Fișierul de reguli auditd decide ce ajunge vreodată la detecție. O regulă prea
largă acolo nu se poate repara în aval: evenimentele sosesc oricum, umplu baza,
și orice regulă de detecție care le citește trebuie să ghicească ce a fost
administrare și ce a fost atac.

Testele de aici vin dintr-un eșec măsurat pe producție. Regula de chmod nu
filtra deloc biții de mod, deși comentariul de deasupra ei vorbea despre binare
setuid. Rezultatul: fiecare instalare producea sute de evenimente, iar fiindcă
împărțeau cheia de audit cu uneltele de rețea, ieșeau la suprafață ca „unealtă
de atacator executată: install".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RULES = (Path(__file__).resolve().parents[2] / "deploy" / "audit" / "sentinel.rules")


@pytest.fixture(scope="module")
def lines() -> list[str]:
    return [ln.strip() for ln in RULES.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def _syscall_rules(lines: list[str], syscall: str) -> list[str]:
    return [ln for ln in lines
            if ln.startswith("-a ") and re.search(rf"-S [^ ]*\b{syscall}\b", ln)]


def test_chmod_rules_filter_on_the_mode_bits(lines: list[str]) -> None:
    """Fără filtru, regula prinde `chmod 0644` la fel ca `chmod u+s`.

    Una e muncă, cealaltă e o ușă din dos. O regulă care nu le deosebește nu
    urmărește escaladarea de privilegii, urmărește activitatea.
    """
    rules = _syscall_rules(lines, "chmod") + _syscall_rules(lines, "fchmodat")
    assert rules, "regulile de chmod au dispărut"
    for rule in rules:
        assert re.search(r"-F a[12]&0?7000", rule), f"fără filtru pe biți de mod: {rule}"


def test_fchmodat_tests_the_right_argument(lines: list[str]) -> None:
    """Argumentul de mod e a1 la chmod/fchmod și a2 la fchmodat.

    O singură regulă pentru toate trei ar testa tăcut argumentul greșit pentru
    a treia — ar trece prin `auditctl` fără să se plângă și n-ar prinde nimic.
    """
    for rule in _syscall_rules(lines, "fchmodat"):
        assert "-F a2&" in rule, f"fchmodat trebuie să testeze a2: {rule}"
    for rule in _syscall_rules(lines, "chmod"):
        if "fchmodat" in rule:
            continue
        assert "-F a1&" in rule, f"chmod/fchmod trebuie să testeze a1: {rule}"


def test_three_different_questions_use_three_different_keys(lines: list[str]) -> None:
    """Cheia de audit e singurul lucru care ajunge la regula de detecție.

    Unelte de rețea, biți setuid și module de kernel sunt trei întrebări
    diferite. Când împărțeau o cheie, o singură regulă răspundea la toate trei
    cu aceeași propoziție — și greșit la două dintre ele.
    """
    def key_of(line: str) -> str | None:
        m = re.search(r"-(?:k|F key=)\s*([A-Za-z0-9_]+)", line)
        return m.group(1) if m else None

    keys = {"exec": set(), "suid": set(), "module": set()}
    for line in lines:
        if not line.startswith("-a "):
            continue
        key = key_of(line)
        if re.search(r"-S execve", line):
            keys["exec"].add(key)
        elif re.search(r"-S [^ ]*chmod", line):
            keys["suid"].add(key)
        elif re.search(r"-S [^ ]*init_module|delete_module", line):
            keys["module"].add(key)

    assert keys["exec"] == {"sentinel_exec"}
    assert keys["suid"] == {"sentinel_suid"}
    assert keys["module"] == {"sentinel_module"}


def test_every_key_used_is_known_to_the_collector(lines: list[str]) -> None:
    """O cheie pe care colectorul nu o cunoaște produce evenimente pe care
    nimeni nu le citește — cost de disc fără niciun semnal."""
    from sentinel.collectors.auditd import _WATCH_KEYS

    used = set(re.findall(r"-(?:k|F key=)\s*(sentinel_[a-z_]+)", "\n".join(lines)))
    unknown = used - set(_WATCH_KEYS)
    assert not unknown, f"chei fără mapare în colector: {unknown}"

    # Și invers: o mapare fără regulă e o regulă de detecție care nu se va
    # declanșa niciodată, fiindcă nucleul nu trimite nimic.
    unused = set(_WATCH_KEYS) - used
    assert not unused, f"mapări fără regulă de nucleu: {unused}"


def test_execve_rules_still_only_name_network_tools(lines: list[str]) -> None:
    """Lista trebuie să rămână scurtă și explicită.

    `attacker_tooling` ignoră acum orice binar despre care nu are o părere. Dacă
    cineva adaugă aici un binar fără să-l adauge și în TOOL_WEIGHT, evenimentele
    ar sosi și ar fi aruncate în tăcere.
    """
    from sentinel.detect.intrusion import TOOL_WEIGHT

    watched = set()
    for line in lines:
        m = re.search(r"-F path=/usr/bin/([a-z0-9_.-]+)", line)
        if m and "execve" in line:
            watched.add(m.group(1))
    assert watched, "nicio regulă de execve"
    assert watched <= set(TOOL_WEIGHT), f"urmărite fără severitate: {watched - set(TOOL_WEIGHT)}"
