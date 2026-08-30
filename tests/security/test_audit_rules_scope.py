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

    keys = {"unealta": set(), "istoric": set(), "suid": set(), "module": set()}
    for line in lines:
        if not line.startswith("-a "):
            continue
        key = key_of(line)
        if re.search(r"-S execve", line):
            # DOUĂ întrebări diferite trec prin același syscall, iar ce le
            # deosebește e `-F path=`:
            #
            #   cu path  — «a rulat cineva `socat`?», un semnal de detecție;
            #   fără     — «ce s-a rulat în sesiunea asta?», o arhivă.
            #
            # Cu o cheie comună, regula care alertează pe unelte de atacator ar
            # primi FIECARE comandă rulată pe gazdă și ar declara fiecare `ls`
            # drept unealtă de atacator. Testul ăsta a fost scris când exista o
            # singură regulă `execve` și cerea egalitate cu numele ei; cerea
            # atunci același lucru pe care îl cere acum, doar că faptul s-a
            # schimbat, nu intenția.
            (keys["unealta"] if "-F path=" in line else keys["istoric"]).add(key)
        elif re.search(r"-S [^ ]*chmod", line):
            keys["suid"].add(key)
        elif re.search(r"-S [^ ]*init_module|delete_module", line):
            keys["module"].add(key)

    assert keys["unealta"] == {"sentinel_exec"}
    assert keys["istoric"] == {"sentinel_cmd"}
    assert keys["suid"] == {"sentinel_suid"}
    assert keys["module"] == {"sentinel_module"}
    assert not keys["unealta"] & keys["istoric"], (
        "regula de unelte de atacator și istoricul de comenzi împart o cheie, "
        "deci fiecare comandă rulată pe gazdă ar sosi la regula de detecție")


def test_the_command_history_only_watches_login_sessions(lines: list[str]) -> None:
    """Filtrul care ține istoricul de comenzi suportabil, și de ce e singurul.

    Regula lui e cea mai largă din tot fișierul: FIECARE `execve`. Ce o face
    posibilă pe o gazdă cu șase containere Docker e `-F auid!=unset` — procesele
    fără sesiune de login în spate (daemoni, cron, tot ce rulează într-un
    container) nu ajung niciodată la ea.

    Scos, filtrul nu produce nicio eroare și niciun test roșu. Produce zeci de
    mii de înregistrări pe oră, umple backlog-ul nucleului, iar de acolo încep să
    se piardă înregistrări — inclusiv cele care contează. Antetul fișierului
    numește exact asta: „aici mor seturile de reguli audit".

    Măsurat pe 24 august 2026: cu filtrul, câteva mii de înregistrări pe zi.
    """
    istoric = [x for x in lines
               if x.startswith("-a ") and "-S execve" in x and "sentinel_cmd" in x]
    assert istoric, "regula de istoric a dispărut din fișier"

    for regula in istoric:
        assert "-F auid!=unset" in regula, (
            f"regula de istoric nu mai cere o sesiune de login: {regula}\n"
            f"Fără filtru, fiecare proces al celor șase containere și fiecare "
            f"rulare de cron intră în istoric.")

    # Amândouă arhitecturile. Un binar pe 32 de biți intră prin altă tabelă, iar
    # un set de reguli care păzește numai b64 are o gaură exact de mărimea lui
    # „compilează-l pe 32 de biți" — una dintre cele mai vechi evaziuni de audit.
    arhitecturi = {x.split("-F arch=")[1].split()[0] for x in istoric}
    assert arhitecturi == {"b64", "b32"}, (
        f"istoricul acoperă doar {arhitecturi}; un binar de altă arhitectură "
        f"rulează nevăzut")


def test_the_kernel_backlog_is_sized_for_the_command_history(lines: list[str]) -> None:
    """Un backlog rămas la valoarea implicită pierde tăcut înregistrări.

    Peste plafon, nucleul ARUNCĂ, iar o înregistrare aruncată arată exact ca o
    comandă care n-a fost rulată. Istoricul tace fix în minutul aglomerat în care
    cineva lucrează repede — adică minutul care contează.

    320 era dimensionat pentru cele 17 urmăriri de fișiere de dinainte. Un singur
    deploy produce câteva mii de înregistrări într-o rafală.
    """
    backlog = [x for x in lines if x.startswith("-b ")]
    assert len(backlog) == 1, f"plafonul de backlog e declarat de {len(backlog)} ori"
    valoare = int(backlog[0].split()[1])
    assert valoare >= 4096, (
        f"backlog de {valoare}: prea mic pentru un `execve` pe fiecare comandă "
        f"dintr-o sesiune, deci se vor pierde înregistrări în rafale")

    astept = [x for x in lines if x.startswith("--backlog_wait_time")]
    assert astept, (
        "fără `--backlog_wait_time`, nucleul aruncă imediat ce backlog-ul se "
        "umple, în loc să aștepte — iar un syscall care întârzie o clipă e o "
        "mașină care pare lentă, pe când o înregistrare aruncată e un istoric "
        "care minte")


def test_bait_lines_are_the_last_rules_in_the_file(lines: list[str]) -> None:
    """Cerut in runda 2: chiar cu filtrul de existenta reparat, ordinea e o
    aparare gratuita. Daca vreodata o linie de momeala ajunge totusi refuzata
    -- o platforma noua, un colt al filtrului neacoperit -- pozitia de ultima
    face ca singurul lucru pierdut sa fie ea insasi, nu `sentinel_cmd` sau
    suprimarile `never,exit`."""
    bait_idx = [i for i, ln in enumerate(lines)
                if ln.startswith("-w ") and ln.rstrip().endswith("sentinel_bait")]
    assert bait_idx, "nicio regula de momeala gasita"
    assert bait_idx == list(range(len(lines) - len(bait_idx), len(lines))), (
        "liniile de momeala nu mai sunt ultimele din fisier: "
        f"{bait_idx} vs ultimele {len(bait_idx)} pozitii din {len(lines)}")


def test_bait_watch_is_read_only(lines: list[str]) -> None:
    """`-p r`, nu `-p rwxa`.

    Un `stat` (deci `ls`/`find`, exact ce face operatorul în diagnostic) nu e
    nici r, nici w, nici x, nici a — kernelul nu-l clasifică sub niciuna dintre
    cele patru, deci nici `-p rwxa` nu s-ar aprinde la o listare. Diferența
    reală e în cealaltă direcție: `a` s-ar aprinde la orice `chmod -R`,
    `chown -R` sau `restorecon` care nu citește conținutul, iar `w` la o
    restaurare de backup viitoare. Momeala trebuie să prindă DOAR citirea.
    """
    bait_rules = [ln for ln in lines
                  if ln.startswith("-w ") and ln.rstrip().endswith("sentinel_bait")]
    assert bait_rules, "nicio regulă de momeală în fișier"
    for rule in bait_rules:
        assert re.search(r"-p\s+r\s", rule), f"momeala nu e -p r: {rule}"
        assert "rwxa" not in rule and "wa" not in rule.split("-p")[1].split()[0], (
            f"momeala prinde mai mult decât citirea: {rule}")


def test_bait_files_sit_outside_every_other_watch(lines: list[str]) -> None:
    """O momeală sub o urmărire deja existentă ar produce acțiunea VECHE
    (`ssh_key_change`, `webroot_change`, ...), nu semnalul dedicat — exact
    coliziunea tăcută împotriva căreia avertizează planul funcționalității 05.
    """
    # Momeala se identifică după CHEIE, nu după o listă de căi copiată aici —
    # o listă scrisă a doua oară ar rămâne neschimbată dacă fișierul de reguli
    # se schimbă și ar trece, vacuu, exact defectul numit în CLAUDE.md.
    watches = [ln for ln in lines if ln.startswith("-w ")]
    bait_lines = [ln for ln in watches if ln.rstrip().endswith("sentinel_bait")]
    other = [ln.split()[1] for ln in watches if not ln.rstrip().endswith("sentinel_bait")]
    bait = [ln.split()[1] for ln in bait_lines]
    assert bait, "nicio cale de momeală găsită"
    for b in bait:
        for prefix in other:
            assert not (b == prefix or b.startswith(prefix.rstrip("/") + "/")), \
                f"{b} e deja acoperit de urmărirea {prefix}"


def test_the_configurable_bait_paths_match_the_shipped_watch_lines(lines: list[str]) -> None:
    """`CANARY_PGPASS_PATH`/`CANARY_AWS_CREDS_PATH` din `install.sh` afirmau
    deja, printr-un comentariu, ca sunt legate de fisierul static de reguli —
    dar nicio garda nu exista, si comentariul mintea. `sentinel.rules` e un
    fisier static: daca cineva schimba implicitul unei variabile fara sa
    schimbe si linia `-w`, sau invers, nucleul ajunge sa supravegheze o cale,
    iar instalatorul planteaza momeala pe alta — cele doua se despart tacut.
    """
    import re as _re

    install_sh = (RULES.parents[1] / "install.sh").read_text(encoding="utf-8")
    watch_paths = {ln.split()[1] for ln in lines
                   if ln.startswith("-w ") and ln.rstrip().endswith("sentinel_bait")}
    assert watch_paths, "nicio regula de momeala in fisierul de reguli"

    for var in ("CANARY_PGPASS_PATH", "CANARY_AWS_CREDS_PATH"):
        m = _re.search(rf'{var}="\$\{{{var}:-([^}}]+)\}}"', install_sh)
        assert m, f"{var} nu mai are o valoare implicita in install.sh"
        default = m.group(1)
        assert default in watch_paths, (
            f"{var} implicit e {default!r}, dar nicio linie -w din sentinel.rules "
            f"nu supravegheaza exact calea asta: {sorted(watch_paths)}")


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


# --- instalarea, nu doar conținutul ----------------------------------------
INSTALL_SH = RULES.parents[1] / "install.sh"


def _shell_function(source: str, name: str) -> str:
    """Corpul funcției livrate, ca aserțiunile să nu se potrivească din alt loc."""
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", source, re.S | re.M)
    assert match, f"funcția {name} nu mai există în install.sh"
    return match.group(0)


def test_rule_loading_does_not_discard_the_kernel_s_complaints() -> None:
    """`augenrules --load 2>/dev/null` face o regulă respinsă să arate ca una
    încărcată: fișierul e pe disc, pasul spune „installed", iar detecția care
    o citește pur și simplu nu se declanșează niciodată."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "augenrules --load 2>/dev/null" not in text
    assert "augenrules --load 2>&1" in text


def test_loaded_rules_are_verified_against_the_kernel() -> None:
    """Intenția noastră nu e o dovadă. O sintaxă pe care nucleul care rulează nu
    o suportă e altfel imposibil de deosebit de una pe care o suportă.

    Aserțiunea de aici era pe TEXTUL avertismentului — exact partea care se
    schimbă când se repară raportarea, deci exact partea care nu păzește nimic.
    Ce nu are voie să se schimbe e ce se compară: fiecare REGULĂ față de ce
    răspunde `auditctl -l`, cu NUMĂRUL ei. Verificarea pe cheie nu vedea o
    regulă respinsă care împărțea cheia cu una încărcată, și nu vedea deloc una
    fără cheie (`-a never,exit -F dir=…`) — măsurat pe Ubuntu 24.04.4, unde
    `auditctl -R` s-a oprit la `-F dir=/var/lib/docker` pe o gazdă fără docker
    și a lăsat neîncărcate exact regulile care opresc Sentinel din a-și audita
    propriile scrieri.

    Comportamentul e verificat prin rularea funcției livrate în
    `tests/security/test_installer_capture_and_rules.py`; aici se păzește doar
    decizia, ca o rescriere să nu se întoarcă tăcut la comparația pe chei.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "auditctl -l" in text

    # Aserțiunile de mai jos sunt pe CORPUL pasului, nu pe fișier. Căutate în
    # tot install.sh, două din trei treceau degeaba: `audit_rule_signatures`
    # apare și la definiție, iar `${#problems[@]}` apare și în pasul 35. O
    # căutare care se potrivește din alt motiv nu păzește nimic — s-a văzut la
    # falsificare, exact tiparul pe care CLAUDE.md îl numește.
    body = _shell_function(text, "install_audit_rules")

    # Nucleul rescrie ce i se dă (`a1&07000` -> `a1&0xE00`, `-k` -> `-F key=`),
    # deci comparația pe text brut e imposibilă și semnăturile sunt mecanismul.
    assert "audit_rule_signatures" in body, \
        "pasul nu mai trece regulile prin semnături, deci nu le mai poate compara"
    # Per regulă, cu numărul: prezența cheii nu mai e de ajuns.
    assert 'got_n >= want_sig["$sig"]' in body, \
        "pasul a revenit la o verificare care nu numără regulile"
    # Iar linia de succes atârnă de lista de probleme găsite, nu de un cod de
    # ieșire — altfel se întoarce „failed" urmat imediat de „confirmed loaded".
    assert "(( ${#problems[@]} ))" in body, \
        "verdictul nu mai atârnă de ce s-a găsit lipsă"


def test_the_beacon_is_restarted_not_merely_enabled() -> None:
    """`enable --now` pe un serviciu deja pornit nu face nimic. Procesul ar
    continua să ruleze codul de la deploy-ul anterior — pornit, sănătos, și
    fără reparația tocmai livrată."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "systemctl restart sentinel-beacon.service" in text
    assert "systemctl enable --now sentinel-beacon.service" not in text
