"""Mesajul către operator: „reparațiile sunt instalate, dar nu rulează încă".

Ce citește operatorul înlocuiește cinci refuzuri și o alarmă la patru ore.
Cerința lui, din 29 septembrie 2026: o singură afirmație limpede — reparația e
instalată, o repornire o aplică, iată ce închide. Nu repornește Sentinel nimic.

`build_pending_reboot_message` e PURĂ, ca `build_message`: forma unui mesaj se
verifică fără bot.
"""
from __future__ import annotations

from sentinel.scan import announce

RUNNING = "5.14.0-687.46.1.el9_8.x86_64"
NEWEST = "5.14.0-687.51.1.el9_8"


def _row(cve="CVE-2026-0001", package="kernel-core", severity="high", kev=False,
         installed=NEWEST, id_=1):
    return {"id": id_, "cve": cve, "package": package, "severity": severity,
            "kev": kev, "installed": installed}


def _msg(rows, *, host="gazda", running=RUNNING):
    return announce.build_pending_reboot_message(rows, host=host, running=running)


def test_the_same_fix_on_five_packages_is_counted_once():
    """Aceeași reparație apare pe `kernel`, `kernel-core`, `kernel-devel`,
    `kernel-modules`, `kernel-modules-core`. Numărat pe rânduri, „15
    vulnerabilități" ar umfla de cinci ori ce se repară de fapt — iar operatorul
    ar decide o repornire pe o cifră pe care n-o poate reproduce.
    """
    pkgs = ("kernel", "kernel-core", "kernel-devel", "kernel-modules",
            "kernel-modules-core")
    rows = [_row(cve=f"CVE-2026-{c}", package=p, id_=i * 10 + j)
            for i, c in enumerate(("0001", "0002", "0003")) for j, p in enumerate(pkgs)]

    text = _msg(rows)

    assert "15 constatări (3 CVE-uri distincte" in text
    for p in pkgs:
        assert f"<code>{p}</code>" in text


def test_severity_is_the_worst_one_per_cve_not_per_row():
    """Un CVE `high` pe un pachet și `medium` pe altul e un CVE, nu două — și
    e `high`: nu se subestimează ce se închide."""
    rows = [_row(cve="CVE-A", package="kernel", severity="medium"),
            _row(cve="CVE-A", package="kernel-core", severity="high"),
            _row(cve="CVE-B", package="kernel", severity="low")]

    text = _msg(rows)

    assert "1 mari · 1 mici" in text, text
    assert "medii" not in text, "un CVE a fost numărat și la severitatea mai mică"


def test_the_actively_exploited_ones_are_named_and_counted_once():
    """KEV înseamnă „se exploatează chiar acum": e cifra care schimbă cât de repede
    repornește operatorul, deci apare cu numele CVE-ului, nu doar ca număr —
    și o dată, nu de cinci ori (o dată per pachet)."""
    rows = [_row(cve="CVE-2025-39964", package=p, kev=True, id_=i)
            for i, p in enumerate(("kernel", "kernel-core", "kernel-devel"))]

    text = _msg(rows)

    assert "1 se exploatează activ (KEV)" in text
    assert text.count("CVE-2025-39964") == 1


def test_a_long_kev_list_is_bounded_and_the_tail_is_the_count():
    rows = [_row(cve=f"CVE-2026-{i:04d}", kev=True, id_=i) for i in range(40)]

    text = _msg(rows)

    assert "40 se exploatează activ" in text
    assert f"și încă {40 - announce.MAX_KEV_LISTED}" in text
    listed = sum(1 for i in range(40) if f"CVE-2026-{i:04d}" in text)
    assert listed == announce.MAX_KEV_LISTED


def test_it_says_what_is_installed_and_what_runs():
    """Cele două versiuni, lângă ele, ca afirmația să nu fie de crezut pe cuvânt:
    operatorul le poate compara cu `uname -r` în zece secunde."""
    text = _msg([_row()])

    assert f"<code>{NEWEST}</code>" in text
    assert f"<code>{RUNNING}</code>" in text


def test_the_newest_installed_kernel_wins_across_rows():
    """Rândurile pot purta instalate diferite (pachete diferite, aceeași gazdă).
    Mesajul numește cea mai nouă — comparată ca rpm, nu ca text: `10` > `9`."""
    rows = [_row(installed="5.14.0-687.9.1.el9_8"),
            _row(installed="5.14.0-687.10.1.el9_8", id_=2)]

    text = _msg(rows)

    assert "<code>5.14.0-687.10.1.el9_8</code>" in text
    assert "687.9.1" not in text


def test_it_says_reboot_is_the_operators_decision():
    """Sentinel nu repornește nimic, și mesajul spune asta cu vorbele lui —
    ca decizia să rămână, vizibil, a operatorului."""
    text = _msg([_row()])

    assert "Sentinel nu repornește nimic" in text
    assert "repornești serverul" in text


def test_it_admits_what_it_cannot_check_and_gives_the_command():
    """Nucleul implicit la pornire nu se poate citi din scanare (`/boot/grub2` e
    doar pentru root). Dacă implicitul ar fi unul VECHI, repornirea n-ar aplica
    nimic — deci mesajul nu presupune, ci spune ce să verifice și cu ce se
    compară."""
    text = _msg([_row()])

    assert "Sentinel nu poate citi <code>/boot</code>" in text
    assert "sudo grubby --default-kernel" in text
    assert f"arate <code>{NEWEST}</code>" in text


def test_it_says_a_patch_plan_would_change_nothing_and_what_happens_after():
    text = _msg([_row()])

    assert "Un plan de patch pentru ele nu are ce instala" in text
    assert "scanarea nocturnă le închide singură" in text


def test_markup_in_a_package_or_host_name_cannot_break_the_message():
    """Numele vin din ieșirea unui scaner și dintr-o etichetă din configurație.
    Un `<` netratat rupe mesajul întreg, iar Telegram răspunde cu 400: singura
    veste despre repornire s-ar pierde din cauza unui caracter."""
    # `kev=True`: doar CVE-urile KEV sunt numite în mesaj.
    text = _msg([_row(package="kernel<script>x", cve="CVE-A&B", kev=True)],
                host="<gazda>")

    assert "<script>" not in text and "<gazda>" not in text
    assert "kernel&lt;script&gt;x" in text and "&lt;gazda&gt;" in text
    assert "CVE-A&amp;B" in text


def test_a_huge_host_still_fits_in_one_telegram_message():
    """500 de constatări pe 60 de pachete, 80 KEV: Telegram taie la 4096, iar ce
    se pierde e coada — adică exact ce scrie ce trebuie făcut. Mărginit aici,
    coada rămâne."""
    rows = [_row(cve=f"CVE-2026-{i:04d}", package=f"kernel-pachet-{i % 60}",
                 kev=(i % 6 == 0), id_=i) for i in range(500)]

    text = _msg(rows)

    assert len(text.encode("utf-16-le")) // 2 <= 4096
    assert "sudo grubby --default-kernel" in text, "coada a fost tăiată"
    assert "și încă" in text


def test_it_does_not_crash_without_versions():
    """Rândurile fără `installed`, sau `uname -r` necitit: mesajul spune ce știe
    și nu inventează o versiune."""
    text = _msg([_row(installed=None)], running=None)

    assert "un nucleu mai vechi" in text
    assert "un nucleu mai nou" in text
    assert "None" not in text


def test_a_long_package_list_is_bounded_and_the_tail_is_the_count():
    """Șaizeci de pachete nu se enumeră toate: lista are un plafon, iar coada e
    numărul. Fără el, pe o gazdă cu multe pachete de nucleu lista ar fi ea
    mesajul, iar ce trebuie făcut ar fi tăiat de Telegram."""
    rows = [_row(package=f"kernel-pachet-{i:02d}", id_=i) for i in range(60)]

    text = _msg(rows)

    listed = sum(1 for i in range(60) if f"<code>kernel-pachet-{i:02d}</code>" in text)
    assert listed == announce.MAX_PACKAGES_LISTED
    assert f"și încă {60 - announce.MAX_PACKAGES_LISTED}" in text


# --- ce spune despre expunere -----------------------------------------------------------
def test_with_an_exploited_cve_it_says_the_host_stays_exposed_and_to_hurry():
    """Constatările rămân deschise (și numărate ca KEV) fiindcă gazda E expusă. Mesajul
    trebuie să spună asta și să nu lase „când îți convine” lângă un CVE exploatat activ.

    Ce se strică altfel: operatorul citește „nicio grabă” despre un nucleu care are un
    CVE folosit în atacuri — iar cifrele din panou (încă KEV deschise) par să-l
    contrazică.
    """
    text = _msg([_row(kev=True, cve="CVE-2025-39964")])

    assert "Gazda rămâne expusă la ele până la repornire" in text
    assert "cât mai curând" in text
    assert "când îți convine" not in text
    assert "Rămân deschise în panou (și numărate ca KEV)" in text


def test_without_an_exploited_cve_it_does_not_manufacture_urgency():
    """Fără KEV nu există un motiv de grabă: „cât mai curând” la fiecare mesaj ar
    învăța operatorul să-l ignore."""
    text = _msg([_row(kev=False)])

    assert "când îți convine" in text
    assert "cât mai curând" not in text and "expusă la ele" not in text


# --- reamintirea zilnică -----------------------------------------------------------------
import datetime as _dt  # noqa: E402

TODAY = _dt.date(2026, 9, 30)


def _reminder(rows, *, host="gazda", running=RUNNING):
    return announce.build_pending_reboot_reminder(
        rows, host=host, running=running, today=TODAY)


def test_the_reminder_says_how_long_it_has_waited():
    """Ziua a treia arată altfel decât prima: „de 4 zile” e ce face un operator
    să repornească. Vine din `since`, dus înainte de la prima constatare."""
    text = _reminder([_row(kev=True) | {"since": "2026-09-26"}])

    assert "de 4 zile" in text


def test_the_reminder_omits_the_duration_on_the_first_day_and_when_unknown():
    """„de 0 zile” și „de None zile” ar fi zgomot."""
    same_day = _reminder([_row(kev=True) | {"since": "2026-09-30"}])
    no_date = _reminder([_row(kev=True)])
    bad_date = _reminder([_row(kev=True) | {"since": "nu e o dată"}])

    for text in (same_day, no_date, bad_date):
        assert "zile" not in text and "None" not in text


def test_the_reminder_names_each_cve_once_and_is_short():
    """Aceeași reparație pe cinci pachete e un CVE. Mesajul e singurul repetat, deci
    trebuie să rămână de câteva rânduri: nu enumeră pachete și nu repetă instrucțiunile
    întregi."""
    rows = [_row(cve="CVE-2025-39964", package=p, kev=True, id_=i)
            for i, p in enumerate(("kernel", "kernel-core", "kernel-devel"))]

    text = _reminder(rows)

    assert text.count("CVE-2025-39964") == 1
    assert "1 vulnerabilitate exploatată activ" in text
    assert len(text.splitlines()) <= 6


def test_the_reminder_is_bounded_for_many_cves():
    rows = [_row(cve=f"CVE-2026-{i:04d}", kev=True, id_=i) for i in range(40)]

    text = _reminder(rows)

    assert "40 vulnerabilități exploatate activ" in text
    assert f"și încă {40 - announce.MAX_KEV_LISTED}" in text
    assert len(text.encode("utf-16-le")) // 2 <= 4096


def test_the_reminder_says_the_host_is_exposed_and_that_it_stops_at_reboot():
    """Ce citește operatorul zilnic: reparația e instalată, gazda e expusă, ce
    verifică, și ce oprește mesajul — repornirea, nu tăcerea lui."""
    text = _reminder([_row(kev=True)])

    assert "gazda e expusă până la repornire" in text
    assert "Sentinel nu repornește nimic" in text
    assert "sudo grubby --default-kernel" in text
    assert "repornirea îl oprește" in text
    assert f"<code>{RUNNING}</code>" in text


def test_the_reminder_escapes_markup_and_survives_missing_data():
    """Ca mesajul integral: un `<` netratat face Telegram să refuze mesajul întreg."""
    text = _reminder([_row(cve="CVE-A<b>", kev=True, installed=None)],
                     host="<gazda>", running=None)

    assert "<gazda>" not in text and "CVE-A<b>" not in text
    assert "CVE-A&lt;b&gt;" in text and "&lt;gazda&gt;" in text
    assert "nucleul vechi" in text and "None" not in text
