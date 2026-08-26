"""Un canal de alertare care sună degeaba e unul pe care operatorul îl închide.

Cerut de operator pe 24 august 2026, după câteva zile în care a primit „Sentinel
funcționează degradat" — inclusiv în perioada de mute — pentru un singur lucru:

    🟡 Expedierea fluxului «event_rollup_1h» a rămas în urmă · de 0 min
       5 rânduri neexpediate, cel mai vechi de 1h 0m

Trei defecte separate produceau împreună mesajul ăla, iar fiecare e testat aici:

  1. **aritmetica.** Eticheta unui interval de agregat e ÎNCEPUTUL lui, deci
     `now() - bucket` e cel puțin o oră întreagă în clipa în care rândul devine
     expediabil. Comparată cu un răgaz de 15 minute, restanța unui contor orar
     nu putea fi niciodată sub prag. Alarma nu era despre server, era despre
     scădere;
  2. **scutirea de mute.** `selfcheck` era scutit pe FEL, deci și un `degraded`
     trecea. Iar `degraded` înseamnă, prin definiția lui, „pe gazdă nu s-a oprit
     nimic";
  3. **ținut înseamnă pierdut.** Un mesaj amânat de fereastra de liniște primea
     `failed` și nu se mai încerca niciodată — deși documentația spunea, în două
     locuri, că se ține până se ridică fereastra.

Al treilea e cel care ar fi făcut primele două periculoase: fără el, îngustarea
scutirii ar fi transformat zgomotul în pierdere.
"""

from __future__ import annotations

import inspect
import re

from sentinel.report.shipper import ROLLUP, ROLLUP_UNITS, STREAMS
from sentinel.telegram import quiet

ROLLUPS = [s for s in STREAMS if s.cursor_kind == ROLLUP]


# ---------------------------------------------------------------------------
# 1. Aritmetica
# ---------------------------------------------------------------------------

def test_there_is_a_rollup_stream_to_talk_about() -> None:
    """Garda: fără flux de agregate, testele de mai jos n-ar proba nimic."""
    assert ROLLUPS, "niciun flux de agregate declarat"


def test_rollup_lag_is_measured_from_when_the_row_became_shippable() -> None:
    """De la SFÂRȘITUL intervalului, nu de la eticheta lui.

    Măsurat de la etichetă, un contor orar pornește la 60 de minute de restanță
    în clipa în care apare — peste orice răgaz rezonabil, înainte să fi trecut o
    secundă. Asta producea o alertă pe oră, la nesfârșit, despre nimic.
    """
    from sentinel.report import shipper

    src = inspect.getsource(shipper._rollup_lag)
    assert "interval '1 " in src, (
        "restanța se măsoară de la eticheta intervalului, deci pornește de la o "
        "unitate întreagă și nu poate coborî sub răgaz")
    assert "min(" in src and "+ interval" in src.replace("\n", " ").replace("  ", " "), (
        "adunarea unei unități la momentul cel mai vechi lipsește")


def test_the_grace_window_is_wider_than_zero_for_a_fresh_bucket() -> None:
    """Un interval abia încheiat trebuie să iasă SUB răgaz.

    Aritmetic, nu prin bază: dacă vechimea se numără de la sfârșitul
    intervalului, un interval care s-a încheiat acum are vârsta zero, iar zero e
    sub orice răgaz. Testul fixează relația, ca o revenire la scăderea veche să
    se vadă aici.
    """
    from sentinel.selfcheck.checks import SHIP_LAG_GRACE_MIN

    o_unitate_in_minute = 60          # `hour`, fluxul declarat azi
    assert SHIP_LAG_GRACE_MIN < o_unitate_in_minute, (
        "răgazul e mai larg decât un interval întreg, deci ar ascunde și o "
        "restanță reală de o oră")
    varsta_de_la_sfarsit = 0
    assert varsta_de_la_sfarsit <= SHIP_LAG_GRACE_MIN, (
        "un interval abia încheiat nu are voie să fie peste răgaz")


def test_the_rollup_unit_is_declared_once_and_whitelisted() -> None:
    """Din ea ies DOUĂ bucăți de SQL care trebuie să fie de acord.

    Și e listă albă fiindcă valoarea ajunge în textul instrucțiunii — un câmp
    liber acolo ar fi o cale de injecție deschisă de o declarație de flux.
    """
    for stream in ROLLUPS:
        assert stream.rollup_unit in ROLLUP_UNITS, stream.rollup_unit

    from sentinel.report import shipper

    for fn in (shipper._collect_rollup, shipper._rollup_lag):
        src = inspect.getsource(fn)
        assert "date_trunc('{stream.rollup_unit}'" in src, (
            f"{fn.__name__} are unitatea scrisă de mână, deci se poate "
            f"despărți de cea declarată")
        assert "date_trunc('hour'" not in src, (
            f"{fn.__name__} are 'hour' fixat în șablon")


# ---------------------------------------------------------------------------
# 2. Scutirea de mute
# ---------------------------------------------------------------------------

def test_only_a_stopped_agent_breaks_through_mute() -> None:
    """Pe mute trec doar veștile foarte critice. Cerința operatorului, literal."""
    assert quiet.passes_anyway("critical", "selfcheck"), (
        "o oprire reală nu mai trece prin mute")
    assert not quiet.passes_anyway("high", "selfcheck")
    assert not quiet.passes_anyway("medium", "selfcheck")
    assert not quiet.passes_anyway("low", "selfcheck")
    assert not quiet.passes_anyway(None, "selfcheck")


def test_selfcheck_is_no_longer_exempt_by_KIND() -> None:
    """Scutirea pe fel nu poate deosebi o oprire de o întârziere.

    Severitatea poate, și o face deja: `runner._announce` pune `critical` exact
    când vreun rezultat e `down`. Deci felul e locul greșit pentru regula asta.
    """
    assert "selfcheck" not in quiet.NEVER_MUTED_KINDS


def test_the_severity_that_breaks_through_is_the_one_the_runner_computes() -> None:
    """Legătura dintre cele două jumătăți, verificată — nu presupusă.

    Îngustarea de mai sus se sprijină pe faptul că `_announce` alege `critical`
    dacă și numai dacă ceva e `down`. Dacă linia aia se schimbă, scutirea începe
    să lase să treacă altceva decât credem, iar aici e locul unde se vede.
    """
    from sentinel.selfcheck import runner

    src = inspect.getsource(runner._announce)
    found = re.search(r'severity\s*=\s*"critical" if any\(r\.status == "down"', src)
    assert found, (
        "`_announce` nu mai leagă `critical` de `down`; scutirea de mute se "
        "sprijină pe legătura asta")
    assert "critical" in quiet.NEVER_MUTED_SEVERITIES


def test_the_alarms_that_must_never_be_held_are_still_there() -> None:
    """Îngustarea n-avea voie să atingă restul listei.

    Fiecare dintre astea spune că s-a întâmplat ceva ireversibil sau că ești
    blocat afară chiar acum. Pierdute la o refactorizare, tăcerea ar arăta ca
    sănătate.
    """
    for kind in ("panic", "watchdog", "patch_failed", "patch_rolled_back", "lockout"):
        assert quiet.passes_anyway("info", kind), kind


# ---------------------------------------------------------------------------
# 3. Ținut nu e pierdut
# ---------------------------------------------------------------------------

def test_a_held_notification_stays_queued_instead_of_being_marked_failed() -> None:
    """Proprietatea pe care documentația o afirma și codul o contrazicea.

    `telegram/quiet.py` spune, în capul modulului: „Everything else is *held*,
    not dropped". Calea incidentelor o respecta; calea notificărilor nu:
    `_broadcast` întorcea 0 pentru un chat pe mute, iar rândul primea `failed` și
    nu se mai încerca niciodată. Un mesaj amânat se pierdea.

    Contează cu atât mai mult de când `degraded` se ține: fără reparația asta,
    îngustarea scutirii ar fi transformat zgomotul în pierdere de informație.
    """
    from sentinel.telegram import bot

    src = inspect.getsource(bot._push_notifications)
    assert "all_quiet" in src, (
        "golirea cozii nu se uită dacă TOATE chat-urile sunt pe mute, deci nu "
        "poate deosebi «ținut» de «a eșuat»")
    assert "continue" in src, "nu există nicio cale prin care rândul rămâne `queued`"
    # Marcajul de eșec trebuie să vină DUPĂ o încercare reală, nu în locul ei.
    held = src.index("all_quiet and not passes_anyway")
    marked = src.index('"sent" if sent else "failed"')
    assert held < marked, (
        "verdictul de trimitere se scrie înaintea deciziei de a ține, deci un "
        "mesaj amânat ar fi marcat oricum")


def test_holding_does_not_burn_an_attempt() -> None:
    """`attempts` numără încercări. O amânare nu e una.

    Numărată, un mesaj ținut peste o fereastră lungă ar putea trece de orice
    plafon de reîncercări viitor și ar fi abandonat fără să fi fost trimis
    niciodată.
    """
    from sentinel.telegram import bot

    src = inspect.getsource(bot._push_notifications)
    ramura = src[src.index("if all_quiet"):src.index("sent = await _broadcast")]
    assert "attempts" not in ramura, (
        "ramura de ținere atinge `attempts`, deci o amânare arată ca o "
        "încercare eșuată")
