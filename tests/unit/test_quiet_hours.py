"""Quiet hours — mostly tests about what still gets through.

An alerting channel that wakes you for a port scan gets muted permanently, and a
permanently muted channel is worse than none: it looks like coverage. So this
feature exists to keep the channel usable. Every test below that matters is
about the boundary between "quiet" and "silent", because only one of those is
acceptable in a security tool.
"""
from __future__ import annotations

from datetime import datetime, time, timedelta, timezone

import pytest

from sentinel.telegram import quiet

UTC = timezone.utc
BUCHAREST = "Europe/Bucharest"      # UTC+3 in August


# --- parsing ----------------------------------------------------------------
@pytest.mark.parametrize("text,start,end", [
    ("22:00-06:00", time(22, 0), time(6, 0)),
    ("22:00 - 06:00", time(22, 0), time(6, 0)),
    ("9:30-17:00", time(9, 30), time(17, 0)),
    ("00:00-23:59", time(0, 0), time(23, 59)),
])
def test_windows_parse(text, start, end):
    w = quiet.parse_window(text)
    assert w and w.start == start and w.end == end


@pytest.mark.parametrize("text", [
    "", "22:00", "25:00-06:00", "22:60-06:00", "22-6", "noapte",
    "22:00-06:00; DROP TABLE", "-06:00",
])
def test_nonsense_windows_are_rejected(text):
    assert quiet.parse_window(text) is None


def test_a_window_that_starts_when_it_ends_is_empty_not_eternal():
    """"22:00-22:00" is almost certainly a typo. Reading it as 24 hours of
    silence is the worst available interpretation of an ambiguous input."""
    w = quiet.parse_window("22:00-22:00")
    assert w is not None
    assert not w.contains(time(23, 0))
    assert not w.contains(time(10, 0))


@pytest.mark.parametrize("text,expected", [
    ("2h", timedelta(hours=2)),
    ("30m", timedelta(minutes=30)),
    ("45 minute", timedelta(minutes=45)),
    ("3 ore", timedelta(hours=3)),
    ("1d", timedelta(hours=24)),
])
def test_durations_parse(text, expected):
    assert quiet.parse_duration(text) == expected


def test_a_long_mute_is_capped_not_refused():
    """The intent of "/mute 7d" is perfectly clear. Honouring it literally would
    leave a security channel dark for a week."""
    assert quiet.parse_duration("7d") == quiet.MAX_ADHOC == timedelta(hours=24)


@pytest.mark.parametrize("text", ["", "0h", "abc", "-2h", "2 weeks"])
def test_nonsense_durations_are_rejected(text):
    assert quiet.parse_duration(text) is None


# --- the window that crosses midnight ---------------------------------------
NIGHT = quiet.Window(time(22, 0), time(6, 0))


@pytest.mark.parametrize("moment,inside", [
    (time(21, 59), False),
    (time(22, 0), True),      # inclusive at the start
    (time(23, 30), True),
    (time(0, 0), True),       # over midnight
    (time(3, 0), True),
    (time(5, 59), True),
    (time(6, 0), False),      # exclusive at the end
    (time(12, 0), False),
])
def test_overnight_window_membership(moment, inside):
    assert NIGHT.contains(moment) is inside


def test_daytime_window_does_not_wrap():
    day = quiet.Window(time(9, 0), time(17, 0))
    assert day.contains(time(12, 0))
    assert not day.contains(time(3, 0))
    assert not day.crosses_midnight


# --- local time, not UTC ----------------------------------------------------
def test_the_window_is_read_in_local_time():
    """The host runs UTC and Bucharest is UTC+3 in August. 20:00 UTC is 23:00
    locally — inside a 22:00-06:00 window. Getting this wrong silences three
    hours the operator wanted covered and leaves three they wanted quiet."""
    at_2000_utc = datetime(2026, 8, 4, 20, 0, tzinfo=UTC)
    assert quiet.evaluate(now=at_2000_utc, window=NIGHT, muted_until=None,
                          tz_name=BUCHAREST).muted
    # The same instant read as UTC would be 20:00 — outside the window.
    assert not quiet.evaluate(now=at_2000_utc, window=NIGHT, muted_until=None,
                              tz_name="UTC").muted


def test_the_host_zone_is_resolved_by_name_where_possible(monkeypatch, tmp_path):
    """`datetime.now().astimezone()` yields a FIXED offset — "+03:00", not
    "Europe/Bucharest". A fixed offset has no DST rules, so on the one night a
    year the clocks change, the end of the window is computed an hour wrong."""
    from pathlib import Path

    real_read = Path.read_text
    # Compared as a Path, not a string: on Windows `Path("/etc/timezone")`
    # stringifies with backslashes and the comparison silently never matches.
    etc_timezone = Path("/etc/timezone")

    def fake_read(self, *a, **kw):
        if self == etc_timezone:
            return "Europe/Bucharest\n"
        return real_read(self, *a, **kw)

    monkeypatch.setattr("pathlib.Path.read_text", fake_read)
    assert quiet.host_zone_name() == "Europe/Bucharest"
    # And a zone resolved by name knows about DST, unlike a fixed offset.
    from zoneinfo import ZoneInfo
    assert isinstance(quiet.zone(None), ZoneInfo)


def test_dst_does_not_shift_the_end_of_the_window():
    """Romania leaves EEST at 04:00 on the last Sunday of October. A window
    ending at 06:00 must still end at 06:00 local, not 05:00 or 07:00."""
    night_of_change = datetime(2026, 10, 24, 23, 0, tzinfo=UTC)  # 02:00 EEST
    state = quiet.evaluate(now=night_of_change, window=NIGHT, muted_until=None,
                           tz_name=BUCHAREST)
    assert state.muted
    local_end = state.until.astimezone(quiet.zone(BUCHAREST))
    assert (local_end.hour, local_end.minute) == (6, 0)


def test_a_named_zone_actually_resolves():
    """Guard the guard: without a tzdb, `zone()` falls back to the host and
    every timezone test above silently stops testing anything."""
    assert str(quiet.zone(BUCHAREST)) == BUCHAREST


def test_an_unknown_timezone_falls_back_loudly(caplog):
    """Silently defaulting to UTC would shift the window by hours without
    anyone knowing which hours are actually covered."""
    import logging

    with caplog.at_level(logging.ERROR):
        quiet.zone("Mars/Olympus_Mons")
    assert any("unknown timezone" in r.message for r in caplog.records)


def test_window_end_is_an_absolute_instant_in_the_future():
    now = datetime(2026, 8, 4, 23, 30, tzinfo=UTC)
    state = quiet.evaluate(now=now, window=NIGHT, muted_until=None, tz_name=BUCHAREST)
    assert state.muted and state.until is not None
    assert state.until > now
    assert state.until - now < timedelta(hours=24)


# --- ad-hoc mutes -----------------------------------------------------------
def test_an_expired_adhoc_mute_stops_muting():
    now = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
    past = now - timedelta(minutes=1)
    assert not quiet.evaluate(now=now, window=None, muted_until=past).muted


def test_an_active_adhoc_mute_wins_outside_any_window():
    now = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
    future = now + timedelta(hours=1)
    state = quiet.evaluate(now=now, window=NIGHT, muted_until=future, tz_name=BUCHAREST)
    assert state.muted and state.until == future


def test_no_mute_at_all_is_the_default():
    assert not quiet.evaluate(now=datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
                              window=None, muted_until=None).muted


# --- what is never muted ----------------------------------------------------
def test_critical_always_passes():
    assert quiet.passes_anyway("critical")
    assert quiet.passes_anyway("CRITICAL")


@pytest.mark.parametrize("sev", ["info", "low", "medium", "high", None, ""])
def test_everything_below_critical_can_be_held(sev):
    assert not quiet.passes_anyway(sev)


@pytest.mark.parametrize("kind", [
    "panic", "watchdog", "patch_failed", "patch_rolled_back", "lockout",
])
def test_the_safety_net_firing_is_never_silenced(kind):
    """These say your own protections fired, or that the host changed and then
    changed back. None of it keeps until morning."""
    assert quiet.passes_anyway("low", kind)
    assert quiet.passes_anyway(None, kind)


def test_the_never_muted_list_lives_in_code_not_config():
    """"Which alerts can be silenced" is a safety property. A config file is the
    wrong place to let someone silence the last one."""
    import inspect

    src = inspect.getsource(quiet)
    assert "NEVER_MUTED_SEVERITIES = frozenset" in src
    cfg = (__import__("pathlib").Path(__file__).resolve().parents[2]
           / "deploy" / "config" / "sentinel.yaml.tmpl").read_text(encoding="utf-8")
    assert "never_muted" not in cfg.lower()


# --- the push loop ----------------------------------------------------------
def test_quiet_hours_hold_alerts_rather_than_dropping_them():
    """`notified_at` stays NULL, so the batch goes out when the window lifts.
    Dropping would turn a convenience into a way to miss things."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_incidents)
    held = src.split("all_quiet", 1)[1].split("threshold", 1)[0]
    assert "mark_notified" not in held, "an alert is marked sent while nobody was told"
    assert "return" in held


def test_a_backlog_arrives_as_one_message():
    """Waking up to sixty notifications is functionally the same as waking up
    to none."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    assert bot.DIGEST_FLOOR >= 5
    assert "_push_incident_digest" in inspect.getsource(bot._push_incidents)


def test_a_broken_preferences_query_alerts_anyway():
    """Failing open is the only safe direction: a database error must not
    silence a security channel."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_loop)
    handler = src.split("except Exception", 1)[1].split("for name, fn", 1)[0]
    assert "quiet_chats = set()" in handler


def test_the_window_is_resolved_once_per_cycle():
    """Three sources must agree on whether it is quiet, and a slow cycle must
    not straddle the end of the window and send half a batch under the old
    answer."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_loop)
    assert src.count("_quiet_chats(") == 1
    assert "await fn(app, cfg, db, quiet_chats)" in src


def test_patch_failures_are_flagged_as_unmutable():
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_executions)
    assert "patch_rolled_back" in src and "patch_failed" in src
    assert "kind=kind" in src


# --- the command ------------------------------------------------------------
def test_mute_is_registered_with_an_unmute_escape_hatch():
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot.build_application)
    # Registered from the alias table rather than one call per command, so the
    # assertion is on the table.
    assert '("mute", "liniste")' in src
    assert '("unmute",)' in src


def test_unmute_clears_both_mechanisms():
    """An operator who says "stop muting" and still gets silence from the other
    mechanism has been handed a control that lies."""
    import inspect

    from sentinel.db.repo import chats
    src = inspect.getsource(chats.clear_all_mutes)
    assert "quiet_hours = NULL" in src and "muted_until = NULL" in src


def test_a_viewer_cannot_mute_anything():
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot.cmd_mute)
    assert "_can_act(cfg, chat_id)" in src
    assert src.index("_can_act") < src.index("context.args")


def test_mute_is_per_chat_not_global():
    """A shared setting would let one operator silence another's phone."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot.cmd_mute)
    assert "chat_id = update.effective_chat.id" in src
    assert "set_quiet_hours(db, chat_id" in src


def test_the_migration_does_not_silence_anyone():
    """A migration that quietly muted an existing installation overnight would
    be a security change nobody asked for."""
    from pathlib import Path

    sql = (Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"
           / "0015_quiet_hours.sql").read_text(encoding="utf-8")
    assert "UPDATE telegram_chats" not in sql
    assert "DEFAULT '22:00" not in sql


# --- programul pe zile ------------------------------------------------------
#
# Sambata dimineata la 06:00 nu e ca martea dimineata la 06:00. Fara reguli pe
# zile, operatorul are doua variante proaste: muta fereastra la 09:00 in fiecare
# zi si pierde trei ore de acoperire in fiecare dimineata de lucru, ori nu o
# muta si e trezit in weekend. A doua duce la un canal oprit permanent.

WEEKEND = "22:00-06:00; weekend 22:00-09:00"
# Ce voia de fapt operatorul: liniste SAMBATA si DUMINICA dimineata. Noptile
# care conteaza sunt ale lui vineri si sambata.
MORNINGS = "22:00-06:00; vi,sa 22:00-09:00"


def _at(day: int, hour: int, minute: int = 0) -> datetime:
    """August 2026: 3 = luni, 8 = sambata, 9 = duminica."""
    return datetime(2026, 8, day, hour, minute, tzinfo=UTC)


def _muted(spec: str, moment: datetime) -> bool:
    return quiet.evaluate(now=moment, schedule=quiet.parse_schedule(spec),
                          muted_until=None, tz_name="UTC").muted


def test_a_bare_window_still_means_every_day():
    """Formatul vechi e scris in bazele de date existente si in configurarile
    livrate. A-l invalida ar face ca o repornire sa dezactiveze tacut linistea
    pe care operatorul o setase — cea mai proasta scurgere posibila."""
    s = quiet.parse_schedule("22:00-06:00")
    assert len(s.rules) == 1
    assert s.rules[0].days == frozenset(range(7))
    assert str(s) == "22:00-06:00"


@pytest.mark.parametrize("text,expected", [
    ("weekend", {5, 6}),
    ("sa,du", {5, 6}),
    ("lu-vi", {0, 1, 2, 3, 4}),
    ("vi-lu", {4, 5, 6, 0}),        # trece peste sfarsitul saptamanii
    ("lucratoare", {0, 1, 2, 3, 4}),
    ("sâmbătă", {5}),
    ("sat sun", {5, 6}),
])
def test_day_sets_parse(text, expected):
    assert quiet.parse_days(text) == frozenset(expected)


@pytest.mark.parametrize("text", ["", "luni-", "marte", "weekendul", "8"])
def test_nonsense_days_are_refused(text):
    """Refuzate, nu interpretate generos. O zi ghicita gresit inseamna liniste
    intr-o zi in care operatorul voia sa fie treaz."""
    assert quiet.parse_days(text) is None


def test_the_specific_rule_beats_the_everyday_one():
    """Cine scrie „22:00-06:00; weekend 22:00-09:00" vrea evident ca weekendul
    sa castige, nu sa fie ignorat fiindca prima regula s-a potrivit deja."""
    # Duminica 07:00: regula zilnica s-ar fi terminat la 06:00.
    assert _muted(WEEKEND, _at(9, 7))


def test_a_crossing_window_belongs_to_the_evening_it_started():
    """Capcana centrala a functionalitatii.

    „weekend 22:00-09:00" acopera diminetile de DUMINICA si LUNI, fiindca
    ferestrele incep sambata si duminica seara. Sambata dimineata ramane pe
    regula zilnica, si se termina la 06:00.
    """
    assert not _muted(WEEKEND, _at(8, 7))       # sambata 07:00 — activ
    assert _muted(WEEKEND, _at(9, 7))           # duminica 07:00 — liniste
    assert _muted(WEEKEND, _at(10, 7))          # luni 07:00 — liniste, din duminica seara


def test_and_the_phrasing_that_gives_the_operator_what_they_asked_for():
    """`vi,sa` acopera exact diminetile de sambata si duminica."""
    assert _muted(MORNINGS, _at(8, 7))          # sambata 07:00
    assert _muted(MORNINGS, _at(9, 7))          # duminica 07:00
    assert not _muted(MORNINGS, _at(10, 7))     # luni 07:00 — inapoi la 06:00


def test_the_confirmation_names_the_mornings_not_just_the_evenings():
    """Diferenta dintre cele doua variante costa o comanda daca e spusa la
    setare, si o dimineata trezita daca e descoperita singur."""
    rule = quiet.parse_schedule("weekend 22:00-09:00").rules[0]
    text = quiet.covers(rule)
    assert "seara" in text and "diminea" in text
    assert "duminică" in text and "luni" in text     # diminetile acoperite


def test_outside_every_rule_the_channel_is_loud():
    for moment in (_at(4, 12), _at(8, 12), _at(9, 21, 59)):
        assert not _muted(WEEKEND, moment)


def test_the_end_reported_is_the_end_of_the_rule_that_matched():
    """Daca raportam sfarsitul regulii zilnice cat timp cea de weekend tine,
    mesajele retinute ar fi eliberate cu trei ore mai devreme — adica exact in
    orele pe care operatorul le ceruse linistite."""
    state = quiet.evaluate(now=_at(9, 7), schedule=quiet.parse_schedule(WEEKEND),
                           muted_until=None, tz_name="UTC")
    assert state.until.hour == 9


def test_a_schedule_round_trips_through_text():
    """Se salveaza ca text in baza de date si se reciteste la fiecare pornire.
    O reprezentare care nu se reciteste identic pierde tacut o regula."""
    for spec in (WEEKEND, MORNINGS, "22:00-06:00", "lu 01:00-02:00"):
        once = quiet.parse_schedule(spec)
        twice = quiet.parse_schedule(str(once))
        assert str(once) == str(twice)
        assert once == twice


def test_an_old_style_window_object_still_works():
    """Un apelant uitat care trece un `Window` trebuie sa taca la aceleasi ore,
    nu sa primeasca tacut un canal fara liniste deloc."""
    w = quiet.parse_window("22:00-06:00")
    assert quiet.evaluate(now=_at(4, 23), window=w, muted_until=None, tz_name="UTC").muted
    assert not quiet.evaluate(now=_at(4, 12), window=w, muted_until=None, tz_name="UTC").muted


def test_critical_still_passes_whatever_the_schedule_says():
    """Programul e despre cand suna telefonul degeaba, nu despre ce poate fi
    ascuns. Nicio combinatie de zile nu are voie sa atinga asta."""
    assert quiet.passes_anyway("critical")
    assert quiet.passes_anyway("info", kind="panic")
    assert quiet.passes_anyway("info", kind="selfcheck")


def test_when_two_rules_both_match_the_specific_one_decides_the_end():
    """Duminica la 23:00 se potrivesc AMANDOUA: si regula zilnica (22:00-06:00),
    si cea de weekend (22:00-09:00). Daca invinge prima scrisa, mesajele
    retinute pleaca la 06:00 — cu trei ore mai devreme decat a cerut operatorul,
    si exact in orele pe care le voia linistite.

    Prima varianta a acestui test folosea duminica la 07:00, cand regula zilnica
    nu se mai potriveste deloc. Trecea si cu „prima castiga", deci nu testa
    precedenta, ci doar ca ceva se potriveste.
    """
    state = quiet.evaluate(now=_at(9, 23), schedule=quiet.parse_schedule(WEEKEND),
                           muted_until=None, tz_name="UTC")
    assert state.muted
    assert state.until.hour == 9, "a castigat regula zilnica in locul celei de weekend"
    assert "weekend" in state.reason


# --- parserul si constrangerea din baza de date -----------------------------
#
# Ce s-a intamplat: `parse_schedule` accepta „22:00-06:00; vi,sa 22:00-09:00",
# adica exact exemplul pe care il ofera textul de ajutor al comenzii, iar CHECK-ul
# creat de migratia 0015 il respingea la scriere. Toate cele trei incercari ale
# operatorului au raspuns „A aparut o eroare la procesarea comenzii.", si ultima
# valoare salvata cu succes era de dinainte ca regulile pe zile sa existe.
#
# Cauza nu a fost pragul gresit, ci ca gramatica era scrisa de doua ori — o data
# in Python, o data in SQL — fara nimic care sa le lege. Testele de aici sunt
# legatura: iau valorile pe care le produce EFECTIV `str(Schedule)` si le trec
# prin regexul citit din FISIERUL DE MIGRATIE, nu dintr-o constanta Python. Un
# test care ar verifica parserul contra propriei lui constante ar trece si daca
# migratia ar lipsi cu totul.

import ast          # noqa: E402 - sectiune adaugata la sfarsitul fisierului
import asyncio      # noqa: E402
import functools    # noqa: E402
import re           # noqa: E402
from pathlib import Path  # noqa: E402
from types import SimpleNamespace  # noqa: E402

_REPO = Path(__file__).resolve().parents[2]
MIGRATIONS = _REPO / "sentinel" / "db" / "migrations"
CONSTRAINT = "telegram_chats_quiet_hours_shape"
BOT_SOURCE = _REPO / "sentinel" / "telegram" / "bot.py"

# Regexul din 0015, cel care a produs defectul. Pastrat aici ca sa se poata
# demonstra ca noul e o supramultime a lui.
OLD_SHAPE = r"^[0-2][0-9]:[0-5][0-9]-[0-2][0-9]:[0-5][0-9]$"


def _body(path: Path) -> str:
    """Fisierul fara liniile de comentariu — ce ajunge de fapt la PostgreSQL."""
    return "\n".join(line for line in path.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("--"))


def _shape_migrations() -> list[Path]:
    """Migratiile care (re)definesc constrangerea de forma, in ordinea versiunii."""
    found = [f for f in MIGRATIONS.glob("*.sql") if CONSTRAINT in _body(f)]
    assert found, f"nicio migratie nu mai defineste {CONSTRAINT}"
    return sorted(found, key=lambda f: int(re.match(r"^(\d+)_", f.name).group(1)))


def _effective_shape_migration() -> Path:
    """ULTIMA migratie care atinge constrangerea — aia decide ce e pe gazda.

    Cautata, nu numita. Prima varianta compara cu `0020_quiet_schedule.sql`
    hard-codat, iar mesajul ei de esec spunea „scrie o migratie noua". Cine facea
    exact asta ramanea rosu, fiindca testul se uita in continuare la 0020 —
    singura cale spre verde era sa EDITEZE 0020, pe care `db/migrate.py` il
    refuza pe orice gazda unde a fost deja aplicat („Migrations are immutable
    once applied"), iar `deploy/install.sh` transforma refuzul in `die`. Adica
    fixarea indruma spre singura editare pe care runner-ul e construit s-o
    respinga.
    """
    return _shape_migrations()[-1]


def _migration_body() -> str:
    return _body(_effective_shape_migration())


@functools.lru_cache(maxsize=1)
def _constraint_pattern() -> str:
    latest = _effective_shape_migration()
    found = re.findall(r"quiet_hours\s*~\s*'([^']*)'", _body(latest))
    assert len(found) == 1, \
        f"astept exact un regex de forma in {latest.name}, am gasit {len(found)}: {found}"
    return found[0]


def _accepted_by_postgres(value: str) -> bool:
    """`quiet_hours ~ '<regex>'` evaluat ca in PostgreSQL, nu ca in Python.

    In Python `$` potriveste si INAINTEA unui newline final; in PostgreSQL
    potriveste doar sfarsitul sirului. Fara conversia asta, o valoare terminata
    in newline ar trece aici si ar fi respinsa pe gazda — exact genul de
    verificare care confirma intentia in loc de efect.
    """
    pattern = _constraint_pattern()
    assert pattern.endswith("$"), "regexul din migratie nu mai e ancorat la sfarsit"
    return re.search(pattern[:-1] + r"\Z", value) is not None


def _accepted_by_the_old_constraint(value: str) -> bool:
    return re.search(OLD_SHAPE[:-1] + r"\Z", value) is not None


# --- ce ar scrie de fapt comanda --------------------------------------------

# Id de fixtura, nu al operatorului. Depozitul e public, iar un chat id real
# leaga depozitul de contul lui de Telegram — pe lista de sanitizare scrie
# explicit „fara chat id".
#
# Telegram NU are un interval rezervat pentru exemple, cum are RFC 5737 pentru
# adrese: id-urile se aloca secvential, deci orice numar scris aici poate fi al
# cuiva. Sirul 1..0 e ales fiindca se citeste ca substituent din prima privire,
# iar codul nu trimite nimic catre el: acelasi numar ajunge si in
# `allowed_chat_ids`, si in `effective_chat.id`, deci se verifica doar ca cele
# doua coincid.
FIXTURE_CHAT_ID = 1234567890


def _cfg(chat_id: int) -> SimpleNamespace:
    return SimpleNamespace(telegram=SimpleNamespace(
        allowed_chat_ids=[chat_id], owner_chat_id=None, operator_chat_ids=[],
        quiet_hours=None, timezone="Europe/Bucharest"))


class _Written:
    """Ce a ajuns in fiecare coloana, dupa o rulare a lui `cmd_mute`."""

    def __init__(self) -> None:
        self.quiet_hours: list[str | None] = []
        self.muted_until: list[object] = []
        self.cleared = 0
        self.replies: list[str] = []


def _run_mute(arg: str, monkeypatch, chat_id: int = FIXTURE_CHAT_ID, *,
              prefs: dict | None = None) -> _Written:
    """Ruleaza `cmd_mute` cu argumentul asta si raporteaza ce s-a scris.

    Prin comanda reala, nu printr-o reimplementare a ramurilor ei: o copie a
    ordinii `off` / program / durata ar ramane in urma tacut, si tocmai despre
    ramas-in-urma-tacut e tot fisierul asta.
    """
    pytest.importorskip("telegram")
    from sentinel.db.repo import chats as chats_repo
    from sentinel.telegram import bot

    seen = _Written()

    async def fake_get_prefs(db, cid):
        return chats_repo.ChatPrefs(chat_id=cid, **(prefs or {}))

    async def fake_set_quiet_hours(db, cid, window, *, tz=None):
        seen.quiet_hours.append(window)

    async def fake_set_muted_until(db, cid, until):
        seen.muted_until.append(until)

    async def fake_clear_all_mutes(db, cid):
        seen.cleared += 1

    monkeypatch.setattr(chats_repo, "get_prefs", fake_get_prefs)
    monkeypatch.setattr(chats_repo, "set_quiet_hours", fake_set_quiet_hours)
    monkeypatch.setattr(chats_repo, "set_muted_until", fake_set_muted_until)
    monkeypatch.setattr(chats_repo, "clear_all_mutes", fake_clear_all_mutes)

    async def reply_text(text, **_kw):
        seen.replies.append(text)

    message = SimpleNamespace(text=f"/mute {arg}", caption=None, reply_text=reply_text)
    update = SimpleNamespace(effective_chat=SimpleNamespace(id=chat_id),
                             effective_message=message, message=message)
    context = SimpleNamespace(args=arg.split(), bot_data={"cfg": _cfg(chat_id), "db": object()})

    asyncio.run(bot.cmd_mute(update, context))
    return seen


def _mute_help_examples() -> list[str]:
    """Argumentele `/mute ...` oferite operatorului, scoase din `_MUTE_HELP`.

    Prin `ast`, din sursa, nu prin import: `bot.py` importa `telegram`, iar un
    `importorskip` la nivel de colectare ar face ca lista sa iasa goala si testul
    parametrizat sa dispara tacut — exact tiparul de test care nu verifica nimic.
    """
    tree = ast.parse(BOT_SOURCE.read_text(encoding="utf-8"))
    text = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "_MUTE_HELP" for t in node.targets):
            text = ast.literal_eval(node.value)
    assert text, "_MUTE_HELP nu a fost gasit in bot.py"
    return [m.group(1).strip() for m in re.finditer(r"<code>/mute ([^<]*)</code>", text)]


def test_the_help_text_examples_were_actually_extracted():
    """Guard pe guard: daca extragerea din `_MUTE_HELP` iese goala, testul
    parametrizat de mai jos trece cu zero cazuri si nu mai apara nimic — iar
    exemplul cu doua reguli e chiar cel care pica pe gazda."""
    examples = _mute_help_examples()
    assert len(examples) >= 4, examples
    assert any(";" in e for e in examples), "exemplul cu doua reguli a disparut din ajutor"
    assert "off" in examples
    assert any(quiet.parse_duration(e) is not None for e in examples)


@pytest.mark.parametrize("example", _mute_help_examples())
def test_every_example_in_the_help_text_can_actually_be_saved(example, monkeypatch):
    """Bug-ul raportat, in forma lui exacta.

    Textul de ajutor al comenzii ofera `/mute 22:00-06:00; vi,sa 22:00-09:00` ca
    exemplu, iar constrangerea din baza il respingea. O comanda care isi
    contrazice propriul ajutor lasa operatorul convins ca a gresit el.
    """
    seen = _run_mute(example, monkeypatch)
    assert seen.replies, f"/mute {example} nu a raspuns nimic"
    assert "Nu am inteles" not in seen.replies[-1] and "Nu am înțeles" not in seen.replies[-1], \
        f"/mute {example} nu mai e inteles de parser"

    for value in seen.quiet_hours:
        assert value is not None
        assert _accepted_by_postgres(value), (
            f"/mute {example} scrie {value!r}, pe care CHECK-ul din 0020 il respinge")

    if example.lower() == "off":
        # `off` sterge scriind NULL; ramura `IS NULL` a constrangerii o acopera.
        assert seen.cleared == 1 and not seen.quiet_hours
    elif quiet.parse_schedule(example) is not None:
        assert len(seen.quiet_hours) == 1
    else:
        # `2h` — pauza ad-hoc, alta coloana; nu atinge `quiet_hours` deloc.
        assert seen.muted_until and not seen.quiet_hours


# Fiecare forma pe care o descrie ajutorul, plus fiecare prescurtare si fiecare
# grup pe care le cunoaste parserul. Scrise ca INTRARI ale operatorului; ce se
# verifica e ce iese din `str(Schedule)`.
TYPEABLE_SCHEDULES = [
    "22:00-06:00",
    "22:00-06:00; du,sa 22:00-09:00",
    "22:00-06:00; vi,sa 22:00-09:00",
    "22:00-06:00; weekend 22:00-09:00",
    "22:00-06:00; lucratoare 23:00-07:00",
    "weekend 22:00-09:00",
    "lucratoare 23:00-07:00",
    "lu-vi 23:00-07:00",
    "vi-lu 22:00-09:00",
    "sâmbătă 08:00-09:00",
    "sat sun 22:00-09:00",
    "zilnic 00:00-23:59",
    "lu 01:00-02:00; ma 02:00-03:00; mi 03:00-04:00; jo 04:00-05:00",
    "22:00 - 06:00",
    "9:30-17:00",
    "00:00-23:59",
] + [f"{day} 22:00-06:00" for day in ("lu", "ma", "mi", "jo", "vi", "sa", "du",
                                      "luni", "marti", "marți", "miercuri", "joi",
                                      "vineri", "sambata", "sâmbătă", "duminica",
                                      "duminică", "mon", "tue", "wed", "thu", "fri",
                                      "sat", "sun")
  ] + [f"{group} 22:00-06:00" for group in ("weekend", "wk", "lucratoare", "lucrătoare",
                                            "weekdays", "zilnic", "toate")]


@pytest.mark.parametrize("typed", TYPEABLE_SCHEDULES)
def test_every_schedule_the_parser_accepts_is_one_the_database_accepts(typed, monkeypatch):
    """Directia care a produs pana: parserul spune da, baza spune nu, si
    operatorul afla ca „a aparut o eroare".

    Numele complete de zile si grupurile alternative sunt aici pentru ca
    `str(Schedule)` le NORMALIZEAZA — „duminică" devine „du", „toate" dispare cu
    totul. Daca normalizarea se schimba si incepe sa scrie forma tastata, regexul
    nu o mai accepta si testul pica aici, nu la 22:00 pe telefonul cuiva.
    """
    assert quiet.parse_schedule(typed) is not None, f"{typed!r} nu mai e acceptat de parser"
    seen = _run_mute(typed, monkeypatch)
    assert len(seen.quiet_hours) == 1, f"/mute {typed} nu a mai ajuns pe ramura de program"
    stored = seen.quiet_hours[0]
    assert _accepted_by_postgres(stored), \
        f"/mute {typed} scrie {stored!r}, pe care CHECK-ul din 0020 il respinge"
    # Si se recitește identic: coloana e recitita la fiecare pornire a botului.
    assert str(quiet.parse_schedule(stored)) == stored


def test_the_constraint_accepts_every_clock_value_the_formatter_can_print():
    """`%H:%M` produce 00:00–23:59. O ora pe care formatorul o scrie si regexul
    nu o accepta ar face ca `/mute` sa mearga pentru unele ore si nu pentru
    altele — cel mai greu fel de defect de crezut cand il raporteaza cineva."""
    for hour in range(24):
        for minute in (0, 1, 30, 59):
            spec = f"{hour:02d}:{minute:02d}-{(hour + 1) % 24:02d}:{minute:02d}"
            stored = str(quiet.parse_schedule(spec))
            assert _accepted_by_postgres(stored), stored
            assert _accepted_by_postgres(str(quiet.parse_schedule(f"vi,sa {spec}")))


def test_nothing_the_old_constraint_allowed_becomes_invalid():
    """`ADD CONSTRAINT` valideaza randurile existente inainte sa se aplice. Daca
    noul regex e mai ingust undeva, migratia cade pe gazda si schema se opreste
    la 19 — inclusiv pentru toate migratiile de dupa.

    Regexul din 0015 accepta ore pana la 29, pe care parserul nu le produce, dar
    pe care cineva le-ar fi putut scrie direct in coloana."""
    for hour in range(30):
        for minute in range(60):
            value = f"{hour:02d}:{minute:02d}-{hour:02d}:{minute:02d}"
            assert _accepted_by_the_old_constraint(value), value
            assert _accepted_by_postgres(value), \
                f"0015 accepta {value!r}, 0020 nu — ADD CONSTRAINT cade pe randul asta"


@pytest.mark.parametrize("junk", [
    "",                                  # gol nu e o stare; „fara program" e NULL
    " ",
    "22:00",
    "noapte",
    "vi,sa",                             # zile fara fereastra
    "22:00-06:00 vi,sa",                 # zilele dupa fereastra
    "weekendul 22:00-06:00",
    "; 22:00-06:00",
    "22:00-06:00; ",
    "22:00-06:00\n",                     # `$` in PostgreSQL nu iarta newline-ul
    "22:00-06:00\n22:00-06:00",
    "DROP TABLE telegram_chats",
    "22:00-06:00; DROP TABLE telegram_chats",
])
def test_the_constraint_still_keeps_garbage_out(junk):
    """CHECK-ul a fost largit, nu desfiintat. O coloana in care incape orice text
    inseamna ca la urmatoarea pornire `parse_schedule` returneaza None si
    linistea dispare tacut — operatorul crede ca e setata si telefonul suna."""
    assert not _accepted_by_postgres(junk), f"{junk!r} nu ar trebui acceptat"


def test_the_latest_migration_carries_exactly_the_regex_the_parser_publishes():
    """Legatura care lipsea.

    Daca gramatica se largeste in `quiet.py` — o zi noua, un separator nou — si
    nimeni nu scrie o migratie, `SCHEDULE_SQL_REGEX` se schimba, ultima migratie
    nu, si testul asta pica. Fara el, urmatoarea largire repeta exact aceeasi
    pana cu alt prag.

    Se uita la ULTIMA migratie care atinge constrangerea, gasita prin cautare.
    Cu un nume hard-codat, remediul pe care il recomanda — „scrie o migratie
    noua" — nu ar fi functionat: cine scria un 0021 corect ramanea rosu, si
    singura cale spre verde era sa editeze o migratie deja aplicata, exact ce
    refuza `db/migrate.py`.
    """
    latest = _effective_shape_migration()
    assert _constraint_pattern() == quiet.SCHEDULE_SQL_REGEX, (
        f"regexul din {latest.name} nu mai e cel produs de "
        "quiet.SCHEDULE_SQL_REGEX.\n"
        "Adauga o migratie NOUA, cu numar mai mare (nu edita una aplicata), care "
        "sa recreeze constrangerea cu:\n  " + quiet.SCHEDULE_SQL_REGEX
    )


def test_clearing_the_schedule_is_still_possible():
    """`/mute off` sterge scriind NULL. O constrangere fara ramura `IS NULL` ar
    face ca oprirea linistii sa fie ea insasi o eroare — adica un canal pe care
    nu-l mai poti reporni de pe telefon."""
    assert re.search(r"CHECK\s*\(\s*quiet_hours IS NULL OR quiet_hours ~", _migration_body())


@pytest.mark.parametrize("path", _shape_migrations(), ids=lambda p: p.name)
def test_no_migration_touches_anyone_s_schedule(path):
    """Ca la 0015: o migratie care ar rescrie programele existente ar schimba
    orele in care serverul cuiva nu mai e supravegheat, fara sa ceara nimeni.

    Toate migratiile care ating constrangerea, nu doar ultima: interdictia e
    despre coloana, si se aplica si celei pe care o scrie urmatorul om.
    """
    body = _body(path)
    assert "UPDATE telegram_chats" not in body
    assert "DELETE" not in body.upper()


# --- momentul afisat operatorului -------------------------------------------
#
# `_fmt_local` era apelat din trei locuri din `bot.py` si nu era definit
# nicaieri — al doilea nume de felul asta in acelasi fisier, dupa `_MUTE_HELP`.
# Consecinta: `/mute 2h` si `/mute` fara argumente cu o pauza activa ridicau
# NameError si raspundeau „A aparut o eroare la procesarea comenzii." — adica
# exact simptomul pentru care operatorul tocmai raportase constrangerea, pe alta
# cauza. Ramuri rar atinse: nu se vad la import si nu se vad cand nu e nicio
# liniste setata.

BUCHAREST_ZONE = "Europe/Bucharest"


def _local_parts(moment: datetime) -> tuple[int, int, int, int]:
    """(zi, luna, ora, minut) in fusul chatului, calculate independent de bot."""
    from zoneinfo import ZoneInfo

    local = moment.astimezone(ZoneInfo(BUCHAREST_ZONE))
    return local.day, local.month, local.hour, local.minute


def _shown_moments(reply: str) -> list[tuple[int, int, int, int]]:
    return [(int(d), int(mo), int(h), int(mi))
            for d, mo, h, mi in re.findall(r"(\d{2})\.(\d{2}) (\d{2}):(\d{2})", reply)]


def test_an_adhoc_pause_answers_with_the_moment_it_expires(monkeypatch):
    """`/mute 2h` e o forma pe care `_MUTE_HELP` o ofera explicit, si raspunsul ei
    e singurul loc in care operatorul afla PANA CAND a tacut canalul. Fara
    momentul asta, comanda de pauza e o comanda pe care nu o poti verifica."""
    seen = _run_mute("2h", monkeypatch)

    assert len(seen.muted_until) == 1 and not seen.quiet_hours
    until = seen.muted_until[0]
    assert seen.replies and "Pauză până la" in seen.replies[0]

    shown = _shown_moments(seen.replies[0])
    assert shown == [_local_parts(until)], \
        f"raspunsul arata {shown}, momentul scris in baza e {_local_parts(until)}"


def test_the_moment_is_shown_in_the_chat_s_zone_not_in_utc(monkeypatch):
    """Gazda ruleaza UTC si baza stocheaza UTC. Un „pana la 21:00" citit in UTC
    de un operator din Bucuresti inseamna doua-trei ore de tacere pe care nu le-a
    cerut si nu le poate explica."""
    seen = _run_mute("2h", monkeypatch)
    until = seen.muted_until[0]
    day, month, hour, minute = _shown_moments(seen.replies[0])[0]

    assert (hour, minute) != (until.hour, until.minute), \
        "momentul e afisat in UTC — `astimezone` lipseste"
    assert (day, month, hour, minute) == _local_parts(until)


def test_the_status_reply_shows_an_active_pause_and_when_it_lifts(monkeypatch):
    """`/mute` fara argumente e comanda cu care afli DACA esti in liniste. Cand
    exista o pauza activa, ea atingea doua apeluri catre `_fmt_local` si pica —
    deci singurul mod de a descoperi ca statusul nu merge era sa-l ceri exact
    atunci cand chiar aveai nevoie de el.

    Momentul e fixat in decembrie, deci Bucurestiul e UTC+2 si nu UTC+3: un fus
    citit cu offset fix in loc de dupa nume ar da alta ora aici.
    """
    pause_ends = datetime(2026, 12, 24, 20, 30, tzinfo=UTC)
    seen = _run_mute("", monkeypatch, prefs={"muted_until": pause_ends})

    assert len(seen.replies) == 1
    reply = seen.replies[0]
    assert "Pauză activă până la" in reply
    assert "pauză temporară" in reply, "linia de stare curenta nu s-a randat"
    # 20:30 UTC pe 24 decembrie = 22:30 la Bucuresti.
    assert _shown_moments(reply) == [(24, 12, 22, 30), (24, 12, 22, 30)]
    assert not seen.quiet_hours and not seen.muted_until and seen.cleared == 0


def test_a_naive_datetime_is_not_read_silently_as_process_local_time(caplog):
    """Baza intoarce `timestamptz`, deci un moment naiv inseamna ca altceva e
    stricat. `.astimezone()` l-ar citi tacut in ora procesului — corect pe gazda,
    gresit oriunde altundeva, si fara nimic care sa spuna ca s-a ghicit."""
    import logging

    pytest.importorskip("telegram")
    from sentinel.telegram import bot

    naive = datetime(2026, 12, 24, 20, 30)
    with caplog.at_level(logging.WARNING, logger="sentinel.telegram.bot"):
        shown = bot._fmt_local(naive, BUCHAREST_ZONE)

    assert shown == "24.12 22:30", shown       # citit ca UTC, afisat la Bucuresti
    assert any("naive datetime" in r.getMessage() for r in caplog.records)


def test_the_format_is_the_one_the_rest_of_the_bot_already_uses():
    """Blocklistul tipareste expirarile ca `%d.%m %H:%M`. Un al doilea format
    pentru acelasi lucru — „pana cand" — face doua mesaje sa nu poata fi
    comparate dintr-o privire pe telefon."""
    pytest.importorskip("telegram")
    from sentinel.telegram import bot

    moment = datetime(2026, 8, 9, 21, 5, tzinfo=UTC)
    assert bot._fmt_local(moment, "UTC") == "09.08 21:05"
