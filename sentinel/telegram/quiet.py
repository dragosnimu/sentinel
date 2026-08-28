"""Quiet hours: when the bot stops buzzing, and what buzzes anyway.

An alerting channel that wakes you at 3 a.m. for a port scan is one you will
mute permanently within a week, and a permanently muted channel is worse than no
channel — it looks like coverage and provides none. So this exists to keep the
channel usable, not to make it quieter.

Two mechanisms, deliberately separate:

  * **A recurring window** — "22:00-06:00", the normal case. Set once, applies
    every night.
  * **An ad-hoc mute until a moment** — "/mute 2h", for a maintenance window or
    a deliberately noisy test. Expires on its own; there is no way to mute
    indefinitely, because a mute you have to remember to undo is one you will
    not undo.

## What is never muted

Silence has to be safe. These pass regardless of any window, any ad-hoc mute,
and any configuration:

  * anything at `critical` severity;
  * the watchdog and PANIC — the messages that say your own safety net fired;
  * a patch that failed or rolled back, because something on the host changed
    and then changed back, and that is not information that keeps until morning.

Everything else is *held*, not dropped: the rows keep `notified_at IS NULL` and
go out when the window ends. Losing an alert to a quiet window would make this
feature a way to miss things.

## Time is local

An operator who types "22:00" means 22:00 where they live. The host runs UTC and
the database stores UTC, so the window is evaluated in a named zone — the host's
own by default, overridable in config. Getting this wrong by three hours would
silence exactly the evening hours the operator wanted covered.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import Any

from sentinel.logging_setup import get_logger
from sentinel.util.tz import host_zone_name, zone  # noqa: F401

log = get_logger(__name__)

# Severities that ignore every mute. Kept as a frozenset in code rather than in
# config: "which alerts can be silenced" is a safety property, and a
# configuration file is the wrong place to let someone silence the last one.
NEVER_MUTED_SEVERITIES = frozenset({"critical"})

# Notification kinds that ignore every mute, whatever their severity.
NEVER_MUTED_KINDS = frozenset({
    "panic",             # the blocklist was flushed — by you or by the watchdog
    "watchdog",          # the safety net fired
    "patch_failed",      # a patch stopped partway
    "patch_rolled_back",  # the host changed and then changed back
    "lockout",           # you may be locked out right now
    # Cineva tocmai a intrat pe server. Cerut de operator pe 24 august 2026, cu
    # o condiție care e jumatate din cerinta: „nu se tace niciodata, dar atentie
    # sa nu generezi fals pozitiv".
    #
    # A doua jumatate e ce face prima suportabila. O alerta care nu poate fi
    # tacuta trebuie sa fie rara si sa fie adevarata, altfel scutirea de la
    # liniste devine chiar mecanismul prin care canalul e abandonat. De-asta
    # `detect/logins.py` alerteaza NUMAI pe sesiunile interactive: masurat pe
    # gazda, 29 pe saptamana in loc de 586.
    "login",
})

# `"selfcheck"` A STAT aici, cu motivul: „o parte din agentul de securitate s-a
# oprit; ținut până la 06:00, orele în care ai ales să nu te uiți la telefon ar fi
# exact orele în care nimeni nu se uită nici la server". Motivul rămâne valabil —
# dar numai pentru jumătatea la care se referea.
#
# Autoverificarea emite DOUĂ feluri de veste, iar `runner._announce` le deosebea
# deja: `critical` când ceva e `down`, `high` când e doar `degraded`. Iar
# `degraded` înseamnă, prin definiția scrisă în `check_ship_lag`, „pe gazdă nu s-a
# oprit nimic; ce e în urmă e o copie din afara ei". Aia nu e vestea pentru care a
# fost făcută scutirea, și ținută sub ea a devenit exact ce scutirea voia să
# prevină: un canal care sună degeaba și pe care operatorul îl închide.
#
# Scoasă din listă, jumătatea care conta trece în continuare — prin
# `NEVER_MUTED_SEVERITIES`, fiindcă `down` produce `critical`. Cealaltă se ȚINE,
# nu se pierde: rândul rămâne `queued` și pleacă la ridicarea ferestrei.
#
# Cerut de operator pe 24 august 2026, după câteva zile de „Sentinel funcționează
# degradat" primite în perioada de mute, toate despre același flux în urmă cu o
# oră prin construcție.

_WINDOW_RE = re.compile(r"^\s*([0-2]?\d):([0-5]\d)\s*-\s*([0-2]?\d):([0-5]\d)\s*$")
_DURATION_RE = re.compile(r"^\s*(\d{1,4})\s*(m|min|minute|h|o|ora|ore|d|zi|zile)\s*$", re.I)

MAX_ADHOC = timedelta(hours=24)


@dataclass(frozen=True)
class Window:
    """A recurring daily window, in local time. May cross midnight."""

    start: time
    end: time

    def __str__(self) -> str:
        return f"{self.start:%H:%M}-{self.end:%H:%M}"

    @property
    def crosses_midnight(self) -> bool:
        return self.start > self.end

    def contains(self, moment: time) -> bool:
        if self.start == self.end:
            # An empty window, not a 24-hour one. "22:00-22:00" almost certainly
            # means a typo, and reading it as "always silent" would be the worst
            # possible interpretation of an ambiguous input.
            return False
        if self.crosses_midnight:
            return moment >= self.start or moment < self.end
        return self.start <= moment < self.end


def parse_window(text: str) -> Window | None:
    """"22:00-06:00" → Window, or None if it is not one."""
    m = _WINDOW_RE.match(text or "")
    if not m:
        return None
    sh, sm, eh, em = (int(g) for g in m.groups())
    if sh > 23 or eh > 23:
        return None
    return Window(time(sh, sm), time(eh, em))


# ---------------------------------------------------------------------------
# Program: aceeași fereastră nu se potrivește tuturor zilelor
# ---------------------------------------------------------------------------
# Sâmbăta dimineața la 06:00 nu e ca marțea dimineața la 06:00. Un operator care
# vrea liniște până la 09:00 în weekend are două variante proaste fără asta: ori
# mută fereastra la 09:00 în fiecare zi și pierde trei ore de acoperire în
# fiecare dimineață de lucru, ori nu o mută și e trezit sâmbăta. A doua e cea
# care duce la un canal oprit permanent.

_DAY_NAMES: dict[str, int] = {
    # Luni = 0, ca în `datetime.weekday()`. Prescurtările sunt cele pe care le
    # scrie cineva care se grăbește, în română și în engleză.
    "lu": 0, "luni": 0, "mon": 0, "monday": 0,
    "ma": 1, "marti": 1, "marți": 1, "tue": 1, "tuesday": 1,
    "mi": 2, "miercuri": 2, "wed": 2, "wednesday": 2,
    "jo": 3, "joi": 3, "thu": 3, "thursday": 3,
    "vi": 4, "vineri": 4, "fri": 4, "friday": 4,
    "sa": 5, "sambata": 5, "sâmbătă": 5, "sat": 5, "saturday": 5,
    "du": 6, "duminica": 6, "duminică": 6, "sun": 6, "sunday": 6,
}

_DAY_GROUPS: dict[str, frozenset[int]] = {
    "weekend": frozenset({5, 6}),
    "wk": frozenset({5, 6}),
    "lucratoare": frozenset({0, 1, 2, 3, 4}),
    "lucrătoare": frozenset({0, 1, 2, 3, 4}),
    "weekdays": frozenset({0, 1, 2, 3, 4}),
    "zilnic": frozenset(range(7)),
    "toate": frozenset(range(7)),
}

_DAY_LABEL = ("luni", "marți", "miercuri", "joi", "vineri", "sâmbătă", "duminică")


def parse_days(text: str) -> frozenset[int] | None:
    """„weekend", „sa,du", „lu-vi" → mulțimea de zile, sau None dacă nu e una."""
    raw = (text or "").strip().lower()
    if not raw:
        return None
    if raw in _DAY_GROUPS:
        return _DAY_GROUPS[raw]

    days: set[int] = set()
    for part in re.split(r"[,\s]+", raw):
        if not part:
            continue
        if part in _DAY_GROUPS:
            days |= _DAY_GROUPS[part]
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a not in _DAY_NAMES or b not in _DAY_NAMES:
                return None
            start, end = _DAY_NAMES[a], _DAY_NAMES[b]
            # Un interval poate trece peste sfârșitul săptămânii: „vi-lu".
            days |= {(start + i) % 7 for i in range((end - start) % 7 + 1)}
            continue
        if part not in _DAY_NAMES:
            return None
        days.add(_DAY_NAMES[part])
    return frozenset(days) or None


def _label(days: frozenset[int]) -> str:
    if days == frozenset(range(7)):
        return "în fiecare zi"
    for name, group in (("în weekend", _DAY_GROUPS["weekend"]),
                        ("în zilele lucrătoare", _DAY_GROUPS["lucratoare"])):
        if days == group:
            return name
    return "; ".join(_DAY_LABEL[d] for d in sorted(days))


@dataclass(frozen=True)
class Rule:
    """O fereastră care se aplică numai în anumite zile."""

    days: frozenset[int]
    window: Window

    def __str__(self) -> str:
        if self.days == frozenset(range(7)):
            return str(self.window)
        return f"{_compact_days(self.days)} {self.window}"

    @property
    def specific(self) -> bool:
        return self.days != frozenset(range(7))


# Prescurtările pe care le SCRIE `_compact_days`, și grupurile pe care le
# preferă în locul unei enumerări. Ținute aparte, nu inline, fiindcă din exact
# aceleași tabele se construiește și `SCHEDULE_SQL_REGEX` de mai jos: o zi sau un
# grup adăugat aici schimbă automat și regexul constrângerii, iar testul care
# compară regexul cu literalul din fișierul de migrație pică până când
# constrângerea e lărgită la rândul ei.
_COMPACT_DAY: tuple[str, ...] = ("lu", "ma", "mi", "jo", "vi", "sa", "du")
_COMPACT_GROUPS: tuple[tuple[str, frozenset[int]], ...] = (
    ("weekend", _DAY_GROUPS["weekend"]),
    ("lucratoare", _DAY_GROUPS["lucratoare"]),
)


def _compact_days(days: frozenset[int]) -> str:
    for name, group in _COMPACT_GROUPS:
        if days == group:
            return name
    return ",".join(_COMPACT_DAY[d] for d in sorted(days))


@dataclass(frozen=True)
class Schedule:
    """Regulile de liniște, în ordinea în care au fost scrise.

    Câte o regulă per set de zile. Regula care numește zile bate regula care se
    aplică tuturor: cine scrie „22:00-06:00; weekend 22:00-09:00" vrea evident
    ca sâmbăta să câștige, nu să fie ignorată fiindcă prima regulă s-a potrivit
    deja.
    """

    rules: tuple[Rule, ...]

    def __str__(self) -> str:
        return "; ".join(str(r) for r in self.rules)

    def active_at(self, local: datetime) -> tuple[Rule, datetime] | None:
        """Regula care tace ACUM și momentul în care se termină.

        Cazul care se greșește ușor: o fereastră care trece peste miezul nopții
        aparține zilei în care a ÎNCEPUT. „sâmbătă 22:00-09:00" acoperă duminică
        la 08:00 — dar numai fiindcă a început sâmbătă seara, nu fiindcă
        duminica ar fi în regulă. Verificat pe ambele capete, separat.
        """
        today, yesterday = local.weekday(), (local.weekday() - 1) % 7
        moment = local.time()
        matches: list[tuple[Rule, bool]] = []

        for rule in self.rules:
            w = rule.window
            if w.start == w.end:
                continue
            if w.crosses_midnight:
                if moment >= w.start and today in rule.days:
                    matches.append((rule, False))       # partea de seară
                elif moment < w.end and yesterday in rule.days:
                    matches.append((rule, True))        # partea de dimineață
            elif today in rule.days and w.start <= moment < w.end:
                matches.append((rule, False))

        if not matches:
            return None
        # Cea mai specifică regulă câștigă; la egalitate, prima scrisă.
        rule, _ = min(matches, key=lambda m: (not m[0].specific,))
        return rule, _rule_end(local, rule.window)


# ---------------------------------------------------------------------------
# Aceeași gramatică, o singură dată — și pentru PostgreSQL
# ---------------------------------------------------------------------------
# Coloana `telegram_chats.quiet_hours` are o constrângere CHECK cu un regex.
# Până la migrația 0020 acel regex accepta o SINGURĂ fereastră zilnică, fiindcă
# fusese scris înainte ca liniștea să aibă zile și reguli multiple. Rezultatul:
# parserul de aici accepta `22:00-06:00; vi,sa 22:00-09:00`, exact exemplul din
# textul de ajutor al comenzii, iar baza îl respingea la scriere. Operatorul
# primea „A apărut o eroare la procesarea comenzii." și nimic altceva.
#
# Cauza nu a fost pragul greșit, ci faptul că gramatica era scrisă de două ori,
# în două limbaje, fără nimic care să le lege. Deci: șirul de mai jos e SINGURA
# definiție a formei acceptate, e construit din tabelele pe care le folosește
# `_compact_days` la scriere, și e copiat verbatim în fișierul de migrație. Un
# test compară cele două și trece prin regex fiecare ieșire pe care o produce
# `str(Schedule)` — o gramatică lărgită aici fără o migrație nouă pică local, nu
# pe telefonul operatorului.
#
# Dialect: subsetul comun între `re` din Python și ARE din PostgreSQL — clase de
# caractere, alternanță, grupuri, `*`, `?`. Fără `\d`, fără lookaround, fără
# backreferințe, ca ambele motoare să dea același răspuns.
#
# Orele rămân `[0-2][0-9]`, ca în 0015, deși `%H` nu produce niciodată peste 23:
# regexul nou trebuie să fie o supramulțime STRICTĂ a celui vechi, altfel
# `ADD CONSTRAINT` validează rândurile existente și migrația cade pe o gazdă
# unde cineva a scris manual în coloană. Forma exactă rămâne treaba lui
# `parse_schedule`; CHECK-ul ține gunoiul afară, cum spunea deja 0015.

def _schedule_sql_regex() -> str:
    day = "(" + "|".join(_COMPACT_DAY) + ")"
    groups = "|".join(name for name, _ in _COMPACT_GROUPS)
    days = f"({day}(,{day})*|{groups})"
    window = "[0-2][0-9]:[0-5][0-9]-[0-2][0-9]:[0-5][0-9]"
    rule = f"({days} )?{window}"          # `Rule.__str__`: zilele înaintea ferestrei
    return f"^{rule}(; {rule})*$"         # `Schedule.__str__`: reguli unite cu „; "


SCHEDULE_SQL_REGEX = _schedule_sql_regex()


def parse_schedule(text: str) -> Schedule | None:
    """„22:00-06:00; weekend 22:00-09:00" → Schedule.

    O fereastră singură, fără zile, rămâne validă și înseamnă „în fiecare zi".
    Formatul vechi e cel scris în bazele de date existente și în fișierele de
    configurare livrate; a-l invalida ar face ca o repornire să dezactiveze
    tăcut liniștea pe care operatorul o setase.
    """
    raw = (text or "").strip()
    if not raw:
        return None

    rules: list[Rule] = []
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        window = parse_window(chunk)
        if window is not None:
            rules.append(Rule(frozenset(range(7)), window))
            continue
        # „weekend 22:00-09:00": zilele înaintea ferestrei.
        head, _, tail = chunk.rpartition(" ")
        window = parse_window(tail)
        days = parse_days(head)
        if window is None or days is None:
            return None
        rules.append(Rule(days, window))

    return Schedule(tuple(rules)) if rules else None


def covers(rule: Rule) -> str:
    """Ce acoperă regula, în seri și dimineți.

    Există fiindcă „weekend 22:00-09:00" nu înseamnă ce pare. O fereastră
    aparține zilei în care începe, deci aceea acoperă sâmbătă și duminică
    SEARA — adică diminețile de duminică și luni. Cine voia liniște sâmbătă
    dimineața trebuie să scrie `vi,sa`.

    Regula nu se schimbă ca să ghicească; propoziția asta se spune în clipa
    setării, când corectarea costă o comandă în loc de o dimineață trezită.
    """
    if not rule.window.crosses_midnight:
        return f"{_label(rule.days)}, între {rule.window.start:%H:%M} și {rule.window.end:%H:%M}"
    mornings = frozenset((d + 1) % 7 for d in rule.days)
    return (f"{_label(rule.days)} seara de la {rule.window.start:%H:%M}, "
            f"până {_label(mornings)} dimineața la {rule.window.end:%H:%M}")


def describe(schedule: Schedule | None) -> str:
    """Programul, în cuvinte, pentru un răspuns în chat."""
    if schedule is None or not schedule.rules:
        return "niciunul"
    return " · ".join(f"{_label(r.days)} {r.window}" for r in schedule.rules)


def parse_duration(text: str) -> timedelta | None:
    """"2h", "30m", "45 minute" → timedelta, capped at 24 hours."""
    m = _DURATION_RE.match(text or "")
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2).lower()
    if unit.startswith(("m",)):
        delta = timedelta(minutes=n)
    elif unit.startswith(("h", "o")):
        delta = timedelta(hours=n)
    else:
        delta = timedelta(days=n)
    if delta <= timedelta(0):
        return None
    # Capped rather than rejected: the intent of "/mute 7d" is clear, and
    # honouring it literally would leave a security channel dark for a week.
    return min(delta, MAX_ADHOC)


# `host_zone_name` și `zone` AU STAT aici și acum vin din `sentinel/util/tz.py`.
# Mutate, nu copiate: de când ora afișată din Telegram, detecția de logări,
# panoul web și autoverificarea folosesc aceeași regulă de fus, o a doua copie
# ar fi însemnat două reguli care se despart tăcut — iar cea care se desparte
# prima e mereu cea pe care n-o testează nimeni.
#
# Reexportate sub aceleași nume fiindcă `telegram/bot.py` cheamă `quiet.zone(...)`
# în `_fmt_local`, iar textul care anunță fusul în confirmarea lui `/mute` și ora
# pe care o tipărește nu au voie să vină din două funcții diferite.


@dataclass(frozen=True)
class MuteState:
    """Why a message is or is not being held, in words fit for a chat reply."""

    muted: bool
    reason: str
    until: datetime | None = None


def evaluate(*, now: datetime, muted_until: datetime | None,
             schedule: Schedule | Window | None = None,
             window: Schedule | Window | None = None,
             tz_name: str | None = None) -> MuteState:
    """Is the channel quiet right now, and until when?

    Acceptă și un `Window` simplu, sub oricare dintre cele două nume. Parametrul
    `window=` a existat înainte ca liniștea să aibă zile, iar un apelant uitat
    care trece o fereastră trebuie să continue să tacă la aceleași ore — nu să
    primească tăcut un canal fără liniște deloc.
    """
    tz = zone(tz_name)
    local = now.astimezone(tz)

    if muted_until is not None and muted_until > now:
        return MuteState(True, "pauză temporară", muted_until)

    spec = schedule if schedule is not None else window
    if isinstance(spec, Window):
        spec = Schedule((Rule(frozenset(range(7)), spec),))

    if spec is not None:
        hit = spec.active_at(local)
        if hit is not None:
            rule, ends = hit
            return MuteState(True, f"ore de liniște ({rule})", ends)

    return MuteState(False, "activ")


# ---------------------------------------------------------------------------
# Cine tace ACUM — o singură dată, pentru toți cei care întreabă
# ---------------------------------------------------------------------------
# Funcțiile de mai jos au trăit în `telegram/bot.py`, ca `_quiet_chats` și ca
# expresia `quiet_chats >= set(cfg.telegram.allowed_chat_ids)` scrisă în
# `_push_notifications`. Câtă vreme le citea numai expeditorul, un singur loc
# era de ajuns.
#
# Nu mai e: autoverificarea trebuie să răspundă la „ar fi plecat mesajul ăsta?",
# iar dacă și-ar fi scris propria regulă de liniște ar fi existat două mecanisme
# de aceeași formă care se pot despărți tăcut — exact ce spune nota din
# `aggregator/lib/prune.ts`. Deci regula stă aici, în modulul care o DEȚINE, iar
# expeditorul și verificarea o cheamă amândoi.
#
# Citirea din bază rămâne la apelant: modulul ăsta e pur și trebuie să rămână
# așa, ca să poată fi testat fără PostgreSQL.


def silent_chats(*, now: datetime, chat_ids: Iterable[int],
                 prefs: Mapping[int, Any] | None = None,
                 default_schedule: str | None = None,
                 default_tz: str | None = None) -> frozenset[int]:
    """Chat-urile care sunt ACUM într-o fereastră de liniște sau pe pauză.

    `prefs` e ce a scris fiecare chat pentru el (`db.repo.chats.all_prefs`);
    lipsa unui rând înseamnă „ia din configurația livrată", nu „fără liniște".
    Tipul preferințelor e citit prin atribute, nu importat: `quiet.py` nu are
    voie să depindă de stratul de bază de date, altfel n-ar mai putea fi testat
    fără PostgreSQL.
    """
    prefs = prefs or {}
    out: set[int] = set()
    for chat_id in chat_ids:
        p = prefs.get(chat_id)
        sched = parse_schedule((getattr(p, "quiet_hours", None) if p else None)
                               or default_schedule or "")
        state = evaluate(now=now, schedule=sched,
                         muted_until=getattr(p, "muted_until", None) if p else None,
                         tz_name=(getattr(p, "timezone", None) if p else None)
                         or default_tz)
        if state.muted:
            out.add(chat_id)
    return frozenset(out)


def all_silent(silent: Collection[int], chat_ids: Iterable[int]) -> bool:
    """Tac TOATE chat-urile cărora li s-ar trimite?

    Numai atunci se ține un mesaj care se poate amuta: dacă măcar unul ascultă,
    mesajul pleacă la el, iar coada nu are de ce să-l mai țină.

    O listă goală de chat-uri iese ADEVĂRAT, și asta e o alegere, nu o scăpare:
    pentru expeditor „nu e nimeni de anunțat" trebuie să însemne „ține rândul",
    fiindcă alternativa e `_broadcast` care întoarce 0 și un rând marcat
    `failed` — adică o alertă pierdută. Cine citește liniștea ca să judece
    SĂNĂTATEA canalului are nevoie de răspunsul celălalt și trebuie să ceară
    separat că există măcar un destinatar; vezi `selfcheck/checks.check_alerting`.
    """
    return set(chat_ids) <= set(silent)


def _rule_end(local: datetime, window: Window) -> datetime:
    """The next moment this window stops, as an absolute instant.

    Built by replacing the time on a local date and re-attaching the zone rather
    than by adding a duration: on the night a DST change lands inside the
    window, the arithmetic answer is off by an hour and the calendar answer is
    right.
    """
    end_today = local.replace(hour=window.end.hour, minute=window.end.minute,
                              second=0, microsecond=0)
    if end_today <= local:
        end_today += timedelta(days=1)
    return end_today.astimezone(timezone.utc)


def passes_anyway(severity: str | None, kind: str | None = None) -> bool:
    """True when this message must be delivered even inside a quiet window."""
    if kind and kind in NEVER_MUTED_KINDS:
        return True
    return bool(severity) and severity.lower() in NEVER_MUTED_SEVERITIES
