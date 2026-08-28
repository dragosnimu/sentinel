"""Aggregated reports: overview counters, time series, breakdowns, drill-down.

The dashboard answers "am I OK right now". This module answers "what has been
happening" — the same tables, read over hours, days, weeks, months and years.

Three rules shape every query here.

**1. The time series never touches `raw_events`.**
`event_rollup_1h` already holds (bucket, asset_id, source, action, n) and its
primary key starts with `bucket`, so a year of event history is an index range
scan over a table with one row per hour per source/action combination. Reading
`raw_events` for the same question would scan up to a month of daily partitions
on a database that is simultaneously serving detection — and detection waiting
on I/O is detection that is not running. `raw_events` is read in exactly one
place: the drill-down, bounded to one bucket and one category, with a LIMIT.

No COUNT is read from `event_rollup_1m`. The smallest bucket offered here is an
hour, and `sentinel_rollup_events_1h` builds the hourly table by summing the
minute one — so re-summing 1m would redo work already done, over sixty times as
many rows. It would only earn its place if a sub-hour bucket were ever added.
Its `min(bucket)` IS read, once per page: that single value is what separates a
gap the maintenance job can still fill from one that is lost for good, and the
two must not be drawn the same way. See `Fallbacks`.

**2. Missing data is not zero.**
Both rollup tables are trimmed by retention (`rollup_1h_days`, 400 by default)
and `raw_events` partitions are dropped after `raw_events_days`. A bucket older
than what the store still holds must NOT render as a bar of height zero: that
reads as "nothing attacked us in March", when the truth is "March was deleted".
Every series therefore carries a per-bucket state — `known`, `partial`,
`unknown` — derived from the *actual* earliest row present, not from the
configured policy. The same applies at the other end: the current bucket is
still filling, and the hourly rollup lags behind real time by up to one
maintenance run, so the trailing bucket is `partial` too.

**3. No number is invented from an aggregate that cannot support it.**
`event_rollup_1h.uniq_src` is a per-bucket distinct count, and per-bucket
distinct counts do not add up — summing them would produce a plausible
"distinct attackers this month" that is simply wrong. Distinct-source counts
are not offered by this module at all.

Everything here is read-only. The reports surface adds no action of any kind;
the web layer never talks to the executor (see `web/app.py`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from sentinel.db.engine import Database
from sentinel.util import tz

# ---------------------------------------------------------------------------
# Vocabularies
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BucketSpec:
    """A bucket size, and how much history is shown at that size.

    `span` is capped so every chart stays under ~50 columns: more than that is
    unreadable on screen and, more importantly, makes the aggregate scan grow
    without telling anyone anything new.
    """

    unit: str       # also the date_trunc field name — they are deliberately equal
    span: int       # how many buckets the chart covers
    label: str      # Romanian, for the selector
    fmt: str        # strftime for the axis tick


# Keys are English because each one is passed straight to date_trunc as its
# field name; a Romanian key here would need a translation table whose only
# purpose is to be forgotten.
BUCKETS: dict[str, BucketSpec] = {
    "hour":  BucketSpec("hour", 48, "pe oră", "%d.%m %H:%M"),
    "day":   BucketSpec("day", 30, "pe zi", "%d.%m"),
    "week":  BucketSpec("week", 26, "pe săptămână", "%d.%m"),
    "month": BucketSpec("month", 18, "pe lună", "%m.%Y"),
    "year":  BucketSpec("year", 3, "pe an", "%Y"),
}
DEFAULT_BUCKET = "day"

# ---------------------------------------------------------------------------
# În ce fus se taie marginile intervalului
# ---------------------------------------------------------------------------
#: Fusul implicit al modulului. NU înseamnă „fusul gazdei": înseamnă depozitarea,
#: care rămâne UTC. O funcție de aici chemată fără fus trebuie să dea același
#: răspuns pe orice mașină, iar `None`-ul lui `util.tz` (= fusul gazdei) ar face
#: rezultatul să depindă de unde rulează testul.
STORAGE_TZ = "UTC"


def align_zone(unit: str, tz_name: str = STORAGE_TZ) -> str:
    """Fusul în care se taie marginile pentru unitatea asta, ca NUME de zonă.

    Zilele, săptămânile, lunile și anii se taie în fusul configurat. Până pe 28
    august 2026 se tăiau în UTC, deci „ziua de 27.08" începea la 03:00 ora
    operatorului: cifra de pe pagină și ce scria în jurnal erau despre două zile
    diferite, fără nimic care s-o spună. Costul mutării, acceptat la decizie:
    fiecare interval istoric se deplasează o dată, iar comparația cu cifrele
    citite înainte se rupe o dată.

    **Ora de vară rămâne vizibilă, și așa trebuie.** În ziua în care se schimbă
    ceasul, `date_trunc('day', ts AT TIME ZONE 'Europe/Bucharest')` produce o zi
    de 23 sau de 25 de ore, deci suma pe acea zi va arăta o anomalie o dată pe
    an. Nu e un bug de vânat: e chiar ziua pe care a trăit-o operatorul.

    **Într-un fus decalat cu jumătate de oră, ziua se rupe în interiorul unei
    găleți, și asta e o limită cunoscută, nu o proprietate.** Evenimentele nu
    se numără din `raw_events`, ci din `event_rollup_1h`, care ține ore UTC
    ÎNTREGI; `events_rows` taie ziua pe `bucket AT TIME ZONE $2`, adică pe
    începutul găleții. Pentru `Europe/Bucharest` ziua începe la 21:00:00+00 —
    exact pe o margine de găleată, deci nu se pierde nimic. Pentru
    `Asia/Kolkata` (+05:30) începe la 18:30:00+00 și pentru `Asia/Kathmandu`
    (+05:45) la 18:15:00+00, adică ÎN MIJLOCUL găleții care începe la 18:00:
    toată găleata pleacă în ziua în care începe, deci până la o jumătate de oră
    (respectiv trei sferturi) de evenimente sunt numărate în ziua locală vecină,
    fără ca nimic de pe pagină s-o spună. Incidentele și patch-urile nu sunt
    atinse — acolo se taie direct o coloană `timestamptz`, nu o găleată gata
    agregată. Reparat, ar cere o găleată mai mică decât ora în rollup; până
    atunci, un fus cu decalaj fracționar e o configurație pe care raportul de
    evenimente o servește aproximativ.

    **ORA rămâne tăiată în UTC**, și asta e o alegere, nu o scăpare. `date_trunc`
    într-un fus numit lucrează pe ceasul de perete, iar în noaptea în care ceasul
    dă înapoi există DOUĂ ore locale „03:00": `GROUP BY` le-ar aduna într-o
    singură coloană, iar vecina ei ar rămâne un zero care nu e zero — exact
    minciuna împotriva căreia e scris tot modulul („Missing data is not zero",
    în capul fișierului). Pentru un fus decalat cu un număr ÎNTREG de ore, cum e
    `Europe/Bucharest`, marginile orare ies oricum aceleași, deci nu se pierde
    nimic; pentru unul decalat cu jumătate de oră, eticheta orară poartă minutele
    și spune adevărul. Același argument, scris pentru sparkline-ul orar de pe
    panou, e în `dashboard.html`.

    Numele iese prin `tz.zone_key`, deci e unul pe care Python l-a rezolvat deja
    — fiindcă de aici pleacă drept PARAMETRU în `date_trunc($1, ts AT TIME ZONE
    $2)`, niciodată interpolat în textul instrucțiunii. Aceeași disciplină ca la
    `EVENT_DIMS` / `INCIDENT_DIMS` mai jos, din același motiv.
    """
    return STORAGE_TZ if unit == "hour" else tz.zone_key(tz_name)

# Overview windows, in hours.
WINDOWS: dict[str, int] = {"24h": 24, "7z": 24 * 7, "30z": 24 * 30}
DEFAULT_WINDOW = "24h"

# Which column each breakdown groups by. Whitelisted rather than interpolated
# from a query string: the value reaches SQL as an identifier, not as a bound
# parameter, so it can only ever come from this table.
EVENT_DIMS: dict[str, str] = {"source": "source", "action": "action"}

INCIDENT_DIMS: dict[str, str] = {
    "severity": "severity",
    # `detections.rule_family` is the authoritative column, but joining every
    # incident to its detections to read it costs a join over the largest table
    # in the report for a value the incident already carries: `fingerprint` is
    # built as "<rule_id>:<discriminators>" and every rule_id starts with its
    # family (auth.ssh_bruteforce → auth). `tests/unit/test_reports.py` asserts
    # that invariant against the real rule modules, so a rule that breaks it
    # fails the suite instead of silently mis-labelling a chart.
    "rule_family": "split_part(split_part(fingerprint, ':', 1), '.', 1)",
}

PATCH_DIMS: dict[str, str] = {"status": "status"}

# Severity renders in rank order, not by volume: a chart where `critical` moves
# because its count changed relative to `info` is a chart nobody can read.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

# Execution statuses that mean the apply did not end well. `rolled_back` is
# separate on purpose — the patch failed but the machine came back, which is the
# system working, not the system breaking.
PATCH_FAILED = ("failed", "rollback_failed", "aborted")

# How far back a drill-down into individual events may reach inside one bucket.
# A year bucket covers 365 days of daily partitions; listing "the events in that
# bucket" without a cap would scan every one of them to return 200 rows.
DRILL_MAX_HOURS = 48

DRILL_LIMIT = 200

# Above this, the hourly rollup is not merely lagging — the maintenance timer is
# not completing. The timer is hourly, so one missed run plus a slow one is
# still normal; three hours is not.
ROLLUP_STALE_HOURS = 3

# The width of one `event_rollup_1h` row. `bucket` is the START of that hour, so
# coverage reaches `max(bucket) + ROLLUP_BUCKET` — see `event_edges`.
ROLLUP_BUCKET = timedelta(hours=1)

# How many rows the "events by source" card shows before folding the tail into
# a stated "altele", and the ceiling on how many it reads.
#
# `source` is validated against `model.event.SOURCES` at ingest, so a GROUP BY
# over it returns a dozen rows at most and the fold is normally a no-op. The
# ceiling exists for the case where it is not — a legacy or hand-inserted value
# — and `truncated` says so, because this card was the one place on the page
# where a category could vanish with nothing to show for it.
SOURCE_ROWS_SHOWN = 7
SOURCE_ROWS_MAX = 25


# ---------------------------------------------------------------------------
# Bucket arithmetic
# ---------------------------------------------------------------------------
def _instant(local_naive: datetime, z: Any) -> datetime:
    """Un ceas de perete dintr-o zonă, ca moment absolut.

    `fold=0` e scris pe față, și motivul NU e un dezacord cu PostgreSQL:
    instrucțiunile de aici nu fac niciodată conversia naiv→instant.
    `date_trunc($1, ts AT TIME ZONE $2)` merge doar în sensul celălalt,
    instant→naiv, iar amândouă marginile ferestrei sunt calculate în Python,
    prin funcția asta. Ce ține `fold` e altceva, și e local.

    Într-un fus în care MIEZUL NOPȚII e ambiguu — `America/Havana`, 1 noiembrie
    2026: 00:00 local se întâmplă de două ori, la 04:00 și la 05:00 UTC —
    eticheta „începutul zilei" are două instante. `truncate` taie pe ceasul de
    perete cu `replace(tzinfo=None)`, care DUCE `fold` mai departe din momentul
    din care s-a tăiat. Fără `fold=0`, aceeași zi ar începe la 04:00 când e
    cerută dintr-un moment obișnuit și la 05:00 când e cerută dintr-unul din ora
    repetată — două margini pentru o singură coloană. Cu `fold=1` ar începe mereu
    la 05:00, iar ora repetată ar cădea în afara lui `WHERE ts >= $3`: o oră de
    evenimente ar dispărea din zi, o dată pe an, fără ca totalul să se plângă.
    """
    return local_naive.replace(tzinfo=z, fold=0).astimezone(timezone.utc)


def truncate(moment: datetime, unit: str, *, tz_name: str = STORAGE_TZ) -> datetime:
    """Start of the bucket containing `moment`, as an absolute instant.

    Weeks start on Monday, matching PostgreSQL's `date_trunc('week', …)`. If the
    two disagreed, a bar drawn for one week would be filled with another week's
    rows and nothing would say so.

    Tăierea se face pe CEASUL DE PERETE al zonei date de `align_zone` și se
    întoarce ca moment absolut, fiindcă instantul e ce ajunge în `WHERE ts >= $1`.
    """
    if unit == "hour":
        # Aliniere absolută; motivul e scris la `align_zone`.
        return moment.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    z = tz.zone(align_zone(unit, tz_name))
    local = moment.astimezone(z).replace(tzinfo=None)
    day = local.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit == "day":
        start = day
    elif unit == "week":
        start = day - timedelta(days=day.weekday())
    elif unit == "month":
        start = day.replace(day=1)
    elif unit == "year":
        start = day.replace(month=1, day=1)
    else:
        raise ValueError(f"unknown bucket unit {unit!r}")
    return _instant(start, z)


def advance(moment: datetime, unit: str, steps: int = 1, *,
            tz_name: str = STORAGE_TZ) -> datetime:
    """Move `steps` buckets forward (or back, for a negative count).

    Pasul se face pe ceasul de perete, nu pe durată. O zi nu are 24 de ore în
    noaptea schimbării ceasului, iar `+ timedelta(days=1)` ar muta marginea la
    23:00 sau la 01:00 locale — adică pe altă margine decât cea pe care o taie
    `date_trunc`, cu bare umplute cu rândurile intervalului vecin.
    """
    if unit == "hour":
        return moment + timedelta(hours=steps)
    z = tz.zone(align_zone(unit, tz_name))
    local = moment.astimezone(z).replace(tzinfo=None)
    if unit == "day":
        local += timedelta(days=steps)
    elif unit == "week":
        local += timedelta(weeks=steps)
    elif unit == "month":
        total = (local.year * 12 + local.month - 1) + steps
        local = local.replace(year=total // 12, month=total % 12 + 1, day=1)
    elif unit == "year":
        local = local.replace(year=local.year + steps, month=1, day=1)
    else:
        raise ValueError(f"unknown bucket unit {unit!r}")
    return _instant(local, z)


def bucket_starts(unit: str, *, now: datetime, count: int,
                  tz_name: str = STORAGE_TZ) -> list[datetime]:
    """The `count` bucket starts ending with the bucket containing `now`."""
    last = truncate(now, unit, tz_name=tz_name)
    starts = [last]
    for _ in range(count - 1):
        starts.append(advance(starts[-1], unit, -1, tz_name=tz_name))
    return list(reversed(starts))


def window_bounds(unit: str, *, now: datetime, count: int,
                  tz_name: str = STORAGE_TZ) -> tuple[datetime, datetime]:
    """Half-open [start, end) covering `count` buckets up to and including now."""
    starts = bucket_starts(unit, now=now, count=count, tz_name=tz_name)
    return starts[0], advance(starts[-1], unit, 1, tz_name=tz_name)


# ---------------------------------------------------------------------------
# Series
# ---------------------------------------------------------------------------
# Four states, because "we have no number for this bucket" has two causes with
# opposite meanings and opposite remedies:
#
#   UNKNOWN — older than anything the store still holds. Retention dropped it.
#             The data is GONE, and this is the state the hatching exists for.
#   PENDING — newer than what the aggregation has reached. The rows are in
#             raw_events; the rollup has not written that bucket yet.
#
# Collapsing them made the newest hourly column hatched almost every hour: the
# maintenance timer's start second drifts (:00:06, :02:16, :03:07 in the live
# journal), and a run that fires at :00:07 finds no minute buckets for the hour
# it is starting, so no hourly row is written for it. A hatch that appears at
# the right-hand edge most of the time is a hatch the operator learns to ignore
# — and it is the only mark that says March really was deleted.
KNOWN, PARTIAL, UNKNOWN, PENDING = "known", "partial", "unknown", "pending"

# ...and a fourth "no number here" case, because `pending` was making a claim
# the code had the data to check and did not.
#
#   MISSED — not aggregated, and it can no longer BE aggregated: the table the
#            hourly rollup is built from does not reach back that far either.
#            Nothing survives and nothing ever will.
#
# It happens when the maintenance timer stays broken for longer than retention:
# the rollup stops advancing while ingestion and pruning carry on.
#
# The edge for MISSED is `event_rollup_1m`, NOT `raw_events`, and the gap
# between the two is a sixty-day band. `sentinel_rollup_events_1h` reads
# `FROM event_rollup_1m` — it never touches `raw_events` — and the retentions
# are 30 days of raw, 90 of minutes, 400 of hours. So for a bucket between 30
# and 90 days old that the hourly rollup has not reached, the raw detail is gone
# while every minute of it is still on disk, and one repaired maintenance run
# rebuilds the bar exactly. Calling that "nothing left" points the operator away
# from the action that fixes it — restart the timer — and towards writing the
# period off as lost.
MISSED = "missed"

# Bucket states that carry a number worth trusting as a count.
COVERED = (KNOWN, PARTIAL)

# States with no bar: nothing to show, for one of three different reasons.
BLANK = (UNKNOWN, PENDING, MISSED)


@dataclass(frozen=True)
class Fallbacks:
    """What still exists BELOW the hourly aggregate, and what each answers.

    Two different questions, two different tables, and conflating them is what
    made a recoverable gap read as a permanent one:

    * `raw_from`    — oldest surviving `raw_events` partition. Decides whether
      the drill-down can list individual events for a bucket.
    * `minute_from` — oldest surviving `event_rollup_1m` row. Decides whether
      the hourly bar can still be rebuilt at all, because that is the table
      `sentinel_rollup_events_1h` sums.

    `None` in either means the store could not be asked. It never means "gone":
    a state that cannot be established must not be reported as loss.
    """

    raw_from: datetime | None = None
    minute_from: datetime | None = None


# For a series with no lower-level store behind it at all — `incidents`,
# `patch_executions`. Nothing to fall back to, and nothing to claim.
NO_FALLBACK = Fallbacks()


@dataclass
class Series:
    """A stacked time series: one row per category, one column per bucket."""

    unit: str
    # Fusul în care au fost TĂIATE marginile și în care se scriu etichetele.
    # Călătorește pe serie, nu se dă separat lui `build_chart`: altfel o serie
    # aliniată într-un fus ar putea fi etichetată în altul, iar diferența — trei
    # ore — nu s-ar vedea nicăieri pe pagină.
    tz_name: str = STORAGE_TZ
    starts: list[datetime] = field(default_factory=list)
    keys: list[str] = field(default_factory=list)
    counts: dict[str, list[int]] = field(default_factory=dict)
    totals: dict[str, int] = field(default_factory=dict)
    per_bucket: list[int] = field(default_factory=list)
    state: list[str] = field(default_factory=list)
    grand_total: int = 0
    # What still exists below the hourly aggregate, carried so the chart can
    # word each tooltip for what is actually known rather than for what is
    # convenient. See `Fallbacks`.
    fallbacks: Fallbacks = NO_FALLBACK

    @property
    def empty(self) -> bool:
        return self.grand_total == 0

    @property
    def has_unknown(self) -> bool:
        return UNKNOWN in self.state

    @property
    def has_pending(self) -> bool:
        return PENDING in self.state

    @property
    def has_missed(self) -> bool:
        return MISSED in self.state

    # Counts, not just flags: an empty chart has to be able to say "zero across
    # the 11 intervals we hold" rather than choosing between "all zero" and "no
    # data" when the truth on a young install is always both at once.
    @property
    def covered_buckets(self) -> int:
        return sum(1 for s in self.state if s in COVERED)

    @property
    def unknown_buckets(self) -> int:
        return sum(1 for s in self.state if s == UNKNOWN)

    @property
    def missed_buckets(self) -> int:
        return sum(1 for s in self.state if s == MISSED)

    @property
    def pending_buckets(self) -> int:
        return sum(1 for s in self.state if s == PENDING)

    @property
    def peak(self) -> int:
        return max(self.per_bucket, default=0)


def _as_utc(value: Any) -> datetime | None:
    """asyncpg hands back a naive datetime for `timestamp` and a date for
    `date`. Both are UTC here by construction; attach the zone so nothing
    downstream compares an aware value with a naive one and raises."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    return None


def _bucket_instant(value: Any, zone_name: str) -> datetime | None:
    """Marginea de interval întoarsă de SQL, ca moment absolut.

    `date_trunc($1, ts AT TIME ZONE $2)` întoarce un `timestamp` FĂRĂ fus: ceasul
    de perete al zonei în care s-a aliniat. Citit ca UTC — corect cât timp
    alinierea chiar era în UTC — ar deplasa fiecare coloană cu tot decalajul,
    barele s-ar potrivi peste alte intervale decât cele desenate, iar totalul din
    antet ar rămâne același. Adică o pagină care se contrazice fără să spună.
    """
    if value is None:
        return None
    z = tz.zone(zone_name)
    if isinstance(value, datetime):
        return (value.astimezone(timezone.utc) if value.tzinfo
                else _instant(value, z))
    if isinstance(value, date):
        return _instant(datetime(value.year, value.month, value.day), z)
    return None


def _bucket_state(
    start: datetime,
    end: datetime,
    known_from: datetime | None,
    complete_to: datetime | None,
    known_to: datetime | None,
    fallbacks: Fallbacks,
) -> str:
    """What can honestly be said about one bucket.

    Three edges, because two were not enough and the missing one drew a bar of
    real data as a "no data kept" hatch:

    * `known_from`  — oldest moment the store still holds anything for;
    * `complete_to` — last moment through which the data is FINAL;
    * `known_to`    — first moment the store holds nothing for at all.

    The gap between `complete_to` and `known_to` is the interval that has data
    which is still growing: the hour the rollup is currently writing, or the day
    that is not over yet. It is `partial` — it must be drawn, and it must not
    claim to be complete.

    Collapsing `complete_to` and `known_to` into one value is what produced the
    bug: `event_rollup_1h.bucket` is a bucket *start*, so using `max(bucket)` as
    the upper edge made `start >= known_to` true for the newest bucket on every
    hourly chart, and once a day at 00:00 UTC on the daily one. That bucket held
    rows and was rendered as a hatched gap, with no drill-down link and a header
    total that disagreed with the sum of the bars — on the page whose whole
    point is that unknown and zero are different.
    """
    if known_from is None or known_to is None:
        return UNKNOWN
    if end <= known_from:
        return UNKNOWN          # dropped by retention: the rows are gone
    if start >= known_to:
        # Not aggregated. Whether it can ever be is a question about
        # `event_rollup_1m` — the table the hourly rollup sums — and the caller
        # has already read that edge, so ask rather than assert. `None` means
        # the store could not be asked; that is not "gone", and must not be
        # reported as loss.
        if fallbacks.minute_from is not None and end <= fallbacks.minute_from:
            return MISSED       # the minute table cannot rebuild it either
        return PENDING          # recoverable: a repaired maintenance run refills it
    if start < known_from:
        return PARTIAL
    if complete_to is None or end > complete_to:
        return PARTIAL
    return KNOWN


def event_edges(
    coverage: dict[str, Any], *, now: datetime
) -> tuple[datetime | None, datetime | None, datetime | None]:
    """`(known_from, complete_to, known_to)` for a series read out of the rollup.

    This function exists so the edge arithmetic has one home that a test can
    call with exactly what the router passes. It used to be three expressions
    inlined in the handler, which is why the guard test for it could be — and
    was — written with a convenient input shape the handler never produces.

    `bucket` is a bucket START, so the rollup's data reaches to
    `max(bucket) + 1h`, and only up to `max(bucket)` is final: the maintenance
    pass rewrites its own watermark bucket on the next run, so the newest row is
    always a partial hour.
    """
    latest = coverage.get("latest")
    if latest is None:
        return None, None, None
    # Clamped to now: an interval that has not happened yet cannot be complete,
    # whatever a clock-skewed row says.
    return coverage.get("earliest"), min(latest, now), coverage.get("covered_to")


def live_edges(
    known_from: datetime | None, *, now: datetime, unit: str,
    tz_name: str = STORAGE_TZ
) -> tuple[datetime | None, datetime | None, datetime | None]:
    """The same three edges for a table written continuously and never pruned —
    `incidents`, `patch_executions`. Everything up to now exists; the bucket
    containing now is still filling.

    `known_to` is the END of the current bucket, not `now`. Returning `now`
    looked equivalent and was not: `_bucket_state` blanks a bucket when
    `start >= known_to`, so at an exact boundary — midnight UTC for a day
    bucket, the top of the hour for an hour bucket, Monday 00:00 for a week —
    `now >= now` held and today's incident column came back `pending`. That is
    meaningless for a table with no aggregation step and no raw store behind it:
    the column carried "Click pentru lista brută" while referring to an hourly
    rollup and a detail table that do not exist for `incidents` at all.

    The comment that used to sit at the call site said this could not happen. It
    could, once per bucket boundary, and nothing tested the claim — so it is
    arithmetic now, and `test_a_live_series_never_goes_pending_on_an_exact_
    bucket_boundary` holds it to that at every bucket size.

    It needs `unit` for the same reason the bug existed: "the end of the current
    bucket" is not a property of the clock alone.
    """
    return known_from, now, advance(truncate(now, unit, tz_name=tz_name), unit, 1,
                                    tz_name=tz_name)


def build_series(
    rows: list[Any],
    *,
    unit: str,
    starts: list[datetime],
    known_from: datetime | None,
    complete_to: datetime | None,
    known_to: datetime | None,
    fallbacks: Fallbacks,
    key_order: tuple[str, ...] | None = None,
    top: int | None = None,
    tz_name: str = STORAGE_TZ,
) -> Series:
    """Fold `(b, k, n)` rows into a dense matrix.

    Dense on purpose: a bucket with no rows is a real zero (inside the covered
    range) and must occupy a column, otherwise a quiet Tuesday disappears and
    Wednesday slides left into its place.
    """
    index = {start: i for i, start in enumerate(starts)}
    counts: dict[str, list[int]] = {}
    totals: dict[str, int] = {}
    zone_name = align_zone(unit, tz_name)

    for row in rows:
        bucket = _bucket_instant(row["b"], zone_name)
        if bucket is None:
            continue
        pos = index.get(bucket)
        if pos is None:
            # Outside the requested span. Can only happen if the caller's window
            # and its bucket list disagree; dropping is safer than mis-placing.
            continue
        key = row["k"] or ""
        n = int(row["n"] or 0)
        counts.setdefault(key, [0] * len(starts))[pos] += n
        totals[key] = totals.get(key, 0) + n

    if key_order is not None:
        keys = [k for k in key_order if k in counts]
        keys += sorted(k for k in counts if k not in key_order)
    else:
        keys = sorted(counts, key=lambda k: (-totals[k], k))

    if top is not None and len(keys) > top:
        kept, folded = keys[:top], keys[top:]
        rest = [0] * len(starts)
        for k in folded:
            for i, v in enumerate(counts[k]):
                rest[i] += v
            del counts[k]
            del totals[k]
        # "altele" is a display bucket, and it is deliberately not clickable in
        # the chart: a drill-down on it would have to guess which categories it
        # stood for, and guessing is how a report starts lying.
        counts["altele"] = rest
        totals["altele"] = sum(rest)
        keys = [*kept, "altele"]

    per_bucket = [sum(counts[k][i] for k in keys) for i in range(len(starts))]
    state = [
        _bucket_state(s, advance(s, unit, 1, tz_name=tz_name),
                      known_from, complete_to, known_to, fallbacks)
        for s in starts
    ]

    # Direct evidence beats inference. `state` is derived from coverage edges;
    # the row count is the database saying it holds those rows. If the two ever
    # disagree, the edges are wrong, and rendering "we hold nothing here" over a
    # bucket that demonstrably holds 100 events is the worse of the two lies —
    # it also makes the header total disagree with the sum of the bars. The edge
    # arithmetic is pinned separately by the tests for `event_edges`; this keeps
    # the page self-consistent if it is ever wrong again.
    for i, n in enumerate(per_bucket):
        if n and state[i] in BLANK:
            state[i] = PARTIAL

    return Series(
        unit=unit,
        tz_name=tz_name,
        starts=starts,
        keys=keys,
        counts=counts,
        totals=totals,
        per_bucket=per_bucket,
        state=state,
        grand_total=sum(per_bucket),
        fallbacks=fallbacks,
    )


# ---------------------------------------------------------------------------
# Chart geometry — server-rendered SVG, no client-side library
# ---------------------------------------------------------------------------
# Everything below produces plain numbers that the template drops into SVG
# geometry attributes. Not a `style="height:…"` anywhere: the CSP is
# `style-src 'self'` with no `unsafe-inline`, and CSP3 falls `style-src-attr`
# back to `style-src`, so a browser enforcing the policy discards inline style
# attributes. A bar chart drawn with them renders as a row of nothing — and,
# worse, renders as a row of nothing that looks exactly like "no data".
# SVG x/y/width/height are presentation attributes, not CSS, so they survive.

CHART_W = 960
CHART_H = 220
PAD_L, PAD_R, PAD_T, PAD_B = 46.0, 8.0, 12.0, 34.0

# Generic palette for categories with no intrinsic ranking (sources, actions).
PALETTE_SIZE = 8


@dataclass(frozen=True)
class Segment:
    x: float
    y: float
    w: float
    h: float
    key: str
    label: str
    n: int
    cls: str
    href: str | None
    title: str


@dataclass(frozen=True)
class Tick:
    x: float
    label: str


@dataclass(frozen=True)
class GapMark:
    """A bucket with no number, and which of the two reasons it is.

    `kind` is `unknown` (retention dropped it — hatched, loud) or `pending` (the
    aggregation has not reached it — a faint dashed outline). They are drawn
    differently on purpose: the hatch is the only mark that says a month is
    really gone, and if it also appeared at the right-hand edge most hours it
    would stop being read.
    """

    x: float
    y: float
    w: float
    h: float
    kind: str
    title: str
    # A `pending` bucket HAS rows — they are in `raw_events`, the rollup just
    # has not summed them yet — so the drill-down can answer for it, and saying
    # "the raw data exists" while offering no way to reach it is a worse answer
    # than saying nothing. `unknown` gets no link: there is genuinely nothing
    # behind it.
    href: str | None = None


@dataclass(frozen=True)
class GridLine:
    y: float
    label: str


@dataclass
class Chart:
    width: int
    height: int
    baseline: float
    segments: list[Segment]
    gaps: list[GapMark]
    ticks: list[Tick]
    grid: list[GridLine]
    legend: list[tuple[str, str, str, int]]   # key, display label, css class, total
    peak: int
    empty: bool


def _class_for(key: str, position: int, palette: dict[str, str] | None) -> str:
    if palette and key in palette:
        return palette[key]
    return f"rep-c{position % PALETTE_SIZE}"


def drill_href(base: dict[str, str], *, start: datetime, value: str) -> str:
    return "/reports/drill?" + urlencode(
        {**base, "start": start.isoformat(), "value": value}
    )


def build_chart(
    series: Series,
    *,
    labels: dict[str, str] | None = None,
    palette: dict[str, str] | None = None,
    drill: dict[str, str] | None = None,
    tick_fmt: str = "%d.%m",
) -> Chart:
    """Lay a stacked bar chart out in SVG user units."""
    n = len(series.starts)
    # Etichetele se scriu în fusul seriei, cu marcajul lui. Marcajul e AL
    # MOMENTULUI, nu al zonei: aceeași zonă e `EET` iarna și `EEST` vara, iar un
    # grafic pe 30 de zile poate trece peste schimbare. Fără el, ora citită de pe
    # pagină ar fi o afirmație pe care cititorul trebuie s-o ghicească — între
    # UTC și EEST sunt trei ore, destul cât să te uiți în jurnal în fereastra
    # greșită.
    def eticheta(moment: datetime, *, marcaj: bool = True) -> str:
        return tz.fmt(moment, tick_fmt, tz_name=series.tz_name, with_zone=marcaj)

    plot_w = CHART_W - PAD_L - PAD_R
    plot_h = CHART_H - PAD_T - PAD_B
    baseline = PAD_T + plot_h
    slot = plot_w / n if n else plot_w
    bar_w = max(3.0, slot * 0.74)
    peak = series.peak or 1

    segments: list[Segment] = []
    gaps: list[GapMark] = []

    for i, start in enumerate(series.starts):
        x = PAD_L + i * slot + (slot - bar_w) / 2
        if series.state[i] in BLANK:
            kind = series.state[i]
            href = None
            fb = series.fallbacks
            bucket_end = advance(start, series.unit, 1, tz_name=series.tz_name)
            if kind == UNKNOWN:
                note = "fără date păstrate pentru acest interval (nu înseamnă zero)"
            elif kind == MISSED:
                # Not aggregated, and `event_rollup_1m` cannot rebuild it
                # either — so this really is final, and now it has been checked
                # against the table the hourly rollup is actually built from
                # rather than against `raw_events`, which is sixty days shorter.
                note = ("neagregat, iar datele din care s-ar fi putut reface au "
                        "expirat — nu a mai rămas nimic pentru acest interval")
            elif fb.raw_from is not None and bucket_end <= fb.raw_from:
                # The 30–90 day band: the raw partitions are gone, so there is
                # no list of events to show and no link to offer — but every
                # minute of it is still in `event_rollup_1m` and the bar comes
                # back on its own. Saying "nothing left" here would point at
                # writing the period off instead of at restarting the timer.
                recovery = ("agregatul se reface din tabela de minute când "
                            "mentenanța repornește"
                            if fb.minute_from is not None else
                            "agregatul s-ar putea reface din tabela de minute, "
                            "dacă îl mai acoperă")
                note = ("încă neagregat — detaliul brut a expirat, deci nu există "
                        f"listă de evenimente de arătat, dar {recovery}")
            else:
                # The drill-down reads `raw_events` directly, so it can answer
                # for exactly this bucket. Promising the rows exist and giving
                # no route to them was worse than staying quiet.
                if fb.raw_from is None:
                    # The catalog could not tell us where the detail starts, so
                    # the claim is not made. The link still stands: the drill
                    # page reads the edge itself and says what it found.
                    detail = "detaliul brut poate exista"
                elif start >= fb.raw_from:
                    detail = "datele brute există"
                else:
                    detail = "datele brute există doar pentru partea recentă"
                note = (f"încă neagregat — {detail}, agregatul orar nu a ajuns aici "
                        "(nu înseamnă zero). Click pentru lista brută")
                href = (drill_href(drill | {"scope": "all"}, start=start, value="")
                        if drill is not None and drill.get("kind") == "events" else None)
            gaps.append(GapMark(
                x=round(x, 1), y=round(PAD_T, 1), w=round(bar_w, 1), h=round(plot_h, 1),
                kind=kind, title=f"{eticheta(start)} — {note}", href=href,
            ))
            continue
        top = baseline
        for pos, key in enumerate(series.keys):
            value = series.counts[key][i]
            if value <= 0:
                continue
            h = value / peak * plot_h
            top -= h
            shown = (labels or {}).get(key) or key or "necunoscut"
            note = " (interval incomplet)" if series.state[i] == PARTIAL else ""
            segments.append(Segment(
                x=round(x, 1), y=round(top, 1), w=round(bar_w, 1), h=round(h, 1),
                key=key, label=shown, n=value,
                cls=_class_for(key, pos, palette),
                # "altele" folds several categories together, so there is no
                # single filter that reproduces it. No link rather than a wrong one.
                href=(drill_href(drill, start=start, value=key)
                      if drill is not None and key not in ("", "altele") else None),
                title=f"{eticheta(start)} · {shown}: {value}{note}",
            ))

    # Roughly a dozen ticks whatever the bucket count, always including the last.
    every = max(1, -(-n // 12))
    # Axa rămâne fără marcaj — s-ar repeta de douăsprezece ori pe același grafic
    # și ar face eticheta ilizibilă. Fusul e spus o dată, în capul paginii, și
    # pe fiecare tooltip, adică exact acolo unde se citește un moment anume.
    ticks = [
        Tick(x=round(PAD_L + i * slot + slot / 2, 1), label=eticheta(s, marcaj=False))
        for i, s in enumerate(series.starts)
        if (n - 1 - i) % every == 0
    ]

    grid = [
        GridLine(y=round(baseline - frac * plot_h, 1), label=str(round(peak * frac)))
        for frac in (0.0, 0.5, 1.0)
    ]

    legend = [
        (k, (labels or {}).get(k) or k or "necunoscut",
         _class_for(k, pos, palette), series.totals.get(k, 0))
        for pos, k in enumerate(series.keys)
    ]

    return Chart(
        width=CHART_W, height=CHART_H, baseline=round(baseline, 1),
        segments=segments, gaps=gaps, ticks=ticks, grid=grid,
        legend=legend, peak=series.peak, empty=series.empty,
    )


# ---------------------------------------------------------------------------
# Coverage — what the store actually holds
# ---------------------------------------------------------------------------
async def rollup_coverage(db: Database, *, now: datetime | None = None) -> dict[str, Any]:
    """The honest bounds of `event_rollup_1h`, plus how stale it is.

    Read from the table, not from `cfg.retention`: the configuration says what
    should be kept, and the only thing worth charting against is what IS kept.
    They differ whenever the disk guard has fired, which is precisely the moment
    somebody is looking at a report wondering where March went.

    `now` is injected so a page renders against one clock reading rather than
    one per call — see `web/deps.now_utc`.
    """
    row = await db.fetchrow(
        "SELECT min(bucket) AS earliest, max(bucket) AS latest FROM event_rollup_1h"
    )
    earliest = _as_utc(row["earliest"]) if row else None
    latest = _as_utc(row["latest"]) if row else None
    now = now or datetime.now(timezone.utc)
    lag_h = None if latest is None else round((now - latest).total_seconds() / 3600, 1)
    return {
        "earliest": earliest,
        # The newest bucket START that has a row. Good for saying "aggregated up
        # to 06:00"; wrong as a coverage edge, because that row covers the hour
        # that BEGINS there. `covered_to` is the edge.
        "latest": latest,
        "covered_to": None if latest is None else latest + ROLLUP_BUCKET,
        "lag_hours": lag_h,
        # Never rolled up at all: the maintenance timer has not completed a pass
        # since install. Every event chart on the page would be empty, and empty
        # must not read as "quiet".
        "never_ran": latest is None,
        "stale": lag_h is not None and lag_h > ROLLUP_STALE_HOURS,
    }


async def raw_coverage(db: Database) -> datetime | None:
    """Oldest day for which a `raw_events` partition still exists.

    From the catalog rather than `min(ts)`: the latter is a scan of every
    partition, and the answer is already in `pg_inherits`. Retention drops whole
    partitions, so the oldest surviving partition IS the edge of the detail —
    anything before it is gone, not quiet.
    """
    day = await db.fetchval(
        """
        SELECT min(to_date(right(c.relname, 8), 'YYYYMMDD'))
        FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class p    ON p.oid = i.inhparent
        WHERE p.relname = 'raw_events'
          AND c.relname ~ '_[0-9]{8}$'
        """
    )
    return _as_utc(day)


async def minute_coverage(db: Database) -> datetime | None:
    """Oldest surviving row in `event_rollup_1m`.

    The recoverability edge. `sentinel_rollup_events_1h` sums this table, so a
    bucket the hourly rollup has not reached can still be rebuilt exactly as
    long as the minute table holds it — and `rollup_1m_days` (90) is three times
    `raw_events_days` (30), which is why "the raw detail expired" and "this is
    lost" are sixty days apart and must not be said in the same breath.

    Same shape and cost as the hourly probe: `bucket` leads the primary key, so
    this is an index-only scan of one row.
    """
    return _as_utc(await db.fetchval("SELECT min(bucket) FROM event_rollup_1m"))


async def installed_at(db: Database) -> datetime | None:
    """When this Sentinel first applied its schema.

    The coverage edge for `incidents` and `patch_executions`, and it has to come
    from somewhere other than those tables. Neither is ever pruned, so a zero in
    them genuinely means zero — but only *after* Sentinel existed. Taking
    `min(first_detection_at)` as the edge instead would paint every quiet month
    before the first incident as "no data", and taking nothing at all would
    paint every month before install as "zero incidents", which reads as a clean
    record for a period when nobody was looking.

    `schema_version` answers it exactly and costs one row.
    """
    return _as_utc(await db.fetchval("SELECT min(applied_at) FROM schema_version"))


def earliest(*moments: datetime | None) -> datetime | None:
    """The oldest moment that is actually known. All-None stays None — that is
    the "we cannot tell" case, and it must not collapse into a date."""
    present = [m for m in moments if m is not None]
    return min(present) if present else None


# ---------------------------------------------------------------------------
# Time series queries
# ---------------------------------------------------------------------------
async def events_rows(
    db: Database, *, unit: str, start: datetime, end: datetime, dim: str,
    tz_name: str = STORAGE_TZ
) -> list[Any]:
    """Event counts per bucket per category, straight out of the hourly rollup.

    `AT TIME ZONE` before truncating is not decoration: `date_trunc` on a
    `timestamptz` truncates in the *session* time zone, which asyncpg does not
    pin. On a host whose PostgreSQL defaults to a local zone, days would silently
    start at 21:00 or 03:00 and never say so. Converting to a naive timestamp in
    a NAMED zone first makes the answer the same on every host.

    Zona ajunge acolo ca PARAMETRU, `$2`, niciodată interpolată în textul
    instrucțiunii — și e una dintre cele pe care `align_zone` le poate întoarce,
    adică una pe care Python a rezolvat-o deja. Aceeași disciplină ca la coloana
    de dimensiune, din același motiv: valoarea vine din configurație, iar un
    `f"AT TIME ZONE '{tz}'"` ar fi o cale de injecție deschisă de un câmp de
    configurare.
    """
    column = EVENT_DIMS[dim]
    return list(await db.fetch(
        f"""
        SELECT date_trunc($1::text, bucket AT TIME ZONE $2::text) AS b,
               COALESCE({column}, '') AS k,
               sum(n)::bigint AS n
        FROM event_rollup_1h
        WHERE bucket >= $3 AND bucket < $4
        GROUP BY 1, 2
        """,  # noqa: S608 - {column} comes from EVENT_DIMS, never from a request
        unit, align_zone(unit, tz_name), start, end,
    ))


async def incidents_rows(
    db: Database, *, unit: str, start: datetime, end: datetime, dim: str,
    tz_name: str = STORAGE_TZ
) -> list[Any]:
    """Incidents per bucket, placed by when they were OPENED.

    Not by `last_detection_at`: an incident that stays open for three weeks
    would then walk across the chart and be counted in whichever bucket it was
    last touched, so "how many incidents did March bring" would answer with
    incidents that started in January.
    """
    column = INCIDENT_DIMS[dim]
    return list(await db.fetch(
        f"""
        SELECT date_trunc($1::text, first_detection_at AT TIME ZONE $2::text) AS b,
               COALESCE({column}, '') AS k,
               count(*) AS n
        FROM incidents
        WHERE first_detection_at >= $3 AND first_detection_at < $4
        GROUP BY 1, 2
        """,  # noqa: S608 - {column} comes from INCIDENT_DIMS, never from a request
        unit, align_zone(unit, tz_name), start, end,
    ))


async def patches_rows(
    db: Database, *, unit: str, start: datetime, end: datetime,
    tz_name: str = STORAGE_TZ
) -> list[Any]:
    """Real applies only. A dry run touches nothing, and counting one as a patch
    would let a page report work that never happened."""
    return list(await db.fetch(
        """
        SELECT date_trunc($1::text, started_at AT TIME ZONE $2::text) AS b,
               COALESCE(status, '') AS k,
               count(*) AS n
        FROM patch_executions
        WHERE started_at >= $3 AND started_at < $4 AND mode = 'apply'
        GROUP BY 1, 2
        """,
        unit, align_zone(unit, tz_name), start, end,
    ))


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class WindowCoverage:
    """How much of a requested window the data actually reaches back over.

    A counter without this is a counter that changes meaning as retention fills
    up: with 5.8 days of rollup on disk, "7z" and "30z" print the same number,
    and next month the same "30z" will print five times more for no reason
    anybody can see. The number is only worth as much as the span behind it, so
    the span travels with it.
    """

    requested_from: datetime
    covered_from: datetime | None
    hours_requested: int
    hours_covered: float | None

    @property
    def unknown(self) -> bool:
        """Nothing at all is known about the window."""
        return self.covered_from is None

    @property
    def partial(self) -> bool:
        return self.covered_from is not None and self.covered_from > self.requested_from


def window_coverage(
    *, since: datetime, now: datetime, edge: datetime | None, hours: int
) -> WindowCoverage:
    """`edge` is the oldest moment the underlying store holds anything for."""
    if edge is None:
        return WindowCoverage(since, None, hours, None)
    covered_from = max(since, edge)
    return WindowCoverage(
        requested_from=since,
        covered_from=covered_from,
        hours_requested=hours,
        hours_covered=round(max(0.0, (now - covered_from).total_seconds() / 3600), 1),
    )


async def overview(
    db: Database,
    *,
    hours: int,
    rollup_from: datetime | None,
    installed_from: datetime | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The headline numbers for one window, plus what is open right now.

    "Open" counts are as of now and deliberately not windowed: an incident
    opened five weeks ago and still open is a fact about today, and hiding it
    behind a 24-hour filter is how a queue grows unread.

    Every WINDOWED number carries a `WindowCoverage` saying how far back the
    data behind it actually goes. `rollup_from` and `installed_from` are passed
    in rather than re-queried so the cards and the charts on the same page are
    reasoning about one snapshot of coverage, not two taken a few milliseconds
    apart.
    """
    now = now or datetime.now(timezone.utc)
    # Floored to the hour, and floored DOWNWARD. `event_rollup_1h` can only
    # answer in whole hours, so `now - 24h` on a `bucket >= …` filter drops the
    # partial oldest hour and quietly turns "24h" into 23 — under-reporting an
    # attack window. Rounding outward can only ever include a little more than
    # was asked for, and the page prints the exact interval it used.
    since = truncate(now - timedelta(hours=hours), "hour")

    ev = await db.fetchrow(
        """
        SELECT COALESCE(sum(n), 0)::bigint AS total,
               COALESCE(sum(n) FILTER (WHERE action IN ('auth_fail','alert')),
                        0)::bigint AS hostile
        FROM event_rollup_1h WHERE bucket >= $1
        """,
        since,
    )
    ev_sources = await db.fetch(
        """
        SELECT source AS k, sum(n)::bigint AS n
        FROM event_rollup_1h WHERE bucket >= $1
        -- ORDER BY 2, not `ORDER BY n`: `n` is also a column of the table, and
        -- a bare name that shadows an input column is the kind of ambiguity
        -- that resolves one way today and another way after a schema change.
        GROUP BY 1 ORDER BY 2 DESC LIMIT $2
        """,
        since, SOURCE_ROWS_MAX,
    )

    inc_open = await db.fetch(
        """
        SELECT severity AS k, count(*) AS n FROM incidents
        WHERE status IN ('open','acknowledged') GROUP BY 1
        """
    )
    inc_new = await db.fetch(
        """
        SELECT severity AS k, count(*) AS n FROM incidents
        WHERE first_detection_at >= $1 GROUP BY 1
        """,
        since,
    )

    patch = await db.fetchrow(
        """
        SELECT count(*) FILTER (WHERE status = 'succeeded') AS succeeded,
               count(*) FILTER (WHERE status = ANY($2::text[])) AS failed,
               count(*) FILTER (WHERE status = 'rolled_back') AS rolled_back,
               count(*) AS total
        FROM patch_executions
        WHERE started_at >= $1 AND mode = 'apply'
        """,
        since, list(PATCH_FAILED),
    )

    fnd = await db.fetchrow(
        """
        SELECT count(*) FILTER (WHERE status = 'open') AS deschise,
               count(*) FILTER (WHERE status = 'open' AND kev) AS kev,
               count(*) FILTER (WHERE status = 'open'
                                  AND severity IN ('high','critical')) AS grave,
               count(*) FILTER (WHERE first_seen >= $1) AS noi,
               count(*) FILTER (WHERE resolved_at >= $1) AS rezolvate
        FROM findings
        """,
        since,
    )

    def as_map(rows: list[Any]) -> dict[str, int]:
        return {r["k"]: int(r["n"] or 0) for r in rows}

    open_by_sev = as_map(inc_open)
    new_by_sev = as_map(inc_new)

    # Events come out of the rollup, so they reach back only as far as the
    # rollup does. Incidents, patch executions and findings are never pruned, so
    # they reach back to the install — which is still not "for ever", and a
    # 30-day card on a 6-day-old install must say so rather than imply calm.
    ev_cov = window_coverage(since=since, now=now, edge=rollup_from, hours=hours)
    live_cov = window_coverage(since=since, now=now, edge=installed_from, hours=hours)

    # The chart folds its tail into a stated "altele"; this card used to just
    # stop at eight rows, which made it the only place on the page where a
    # category could disappear leaving nothing behind.
    src_rows = [{"key": r["k"], "n": int(r["n"] or 0)} for r in ev_sources]
    src_shown, src_rest = src_rows[:SOURCE_ROWS_SHOWN], src_rows[SOURCE_ROWS_SHOWN:]
    if src_rest:
        src_shown.append({"key": "altele", "n": sum(r["n"] for r in src_rest),
                          "folded": len(src_rest)})

    return {
        "since": since,
        "now": now,
        "hours": hours,
        "events": {
            "total": int(ev["total"] or 0) if ev else 0,
            "hostile": int(ev["hostile"] or 0) if ev else 0,
            "by_source": src_shown,
            # The read itself hit its ceiling, so even "altele" is incomplete.
            "sources_truncated": len(ev_sources) >= SOURCE_ROWS_MAX,
            "coverage": ev_cov,
        },
        "incidents": {
            "open": open_by_sev,
            "open_total": sum(open_by_sev.values()),
            "open_grave": open_by_sev.get("high", 0) + open_by_sev.get("critical", 0),
            "new": new_by_sev,
            "new_total": sum(new_by_sev.values()),
            "coverage": live_cov,
        },
        "patches": {
            "succeeded": int(patch["succeeded"] or 0) if patch else 0,
            "failed": int(patch["failed"] or 0) if patch else 0,
            "rolled_back": int(patch["rolled_back"] or 0) if patch else 0,
            "total": int(patch["total"] or 0) if patch else 0,
            "coverage": live_cov,
        },
        "findings": {
            "open": int(fnd["deschise"] or 0) if fnd else 0,
            "kev": int(fnd["kev"] or 0) if fnd else 0,
            "grave": int(fnd["grave"] or 0) if fnd else 0,
            "new": int(fnd["noi"] or 0) if fnd else 0,
            "resolved": int(fnd["rezolvate"] or 0) if fnd else 0,
            "coverage": live_cov,
        },
    }


# ---------------------------------------------------------------------------
# Drill-down
# ---------------------------------------------------------------------------
def drill_bounds(unit: str, start: datetime, *,
                 tz_name: str = STORAGE_TZ) -> tuple[datetime, datetime]:
    return start, advance(start, unit, 1, tz_name=tz_name)


@dataclass(frozen=True)
class RawWindow:
    """Which slice of a bucket the drill-down actually reads, and why."""

    start: datetime
    end: datetime
    expired: bool     # the whole bucket predates the oldest surviving partition
    capped: bool      # narrowed by DRILL_MAX_HOURS
    trimmed: bool     # narrowed further by retention

    @property
    def narrowed(self) -> bool:
        return self.capped or self.trimmed


def clamp_raw_window(
    start: datetime, end: datetime, *, raw_from: datetime | None
) -> RawWindow:
    """Narrow a bucket to something `raw_events` can answer cheaply.

    Two independent reasons the read window can be smaller than the bucket, and
    the page has to be able to say which:

    * `capped`  — the bucket is longer than DRILL_MAX_HOURS, so only its tail is
      read. Scanning a year of daily partitions to fill one screen of rows is
      how a report page becomes the reason detection stalled.
    * `trimmed` — retention has already dropped the older partitions inside the
      bucket. Nothing was skipped for cost; those rows are gone.

    `trimmed` is computed AFTER retention is applied, not before. Deriving it
    from the cap alone meant that when the oldest surviving partition fell
    inside the last DRILL_MAX_HOURS of a bucket, the window silently narrowed
    with neither flag set: the header showed the whole bucket and the table came
    from a shorter one.

    `expired` is the whole bucket being older than anything kept — then there is
    nothing to read at all, and saying so is the difference between "we deleted
    it" and "nothing happened".
    """
    cap_start = end - timedelta(hours=DRILL_MAX_HOURS)
    lo = max(start, cap_start)
    capped = lo > start

    trimmed = False
    if raw_from is not None and raw_from > lo:
        lo = raw_from
        trimmed = True

    expired = raw_from is not None and end <= raw_from
    if expired:
        # Nothing survives in this bucket; the narrowing flags would only add
        # noise to a page that has a stronger thing to say.
        return RawWindow(start=start, end=end, expired=True, capped=False, trimmed=False)
    return RawWindow(start=lo, end=end, expired=False, capped=capped, trimmed=trimmed)


async def drill_incidents(
    db: Database, *, start: datetime, end: datetime, dim: str, value: str
) -> list[dict[str, Any]]:
    column = INCIDENT_DIMS[dim]
    rows = await db.fetch(
        f"""
        SELECT id, severity, status, title, actor_key, detection_count,
               first_detection_at, last_detection_at
        FROM incidents
        WHERE first_detection_at >= $1 AND first_detection_at < $2
          AND COALESCE({column}, '') = $3
        ORDER BY first_detection_at DESC
        LIMIT $4
        """,  # noqa: S608 - {column} comes from INCIDENT_DIMS, never from a request
        start, end, value, DRILL_LIMIT,
    )
    return [dict(r) for r in rows]


_DRILL_EVENT_COLS = """
        SELECT ts, source, action, host(src_ip) AS src_ip, username,
               http_method, http_path, http_status, http_host,
               geo_country, geo_asn, process
        FROM raw_events
"""


async def drill_events(
    db: Database, *, start: datetime, end: datetime, dim: str, value: str,
    all_categories: bool = False,
) -> list[dict[str, Any]]:
    """Individual events in one bucket.

    `all_categories` drops the category predicate. It exists for the `pending`
    columns of the chart: those have no categories yet — the rollup has not
    summed them — but the rows are in `raw_events` and this is what reaches
    them. Two statements rather than one with `($3 = '' OR col = $3)`, because a
    predicate that is sometimes a no-op is a predicate the planner has to guess
    about on every call.
    """
    if all_categories:
        rows = await db.fetch(
            _DRILL_EVENT_COLS + """
        WHERE ts >= $1 AND ts < $2
        ORDER BY ts DESC
        LIMIT $3
        """,
            start, end, DRILL_LIMIT,
        )
        return [dict(r) for r in rows]

    column = EVENT_DIMS[dim]
    rows = await db.fetch(
        _DRILL_EVENT_COLS + f"""
        WHERE ts >= $1 AND ts < $2 AND {column} = $3
        ORDER BY ts DESC
        LIMIT $4
        """,  # noqa: S608 - {column} comes from EVENT_DIMS, never from a request
        start, end, value, DRILL_LIMIT,
    )
    return [dict(r) for r in rows]


async def drill_patches(
    db: Database, *, start: datetime, end: datetime, value: str
) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT e.id, e.plan_id, e.status, e.started_at, e.duration_ms,
               e.post_verification_passed, e.rollback_reason, e.error,
               p.risk_level, p.plan->'target'->>'asset_name' AS asset_name
        FROM patch_executions e
        JOIN patch_plans p ON p.id = e.plan_id
        WHERE e.started_at >= $1 AND e.started_at < $2
          AND e.mode = 'apply' AND e.status = $3
        ORDER BY e.started_at DESC
        LIMIT $4
        """,
        start, end, value, DRILL_LIMIT,
    )
    return [dict(r) for r in rows]
