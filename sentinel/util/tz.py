"""Ora pe care o citește operatorul, și fusul în care se evaluează ferestrele.

Baza de date scrie și păstrează UTC, și rămâne așa. Ce se schimbă aici e ce
vede un om și în ce fus se judecă „ora e nefirească" — două lucruri diferite,
amândouă greșite până acum în același fel.

## Eșecurile pe care le previne, măsurate pe gazdă

Fusul configurat e `Europe/Bucharest`, adică UTC+3 vara. Fereastra „ore
nefirești" din `detect/logins.py` era `range(1, 6)` evaluat pe ORA UTC:

  * **fals pozitiv** — o logare la 08:54 local e 05:54 UTC, deci în fereastră.
    Opt fără cinci dimineața nu e o oră nefirească, iar o alertă care se
    înșală în mod evident e o alertă pe care operatorul învață s-o ignore;
  * **fals negativ, mai grav** — o logare la 03:00 local e 00:00 UTC, care NU e
    în `range(1, 6)`. Adică exact orele la care cineva ar intra pe furiș erau
    singurele care taceau.

Aceeași greșeală, în varianta ei blândă, era în afișare: mesajele spuneau
`21:15 UTC` pentru ceva întâmplat la miezul nopții, iar operatorul trebuia să
adune trei ore în cap la 3 dimineața.

## Nume de zonă, nu decalaj

`ZoneInfo("Europe/Bucharest")`, niciodată `timedelta(hours=3)`. Argumentul e
scris deja în `sentinel/telegram/quiet.py` și e la fel de valabil aici: un
decalaj fix n-are reguli de oră de vară, deci în noaptea în care se schimbă
ceasurile totul se calculează cu o oră greșit — o dată pe an, pe întuneric,
adică exact când nu se uită nimeni.

## De ce trăiesc `zone` și `host_zone_name` aici și nu în `quiet.py`

Fiindcă acum le folosesc și detecția, panoul web și autoverificarea, iar un
mecanism copiat e un mecanism care se desincronizează. `quiet.py` le
reexportă, deci `quiet.zone(...)` — chemat din `telegram/bot.py` — înseamnă
exact ce însemna. Comportamentul lor NU s-a schimbat la mutare; testele lui
`quiet` sunt dovada.

## Marcajul de fus e obligatoriu

Fiecare oră afișată poartă zona: `27.08 21:15 EEST`. Fără el, o oră e o
afirmație pe care cititorul trebuie s-o ghicească, iar între UTC și EEST sunt
trei ore — destul cât să te uiți în jurnal în fereastra greșită.

Când fusul cerut nu există, `zone()` coboară zgomotos (o linie de eroare) la
fusul gazdei și, în ultimă instanță, la ceasul procesului. Ora NU dispare din
mesaj în niciunul dintre cazuri, iar marcajul spune în ce fus a ieșit până la
urmă — inclusiv `UTC`, dacă acolo s-a ajuns. „Nu știu în ce fus" și „e ora
locală" sunt stări diferite, iar marcajul e ce le ține diferite.
"""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sentinel.logging_setup import get_logger

log = get_logger(__name__)

#: Forma implicită: zi.lună, oră:minut. Aceeași pe care o folosea deja
#: `bot._fmt_local` pentru expirări, ca două ore din același mesaj să nu arate
#: diferit.
SHORT = "%d.%m %H:%M"

#: Cu an, pentru momentele care pot fi vechi de luni de zile.
LONG = "%Y-%m-%d %H:%M"


def host_zone_name() -> str | None:
    """The host's IANA zone name, or None if it cannot be determined.

    Worth the effort over `datetime.now().astimezone()`, which yields a FIXED
    offset captured at that instant — "+03:00", not "Europe/Bucharest". A fixed
    offset has no DST rules, so on the night the clocks change, the end of a
    22:00-06:00 window is computed an hour wrong. Once a year, in the dark,
    is exactly when nobody is watching.

    Both supported families are covered: Debian writes the name to
    /etc/timezone, RHEL symlinks /etc/localtime into the zoneinfo tree.
    """
    from pathlib import Path

    try:
        text = Path("/etc/timezone").read_text(encoding="utf-8").strip()
        if text:
            return text
    except OSError:
        pass
    try:
        target = Path("/etc/localtime").resolve()
        parts = target.parts
        if "zoneinfo" in parts:
            return "/".join(parts[parts.index("zoneinfo") + 1:]) or None
    except OSError:
        pass
    return None


def zone(name: str | None) -> ZoneInfo | timezone:
    """The zone the window is read in. Falls back loudly, never silently to UTC.

    A three-hour error here silences the wrong three hours — the evening the
    operator wanted covered stays loud and the morning goes quiet.
    """
    for candidate, explicit in ((name, True), (host_zone_name(), False)):
        if not candidate:
            continue
        try:
            return ZoneInfo(candidate)
        except (ZoneInfoNotFoundError, ValueError):
            if explicit:
                log.error("unknown timezone, falling back to host local",
                          extra={"timezone": candidate})
    # Last resort: a fixed offset from the running process. Correct right now,
    # and wrong for one night per year at the DST boundary.
    local = datetime.now().astimezone().tzinfo
    return local if local is not None else timezone.utc


def to_local(moment: datetime, tz_name: str | None = None) -> datetime:
    """`moment` in the configured zone. Never raises, never returns naive.

    Un `datetime` naiv nu e un moment, e o ghicitoare. `.astimezone()` l-ar citi
    tăcut în ora procesului, care pe gazdă e UTC și pe altă mașină nu e — adică
    o oră afișată greșit fără nimic care să spună asta. Baza întoarce
    `timestamptz`, deci dacă ajunge aici unul naiv, altceva e stricat și trebuie
    să se vadă în jurnal.
    """
    if moment.tzinfo is None:
        log.warning("naive datetime on a display path, reading it as UTC",
                    extra={"moment": moment.isoformat()})
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(zone(tz_name))


def label(moment: datetime, tz_name: str | None = None) -> str:
    """Marcajul de fus pentru momentul ăsta: `EEST`, `EET`, `UTC`.

    Al momentului, nu al zonei: aceeași zonă e `EET` iarna și `EEST` vara, iar
    un marcaj care nu ține cont de asta ar fi greșit jumătate de an.

    Când `%Z` nu dă nimic — se întâmplă cu decalajele fixe pe care le întoarce
    `zone()` în ultimă instanță — se scrie decalajul, `UTC+03:00`. Un marcaj
    urât e în continuare un marcaj; unul absent lasă cititorul să ghicească.
    """
    aware = to_local(moment, tz_name)
    name = aware.strftime("%Z").strip()
    if name and " " not in name:
        return name
    offset = aware.utcoffset()
    if offset is None:  # pragma: no cover - to_local always returns aware
        return "UTC"
    total = int(offset.total_seconds())
    semn = "+" if total >= 0 else "-"
    total = abs(total)
    return f"UTC{semn}{total // 3600:02d}:{total % 3600 // 60:02d}"


def fmt(moment: datetime | None, pattern: str = SHORT, *,
        tz_name: str | None = None, with_zone: bool = True,
        missing: str = "necunoscut") -> str:
    """Un moment, scris pentru un om, în fusul configurat și cu marcajul lui.

    `None` întoarce `missing`, nu un șir gol și nu ora curentă: „nu se știe" și
    „acum" sunt stări diferite, iar una scrisă în locul celeilalte e chiar
    tiparul după care e numit depozitul ăsta.

    `with_zone=False` există pentru rândurile în care marcajul se scrie o
    singură dată pentru tot tabelul — nu ca să poată fi omis.
    """
    if moment is None:
        return missing
    aware = to_local(moment, tz_name)
    text = aware.strftime(pattern)
    return f"{text} {label(moment, tz_name)}" if with_zone else text


def hour(moment: datetime, tz_name: str | None = None) -> int:
    """Ora din zi, în fusul configurat.

    Există ca funcție, și nu ca `to_local(...).hour` scris de fiecare apelant,
    fiindcă ăsta e locul în care greșeala a costat: o fereastră de ore evaluată
    pe `.hour` al unui moment UTC e mutată cu tot decalajul, iar simptomul e
    jumătate alarme false și jumătate tăcere.
    """
    return to_local(moment, tz_name).hour
