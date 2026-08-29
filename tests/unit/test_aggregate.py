"""`aggregate.sources` — the "Surse de date" card, and the query behind it.

The interesting failures here are all in SQL, so the tests run the SHIPPED
query — the one `sources` actually hands to the driver — against an in-memory
SQLite. A stub that returned canned rows would agree with any query at all,
including one that lost half the sources; that is the shape of dead test this
repository has already paid for twice.

Only the constructs SQLite does not have are rewritten, each one a change of
form and not of meaning, and `_tradu` refuses to hand over a query that still
contains a PostgreSQL construct it did not translate.
"""
from __future__ import annotations

import asyncio
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from sentinel.analytics import aggregate


def run(coro):
    return asyncio.run(coro)


#: Momentul de referință al fișierului, luat O SINGURĂ DATĂ.
#:
#: `_t()` era chemat de două ori pentru același moment — o dată la construirea
#: fixturii, o dată în aserțiune — iar între cele două apeluri se putea trece o
#: graniță de secundă. Măsurat pe 29 august 2026: ~0,25% eșec pe rulare de
#: fișier, adică un roșu fals la câteva sute de rulări de suită. Un roșu fals e
#: mai puțin grav decât un verde fals, dar are același efect asupra omului care
#: îl vede: îl învață că suita minte uneori, și atunci nu mai crede nici roșul
#: adevărat.
#:
#: Înghețat aici, `_t(minutes=70)` întoarce același șir oriunde e chemat în
#: aceeași rulare. Interogările folosesc `now()`-ul real al lui SQLite, deci
#: între import și rulare se pot scurge secundele suitei — inofensiv, fiindcă
#: ferestrele testelor sunt de ordinul minutelor și al zilelor, iar decalajul
#: mută toate momentele împreună.
_ACUM = datetime.now(timezone.utc)


def _t(**delta) -> str:
    """Un moment din trecut, în formatul în care SQLite compară text cu text."""
    return (_ACUM - timedelta(**delta)).strftime("%Y-%m-%d %H:%M:%S")


def _minut(ts: str) -> str:
    """Bucketul de rollup în care ar cădea momentul dat."""
    return ts[:16] + ":00"


#: `LEFT JOIN LATERAL` nu există în SQLite. Subinterogarea numără, deci
#: întoarce ÎNTOTDEAUNA exact un rând — 0 când nu găsește nimic. Un `LEFT JOIN`
#: cu numărătoarea deja grupată dă `NULL` în locul acelui 0, iar `sources` îl
#: trece prin `COALESCE(..., 0)`: aceleași cifre, altă formă.
_LATERAL_24H = re.compile(
    r"LEFT JOIN LATERAL \(\s*"
    r"SELECT count\(\*\) AS n FROM raw_events e\s*"
    r"WHERE e\.source = a\.source AND e\.action = a\.action\s*"
    r"AND e\.ts > now\(\) - interval '24 hours'\) c ON true",
    re.S)
_LATERAL_24H_SQLITE = (
    "LEFT JOIN (SELECT source, action, count(*) AS n FROM raw_events "
    "WHERE ts > now() - interval '24 hours' GROUP BY 1, 2) c "
    "ON c.source = a.source AND c.action = a.action")

#: Restul e formă pură: `datetime('now', ...)` e chiar aritmetica de interval,
#: iar `::bigint` e o conversie pe care SQLite o face oricum.
_TRADUCERI = (
    (re.compile(r"now\(\)\s*-\s*interval\s*'(\d+) (\w+)'"), r"datetime('now','-\1 \2')"),
    (re.compile(r"::bigint"), ""),
)

#: Ce nu are voie să rămână după traducere. Fără verificarea asta, o rescriere a
#: interogării din `aggregate.py` ar putea face regexul de mai sus să nu mai
#: potrivească nimic, iar testele ar pica pe o eroare de sintaxă confuză — sau,
#: mai rău, SQLite ar accepta construcția cu ALT înțeles și testele ar compara
#: liniștite două lucruri greșite.
_RAMASITE_PG = ("LATERAL", "ON true", "interval '", "now()", "::", "->>")


def _tradu(sql: str) -> str:
    sql = _LATERAL_24H.sub(_LATERAL_24H_SQLITE, sql)
    for tipar, inlocuire in _TRADUCERI:
        sql = tipar.sub(inlocuire, sql)
    ramase = [m for m in _RAMASITE_PG if m in sql]
    assert not ramase, f"construcții PostgreSQL netraduse: {ramase}"
    return sql


class _SQLite:
    """Cât din `Database` îi trebuie lui `sources`: un `fetch` care chiar rulează."""

    def __init__(self, rollup=(), raw=()):
        self.rollup = list(rollup)
        self.raw = list(raw)
        self.sql: str | None = None

    async def fetch(self, sql, *args):
        self.sql = sql
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        con.execute("CREATE TABLE event_rollup_1m (bucket TEXT, asset_id INTEGER, "
                    "source TEXT, action TEXT, n INTEGER)")
        con.execute("CREATE TABLE raw_events (id INTEGER PRIMARY KEY, ts TEXT, "
                    "source TEXT, action TEXT)")
        con.executemany("INSERT INTO event_rollup_1m (bucket, asset_id, source, action, n) "
                        "VALUES (?, 0, ?, ?, ?)", self.rollup)
        con.executemany("INSERT INTO raw_events (ts, source, action) VALUES (?, ?, ?)",
                        self.raw)
        try:
            return [dict(r) for r in con.execute(_tradu(sql)).fetchall()]
        finally:
            con.close()


def _pe_sursa(randuri):
    return {r["source"]: r for r in randuri}


# --- inventarul nu are voie să se subțieze ---------------------------------
def test_a_silent_source_stays_in_the_table_with_a_zero():
    """O sursă tăcută trebuie să rămână în tabel, cu zero.

    Pana pe care o previne: cardul „Surse de date" e singurul loc din panou în
    care un colector mort se vede — și se vede fiindcă scrie zero, nu fiindcă
    lipsește. Dacă un rând dispare, operatorul citește „sshd nu există aici",
    nu „sshd a amuțit", și treizeci de zile de autentificări nevăzute arată
    identic cu o lună liniștită. E exact pana de trei zile din care s-a născut
    `_gap_insights`, mutată în tabelul de alături.

    E ușor de pierdut fix la schimbarea asta: ultima activitate nu mai vine
    dintr-un `LEFT JOIN` peste inventar, ci dintr-o reuniune — iar o reuniune
    din care lipsește ramura de rollup conține doar sursele care AU scris.
    """
    db = _SQLite(
        rollup=[(_minut(_t(days=8)), "sudo", "auth_ok", 3),
                (_minut(_t(minutes=2)), "nginx", "alert", 40)],
        raw=[(_t(minutes=2), "nginx", "alert"), (_t(hours=5), "nginx", "alert")],
    )
    out = _pe_sursa(run(aggregate.sources(db)))
    assert "sudo" in out, "sursa tăcută a dispărut din tabel"
    assert out["sudo"]["ev_24h"] == 0
    assert out["sudo"]["ultim"] == _minut(_t(days=8))
    assert out["nginx"]["ev_24h"] == 2


def test_a_pair_seen_in_both_halves_does_not_double_its_events():
    """Numărul de evenimente pe 24 h nu are voie să se dubleze.

    Pana pe care o previne: ultima activitate se citește din două locuri —
    rollup-ul și coada neagregată — iar o pereche activă apare în amândouă.
    Dacă reuniunea iese cu două rânduri pe pereche, numărătoarea legată de ele
    se face de două ori, iar panoul raportează dublul traficului real. Un
    contor de securitate care exagerează antrenează exact reflexul greșit:
    operatorul învață că cifrele de acolo nu înseamnă nimic.
    """
    db = _SQLite(
        rollup=[(_minut(_t(minutes=30)), "nginx", "alert", 5)],
        raw=[(_t(minutes=m), "nginx", "alert") for m in (5, 10, 20, 40, 90)],
    )
    out = _pe_sursa(run(aggregate.sources(db)))
    assert out["nginx"]["ev_24h"] == 5, "evenimentele au fost numărate de două ori"


def test_the_fresh_tail_reaches_back_to_the_rollup_frontier():
    """Coada citită din `raw_events` trebuie să ajungă până la rollup.

    Pana pe care o previne: `sentinel-maintenance.timer` e `OnCalendar=hourly`
    cu `RandomizedDelaySec=300`, deci între două rulări pot trece peste 66 de
    minute fără ca nimic să fie stricat. Cu o coadă fixă de o oră, evenimentele
    din minutele dintre frontiera rollup-ului și ora aia nu se văd nicăieri: o
    sursă care tocmai s-a întors la viață rămâne afișată ca tăcută de zile, iar
    `_gap_insights` — care pune aceeași întrebare — ar da alarma „sursa a
    amuțit" despre un colector care scrie chiar acum.
    """
    db = _SQLite(
        # Frontiera rollup-ului e acum 80 de minute: rularea a întârziat.
        rollup=[(_minut(_t(minutes=80)), "nginx", "alert", 9),
                (_minut(_t(days=3)), "sshd", "auth_fail", 2)],
        # sshd a scris acum 70 de minute — după frontieră, dar nu în ultima oră.
        raw=[(_t(minutes=70), "sshd", "auth_fail"), (_t(minutes=81), "nginx", "alert")],
    )
    out = _pe_sursa(run(aggregate.sources(db)))
    assert out["sshd"]["ultim"] == _t(minutes=70), \
        "ultima activitate a căzut în gaura dintre rollup și coadă"


def test_an_empty_rollup_does_not_empty_the_table():
    """Un rollup gol nu are voie să golească tabelul.

    Pana pe care o previne: coada din `raw_events` pornește de la frontiera
    rollup-ului, iar pe o bază nouă — sau după o curățare a agregatelor —
    frontiera aia e NULL. În SQL, orice comparație cu NULL e falsă, deci fără
    `COALESCE` reuniunea n-ar întoarce niciun rând brut, iar cardul „Surse de
    date" ar fi complet gol pe o gazdă care primește evenimente. Gol nu se
    citește ca „nu știu"; se citește ca „nu vine nimic".
    """
    db = _SQLite(rollup=[], raw=[(_t(hours=2), "nginx", "alert"),
                                 (_t(minutes=3), "nginx", "alert")])
    out = _pe_sursa(run(aggregate.sources(db)))
    assert "nginx" in out, "cu rollup-ul gol, tabelul a rămas fără surse"
    assert out["nginx"]["ultim"] == _t(minutes=3)
    assert out["nginx"]["ev_24h"] == 2


def test_last_activity_survives_the_pruning_of_the_raw_rows():
    """Ultima activitate nu mai depinde de rândurile brute, care expiră.

    Pana pe care o previne: `raw_events` se taie la `raw_events_days` (30, și
    până la 7 când `disk_guard` strânge din retenție), pe când rollup-ul ține
    90 de zile. Citită din rândurile brute, ultima activitate a unei surse
    tăcute de mai mult decât retenția ieșea NULL — „niciun eveniment
    vreodată" — despre un colector despre care rollup-ul știe exact când a
    vorbit ultima dată. Testul ăsta e și dovada că interogarea nu mai citește
    30 de zile de `raw_events`: dacă ar citi, aici n-ar găsi nimic.
    """
    db = _SQLite(
        rollup=[(_minut(_t(days=20)), "suricata", "alert", 11)],
        raw=[],                       # partițiile vechi au fost eliminate
    )
    out = _pe_sursa(run(aggregate.sources(db)))
    assert "suricata" in out
    assert out["suricata"]["ultim"] == _minut(_t(days=20)), \
        "ultima activitate s-a pierdut odată cu rândurile brute"
    assert out["suricata"]["ev_24h"] == 0


def test_a_rollup_older_than_thirty_days_does_not_revive_a_dead_source():
    """O sursă scoasă din uz de luni de zile nu are voie să reapară.

    Pana pe care o previne: rollup-ul ține 90 de zile, de trei ori retenția
    evenimentelor brute. Fără fereastra de 30 de zile, cardul s-ar umple cu
    colectoare dezafectate — Wazuh a fost scos — fiecare cu zero evenimente,
    adică fiecare arătând exact ca un colector mort. Trei rânduri false de
    „tăcut" ascund unul adevărat.
    """
    db = _SQLite(
        rollup=[(_minut(_t(days=45)), "wazuh", "alert", 4),
                (_minut(_t(minutes=10)), "nginx", "alert", 7)],
        raw=[(_t(minutes=10), "nginx", "alert")],
    )
    out = _pe_sursa(run(aggregate.sources(db)))
    assert "wazuh" not in out, "o sursă dinaintea ferestrei de 30 de zile a reapărut"
    assert "nginx" in out


def test_the_minute_of_precision_is_lost_only_backwards():
    """Precizia pierdută e de un minut, și numai spre trecut.

    Pana pe care o previne: `bucket` e trunchiat la minut, deci un eveniment de
    la 09:20:59 deja agregat se citește 09:20:00. Asta e acceptabil fiindcă
    pragurile care judecă tăcerea sunt în ORE — dar numai atâta vreme cât
    eroarea rămâne într-o singură direcție. O valoare rotunjită în sus, oricât
    de puțin, ar face o sursă să pară mai proaspătă decât e, iar asta e chiar
    forma de minciună pe care panoul există ca s-o prevină. Coada neagregată
    păstrează secundele exacte pentru ce e după frontieră.
    """
    tarziu = _t(minutes=30)[:17] + "59"          # ...:59, deja agregat
    db = _SQLite(
        # Frontiera e mai nouă decât evenimentul, deci răspunsul vine din rollup.
        rollup=[(_minut(tarziu), "sshd", "auth_ok", 1),
                (_minut(_t(minutes=20)), "nginx", "alert", 1)],
        raw=[(tarziu, "sshd", "auth_ok"), (_t(minutes=20), "nginx", "alert")],
    )
    agregat = _pe_sursa(run(aggregate.sources(db)))["sshd"]["ultim"]
    assert agregat <= tarziu, "ultima activitate a ieșit mai nouă decât evenimentul"
    assert agregat == _minut(tarziu), "nu e bucketul de rollup"

    # Același eveniment, dar după frontieră: secundele se păstrează întregi.
    proaspat = _SQLite(
        rollup=[(_minut(_t(minutes=90)), "sshd", "auth_ok", 1)],
        raw=[(tarziu, "sshd", "auth_ok")],
    )
    assert _pe_sursa(run(aggregate.sources(proaspat)))["sshd"]["ultim"] == tarziu


def test_the_tail_ceiling_never_drops_below_the_silence_floor():
    """Plafonul cozii rămâne cel puțin cât pragul de la care se judecă tăcerea.

    Pana pe care o previne: `_gap_insights` refuză să răspundă când rollup-ul e
    mai vechi de `_TACERE_MINIMA_H` — asta e apărarea lui împotriva unei surse
    care a amuțit fără să se vadă. Coada din `last_activity_sql()` e plafonată
    la `_PLAFON_COADA_ORE`; dacă plafonul ar fi mai MIC decât pragul, ar exista
    o fereastră în care rollup-ul e destul de proaspăt cât regula să răspundă,
    dar coada nu mai acoperă golul dintre frontieră și acum. Regula ar judeca
    atunci tăcerea pe un `ultim` fals de vechi și ar striga „sursa a amuțit"
    despre un colector care scrie — chiar alarma pe care întregul mecanism
    există ca s-o evite, întoarsă pe dos.

    Invariantul era scris doar în comentariu. Măsurat de verificator pe 29
    august 2026: orice valoare între 2 și 5 trecea toată suita fără să atingă
    un test. Constantele stau în module diferite și NU se importă una din alta,
    ca să nu se inverseze dependența `insights → aggregate`; aserțiunea de aici
    e singurul loc în care se pot privi împreună.
    """
    from sentinel.analytics import insights

    assert aggregate._PLAFON_COADA_ORE >= insights._TACERE_MINIMA_H, (
        f"coada e plafonată la {aggregate._PLAFON_COADA_ORE}h, dar tăcerea se "
        f"judecă abia de la {insights._TACERE_MINIMA_H}h — între ele, "
        f"`_gap_insights` ar citi o ultimă activitate mai veche decât e")


# --- numărătoarea de servicii nu are voie să numere ce nu mai există --------
#
# `LEFT JOIN LATERAL … ON true` nu există în SQLite. Lateralul alege ULTIMUL
# eșantion al fiecărui activ; rescris ca `LEFT JOIN` peste un `GROUP BY
# asset_id` cu `max(ts)`, SQLite întoarce coloanele goale din CHIAR rândul cu
# maximul — comportament documentat pentru `max` — deci același rând, altă
# formă. Ce NU se atinge e clauza `WHERE` a interogării, adică fix ce testează
# testele de mai jos.
_LATERAL_SANATATE = re.compile(
    r"LEFT JOIN LATERAL \(\s*"
    r"SELECT status FROM health_samples h\s*"
    r"WHERE h\.asset_id = a\.id ORDER BY ts DESC LIMIT 1\s*"
    r"\) s ON true",
    re.S)
_LATERAL_SANATATE_SQLITE = (
    "LEFT JOIN (SELECT asset_id, status, max(ts) FROM health_samples "
    "GROUP BY asset_id) s ON s.asset_id = a.id")


def _tradu_sanatate(sql: str) -> str:
    sql = _LATERAL_SANATATE.sub(_LATERAL_SANATATE_SQLITE, sql)
    ramase = [m for m in _RAMASITE_PG if m in sql]
    assert not ramase, f"construcții PostgreSQL netraduse: {ramase}"
    return sql


class _SQLiteSanatate:
    """Cât din `Database` îi trebuie lui `service_health`: un `fetch` care rulează.

    Ține active și eșantioane, și execută interogarea LIVRATĂ. Un dublu care ar
    întoarce rânduri pregătite ar fi de acord cu orice interogare, inclusiv cu
    una care numără activele retrase — adică exact cu defectul.
    """

    def __init__(self, assets=(), samples=()):
        self.assets = list(assets)
        self.samples = list(samples)
        self.sql: str | None = None

    async def fetch(self, sql, *args):
        self.sql = sql
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        con.execute("CREATE TABLE assets (id INTEGER PRIMARY KEY, name TEXT, "
                    "retired_at TEXT)")
        con.execute("CREATE TABLE health_samples (id INTEGER PRIMARY KEY, "
                    "asset_id INTEGER, ts TEXT, status TEXT)")
        con.executemany("INSERT INTO assets (id, name, retired_at) VALUES (?, ?, ?)",
                        self.assets)
        con.executemany("INSERT INTO health_samples (asset_id, ts, status) "
                        "VALUES (?, ?, ?)", self.samples)
        try:
            return [dict(r) for r in con.execute(_tradu_sanatate(sql)).fetchall()]
        finally:
            con.close()


def _gazda(retrase=True):
    """Gazda din 29 august 2026, în mic.

    Patru active dezinstalate, fiecare cu ultima sondă `down` de săptămâni; unul
    viu și `up`; unul viu și chiar picat. `retrase=False` dă exact aceleași date
    fără nicio retragere — perechea din care se vede că filtrul taie după
    retragere, nu după vechimea eșantionului.
    """
    retras = _t(days=18) if retrase else None
    return _SQLiteSanatate(
        assets=[(1, "sshd", None), (2, "postgresql", None),
                (3, "n8n", retras), (4, "n8n-traefik", retras),
                (5, "qdrant", retras), (6, "webmin", retras)],
        samples=[(1, _t(minutes=2), "up"), (2, _t(minutes=2), "down"),
                 (3, _t(days=18), "down"), (4, _t(days=18), "down"),
                 (5, _t(days=18), "down"), (6, _t(days=22), "down")],
    )


def test_a_retired_asset_is_counted_neither_red_nor_green():
    """Patru servicii dezinstalate ținuseră panoul pe „🔴 4" optsprezece zile.

    Pana pe care o previne: starea citită aici e ULTIMUL eșantion al activului,
    fără nicio margine de timp. Un activ care nu se mai sondează îngheață pe
    ultima măsurătoare făcută vreodată, iar dacă ea era `down` rămâne roșu la
    nesfârșit. Pe gazdă erau `n8n`, `n8n-traefik`, `qdrant` și `webmin` —
    dezinstalate, nu picate. Patru rânduri roșii care nu se pot stinge prin
    nimic din ce ar face operatorul îl învață exact obiceiul de a nu mai citi
    roșul, iar atunci și al cincilea, cel adevărat, trece neobservat.

    Interogarea asta NU trece prin `assets_repo.list_all`, deci nu moștenește
    filtrul de acolo. Fără clauza ei proprie, retragerea unui activ n-ar
    schimba cu nimic chiar cifra pentru care a fost făcută — linia
    `Servicii: 🟢 10 · 🔴 4` de pe Telegram și cardul de pe prima pagină.
    """
    stare = run(aggregate.service_health(_gazda()))

    assert stare.get("down", 0) == 1, \
        f"activele retrase încă se numără la roșu: {stare}"
    assert stare.get("up", 0) == 1
    assert sum(stare.values()) == 2, \
        f"retrasele au ieșit din roșu, dar au intrat în altă căsuță: {stare}"


def test_a_live_asset_whose_last_probe_failed_stays_red():
    """Perechea: filtrul nu are voie să stingă un serviciu chiar picat.

    Pana pe care o previne: un filtru scris prea larg — pe vechimea
    eșantionului, de pildă — ar scoate din numărătoare și un serviciu picat de
    trei zile, adică fix rândul pentru care există toată pagina. Un panou care
    ascunde roșul adevărat e mai rău decât unul care arată roșu fals: primul
    tace, al doilea măcar minte tare.
    """
    db = _SQLiteSanatate(
        assets=[(1, "sshd", None), (2, "nginx", None)],
        samples=[(1, _t(minutes=2), "up"), (2, _t(days=3), "down")],
    )

    stare = run(aggregate.service_health(db))

    assert stare.get("down", 0) == 1, f"serviciul picat a dispărut: {stare}"
    assert stare.get("up", 0) == 1


def test_an_asset_never_probed_is_unknown_not_missing():
    """Un activ fără niciun eșantion se numără la „necunoscut", nu dispare.

    Pana pe care o previne: „n-a fost măsurat niciodată" și „e în regulă" sunt
    stări diferite. Un activ adăugat acum în inventar, sau unul pe care sonda
    n-a reușit niciodată să-l atingă, trebuie să apară ca necunoscut — altfel
    totalul de pe panou e mai mic decât inventarul și nimeni nu observă că
    lipsește ceva. `LEFT JOIN`-ul e cel care ține rândul; un `JOIN` obișnuit
    l-ar tăia tăcut, iar filtrul adăugat acum e chiar în zona aia a interogării.
    """
    db = _SQLiteSanatate(
        assets=[(1, "sshd", None), (2, "abia-adaugat", None)],
        samples=[(1, _t(minutes=2), "up")],
    )

    stare = run(aggregate.service_health(db))

    assert stare.get("necunoscut", 0) == 1, f"activul nemăsurat a dispărut: {stare}"
    assert sum(stare.values()) == 2


def test_the_retired_filter_cuts_on_retirement_not_on_sample_age():
    """Eșantioanele activului retras rămân pe disc și rămân interogabile.

    Pana pe care o previne: dacă tăietura ar fi pusă pe eșantioane în loc de pe
    active — „nu citi măsurători mai vechi de X" — un activ retras ar aluneca
    din roșu în „necunoscut" în loc să iasă din numărătoare, iar operatorul ar
    citi șase servicii dintre care patru nemăsurate. Și, mai rău, un serviciu
    VIU pe care sonda nu l-a mai atins de o zi ar fi stins la fel.

    Aceleași date, singura diferență fiind retragerea: cu ea, cele patru ies cu
    totul; fără ea, se întorc la roșu. Dacă tăietura ar fi după vechime, cele
    două rulări ar da același rezultat.
    """
    cu_retragere = run(aggregate.service_health(_gazda()))
    fara_retragere = run(aggregate.service_health(_gazda(retrase=False)))

    assert cu_retragere.get("down", 0) == 1
    assert fara_retragere.get("down", 0) == 5, \
        f"fără retragere, cele patru vechi trebuie numărate la roșu: {fara_retragere}"
    assert sum(fara_retragere.values()) == 6


def test_sources_does_not_read_the_asset_inventory_at_all():
    """`sources` numără colectoare, nu active — retragerea nu-l atinge.

    Nu previne o pană trăită; înregistrează concluzia unei căutări, ca să nu
    trebuiască refăcută. `sources` a fost rescris să citească ultima activitate
    din `event_rollup_1m` prin `last_activity_sql()`, iar tabela aia ARE o
    coloană `asset_id`. Interogarea nu o atinge: grupează pe `(source, action)`,
    unde `source` e colectorul — `nginx`, `sshd`, `auditd`, `suricata` — nu
    activul. Deci un activ retras nu poate intra în cardul „Surse de date".

    Dacă vreodată se leagă — un `GROUP BY asset_id`, sau un inventar pornit din
    `assets` — o sursă ar tăcea fiindcă s-a schimbat inventarul, iar
    `_gap_insights` ar da alarma „colectorul a amuțit" despre o ingestie
    perfect sănătoasă. Aserțiunea asta pică în clipa aia, și atunci filtrul de
    retragere trebuie regândit și acolo.
    """
    db = _SQLite(rollup=[(_minut(_t(minutes=5)), "nginx", "alert", 3)],
                 raw=[(_t(minutes=5), "nginx", "alert")])
    run(aggregate.sources(db))

    assert "assets" not in db.sql, \
        f"`sources` a început să citească inventarul de active:\n{db.sql}"
    assert "asset_id" not in db.sql, \
        f"`sources` grupează pe activ, nu pe colector:\n{db.sql}"
