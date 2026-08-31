"""The insight engine decides what an operator is told. A rule that fires on
weak evidence trains people to ignore the page, so the thresholds are pinned
here alongside the rule that one broken query must never blank the dashboard.

A stub DB answers by matching on the SQL text — enough to drive each rule down
its interesting branch without a live PostgreSQL.
"""
from __future__ import annotations

import asyncio
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from sentinel.analytics import insights as ins

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)


class _StubDB:
    """`fetch_map` / `val_map` map a distinctive SQL fragment to a result."""

    def __init__(self, fetch_map=None, val_map=None, row_map=None):
        self.fetch_map = fetch_map or {}
        self.val_map = val_map or {}
        self.row_map = row_map or {}

    async def fetch(self, sql, *a):
        for needle, rows in self.fetch_map.items():
            if needle in sql:
                return rows
        return []

    async def fetchrow(self, sql, *a):
        for needle, row in self.row_map.items():
            if needle in sql:
                return row
        return None

    async def fetchval(self, sql, *a):
        for needle, v in self.val_map.items():
            if needle in sql:
                return v
        return 0


def run(coro):
    return asyncio.run(coro)


# --- silent collector detection --------------------------------------------
def test_silent_always_on_source_is_flagged():
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "sshd", "last_seen": NOW - timedelta(hours=30), "hours_silent": 30.0},
    ]})
    out = run(ins._gap_insights(db))
    assert len(out) == 1
    assert "sshd" in out[0].title
    assert out[0].level == "critical"      # 30h on an always-on source


def test_briefly_quiet_source_is_not_flagged():
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "nginx", "last_seen": NOW - timedelta(hours=2), "hours_silent": 2.0},
    ]})
    assert run(ins._gap_insights(db)) == []


def test_intermittent_source_gets_a_longer_leash():
    """Zece ore fără `sudo` nu produc niciun card — nici măcar unul informativ.

    Pana pe care o previne: `sudo` scrie doar când cineva lucrează pe server,
    deci o dimineață în care n-a intrat nimeni e starea obișnuită. Dacă regula
    ar raporta tăcerea de la prima oră, panoul ar purta un card permanent
    despre nimic — iar un panou pe care scrie mereu același lucru se citește o
    dată și pe urmă se sare peste el, împreună cu rândul de sub el, care
    contează.
    """
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "sudo", "last_seen": NOW - timedelta(hours=10), "hours_silent": 10.0},
    ]})
    assert run(ins._gap_insights(db)) == []


def test_a_human_driven_source_is_reported_without_being_called_a_fault():
    """`su` tăcut de 81 de ore, cu `sshd` viu, nu e un defect — dar rămâne vizibil.

    Pana pe care o previne, verbatim din `/dashboard`: „🟡 Sursa «su» a amuțit
    de 81 ore … → Verifică colectorul". `su` scrie un eveniment doar când un om
    îi tastează numele, deci 81 de ore de tăcere sunt exact ce arată un server
    pe care n-a lucrat nimeni de vineri. Un avertisment galben pe starea
    normală, cu un sfat de reparat ce nu e stricat, e cum se pierde încrederea
    în canal — și, odată cu ea, alarma adevărată de dedesubt.

    Ce nu are voie să dispară odată cu alarma: momentul ultimei activități.
    Ăla era singurul lucru util din card, și rămâne în text.
    """
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "su", "last_seen": NOW - timedelta(hours=81), "hours_silent": 81.0},
        # Vecinul care chiar dovedește că citirea merge: același cititor
        # journald scrie și `sshd`, iar el a scris acum două minute.
        {"source": "sshd", "last_seen": NOW - timedelta(minutes=2), "hours_silent": 0.03},
    ]})
    out = run(ins._gap_insights(db))
    assert [i.level for i in out] == ["info"], (
        f"tăcerea unei surse tastate de om a fost raportată ca defect: "
        f"{[(i.level, i.title) for i in out]}")
    assert "su" in out[0].title
    assert "31.07 03:00" in out[0].detail, (
        f"cardul nu mai spune când a scris „su” ultima dată: {out[0].detail}")
    assert out[0].action is None, (
        f"tot mai cere o reparație pentru un colector care funcționează: "
        f"{out[0].action}")


def test_a_traffic_driven_source_over_its_threshold_is_still_a_fault():
    """`nginx` și `sshd` tăcute peste prag rămân constatări, cu vecinii vii.

    Pana pe care o previne: scutirea surselor tastate de om e o listă, nu o
    relaxare generală. Dacă ea se lățește peste sursele care scriu un rând la
    fiecare conexiune, se pierde chiar detectorul pentru care există regula —
    pana de trei zile în care colectarea SSH murise și fiecare ecran arăta un
    zero liniștitor.

    Cele două surse sunt alese pe măsurătoare, nu pe intuiție: în 14 zile de
    date de pe gazdă, cel mai mare gol al lor a fost 31m46s și 18m45s. Șase ore
    de tăcere nu li se pot întâmpla dintr-o zi liniștită.
    """
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "nginx", "last_seen": NOW - timedelta(hours=30), "hours_silent": 30.0},
        {"source": "sshd", "last_seen": NOW - timedelta(hours=8), "hours_silent": 8.0},
        {"source": "sudo", "last_seen": NOW - timedelta(minutes=5), "hours_silent": 0.08},
    ]})
    out = run(ins._gap_insights(db))
    dupa_sursa = {i.evidence["sursa"]: i for i in out}
    assert set(dupa_sursa) == {"nginx", "sshd"}, (
        f"altcine decât sursele continue tăcute a fost raportat: {set(dupa_sursa)}")
    assert dupa_sursa["nginx"].level == "critical"      # 30h ≥ 4 × 6h
    assert dupa_sursa["sshd"].level == "warning"        # 8h ≥ 6h, sub 24h
    assert all("sentinel-ingest" in (i.action or "") for i in out), (
        "constatarea de defect nu mai spune ce colector să fie verificat")


def test_the_largest_real_suricata_gap_is_not_a_fault():
    """Cel mai mare gol real al lui `suricata` — 6h43m — nu are voie să fie alarmă.

    Pana pe care o previne, măsurată pe gazdă pe 14 zile de date: `suricata` a
    avut un gol de 6h42m59s, unul peste 3h și nouă peste o oră, în timp ce
    `eve.json` creștea cu ~333 MB/zi. Cititorul lucra; doar că nimic nu depășea
    un prag de semnătură. Judecată cu pragul surselor continue (6h), regula ar
    fi anunțat „Sursa «suricata» a amuțit" o dată la două săptămâni despre un
    colector sănătos — exact falsul pozitiv scos din selfcheck pe 28 august
    2026, mutat pe celălalt ecran. Al doilea card fals despre același colector,
    pe alt ecran, e cum se termină de pierdut încrederea în amândouă.

    Vecinii sunt vii, deci nu e o gazdă moartă: `nginx` și `sshd` au scris în
    ultimele minute.
    """
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "suricata", "last_seen": NOW - timedelta(hours=6, minutes=43),
         "hours_silent": 6 + 43 / 60},
        {"source": "nginx", "last_seen": NOW - timedelta(minutes=4), "hours_silent": 0.07},
        {"source": "sshd", "last_seen": NOW - timedelta(minutes=2), "hours_silent": 0.03},
    ]})
    out = run(ins._gap_insights(db))
    assert out == [], (
        f"un gol măsurat ca normal a fost raportat ca defect: "
        f"{[(i.level, i.title) for i in out]}")


def test_a_suricata_gap_of_two_days_is_still_not_a_fault():
    """Pragul larg nu are voie să fie strâns înapoi peste coada golurilor reale.

    Pana pe care o previne: falsul pozitiv de la 28 august 2026, reintrodus
    printr-o cifră. Perechea de teste de deasupra și de dedesubt prinde pragul
    între 6h43m (fără alarmă) și 120h (cu alarmă), deci ORICE valoare din
    (6,72h, 120h] trecea suita — inclusiv 7, adică la șaptesprezece minute peste
    cel mai mare gol pe care `suricata` chiar l-a avut în 14 zile. Cineva care
    strânge pragul crezând că apără colectorul primește înapoi „🟡 Sursa
    «suricata» a amuțit" o dată la două săptămâni despre un cititor sănătos, și
    nimic din suită nu-l oprește. Comentariul de lângă constantă avertizează
    exact împotriva asta — un comentariu nu e un test.

    De ce 48 de ore, și nu 12 sau 24: codul le respinge deja pe amândouă, pe
    măsurătoare. Golul de 6h42m59s s-a întâmplat O DATĂ în 14 zile, iar unul
    peste 3h încă o dată; un prag la 12 sau la 24 nu face decât să aștepte
    săptămâna mai liniștită ca să dea aceeași alarmă falsă. 48 de ore sunt ~7×
    cel mai mare gol observat și prima valoare rotundă dincolo de ce respinge
    codul însuși. Împreună cu testul de 120 de ore, pragul rămâne prins în
    (48h, 120h]: nu poate fi nici strâns pe coada măsurată, nici lărgit până la
    „niciodată".

    Vecinii au scris în ultimele minute, deci nu e o gazdă moartă — dacă ar fi,
    răspunsul corect ar fi altul și l-ar da alt test.
    """
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "suricata", "last_seen": NOW - timedelta(hours=48),
         "hours_silent": 48.0},
        {"source": "nginx", "last_seen": NOW - timedelta(minutes=4), "hours_silent": 0.07},
        {"source": "sshd", "last_seen": NOW - timedelta(minutes=2), "hours_silent": 0.03},
    ]})
    out = run(ins._gap_insights(db))
    assert out == [], (
        f"pragul larg a fost strâns sub două zile, deci un `suricata` sănătos "
        f"redevine alarmă: {[(i.level, i.title) for i in out]}")


def test_a_suricata_silent_for_days_is_still_a_fault():
    """Peste pragul larg, tăcerea lui `suricata` rămâne constatare.

    Pana pe care o previne: perechea testului de mai sus. Mutarea lui
    `suricata` pe pragul larg e o lărgire, nu o scutire — dacă cititorul de
    `eve.json` chiar moare, panoul trebuie să spună. Un prag lărgit până la
    „niciodată", sau o mutare pe lista surselor tastate de om, ar pierde
    colectorul în al doilea fel, mai liniștit decât primul: nu cu o alarmă
    falsă, ci cu o pagină verde peste un IDS mort.

    Se verifică și NIVELUL, nu doar existența: un card `info` — ce primesc
    sursele acționate de om — nu ajunge în `/dashboard` pe Telegram, deci un
    suricata mort ar rămâne nespus acolo unde se citește la 3 dimineața.

    Cele 120 de ore sunt scrise ca număr, nu ca `_TACERE_ALTE_SURSE_H + ceva`.
    Prima variantă a testului era relativă la constantă și trecea liniștită cu
    pragul mutat la 100 000 de ore — adică exact pe defectul pe care spunea că
    îl păzește. Un număr absolut îl mărginește pe celălalt capăt: împreună cu
    testul de deasupra (6h43m nu e alarmă), pragul e prins între golul real
    măsurat și cinci zile. Cinci zile sunt ~18× cel mai mare gol observat în
    14 zile, pe o gazdă cu mii de adrese ostile pe lună: acolo nu mai există
    explicația „n-a trecut nimic de un prag de semnătură".
    """
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "suricata", "last_seen": NOW - timedelta(hours=120),
         "hours_silent": 120.0},
        {"source": "nginx", "last_seen": NOW - timedelta(minutes=4), "hours_silent": 0.07},
    ]})
    out = run(ins._gap_insights(db))
    assert [i.evidence["sursa"] for i in out] == ["suricata"], (
        f"un IDS tăcut de cinci zile n-a produs constatarea: "
        f"{[(i.level, i.title) for i in out]}")
    assert out[0].level in ("warning", "critical"), (
        f"constatarea a ajuns pe `{out[0].level}`, nivel care nu se vede în "
        f"`/dashboard` pe Telegram — un IDS mort ar rămâne nespus acolo")
    assert "sentinel-ingest" in (out[0].action or "")


def test_a_missing_last_activity_says_it_cannot_know_instead_of_all_clear():
    """O ultimă activitate lipsă nu are voie să se citească „văzută acum".

    Eșecul pe care îl previne: `float(r["hours_silent"] or 0)`. Ramura asta a
    răspuns până acum la „sursa e în inventar, dar n-a scris nimic în
    fereastră", iar `or 0` ar fi citit-o ca „văzută acum" — regula ar fi tăcut
    exact despre colectorul cel mai mort din listă.

    Întrebarea aia are acum alt răspuns: inventarul și ultima activitate vin
    din același `max` (vezi `test_a_source_alive_only_in_the_rollup_keeps_its_real_age`),
    deci o sursă listată iese cu vârsta ei adevărată și cade în pragurile
    obișnuite. Rămâne cazul în care valoarea lipsește totuși — o formă a
    datelor pe care n-o cunoaștem. Atunci nu se știe nimic despre sursa aia, iar
    „nu pot ști" și „e bine" sunt stări diferite: se raportează, nu se tace.
    """
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "suricata", "last_seen": None, "hours_silent": None},
    ]})
    out = run(ins._gap_insights(db))
    assert len(out) == 1, "o sursă fără ultimă activitate a produs tăcere"
    assert "suricata" in out[0].title
    assert out[0].level in ("warning", "critical"), (
        f"starea „nu pot ști” a ajuns pe un nivel care nu se vede: {out[0].level}")
    assert out[0].evidence["ore_tacere"] is None, (
        "s-a inventat o vechime pentru o sursă despre care nu se știe nimic")


def test_an_empty_inventory_says_it_cannot_know_instead_of_all_clear():
    """Fără inventar de surse, „nimic tăcut" e o minciună, nu o constatare.

    Eșecul pe care îl previne: inventarul de perechi (sursă, acțiune) vine din
    `event_rollup_1m`. O sursă care a amuțit nu apare în date — de-aia e nevoie
    de inventar ca să se știe că ar fi trebuit să apară. Dacă jobul de
    întreținere moare, tabela rămâne pe loc, lista se golește, iar regula ar
    întoarce zero constatări: operatorul citește „niciun colector oprit" fix
    când nimeni nu mai poate spune dacă vreunul e oprit.
    """
    db = _StubDB(val_map={"max(bucket)": None}, fetch_map={"hours_silent": []})
    out = run(ins._gap_insights(db))
    assert len(out) == 1, "un inventar gol a produs tăcere, nu o constatare"
    assert "amuțit" in out[0].title or "nu se poate" in out[0].title.lower()
    assert out[0].evidence["rollup_lag_ore"] is None


def test_a_stale_inventory_is_also_refused():
    """Un inventar mai vechi decât cel mai scurt prag de tăcere nu poate fi crezut.

    Eșecul pe care îl previne: rollup-ul rămâne în urmă cu o zi (jobul rulează,
    dar cade). O sursă pornită și amuțită între timp nu intră niciodată în
    inventar, deci regula raportează liniștită „nimic tăcut". Pragul nu e ales:
    e cel mai scurt interval pe care regula însăși îl numește tăcere.
    """
    lag = ins._TACERE_MINIMA_H + 1
    db = _StubDB(val_map={"max(bucket)": float(lag)}, fetch_map={"hours_silent": []})
    out = run(ins._gap_insights(db))
    assert len(out) == 1, f"un inventar vechi de {lag}h a fost crezut pe cuvânt"
    assert out[0].evidence["rollup_lag_ore"] == lag


def test_a_fresh_inventory_is_used_rather_than_refused():
    """Cealaltă margine: un rollup normal nu are voie să blocheze regula.

    Eșecul pe care îl previne: garda de mai sus scrisă cu `>=` sau cu pragul
    greșit. Jobul de întreținere rulează din oră în oră, deci un lag de câteva
    ore e starea OBIȘNUITĂ; o gardă prea strâmtă ar înlocui permanent
    detectorul de colectori tăcuți cu un avertisment despre el însuși, iar
    tăcerea unei surse n-ar mai fi raportată niciodată.
    """
    db = _StubDB(val_map={"max(bucket)": float(ins._TACERE_MINIMA_H - 0.5)},
                 fetch_map={"hours_silent": [
                     {"source": "sshd", "last_seen": NOW - timedelta(hours=30),
                      "hours_silent": 30.0}]})
    out = run(ins._gap_insights(db))
    assert len(out) == 1
    assert "sshd" in out[0].title, (
        "garda de prospețime a înghițit constatarea reală: "
        f"{out[0].title}")


def test_the_inventory_guard_matches_the_shortest_silence_the_rule_reports():
    """Garda inventarului și pragul de tăcere se mișcă împreună.

    Eșecul pe care îl previne: cineva coboară pragul surselor mereu-active de la
    6 ore la 2 („să aflăm mai repede"), garda rămâne la 6, iar între 2 și 6 ore
    inventarul are voie să fie mai vechi decât tăcerea pe care regula o judecă —
    fereastra în care o sursă poate apărea și amuți fără să fie văzută vreodată.
    Se verifică pe PURTARE: o tăcere exact cât garda trebuie să fie raportată.
    """
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "nginx", "last_seen": NOW - timedelta(hours=ins._TACERE_MINIMA_H),
         "hours_silent": float(ins._TACERE_MINIMA_H)},
    ]})
    out = run(ins._gap_insights(db))
    assert len(out) == 1, (
        f"o tăcere de {ins._TACERE_MINIMA_H}h — exact cât e garda inventarului — "
        f"n-a fost raportată, deci garda e mai largă decât regula pe care o "
        f"apără")


def test_the_two_screens_agree_on_which_sources_a_human_drives():
    """Panoul și autoverificarea nu au voie să se contrazică pe aceeași sursă.

    Pana pe care o previne: `selfcheck` ține deja lista asta (`HUMAN_DRIVEN`),
    din același motiv și după aceeași pățanie. Dacă listele se despart — cineva
    adaugă o sursă tastată de om într-un singur loc — operatorul primește două
    verdicte contrare despre același colector: `/selfcheck` spune „normal,
    evenimentele apar doar când cineva lucrează pe server", iar panoul spune
    „a amuțit de 81 de ore, verifică colectorul". Când două ecrane ale
    aceluiași agent nu sunt de acord, cel crezut e cel care sperie.

    Listele stau în module separate și NU se importă una din alta:
    `selfcheck/checks.py` e diagnosticul gazdei și vine cu `yaml`, `subprocess`
    și configurația după el, iar `insights.py` se încarcă la fiecare afișare a
    panoului. Testul ăsta e singurul loc care are voie să le vadă pe amândouă —
    același tipar ca invariantul dintre `_PLAFON_COADA_ORE` și
    `_TACERE_MINIMA_H` din test_aggregate.py.
    """
    from sentinel.selfcheck import checks

    assert ins._SURSE_ACTIONATE_DE_OM == checks.HUMAN_DRIVEN, (
        f"panoul scutește {sorted(ins._SURSE_ACTIONATE_DE_OM)}, autoverificarea "
        f"{sorted(checks.HUMAN_DRIVEN)} — două ecrane, două verdicte")
    # `sshd` e dovada de viață pe care se sprijină scutirea celorlalte două: vin
    # din același cititor journald, iar el, expus la internet, nu tace. Dacă ar
    # ajunge și el pe lista scutiților, argumentul s-ar sprijini pe nimic, iar
    # un cititor stricat n-ar mai fi raportat de nicăieri.
    assert not (ins._SURSE_CONTINUE & ins._SURSE_ACTIONATE_DE_OM), (
        f"o sursă e și continuă, și tastată de om: "
        f"{sorted(ins._SURSE_CONTINUE & ins._SURSE_ACTIONATE_DE_OM)}")
    assert "sshd" in ins._SURSE_CONTINUE, (
        "`sshd` nu mai e judecat ca sursă continuă, deci nu mai poate fi dovada "
        "de viață pentru `sudo` și `su`")


# --- interogarea de inventar, rulată ----------------------------------------
#
# Ce se dovedește mai jos: `_GAP_SQL` nu mai află ultima activitate dintr-un
# `max(ts)` per pereche peste 30 de zile de `raw_events`, ci din
# `event_rollup_1m`, prin `aggregate.last_activity_sql()`. Mutarea schimbă și
# cifrele, nu doar viteza — o sursă tăcută de mai mult decât retenția rândurilor
# brute ieșea NULL, iar acum iese cu vârsta ei adevărată — deci interogarea se
# RULEAZĂ. Un stub care întoarce rânduri gata făcute ar fi de acord cu orice
# interogare, inclusiv cu una care pierde exact sursele tăcute.
#
# Ce NU se dovedește aici: planul ales de PostgreSQL și timpul câștigat pe
# gazdă. Alea se măsoară acolo.

#: Momentul de referință al secțiunii, luat O SINGURĂ DATĂ — vezi `_ACUM` din
#: test_aggregate.py: `_t()` chemat de două ori pentru același moment putea
#: cădea de o parte și de alta a unei granițe de secundă, iar un roșu fals la
#: câteva sute de rulări îl învață pe om că suita minte uneori.
_ACUM_GAP = datetime.now(timezone.utc)


def _t(**delta) -> str:
    """Un moment din trecut, în formatul în care SQLite compară text cu text."""
    return (_ACUM_GAP - timedelta(**delta)).strftime("%Y-%m-%d %H:%M:%S")


def _minut(ts: str) -> str:
    """Bucketul de rollup în care ar cădea momentul dat."""
    return ts[:16] + ":00"


#: Singurele construcții din `_GAP_SQL` pe care SQLite nu le are. `julianday`
#: dă zile, deci înmulțit cu 24 e chiar `EXTRACT(EPOCH FROM …) / 3600`.
_TRADUCERI_GAP = (
    (re.compile(r"EXTRACT\(EPOCH FROM \(now\(\) - max\(ultim\)\)\) / 3600"),
     "(julianday('now') - julianday(max(ultim))) * 24"),
    (re.compile(r"now\(\)\s*-\s*interval\s*'(\d+) (\w+)'"), r"datetime('now','-\1 \2')"),
)

#: Ce nu are voie să rămână după traducere: o construcție PostgreSQL rămasă pe
#: loc ar putea fi acceptată de SQLite cu ALT înțeles, iar testul ar compara
#: liniștit două lucruri greșite.
_RAMASITE_GAP = ("LATERAL", "ON true", "interval '", "now()", "EXTRACT", "::", "->>")


def _tradu_gap(sql: str) -> str:
    for tipar, inlocuire in _TRADUCERI_GAP:
        sql = tipar.sub(inlocuire, sql)
    ramase = [m for m in _RAMASITE_GAP if m in sql]
    assert not ramase, f"construcții PostgreSQL netraduse: {ramase}"
    return sql


def _ruleaza_gap(rollup=(), raw=()):
    """`_GAP_SQL` peste rollup-ul și evenimentele brute date."""
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE event_rollup_1m (bucket TEXT, asset_id INTEGER, "
                "source TEXT, action TEXT, n INTEGER)")
    con.execute("CREATE TABLE raw_events (id INTEGER PRIMARY KEY, ts TEXT, "
                "source TEXT, action TEXT)")
    con.executemany("INSERT INTO event_rollup_1m (bucket, asset_id, source, action, n) "
                    "VALUES (?, 0, ?, ?, ?)", list(rollup))
    con.executemany("INSERT INTO raw_events (ts, source, action) VALUES (?, ?, ?)",
                    list(raw))
    try:
        return [dict(r) for r in con.execute(_tradu_gap(ins._GAP_SQL)).fetchall()]
    finally:
        con.close()


def test_a_source_alive_only_in_the_rollup_keeps_its_real_age():
    """Vârsta unei surse tăcute nu mai depinde de rândurile brute, care expiră.

    Pana pe care o previne: `raw_events` se taie la 30 de zile, și până la 7
    când `disk_guard` strânge retenția; rollup-ul ține 90. Citită din rândurile
    brute, o sursă moartă de trei săptămâni ieșea cu ultima activitate NULL —
    „niciun eveniment vreodată" — și era raportată cu un plafon inventat de 30
    de zile, deși rollup-ul știe exact când a vorbit ultima dată. Un card care
    spune „720 de ore" despre o tăcere de 480 face imposibil de aflat din panou
    când a murit colectorul, adică fix întrebarea pentru care e deschis panoul.

    E și dovada că interogarea chiar citește rollup-ul: pentru `suricata` nu
    există niciun rând brut, deci o interogare care ar întreba `raw_events`
    n-ar găsi nimic aici.
    """
    randuri = {r["source"]: r for r in _ruleaza_gap(
        rollup=[(_minut(_t(days=20)), "suricata", "alert", 3),
                (_minut(_t(minutes=4)), "nginx", "request", 9)],
        raw=[(_t(minutes=4), "nginx", "request")])}
    assert "suricata" in randuri, "sursa tăcută a dispărut din inventar"
    assert randuri["suricata"]["last_seen"] == _minut(_t(days=20)), (
        f"ultima activitate s-a pierdut odată cu rândurile brute: "
        f"{randuri['suricata']['last_seen']}")
    assert 479 < randuri["suricata"]["hours_silent"] < 481, (
        f"vechimea raportată nu e cea reală: {randuri['suricata']['hours_silent']}")


def test_a_source_with_several_actions_produces_one_row():
    """O sursă cu mai multe acțiuni dă un singur rând, cu cea mai nouă activitate.

    Pana pe care o previne: `last_activity_sql()` dă un rând pe PERECHE (sursă,
    acțiune), iar `sshd` are și `auth_fail`, și `auth_ok`. Fără gruparea pe
    sursă, bucla din `_gap_insights` ar vedea două rânduri și ar scrie două
    carduri despre același colector — al doilea cu vechimea perechii mai rare:
    „Sursa «sshd» a amuțit de 40 de ore" lângă un `sshd` care scrie de trei.
    Un panou care se contrazice singur nu mai poate fi folosit ca să se decidă
    ceva.
    """
    randuri = _ruleaza_gap(
        rollup=[(_minut(_t(hours=3)), "sshd", "auth_fail", 12),
                (_minut(_t(hours=40)), "sshd", "auth_ok", 1)],
        raw=[(_t(hours=3), "sshd", "auth_fail")])
    assert [r["source"] for r in randuri] == ["sshd"], (
        f"o sursă cu două acțiuni a ieșit pe mai multe rânduri: {randuri}")
    assert randuri[0]["last_seen"] == _t(hours=3), (
        f"a rămas cu activitatea perechii mai vechi: {randuri[0]['last_seen']}")
    assert 2.9 < randuri[0]["hours_silent"] < 3.5


# --- multi-vector attackers -------------------------------------------------
def test_multivector_requires_three_sources():
    db = _StubDB(fetch_map={"count(DISTINCT source) >= 3": [
        {"ip": "45.1.2.3", "surse": 3, "care": "nginx+sshd+suricata", "ev": 90},
    ]})
    out = run(ins._multivector_insights(db))
    assert len(out) == 1 and "45.1.2.3" in out[0].action


def test_no_multivector_no_insight():
    assert run(ins._multivector_insights(_StubDB())) == []


# --- SSH targeting ----------------------------------------------------------
def test_root_targeting_raises_a_hardening_action():
    db = _StubDB(fetch_map={"source = 'sshd' AND action = 'auth_fail'": [
        {"username": "root", "n": 919, "ips": 73},
        {"username": "admin", "n": 98, "ips": 16},
    ]})
    out = run(ins._ssh_target_insights(db))
    assert len(out) == 2
    hardening = [i for i in out if "PermitRootLogin" in (i.action or "")]
    assert hardening and hardening[0].level == "warning"


def test_light_root_targeting_does_not_nag():
    db = _StubDB(fetch_map={"source = 'sshd' AND action = 'auth_fail'": [
        {"username": "root", "n": 4, "ips": 1},
    ]})
    out = run(ins._ssh_target_insights(db))
    assert all("PermitRootLogin" not in (i.action or "") for i in out)


# --- probe campaigns --------------------------------------------------------
def test_probe_for_uninstalled_app_is_downgraded_to_info():
    db = _StubDB(fetch_map={
        "http_status = 404": [{"http_path": "/glpi/front/inventory.php", "n": 375, "ips": 2}],
        "SELECT name FROM assets": [{"name": "nginx"}, {"name": "n8n"}],
    })
    out = run(ins._probe_campaign_insights(db))
    assert len(out) == 1
    assert out[0].level == "info"            # not installed -> cannot be hit
    assert out[0].evidence["instalat"] is False


def test_probe_for_installed_app_is_a_warning():
    db = _StubDB(fetch_map={
        "http_status = 404": [{"http_path": "/wp-content/x.php", "n": 40, "ips": 25}],
        "SELECT name FROM assets": [{"name": "wordpress-site"}],
    })
    out = run(ins._probe_campaign_insights(db))
    assert out and out[0].level == "warning" and out[0].action


class _StubDBActive:
    """Ca `_StubDB`, dar interogarea de active se EXECUTĂ, pe SQLite.

    `_probe_campaign_insights` decide din rândurile de `assets` dacă urcă
    severitatea, iar ce hotărăște acum e o clauză `WHERE`. Un stub care întoarce
    rânduri gata făcute ar fi de acord și cu interogarea care n-o are — deci
    rândurile stau într-o tabelă și filtrul chiar rulează.
    """

    def __init__(self, sonde, active):
        self.sonde = sonde
        self.active = active            # (name, retired_at) — NULL = urmărit

    async def fetch(self, sql, *a):
        if "FROM assets" not in sql:
            return self.sonde
        strain = [c for c in ("::", "interval '", "now()", "->>") if c in sql]
        assert not strain, (
            f"interogarea de active a devenit specifică PostgreSQL ({strain}); "
            f"testul n-o mai poate rula, deci n-o mai poate dovedi")
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        con.execute("CREATE TABLE assets (name TEXT, retired_at TEXT)")
        con.executemany("INSERT INTO assets (name, retired_at) VALUES (?, ?)",
                        self.active)
        try:
            return [dict(r) for r in con.execute(sql).fetchall()]
        finally:
            con.close()


_SONDE_GLPI = [{"http_path": "/glpi/front/inventory.php", "n": 375, "ips": 2}]


def test_a_retired_asset_no_longer_counts_as_installed():
    """Un pachet dezinstalat nu mai face sondele după el „relevante".

    Pana pe care o previne: un activ scos din `inventory.yaml` nu se șterge —
    istoricul lui e referit de `incidents`, `findings`, `scans`, `health_samples`
    — ci se marchează retras (`assets.retired_at`, migrația 0032). Interogarea
    din regula asta e SQL crud și NU trece prin filtrul lui
    `assets_repo.list_all`, deci fără `WHERE retired_at IS NULL` un pachet
    dezinstalat rămâne „instalat" pe vecie: sondele după el urcă la `warning`
    cu „**Rulezi această aplicație** — merită verificată versiunea", iar
    operatorul e trimis să caute versiunea a ceva ce nu mai are pe server.
    Greșeala e în direcția care sperie degeaba, adică exact cea care golește de
    înțeles culoarea galbenă.
    """
    db = _StubDBActive(_SONDE_GLPI, [("glpi", "2026-08-20 10:00:00")])
    out = run(ins._probe_campaign_insights(db))
    assert len(out) == 1
    assert out[0].evidence["instalat"] is False, (
        "un activ retras încă trece drept instalat")
    assert out[0].level == "info"
    assert out[0].action is None, (
        f"tot cere verificarea versiunii unui pachet dezinstalat: {out[0].action}")


def test_an_asset_still_in_the_inventory_keeps_raising_the_severity():
    """Perechea: filtrul nu are voie să golească lista de active.

    Pana pe care o previne: `WHERE retired_at IS NULL` scris greșit — pe o
    coloană `NOT NULL`, cu `= NULL` în loc de `IS NULL`, sau negat — nu dă o
    eroare, dă o listă goală. Atunci NIMIC nu mai e „instalat", fiecare campanie
    de sondare devine `info` cu textul „nu te poate atinge", și tocmai sondele
    după singurul lucru pe care chiar îl rulezi ar fi cele coborâte. Un filtru
    prea larg se citește la fel de liniștitor ca unul care lipsește.
    """
    db = _StubDBActive(_SONDE_GLPI, [("glpi", None)])
    out = run(ins._probe_campaign_insights(db))
    assert len(out) == 1
    assert out[0].evidence["instalat"] is True, (
        "un activ urmărit nu mai e văzut ca instalat")
    assert out[0].level == "warning" and out[0].action


# --- blocklist drift --------------------------------------------------------
def test_no_drift_insight_when_nothing_is_blocked():
    assert run(ins._blocklist_drift_insight(_StubDB(val_map={"WHERE active": 0}))) == []


# --- incident flood ---------------------------------------------------------
def test_flood_fires_only_past_both_thresholds():
    dominated = _StubDB(fetch_map={"split_part(fingerprint": [
        {"regula": "ids.suricata", "n": 462}, {"regula": "web.enumeration", "n": 33},
    ]})
    out = run(ins._incident_flood_insight(dominated))
    assert len(out) == 1 and "ids.suricata" in out[0].evidence["regula"]

    balanced = _StubDB(fetch_map={"split_part(fingerprint": [
        {"regula": "a", "n": 40}, {"regula": "b", "n": 40}, {"regula": "c", "n": 40},
    ]})
    assert run(ins._incident_flood_insight(balanced)) == []

    small = _StubDB(fetch_map={"split_part(fingerprint": [{"regula": "a", "n": 10}]})
    assert run(ins._incident_flood_insight(small)) == []


# --- active campaigns --------------------------------------------------------
def test_campaign_insight_names_the_count_and_the_biggest_one():
    """The operator reading the dashboard must see how many fronts are open
    and which is largest without having to scroll a raw incident list — the
    measured case this insight exists for: 968 open incidents read as 14
    campaigns, one of which (auth.ssh_bruteforce) accounts for 37 of them."""
    db = _StubDB(fetch_map={"FROM incident_campaigns": [
        {"id": 1, "campaign_key": "auth.ssh_bruteforce", "severity": "medium",
         "title": "Campanie: auth.ssh_bruteforce", "first_seen_at": None,
         "last_activity_at": None, "incident_count": 37, "actor_count": 37},
        {"id": 2, "campaign_key": "web.enumeration", "severity": "medium",
         "title": "Campanie: web.enumeration", "first_seen_at": None,
         "last_activity_at": None, "incident_count": 24, "actor_count": 24},
    ]})
    out = run(ins._campaign_insight(db))
    assert len(out) == 1
    assert "2 campanii" in out[0].title
    assert "auth.ssh_bruteforce" in out[0].title
    assert out[0].evidence["cea_mai_mare"]["incidente"] == 37


def test_no_active_campaigns_is_quiet_not_an_empty_card():
    """No active campaign is a legitimate state (a quiet host, or one where
    every campaign has gone `quiet`) and must not render a zero-value card —
    same rule as every other insight here: absence is silence, not a claim."""
    assert run(ins._campaign_insight(_StubDB(fetch_map={"FROM incident_campaigns": []}))) == []


def test_campaign_insight_is_registered_in_collect():
    """A rule written and never wired into `collect()` never runs, in
    silence — the two direct tests above would keep passing forever while
    the dashboard never showed a thing. Same failure `test_maintenance.py`
    guards for `run()`'s step list.

    Word-boundary match, not a bare substring: `_campaign_insight` is itself
    a substring of the unrelated, already-registered `_probe_campaign_insights`
    (probe-pattern insight, section 4), so a plain `in` check here would pass
    whether or not THIS rule was ever added to the tuple."""
    import inspect
    import re
    src = inspect.getsource(ins.collect)
    assert re.search(r"\b_campaign_insight\b", src)


# --- vulnerability posture --------------------------------------------------
def test_kev_is_critical_and_outranks_the_rest():
    db = _StubDB(row_map={"FROM findings": {"deschise": 50, "kev": 43, "rezolvate": 0}})
    out = run(ins._vuln_insight(db))
    assert out[0].level == "critical" and "43" in out[0].title


def test_clean_scan_is_reported_as_good_news():
    db = _StubDB(row_map={"FROM findings": {"deschise": 0, "kev": 0, "rezolvate": 4716}})
    out = run(ins._vuln_insight(db))
    assert out[0].level == "good"


# --- trend ------------------------------------------------------------------
def test_doubling_is_flagged_but_noise_is_not():
    doubled = _StubDB(row_map={"interval '48 hours'": {"azi": 400, "ieri": 100}})
    assert run(ins._trend_insight(doubled))[0].level == "warning"

    tiny = _StubDB(row_map={"interval '48 hours'": {"azi": 8, "ieri": 2}})
    assert run(ins._trend_insight(tiny)) == []   # too little data to mean anything


# --- enrichment -------------------------------------------------------------
def test_missing_geoip_is_reported_once_there_is_enough_traffic():
    db = _StubDB(row_map={"geo_country IS NOT NULL": {"tot": 5000, "cu_tara": 0}})
    out = run(ins._enrichment_insight(db))
    assert out and "geoip-refresh" in out[0].action

    quiet = _StubDB(row_map={"geo_country IS NOT NULL": {"tot": 10, "cu_tara": 0}})
    assert run(ins._enrichment_insight(quiet)) == []


# --- privilege escalation ---------------------------------------------------
def test_failed_privilege_escalation_is_critical():
    db = _StubDB(row_map={"source IN ('sudo', 'su')": {"folosiri": 2, "esecuri": 7, "useri": 1}})
    out = run(ins._privilege_insight(db))
    assert out and out[0].level == "critical"


# --- resilience -------------------------------------------------------------
def test_a_broken_rule_never_blanks_the_page():
    class Exploding:
        async def fetch(self, *a): raise RuntimeError("boom")
        async def fetchrow(self, *a): raise RuntimeError("boom")
        async def fetchval(self, *a): raise RuntimeError("boom")
    # Every rule fails; collect() must still return cleanly rather than 500.
    assert run(ins.collect(Exploding())) == []


def test_insights_are_sorted_most_severe_first():
    items = [ins.Insight("info", "i", ""), ins.Insight("critical", "c", ""),
             ins.Insight("good", "g", ""), ins.Insight("warning", "w", "")]
    order = {lvl: i for i, lvl in enumerate(ins.LEVELS)}
    items.sort(key=lambda i: order.get(i.level, 99))
    assert [i.level for i in items] == ["critical", "warning", "info", "good"]


# --- headline verdict: "did somebody get in?" -------------------------------
#
# Rândurile de mai jos sunt măsurate pe gazdă, nu inventate: sesiunea de deploy
# din 28 august 2026 și ziua operatorului. Prima
# a produs verdictul „Autentificare reușită de la un atacator — verifică ACUM”
# fără să fi fost spart nimic; pe 30 de zile de date, regula veche n-a avut
# dreptate niciodată.
def _posture_db(rows, atacatori=629, ev=3861):
    """Stub pentru `posture`: interogarea de titlu plus numărătoarea de atacatori."""
    return _StubDB(
        fetch_map={"esecuri_cont": rows},
        row_map={"count(DISTINCT host(src_ip))": {"atacatori": atacatori, "ev": ev}},
    )


def _ok(cont, metoda, esecuri_cont, esecuri_ip=None, ip="198.51.100.62"):
    return {"ip": ip, "cont": cont, "metoda": metoda,
            "esecuri_cont": esecuri_cont,
            "esecuri_ip": esecuri_cont if esecuri_ip is None else esecuri_ip}


def test_a_deploy_session_is_not_announced_as_a_break_in():
    """Cazul real din 28 august: refuzuri pe alte conturi, apoi intrarea de deploy.

    Eșecul pe care îl previne: exact panica de care a avut parte operatorul.
    Trei chei refuzate pe `admin`, `deploy` și pe contul operatorului, la
    16:59:20-22, apoi o autentificare reușită pe `sentinel-deploy` de pe
    ACEEAȘI adresă — regula
    veche cerea doar „aceeași adresă a și eșuat, și a și reușit în 24h” și
    striga cel mai tare mesaj pe care Sentinel îl poate produce. Contul pe care
    s-a intrat nu e printre cele pe care s-a eșuat, iar reușita e pe cheie.

    Testul ăsta nu pică la scoaterea unei singure apărări, și asta e o
    proprietate a incidentului, nu o scăpare: cifrele lui reale (0 eșecuri pe
    cont, 3 pe adresă) trec și de garda de metodă, și de prag, deci oricare
    dintre ele îl ține verde singură.

    Dar NU e fără dinți, și prima versiune a notei ăsteia lăsa impresia asta.
    Măsurat de verificator pe 29 august 2026: reintroducerea regulii VECHI —
    garda de metodă scoasă, numărătoarea pe adresă în loc de cont, pragul la
    `> 0` — îl înroșește, împreună cu încă trei. Adică pică exact pe defectul
    pe care îl numește, doar că defectul ăla e o revenire de proiectare, nu o
    mutație de o linie. Ăsta e felul de martor pe care îl vrei pentru un
    incident: nu se aprinde la fiecare atingere, se aprinde când cineva
    reface greșeala.

    Apărările individuale sunt fixate separat, pe cifre destul de mari cât să
    conteze una singură: `test_a_key_login_is_not_called_a_successful_guess`
    (312 eșecuri pe contul care intră, pe cheie) apără metoda, iar
    `test_the_operators_own_seven_failures_are_not_a_break_in` apără pragul.
    Umflarea cifrelor de aici ca să pice la o mutație singură ar însemna alt
    incident decât cel din 28 august.
    """
    p = run(ins.posture(_posture_db([
        _ok("sentinel-deploy", "publickey", esecuri_cont=0, esecuri_ip=3),
    ]), []))
    assert p["intruziuni"] == 0, (
        f"o sesiune de deploy a fost numărată ca intruziune: {p['verdict']}")
    assert p["level"] != "critical"


def test_the_operators_own_seven_failures_are_not_a_break_in():
    """Ziua operatorului: 7 eșecuri și o intrare, același cont.

    Eșecul pe care îl previne: pragul pus prea jos, sau lipsa lui. Adresa
    operatorului a produs 7 eșecuri în aceeași fereastră de 24h în care s-a și
    conectat; dacă ar fi de ajuns ca eșecurile să fie pe același cont, fiecare
    tastare greșită de parolă i-ar spune operatorului că i-a fost spart
    serverul. Metoda e necunoscută aici dinadins, ca testul să pice pe prag, nu
    pe altă apărare.
    """
    p = run(ins.posture(_posture_db([
        _ok("cont-operator", None, esecuri_cont=7, ip="203.0.113.78"),
    ]), []))
    assert p["intruziuni"] == 0, (
        f"7 eșecuri au fost citite ca forțare: {p['verdict']}")


def test_failures_on_other_accounts_do_not_convict_the_account_that_got_in():
    """Sute de eșecuri pe `root`, dar intrarea e pe alt cont — nu e forțare reușită.

    Eșecul pe care îl previne: numărarea eșecurilor pe adresă în loc de pe
    contul care a intrat. O gazdă cu un scaner pe `root` și un deploy legitim
    de la aceeași adresă (proxy, VPN, NAT-ul unui furnizor) ar fi raportată ca
    spartă la fiecare livrare.
    """
    p = run(ins.posture(_posture_db([
        _ok("sentinel-deploy", "password", esecuri_cont=0, esecuri_ip=412),
    ]), []))
    assert p["intruziuni"] == 0, (
        f"eșecurile pe alt cont au condamnat o intrare legitimă: {p['verdict']}")


def test_hundreds_of_failures_on_the_account_that_got_in_stay_critical():
    """O forțare care CHIAR reușește trebuie să rămână cel mai tare mesaj.

    Eșecul pe care îl previne: o regulă moartă. Dacă apărarea împotriva falsului
    pozitiv taie și cazul real, operatorul află despre o spargere de pe `root`
    dintr-un rând de listă, nu din titlul paginii. Se verifică și că titlul
    duce cu el faptele (contul și numărul de eșecuri), nu doar culoarea.
    """
    p = run(ins.posture(_posture_db([
        _ok("root", "password", esecuri_cont=312, ip="45.134.26.7"),
    ]), []))
    assert p["intruziuni"] == 1
    assert p["level"] == "critical"
    assert "root" in p["verdict"] and "312" in p["verdict"], (
        f"titlul nu poartă dovada: {p['verdict']}")


def test_the_breach_verdict_outranks_a_page_full_of_critical_insights():
    """Când chiar s-a intrat, asta e ce citește operatorul primul.

    Eșecul pe care îl previne: verdictul de forțare pus după ramura `crit`, deci
    înlocuit de „Necesită atenție acum” ori de câte ori mai există o constatare
    critică pe pagină — adică fix în ziua în care se întâmplă totul deodată.
    """
    p = run(ins.posture(_posture_db([
        _ok("root", "password", esecuri_cont=312, ip="45.134.26.7"),
    ]), [ins.Insight("critical", "KEV", "d"), ins.Insight("warning", "w", "d")]))
    assert "Reușită SSH" in p["verdict"], (
        f"forțarea reușită a fost îngropată sub restul paginii: {p['verdict']}")


def test_an_unknown_auth_method_is_not_read_as_safe():
    """Fără metodă în jurnal, „nu știu” nu are voie să devină „e în regulă”.

    Eșecul pe care îl previne: filtrul scris invers — „raportează doar dacă
    metoda e `password`”. Liniile „Invalid user …” nu poartă deloc metoda (vezi
    `collectors/sshd.py`), iar un jurnal mai vechi sau alt colector poate lăsa
    câmpul gol; un filtru pozitiv ar tăcea tocmai despre rândurile despre care
    se știe cel mai puțin.
    """
    p = run(ins.posture(_posture_db([
        _ok("root", None, esecuri_cont=312, ip="45.134.26.7"),
    ]), []))
    assert p["intruziuni"] == 1, (
        f"o metodă necunoscută a fost tratată ca sigură: {p['verdict']}")


def test_a_key_login_is_not_called_a_successful_guess():
    """O cheie nu se nimerește din încercări, oricâte eșecuri ar fi înainte.

    Eșecul pe care îl previne: chiar alarma din 28 august. Sesiunile de deploy
    intră pe `publickey`; dacă metoda nu contează, orice zi în care agentul
    operatorului greșește contul de destinație de destule ori se termină cu
    „ai fost spart”.
    """
    p = run(ins.posture(_posture_db([
        _ok("sentinel-deploy", "publickey", esecuri_cont=312),
    ]), []))
    assert p["intruziuni"] == 0, (
        f"o intrare pe cheie a fost numită forțare reușită: {p['verdict']}")


def test_a_success_without_a_username_falls_back_instead_of_going_quiet():
    """Un `auth_ok` fără cont e o necunoscută, nu o dovadă de liniște.

    Eșecul pe care îl previne: potrivirea pe cont scrisă în SQL, unde un
    `username` NULL nu se potrivește cu nimic, deci iese zero eșecuri și
    rândul dispare tăcut. O intrare pe care sistemul n-o poate atribui, de pe o
    adresă cu sute de eșecuri, e ultimul lucru care ar trebui să treacă
    neobservat.
    """
    p = run(ins.posture(_posture_db([
        _ok(None, None, esecuri_cont=0, esecuri_ip=312, ip="45.134.26.7"),
    ]), []))
    assert p["intruziuni"] == 1, "o intrare neatribuită a fost trecută cu vederea"
    assert p["level"] == "critical"


def test_an_attacker_chosen_username_cannot_wreck_the_headline():
    """Numele contului vine din jurnal, deci îl scrie atacatorul.

    Eșecul pe care îl previne: titlul paginii și prima linie din Telegram sunt
    construite acum dintr-un text ales de cel care atacă. O sută de rânduri noi
    sau cinci sute de caractere într-un `<b>` deschis strică exact ecranul care
    trebuie citit în timpul unui incident. Scăparea de HTML o fac șabloanele;
    lungimea și caracterele de control se taie aici.
    """
    p = run(ins.posture(_posture_db([
        _ok("root\n\n<b>" + "A" * 500, "password", esecuri_cont=312),
    ]), []))
    assert p["level"] == "critical"
    assert "\n" not in p["verdict"], "un nume de cont cu linii noi a spart titlul"
    assert len(p["verdict"]) < 160, (
        f"titlul a ajuns la {len(p['verdict'])} caractere")


def test_absurd_ratio_is_reported_as_unreliable_not_as_a_surge():
    # ×37 means the comparison window was broken (collector down, rows pruned),
    # not that attacks grew 37-fold. Saying "surge" sends someone hunting a
    # campaign that does not exist — observed live after a data cleanup.
    db = _StubDB(row_map={"interval '48 hours'": {"azi": 100000, "ieri": 2700}})
    out = run(ins._trend_insight(db))
    assert out and out[0].level == "info"
    assert "nu este de încredere" in out[0].title


def test_the_loudest_forcing_is_the_one_in_the_headline():
    """Cu mai multe forțări deodată, titlul o poartă pe cea mai gravă.

    Eșecul pe care îl previne: `fortari[0]` scris ca `fortari[-1]` (sau lista
    parcursă în altă ordine). Interogarea întoarce rândurile descrescător după
    eșecuri, deci prima e cea mai apăsată; dacă titlul o ia pe ultima,
    operatorul citește „25 de eșecuri pe deploy” în ziua în care `root` a fost
    forțat de 312 ori, și pornește de la capătul greșit. Numărul din colț rămâne
    corect, ceea ce face greșeala invizibilă în restul suitei — niciun alt test
    de aici nu are mai mult de o forțare în listă.
    """
    p = run(ins.posture(_posture_db([
        _ok("root", "password", esecuri_cont=312, ip="45.134.26.7"),
        _ok("deploy", "password", esecuri_cont=25, ip="203.0.113.9"),
    ]), []))
    assert p["intruziuni"] == 2
    assert "root" in p["verdict"] and "312" in p["verdict"], (
        f"titlul poartă altă forțare decât cea mai gravă: {p['verdict']}")


# --- forma agregată a interogării de titlu ----------------------------------
#
# Ce se dovedește mai jos: `_FORTARE_SQL` agregă eșecurile ÎNAINTE de join (ca
# să nu mai fie un nested loop `reușite × eșecuri`) și scoate reușitele pe cheie
# din CTE. Amândouă schimbă forma cifrelor, nu doar viteza — deci se rulează
# AMÂNDOUĂ variantele peste aceleași evenimente și se cere egalitate, nu se
# citește SQL-ul și se dă din cap.
#
# Rulează pe SQLite, fiindcă aici nu există PostgreSQL. Traducerea e mică și
# declarată mai jos, iar ce rămâne netradus face testul să crape, nu să treacă.
# **Ce NU dovedesc testele astea**: comportamentul tipurilor proprii lui
# PostgreSQL — `inet` la egalitate, `jsonb ->>` peste un `raw` NULL, `host()` —
# și nici planul de execuție ales de planificator. Alea se văd pe gazdă.

#: Forma pe rânduri, dinainte de agregare (de1dcb5), păstrată ca martor. NU se
#: actualizează când se schimbă `_FORTARE_SQL`: rostul ei e să fie cealaltă
#: variantă, nu aceeași.
_SQL_PE_RANDURI = """
        WITH ok AS (
            SELECT id, src_ip, username, raw->>'auth_method' AS metoda
              FROM raw_events
             WHERE source = 'sshd' AND action = 'auth_ok'
               AND src_ip IS NOT NULL
               AND ts > now() - interval '24 hours'
        )
        SELECT host(ok.src_ip) AS ip, ok.username AS cont, ok.metoda AS metoda,
               count(f.id) FILTER (WHERE f.username = ok.username) AS esecuri_cont,
               count(f.id) AS esecuri_ip
          FROM ok
          LEFT JOIN raw_events f
            ON f.src_ip = ok.src_ip AND f.source = 'sshd'
           AND f.action = 'auth_fail'
           AND f.ts > now() - interval '24 hours'
           AND f.raw->>'auth_method' IS DISTINCT FROM 'publickey'
         GROUP BY ok.id, ok.src_ip, ok.username, ok.metoda
         ORDER BY 4 DESC, 5 DESC
"""

#: Singurele lucruri pe care SQLite nu le are din dialectul folosit în
#: interogare. Fiecare e o înlocuire de formă, nu de înțeles: `IS NOT` din
#: SQLite are exact semantica lui `IS DISTINCT FROM` (adevărat și pe NULL), iar
#: `json_extract` întoarce NULL exact unde `->>` întoarce NULL.
_TRADUCERI = (
    (re.compile(r"host\(([^()]*)\)"), r"\1"),
    (re.compile(r"now\(\)\s*-\s*interval\s*'24 hours'"), "datetime('now','-24 hours')"),
    (re.compile(r"(\w+\.)?raw->>'auth_method'"), r"json_extract(\1raw, '$.auth_method')"),
    (re.compile(r"\bIS DISTINCT FROM\b"), "IS NOT"),
    (re.compile(r"::bigint"), ""),
)

#: Ce nu are voie să rămână după traducere. Fără verificarea asta, o construcție
#: PostgreSQL rămasă pe loc ar putea fi acceptată de SQLite cu ALT înțeles, iar
#: testul ar compara liniștit două lucruri greșite — exact tiparul „grep după un
#: tipar care nu există” din CLAUDE.md.
_RAMASITE_PG = ("->>", "::", "interval '", "host(", "IS DISTINCT FROM", "now()")


def _tradu(sql: str) -> str:
    for tipar, inlocuire in _TRADUCERI:
        sql = tipar.sub(inlocuire, sql)
    ramase = [m for m in _RAMASITE_PG if m in sql]
    assert not ramase, f"construcții PostgreSQL netraduse: {ramase}"
    return sql


def _ev(minute_in_urma, source, action, ip, user, metoda, fara_raw=False):
    ts = datetime.now(timezone.utc) - timedelta(minutes=minute_in_urma)
    if fara_raw:
        raw = None                       # rând fără `raw` deloc
    elif metoda is None:
        raw = '{"port": 22}'             # linie „Invalid user”: fără metodă
    else:
        raw = f'{{"auth_method": "{metoda}"}}'
    return (ts.strftime("%Y-%m-%d %H:%M:%S"), source, action, ip, user, raw)


def _ruleaza(sql, evenimente):
    """Execută interogarea peste evenimentele date, pe SQLite."""
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE raw_events (id INTEGER PRIMARY KEY, ts TEXT, "
                "source TEXT, action TEXT, src_ip TEXT, username TEXT, raw TEXT)")
    con.executemany("INSERT INTO raw_events (ts, source, action, src_ip, username, raw) "
                    "VALUES (?, ?, ?, ?, ?, ?)", evenimente)
    try:
        return [dict(r) for r in con.execute(_tradu(sql)).fetchall()]
    finally:
        con.close()


def _evenimente_amestecate():
    """Mai multe conturi și adrese încrucișate, plus fiecare margine a regulii."""
    return [
        # 45.134.26.7 — forțare adevărată pe `root`, plus zgomot pe alt cont.
        _ev(10, "sshd", "auth_ok", "45.134.26.7", "root", "password"),
        _ev(20, "sshd", "auth_ok", "45.134.26.7", "root", "password"),
        *[_ev(30 + i, "sshd", "auth_fail", "45.134.26.7", "root", "password")
          for i in range(7)],
        *[_ev(40 + i, "sshd", "auth_fail", "45.134.26.7", "admin", None)
          for i in range(3)],
        # Eșec pe cheie: nu se numără nicăieri (agentul refuză cheie cu cheie).
        _ev(41, "sshd", "auth_fail", "45.134.26.7", "root", "publickey"),
        # În afara ferestrei și din altă sursă: nu intră în niciun număr.
        _ev(60 * 25, "sshd", "auth_fail", "45.134.26.7", "root", "password"),
        _ev(15, "sudo", "auth_fail", "45.134.26.7", "root", "password"),

        # 198.51.100.62 — sesiunea de deploy: intrare pe cheie, refuzuri pe alții.
        _ev(5, "sshd", "auth_ok", "198.51.100.62", "sentinel-deploy", "publickey"),
        _ev(5, "sshd", "auth_fail", "198.51.100.62", "admin", "publickey"),
        _ev(5, "sshd", "auth_fail", "198.51.100.62", "deploy", None),
        # ...și o intrare pe parolă de la ACEEAȘI adresă, pe un cont fără eșecuri.
        _ev(6, "sshd", "auth_ok", "198.51.100.62", "operator", "password"),

        # 203.0.113.78 — ziua operatorului: metodă necunoscută, eșecuri pe cont.
        _ev(3, "sshd", "auth_ok", "203.0.113.78", "cont-operator", None),
        *[_ev(50 + i, "sshd", "auth_fail", "203.0.113.78", "cont-operator", "password")
          for i in range(4)],
        _ev(55, "sshd", "auth_fail", "203.0.113.78", None, "password"),
        _ev(56, "sshd", "auth_fail", "203.0.113.78", "root", None, fara_raw=True),

        # 203.0.113.9 — reușită fără cont: numai eșecurile adresei stau martor.
        _ev(4, "sshd", "auth_ok", "203.0.113.9", None, "password"),
        *[_ev(12 + i, "sshd", "auth_fail", "203.0.113.9", "root", "password")
          for i in range(6)],

        # 198.51.100.4 — reușită curată, niciun eșec: rândul trebuie să rămână.
        _ev(2, "sshd", "auth_ok", "198.51.100.4", "nobody", "password"),
    ]


def _cheie(r):
    return (r["ip"], r["cont"], r["metoda"], int(r["esecuri_cont"]), int(r["esecuri_ip"]))


def test_aggregating_failures_before_the_join_keeps_the_same_numbers():
    """Agregarea de dinaintea join-ului nu are voie să schimbe nicio cifră.

    Eșecul pe care îl previne: interogarea de titlu a fost rescrisă ca să nu mai
    facă un nested loop `reușite × eșecuri` (20 s măsurate pe gazdă, peste
    `statement_timeout_ms` de 30 s doar cu o fereastră mai lungă — adică 500 pe
    panou fix în ziua în care regula se aprinde). O rescriere de genul ăsta
    strică ușor exact ce numără: `sum` peste grupuri în loc de `count` peste
    rânduri, `FILTER` mutat de partea greșită a agregării, sau un `LEFT JOIN`
    devenit `JOIN`, care face să dispară reușitele fără niciun eșec. Cifrele
    sunt tot ce citește pragul de forțare, deci se cere egalitate rând cu rând
    cu forma pe rânduri, pe conturi și adrese încrucișate.
    """
    ev = _evenimente_amestecate()
    noi = _ruleaza(ins._FORTARE_SQL, ev)
    vechi = _ruleaza(_SQL_PE_RANDURI, ev)

    # Singura deosebire admisă: forma nouă scoate reușitele pe cheie din CTE, pe
    # care forma veche le întorcea ca să le arunce Python-ul pe linia următoare.
    assert [r for r in vechi if r["metoda"] == "publickey"], (
        "fixture-ul nu conține nicio reușită pe cheie, deci nu deosebește cele "
        "două forme acolo unde chiar diferă")
    vechi_fara_cheie = [r for r in vechi if r["metoda"] != "publickey"]

    # `key=repr`: cheile poartă `None` pe poziția contului, iar `None` nu se
    # compară cu un șir — fără el, un rând nou în fixture ar da TypeError în loc
    # de o comparație.
    agregat = sorted(map(_cheie, noi), key=repr)
    randuri = sorted(map(_cheie, vechi_fara_cheie), key=repr)
    assert agregat == randuri, (
        f"forma agregată dă alte cifre decât cea pe rânduri:\n"
        f"  agregat: {agregat}\n"
        f"  rânduri: {randuri}")

    # Egalitatea de mai sus ar fi adevărată și despre două interogări greșite la
    # fel, așa că se fixează și cifrele, pe fiecare margine care contează.
    numere = {r["cont"]: (int(r["esecuri_cont"]), int(r["esecuri_ip"])) for r in noi}
    assert numere["root"] == (7, 10), (
        f"eșecurile pe cont și pe adresă nu mai sunt deosebite: {numere['root']}")
    assert numere[None] == (0, 6), (
        f"o reușită fără cont iese 0 pe cont și 6 pe adresă: {numere[None]}")
    assert numere["nobody"] == (0, 0), (
        "o reușită fără niciun eșec a dispărut — join-ul nu mai e LEFT")
    assert numere["cont-operator"] == (4, 6), (
        f"eșecurile fără cont sau fără `raw` s-au pierdut din numărul pe "
        f"adresă: {numere['cont-operator']}")
    assert sum(1 for r in noi if r["cont"] == "root") == 2, (
        "cele două reușite de pe același cont și aceeași adresă au fost topite "
        "într-un singur rând")


def test_key_logins_never_reach_the_python_guard():
    """Reușitele pe cheie sunt scoase din interogare, nu doar sărite în Python.

    Eșecul pe care îl previne: filtrul pus în CTE ca `<> 'publickey'` în loc de
    `IS DISTINCT FROM`. Cu `<>`, un rând cu metodă NECUNOSCUTĂ (liniile „Invalid
    user” nu poartă metoda) iese din comparație ca NULL, deci nu trece filtrul
    și dispare din rezultat — iar regula ar tăcea tocmai despre rândurile despre
    care se știe cel mai puțin. Al doilea eșec prevenit: filtrul scăpat de tot
    la o rescriere, care redă bazei tot costul mutării lui în CTE.
    """
    noi = _ruleaza(ins._FORTARE_SQL, _evenimente_amestecate())
    assert all(r["metoda"] != "publickey" for r in noi), (
        "o reușită pe cheie a ieșit din interogare, deci filtrul din CTE lipsește")
    conturi = {r["cont"] for r in noi}
    assert "sentinel-deploy" not in conturi
    assert "cont-operator" in conturi, (
        "reușita cu metodă necunoscută a fost înghițită de filtru — `<>` în loc "
        "de `IS DISTINCT FROM`")
    assert "operator" in conturi, (
        "reușita pe parolă de la adresa de deploy s-a pierdut odată cu reușita "
        "pe cheie de la aceeași adresă")


def test_the_headline_query_returns_the_hardest_pressed_account_first():
    """Ordinea rândurilor e ce alege forțarea din titlu.

    Eșecul pe care îl previne: `ORDER BY`-ul pierdut sau ajuns pe alte coloane
    la rescriere. `posture` ia `fortari[0]` ca titlu și nimic din Python nu
    resortează, deci dacă interogarea nu mai întoarce cea mai apăsată reușită
    prima, titlul arată o forțare minoră în ziua în care una mare e în listă.
    """
    noi = _ruleaza(ins._FORTARE_SQL, _evenimente_amestecate())
    ordonate = [(int(r["esecuri_cont"]), int(r["esecuri_ip"])) for r in noi]
    assert ordonate == sorted(ordonate, reverse=True), (
        f"rândurile nu mai vin descrescător după eșecuri: {ordonate}")
    assert noi[0]["cont"] == "root", (
        f"prima reușită întoarsă nu e cea mai apăsată: {noi[0]}")
