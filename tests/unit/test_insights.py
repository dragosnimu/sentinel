"""The insight engine decides what an operator is told. A rule that fires on
weak evidence trains people to ignore the page, so the thresholds are pinned
here alongside the rule that one broken query must never blank the dashboard.

A stub DB answers by matching on the SQL text — enough to drive each rule down
its interesting branch without a live PostgreSQL.
"""
from __future__ import annotations

import asyncio
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
    # sudo genuinely goes quiet on an idle host; flagging it at 6h is noise.
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "sudo", "last_seen": NOW - timedelta(hours=10), "hours_silent": 10.0},
    ]})
    assert run(ins._gap_insights(db)) == []


def test_a_source_with_no_events_at_all_is_the_loudest_silence():
    """O sursă din inventar fără niciun eveniment în 30 de zile e cel mai mort colector.

    Eșecul pe care îl previne: `float(r["hours_silent"] or 0)`. Când
    `max(ts)` nu găsește nimic, `hours_silent` iese NULL, iar `or 0` îl citește
    ca „văzută acum" — deci regula tace exact despre sursa care n-a mai scris
    niciodată. E aceeași formă cu pana pe care regula o previne (tăcerea arată
    identic cu liniștea), doar mutată în Python.
    """
    db = _StubDB(fetch_map={"hours_silent": [
        {"source": "suricata", "last_seen": None, "hours_silent": None},
    ]})
    out = run(ins._gap_insights(db))
    assert len(out) == 1, "o sursă fără niciun eveniment n-a produs nicio constatare"
    assert out[0].level == "critical"
    assert "suricata" in out[0].title


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
# din 28 august 2026 (185.53.199.62) și ziua operatorului (86.35.255.78). Prima
# a produs verdictul „Autentificare reușită de la un atacator — verifică ACUM”
# fără să fi fost spart nimic; pe 30 de zile de date, regula veche n-a avut
# dreptate niciodată.
def _posture_db(rows, atacatori=629, ev=3861):
    """Stub pentru `posture`: interogarea de titlu plus numărătoarea de atacatori."""
    return _StubDB(
        fetch_map={"esecuri_cont": rows},
        row_map={"count(DISTINCT host(src_ip))": {"atacatori": atacatori, "ev": ev}},
    )


def _ok(cont, metoda, esecuri_cont, esecuri_ip=None, ip="185.53.199.62"):
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
    """
    p = run(ins.posture(_posture_db([
        _ok("sentinel-deploy", "publickey", esecuri_cont=0, esecuri_ip=3),
    ]), []))
    assert p["intruziuni"] == 0, (
        f"o sesiune de deploy a fost numărată ca intruziune: {p['verdict']}")
    assert p["level"] != "critical"


def test_the_operators_own_seven_failures_are_not_a_break_in():
    """Ziua operatorului (86.35.255.78): 7 eșecuri și o intrare, același cont.

    Eșecul pe care îl previne: pragul pus prea jos, sau lipsa lui. Adresa
    operatorului a produs 7 eșecuri în aceeași fereastră de 24h în care s-a și
    conectat; dacă ar fi de ajuns ca eșecurile să fie pe același cont, fiecare
    tastare greșită de parolă i-ar spune operatorului că i-a fost spart
    serverul. Metoda e necunoscută aici dinadins, ca testul să pice pe prag, nu
    pe altă apărare.
    """
    p = run(ins.posture(_posture_db([
        _ok("cont-operator", None, esecuri_cont=7, ip="86.35.255.78"),
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
