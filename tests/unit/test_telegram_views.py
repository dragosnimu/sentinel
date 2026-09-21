"""The dashboard, on a phone.

These commands render database rows into `parse_mode=HTML` messages. Almost
every field they touch — HTTP paths, usernames, user agents, IDS signature
names — is written by whoever is attacking the host, so the tests that matter
most here are the escaping ones.

The rest is about the three ways a chat message is not a web page: it has a hard
length limit, it has no columns, and it has no scrollbar.
"""
from __future__ import annotations

import asyncio
import html
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.telegram import views  # noqa: E402

NOW = datetime(2026, 8, 4, 12, 34, 56, tzinfo=timezone.utc)


class _Msg:
    def __init__(self):
        self.sent: list[str] = []

    async def reply_text(self, text, **kw):
        self.sent.append(text)


def _update():
    msg = _Msg()
    return SimpleNamespace(effective_message=msg, message=msg), msg


def _ctx(db, args=None):
    # `timezone` e in configuratia reala si e citita de fiecare afisare de
    # ora; o fixtura fara ea ar fi testat un obiect pe care procesul nu-l are.
    return SimpleNamespace(
        bot_data={"db": db, "cfg": SimpleNamespace(timezone="Europe/Bucharest")},
        args=args or [])


def run(c):
    return asyncio.run(c)


# --- escaping ---------------------------------------------------------------
def test_an_http_path_cannot_inject_markup():
    """A request path is chosen entirely by the client. The alert is HTML."""
    line = views._format_event(
        {"ts": NOW, "source": "nginx", "action": "http",
         "src_ip": "203.0.113.9", "http_method": "GET",
         "http_path": "/<img src=x onerror=alert(1)>", "http_status": 404},
        with_ip=True, tz_name="UTC")
    assert "<img" not in line
    assert "&lt;img" in line


def test_a_username_cannot_inject_markup():
    line = views._format_event(
        {"ts": NOW, "source": "sshd", "action": "auth_fail",
         "src_ip": "203.0.113.9", "username": "<b>root</b>"},
        with_ip=True, tz_name="UTC")
    assert "<b>root</b>" not in line
    assert "&lt;b&gt;root" in line


def test_a_long_path_is_truncated_before_escaping():
    """Truncating after escaping can cut `&lt;` in half and leave `&l` — broken
    markup that Telegram rejects, turning one hostile request into a message
    that never arrives."""
    line = views._format_event(
        {"ts": NOW, "source": "nginx", "action": "http", "src_ip": "203.0.113.9",
         "http_method": "GET", "http_path": "<" * 200},
        with_ip=True, tz_name="UTC")
    assert "&l;" not in line and "&" not in line.replace("&lt;", "")


def test_esc_handles_missing_values():
    assert views.esc(None) == "—"
    assert views.esc(0) == "0"


# --- the length limit -------------------------------------------------------
def _u16(text: str) -> int:
    """Unitati UTF-16, numarate AICI.

    Nu prin `views.w16`: masurata cu chiar functia pusa sub test, aserttiunea
    trece si cu ea stricata — s-a si intamplat, prima data cand a fost scrisa.
    """
    return len(text.encode("utf-16-le")) // 2


def test_a_long_list_is_cut_and_says_so():
    """Silently truncating is how an operator concludes there were four
    attackers when there were forty."""
    out = views.clamp([f"rând {i} " + "x" * 80 for i in range(200)])
    assert len(out) <= 4096
    assert "listă scurtată" in out
    assert "rânduri" in out


def test_a_short_list_is_untouched():
    out = views.clamp(["unu", "doi"])
    assert out == "unu\ndoi"
    assert "scurtată" not in out


def test_clamp_numara_unitati_utf16():
    """`clamp` e singura margine de lungime a cinci comenzi.

    /dashboard, /evenimente, /blocklist, /selfcheck si /comportament nu trec
    prin `fit_blocks` — acolo `clamp` decide totul. Numarat in caractere
    Python, un corp de 60 de randuri de emoji da len=1866 u16=3607 corect si
    len=3565 u16=7046 gresit: peste 4096, deci Telegram refuza mesajul INTREG
    si operatorul primeste eroarea generica a lui `_guard` in loc de raspuns.

    Testul din `/vulnerabilitati` nu vede asta: acolo `fit_blocks` taie primul
    si `clamp` nu mai ajunge sa lucreze niciodata.
    """
    body = ["💥" * 60 for _ in range(60)]
    out = views.clamp(body, tail="\n/x")

    assert _u16(out) <= views.MAX_MESSAGE, (
        f"{_u16(out)} unitati UTF-16 pentru len={len(out)}")
    assert "listă scurtată" in out, "a taiat fara sa spuna"
    assert out.endswith("/x"), "coada s-a pierdut la taiere"


def test_the_tail_survives_truncation():
    """The closing hint is the one line worth keeping when everything else is
    cut — it says what to type next."""
    out = views.clamp(["x" * 200 for _ in range(100)], tail="/ajutor")
    assert out.endswith("/ajutor")


# --- dashboard --------------------------------------------------------------
class _DashDB:
    """Enough of a database for the dashboard, with nothing in it."""

    async def fetchrow(self, *a, **k):
        return {"atacatori": 0, "ev": 0}

    async def fetchval(self, *a, **k):
        return 0

    async def fetch(self, *a, **k):
        return []

    async def healthy(self):
        return True


def test_dashboard_leads_with_the_verdict(monkeypatch):
    """Someone reading this at 3 a.m. should be able to stop after line one."""
    monkeypatch.setattr(views.insights_mod, "collect", _async([]))
    monkeypatch.setattr(views.insights_mod, "posture", _async(
        {"level": "good", "verdict": "Nimic de semnalat", "atacatori": 0,
         "evenimente": 0, "critice": 0, "avertismente": 0, "intruziuni": 0}))
    monkeypatch.setattr(views.aggregate, "kpis", _async(_KPI))
    monkeypatch.setattr(views.aggregate, "deltas", _async({}))
    monkeypatch.setattr(views.aggregate, "service_health", _async({"up": 3}))
    monkeypatch.setattr(views.aggregate, "top_attackers", _async([]))
    monkeypatch.setattr(views.aggregate, "by_country", _async([]))

    upd, msg = _update()
    run(views.cmd_dashboard(upd, _ctx(_DashDB())))
    first = msg.sent[0].splitlines()[0]
    assert "Nimic de semnalat" in first


def test_dashboard_shows_only_insights_worth_colouring(monkeypatch):
    """A phone has no room for the "everything is fine" cards, and reading them
    trains you to skim past the ones that matter."""
    from sentinel.analytics.insights import Insight

    found = [Insight("good", "Totul bine", "d"), Insight("critical", "Ceva rău", "d", "fă X")]
    monkeypatch.setattr(views.insights_mod, "collect", _async(found))
    monkeypatch.setattr(views.insights_mod, "posture", _async(
        {"level": "critical", "verdict": "Necesită atenție", "atacatori": 1,
         "evenimente": 9, "critice": 1, "avertismente": 0, "intruziuni": 0}))
    monkeypatch.setattr(views.aggregate, "kpis", _async(_KPI))
    monkeypatch.setattr(views.aggregate, "deltas", _async({}))
    monkeypatch.setattr(views.aggregate, "service_health", _async({}))
    monkeypatch.setattr(views.aggregate, "top_attackers", _async([]))
    monkeypatch.setattr(views.aggregate, "by_country", _async([]))

    upd, msg = _update()
    run(views.cmd_dashboard(upd, _ctx(_DashDB())))
    assert "Ceva rău" in msg.sent[0]
    assert "Totul bine" not in msg.sent[0]
    assert "fă X" in msg.sent[0]


_KPI = {"evenimente_24h": 10, "ostile_24h": 5, "atacatori_24h": 2,
        "incidente_deschise": 1, "incidente_grave": 0, "vuln_deschise": 0,
        "vuln_kev": 0, "blocate": 0}


def _async(value):
    async def _f(*a, **k):
        return value
    return _f


# --- vulnerabilities --------------------------------------------------------
#
# Forma de pe gazda de productie, 21 septembrie 2026: 1055 constatari deschise,
# dintre care 477 pe pachetele sistemului — si NICIUNA dintre ele in primele 200
# de randuri dupa prioritate, fiindca `dnf` urca pana la 83 iar imaginile pana la
# 100. Fixturile de mai jos pastreaza forma asta, fiindca ea e ce deosebeste un
# filtru aplicat in SQL de unul aplicat dupa taiere: al doilea raspunde la
# „arata-mi criticele" cu „criticele dintre primele 20 dupa prioritate", iar pe
# gazda reala cele doua multimi nu au niciun rand comun.
_FINDING = {
    "id": 42, "cve": "CVE-2026-9538", "advisory_id": None,
    "title": "perl-Archive-Tar security update", "severity": "high",
    "cvss": 7.5, "epss": 0.12, "kev": False, "priority": 61,
    "package": "perl-Archive-Tar", "installed_version": "2.38-5",
    "fixed_version": "2.38-6.el9_8.2", "scanner": "dnf", "location": None,
    "status": "open", "last_seen": NOW, "asset_name": None,
}


class _Findings:
    """Repository-ul de constatari, cu semantica lui, peste o lista in memorie.

    Filtrele si `limit` sunt implementate, nu simulate, si in ORDINEA din SQL:
    intai `WHERE`, pe urma `ORDER BY`, pe urma `LIMIT`. Un ciot care ar intoarce
    aceeasi lista indiferent de argumente ar face sa treaca exact defectul pe
    care testele astea il prind — comanda ar cere 20 de randuri, le-ar filtra in
    Python si n-ar observa nimeni ca filtrul a ajuns dupa taiere.

    Ordonarea e numai (prioritate desc, id desc): corpusul e construit ca
    severitatea si `last_seen` sa nu departajeze nimic, deci coincide cu
    `ORDER BY f.priority DESC, f.severity DESC, f.last_seen DESC, f.id DESC`.
    """

    def __init__(self, rows):
        self.rows = list(rows)
        self.calls: list[dict] = []

    @staticmethod
    def _match(row, scanners, severities, kev_only) -> bool:
        # `None` = fara filtru; lista goala = niciun rand. Aceeasi distinctie ca
        # `_scanner_clause`, fiindcă o categorie fara scanere trebuie sa dea zero
        # randuri, nu toate randurile.
        if scanners is not None and (row.get("scanner") or "") not in scanners:
            return False
        if severities is not None and row["severity"] not in severities:
            return False
        return not (kev_only and not row.get("kev"))

    def _selected(self, scanners, severities, kev_only):
        return [r for r in self.rows
                if r["status"] == "open"
                and self._match(r, scanners, severities, kev_only)]

    async def list_open(self, db, *, limit=100, offset=0, scanners=None,
                        severities=None, kev_only=False):
        self.calls.append({"limit": limit, "offset": offset, "scanners": scanners,
                           "severities": severities, "kev_only": kev_only})
        sel = sorted(self._selected(scanners, severities, kev_only),
                     key=lambda r: (-r["priority"], -r["id"]))
        return sel[offset:offset + limit]

    async def open_counts(self, db, *, scanners=None, severities=None,
                          kev_only=False):
        sel = self._selected(scanners, severities, kev_only)
        counts: dict[str, int] = {}
        for r in sel:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        counts["total"] = len(sel)
        counts["kev"] = sum(1 for r in self._selected(scanners, severities, False)
                            if r.get("kev"))
        return counts

    async def open_counts_by_scanner(self, db):
        out: dict[str, int] = {}
        for r in self.rows:
            if r["status"] == "open":
                key = r.get("scanner") or ""
                out[key] = out.get(key, 0) + 1
        return out

    async def get_finding(self, db, finding_id):
        return next((r for r in self.rows if r["id"] == finding_id), None)

    def install(self, monkeypatch):
        for name in ("list_open", "open_counts", "open_counts_by_scanner",
                     "get_finding"):
            monkeypatch.setattr(views.findings_repo, name, getattr(self, name))
        return self


def _productie() -> _Findings:
    """1055 deschise, in distributia MASURATA pe gazda: 486 `trivy_image`,
    477 `dnf`, 92 `trivy_fs`.

    Prima versiune a fixturii scria „561 in imagini, 17 in aplicatii". Suma
    inchidea (578 in ambele feluri), dar cele doua numere erau derivate, nu
    masurate: 17 e cate randuri `trivy_fs` incap in PRIMELE 200 de randuri dupa
    prioritate — numaratoarea din docstring-ul lui `subject.py` — iar restul
    fusese pus pe seama imaginilor. Un numar dedus, prezentat drept masurat,
    e exact tiparul pe care il numeste CLAUDE.md.

    Criticele si cele din KEV stau intre randurile de sistem, sub pragul de
    prioritate al primelor 20 — adica in afara feliei pe care o citea comanda
    inainte sa filtreze.
    """
    rows = []
    for i in range(486):
        rows.append({**_FINDING, "id": 1000 + i, "scanner": "trivy_image",
                     "location": "mariadb:11.4.7", "package": f"lib{i}",
                     "severity": "high", "kev": False, "priority": 84 + i % 17})
    for i in range(92):
        rows.append({**_FINDING, "id": 2000 + i, "scanner": "trivy_fs",
                     "location": f"html/phpMyAdmin{i}/composer.lock",
                     "package": f"vendor/pkg{i}", "severity": "high",
                     "kev": False, "priority": 84 + i % 17})
    for i in range(477):
        rows.append({**_FINDING, "id": 3000 + i, "scanner": "dnf",
                     "location": None, "package": f"pkg-{i}",
                     "severity": "high", "kev": False, "priority": 20 + i % 60})
    for i in range(3):
        rows[578 + i]["severity"] = "critical"
    for i in range(2):
        rows[600 + i]["kev"] = True
    return _Findings(rows)


_ID_IN_LIST = re.compile(r"<b>#(\d+)</b>")




def _aratate(text: str) -> int:
    """Cifra pe care mesajul o da drept numar de constatari afisate."""
    m = re.search(r"(\d+) afișate din", text)
    assert m, f"antetul nu mai spune cate arata: {text[:200]!r}"
    return int(m.group(1))


def test_vulns_links_every_cve(monkeypatch):
    _Findings([_FINDING]).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    # dnf finding: Red Hat first, because backport status is the real question.
    assert "access.redhat.com/security/cve/CVE-2026-9538" in msg.sent[0]
    # Si invers fata de defectul reparat: cand se arata TOT ce exista, mesajul
    # nu are voie sa sugereze ca mai e ceva dincolo de ecran.
    assert "și încă" not in msg.sent[0], msg.sent[0]


def test_vulns_nu_spune_mai_mult_decat_arata(monkeypatch):
    """Antetul numara randurile tiparite, nu randurile cerute.

    Defectul masurat: comanda cerea 200, tiparea 20 si scria „200 afișate" —
    operatorul citea ca are in fata tot ce e important si inchidea telefonul.
    Testul cere egalitate stricta intre cifra din antet si cate constatari sunt
    in mesaj, pe o fixtura in care mesajul SE umple si taierea chiar se produce.
    """
    rows = [{**_FINDING, "id": 5000 + i, "scanner": "trivy_image",
             "location": "registry.example.test/echipa/imagine-cu-nume-lung:v1.2.3",
             "package": f"pachet-cu-nume-lung-{i}" + "x" * 40,
             "cve": f"CVE-2026-{7000 + i}", "priority": 90 - i}
            for i in range(views.VULN_LIMIT)]
    _Findings(rows).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    text = msg.sent[0]

    # In unitati UTF-16, ca Telegram: `len()` e o margine mai slaba, iar pe
    # un mesaj cu emoji citeste ca o verificare stransa fara sa mai fie.
    assert _u16(text) <= views.MAX_MESSAGE, "mesajul depaseste bugetul de lungime"
    assert "listă scurtată" not in text, (
        "taierea a ajuns la `clamp`, deci antetul a fost scris inainte sa se "
        "stie cate randuri incap")
    assert _aratate(text) == len(_ID_IN_LIST.findall(text)), (
        f"antetul spune {_aratate(text)}, in mesaj sunt "
        f"{len(_ID_IN_LIST.findall(text))} constatari")
    assert _aratate(text) < len(rows), (
        "fixtura nu mai umple mesajul, deci testul nu mai verifica taierea")


def test_vulns_spune_si_cate_exista_dincolo_de_ecran(monkeypatch):
    """Trei cifre, nu una: cate arata, cate sunt in multimea ceruta, cate deschise.

    Cu o singura cifra, „20 afișate" langa 1055 deschise se citeste ca „astea
    sunt", iar restul de 1035 nu sunt cerute niciodata de nimeni.
    """
    _productie().install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    text = msg.sent[0]
    aratate = _aratate(text)
    assert aratate == len(_ID_IN_LIST.findall(text))
    assert 0 < aratate <= views.VULN_LIMIT
    assert "din 1055 deschise" in text, text[:300]
    assert f"…și încă {1055 - aratate} neafișate" in text, (
        "coada nu spune cate raman neafisate")


def test_filtrul_de_severitate_se_aplica_inainte_de_limita(monkeypatch):
    """`/vulnerabilitati critice` intreaba baza, nu primele 20 de randuri.

    Pe gazda de productie criticele stau sub pragul de prioritate al feliei
    afisate. Filtrate in Python dupa taiere, comanda raspundea „niciuna" despre
    trei vulnerabilitati critice deschise — iar raspunsul era „✅".
    """
    corpus = _productie().install(monkeypatch)
    critice = sorted(r["id"] for r in corpus.rows if r["severity"] == "critical")
    assert critice, "fixtura nu mai contine constatari critice"

    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, ["critice"])))
    text = msg.sent[0]

    aparute = sorted(int(x) for x in _ID_IN_LIST.findall(text))
    assert aparute == critice, f"criticele deschise nu sunt in mesaj: {aparute}"
    assert corpus.calls[-1]["severities"] == ["critical"], (
        "filtrul n-a ajuns in interogare, deci s-a aplicat dupa LIMIT")


def test_filtrul_kev_se_aplica_inainte_de_limita(monkeypatch):
    """Acelasi lucru pentru `/vulnerabilitati kev`.

    KEV inseamna „se exploateaza acum". O lista goala fiindca randurile sunt in
    afara primelor 20 dupa prioritate e cel mai scump fals negativ de aici.
    """
    corpus = _productie().install(monkeypatch)
    kev_ids = sorted(r["id"] for r in corpus.rows if r["kev"])

    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, ["kev"])))
    text = msg.sent[0]
    assert sorted(int(x) for x in _ID_IN_LIST.findall(text)) == kev_ids
    assert corpus.calls[-1]["kev_only"] is True


def test_categoria_sistem_ajunge_la_randurile_de_sub_prag(monkeypatch):
    """`/vulnerabilitati sistem` aduce pachetele gazdei, care altfel n-au drum.

    477 de constatari pe pachetele sistemului, niciuna in primele 200 de randuri
    dupa prioritate: fara argumentul asta, singurul raspuns pe care botul il
    putea da despre ele era tacerea.
    """
    corpus = _productie().install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, ["sistem"])))
    text = msg.sent[0]

    assert corpus.calls[-1]["scanners"] is not None
    assert "dnf" in corpus.calls[-1]["scanners"]
    aparute = [int(x) for x in _ID_IN_LIST.findall(text)]
    assert aparute and all(i >= 3000 for i in aparute), (
        f"au ajuns in lista randuri care nu sunt ale sistemului: {aparute}")
    assert "din 477 deschise în „sistem de operare”" in text, text[:400]
    assert "1055 deschise în total" in text, (
        "multimea filtrata e aratata fara numitorul intreg")


def test_numerele_din_antet_descriu_multimea_aratata(monkeypatch):
    """Pastila „🔥 N KEV" langa o lista in care nu e niciun KEV.

    Exact defectul prins pe pagina: numaratoarea era globala, lista era
    filtrata, iar cele doua stateau pe acelasi ecran. Aici multimea „aplicatie"
    nu contine niciun rand din KEV, desi gazda are doua.
    """
    corpus = _productie().install(monkeypatch)
    assert any(r["kev"] for r in corpus.rows), "fixtura n-are randuri KEV"

    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, ["aplicatie"])))
    text = msg.sent[0]
    antet = "\n".join(text.splitlines()[:4])
    assert "KEV" not in antet and "🔥" not in antet, (
        f"antetul numara KEV-uri care nu sunt in lista: {antet!r}")
    assert "din 92 deschise în „aplicație”" in text, text[:300]


def test_un_filtru_neinteles_e_spus_nu_ignorat(monkeypatch):
    """Un argument pe care botul nu-l intelege nu devine „arata tot" in tacere.

    1055 de randuri sub un titlu pe care operatorul a cerut sa-l restranga se
    citesc ca 1055 de randuri DIN categoria ceruta.
    """
    _productie().install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, ["retea"])))
    text = msg.sent[0]
    assert "Filtru neînțeles" in text and "retea" in text
    assert "din 1055 deschise" in text


def test_al_doilea_filtru_nu_e_inghitit_in_tacere(monkeypatch):
    """`/vulnerabilitati critice sistem` — doua filtre, unul singur se aplica.

    De cand coada listei anunta sapte cuvinte, combinarea lor e tastarea
    fireasca. Comanda ia doar primul argument; tacerea ar da un raspuns despre
    criticele din TOATE categoriile sub un cuvant care cerea una singura, adica
    exact numarul gresit langa eticheta corecta.
    """
    corpus = _productie().install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, ["critice", "sistem"])))
    text = msg.sent[0]

    assert "un singur filtru" in text, text[:300]
    assert "critice" in text
    # Primul argument chiar s-a aplicat; avertismentul nu-l inlocuieste.
    assert corpus.calls[-1]["severities"] == ["critical"]


def test_filtrul_neinteles_nu_reflecta_orice_lungime(monkeypatch):
    """Argumentul se intoarce escapat si scurtat.

    Mesajul e `parse_mode=HTML`, iar argumentul il scrie cine trimite comanda.
    Nemarginit, un singur cuvant de 4 kB ar impinge mesajul peste limita si
    raspunsul n-ar mai pleca deloc.
    """
    _productie().install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, ["<b>" + "z" * 4000])))
    text = msg.sent[0]
    assert "<b>z" not in text and "&lt;b&gt;z" in text
    assert _u16(text) <= views.MAX_MESSAGE
    # Si lista ramane. Necitat marginit, avertismentul singur consuma tot
    # bugetul: operatorul care a gresit un cuvant pierde si raspunsul.
    assert _aratate(text) >= 10, f"avertismentul a mancat lista: {_aratate(text)}"


def test_fiecare_rand_spune_pe_ce_sta(monkeypatch):
    """Plangerea operatorului, pe bot: `openssl` nu spune daca e gazda sau o imagine.

    Reparatia e aceeasi pe care o are pagina — `scan.subject.describe` — nu o a
    doua harta scaner→categorie, care ar diverge de prima exact pe scanerul
    adaugat ultimul.
    """
    rows = [
        {**_FINDING, "id": 1, "scanner": "dnf", "location": None, "priority": 90},
        {**_FINDING, "id": 2, "scanner": "trivy_image",
         "location": "mariadb:11.4.7", "priority": 89},
        {**_FINDING, "id": 3, "scanner": "trivy_fs",
         "location": "html/phpMyAdmin/composer.lock", "priority": 88},
        {**_FINDING, "id": 4, "scanner": "scaner-nou", "location": "ceva",
         "priority": 87},
    ]
    _Findings(rows).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    text = msg.sent[0]
    assert "Sistem de operare" in text
    assert "Container · mariadb:11.4.7" in text
    assert "Aplicație · phpMyAdmin (composer.lock)" in text
    assert "Necunoscut · scaner-nou" in text, (
        "un scaner neclasificat e trecut tacut intr-una dintre categorii")


def test_o_eticheta_lunga_nu_mananca_mesajul(monkeypatch):
    """O referinta de imagine de 300 de caractere nu are voie sa taie lista.

    `location` e text scris de scaner peste ce gaseste pe gazda. O singura
    eticheta nemarginita ar lasa in mesaj doua constatari din douazeci.
    """
    rows = [{**_FINDING, "id": 10 + i, "scanner": "trivy_image",
             "location": "registry.example.test/" + "n" * 300 + f":v{i}",
             "priority": 90 - i} for i in range(views.VULN_LIMIT)]
    _Findings(rows).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    text = msg.sent[0]
    assert "n" * 100 not in text, "eticheta intra netaiata in mesaj"
    assert _aratate(text) >= 10, (
        f"o eticheta lunga a redus lista la {_aratate(text)} randuri")
    assert _aratate(text) == len(_ID_IN_LIST.findall(text))


def test_scurtarea_se_face_inainte_de_escapare():
    """Ordinea celor doua operatii, verificata pe rezultat, nu pe intentie.

    Taiat DUPA escapare, `&lt;` ramane `&l`: Telegram refuza mesajul INTREG,
    deci o singura cale ostila sub un web root opreste raspunsul la
    `/vulnerabilitati`, nu doar randul ei. Testul care exista verifica doar ca
    escaparea s-a facut — pe valori prea scurte ca sa fie taiate — deci
    inversarea celor doua trecea verde.

    Criteriul e exact: ce iese, dezescapat, trebuie sa fie chiar prefixul
    textului brut. Asta se poate obtine doar taind brutul si escapand pe urma.
    """
    raw = "html/" + "<a>" * 40 + "/composer.lock"
    out = views._short(raw, 20)

    assert html.unescape(out) == raw[:19] + "…", out
    # Nicio entitate rupta: scoase cele intregi, nu mai ramane niciun `&`.
    rest = out.replace("&lt;", "").replace("&gt;", "").replace("&amp;", "")
    assert "&" not in rest, f"entitate taiata la jumatate: {out!r}"
    # Si bugetul numara ce vede operatorul, nu entitatile: 20 de caractere
    # brute, nu 20 impartite la 12 caractere de entitate.
    assert html.unescape(out).count("<") == 5


def test_o_valoare_uriasa_pe_un_rand_nu_goleste_lista(monkeypatch):
    """Un singur rand ostil nu are voie sa ia tot bugetul mesajului.

    `package`, `fixed_version` si `cve` vin din manifeste scanate sub un web
    root; lungimea lor o alege cine scrie manifestul. Nemarginite, blocul
    primului rand (cel mai prioritar!) depaseste singur bugetul, `fit_blocks`
    se opreste la el si operatorul primeste un antet cinstit — „0 afișate" —
    deasupra unei liste goale, cu 1055 de constatari deschise pe gazda.
    """
    rows = [{**_FINDING, "id": 900, "priority": 100,
             "package": "p" * 3000, "fixed_version": "v" * 3000,
             "cve": "CVE-2026-" + "9" * 3000}]
    rows += [{**_FINDING, "id": 500 + i, "priority": 90 - i} for i in range(19)]
    _Findings(rows).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    text = msg.sent[0]

    assert _aratate(text) >= 10, (
        f"un singur rand a redus lista la {_aratate(text)} randuri")
    assert _aratate(text) == len(_ID_IN_LIST.findall(text))
    assert "#900" in text, "randul ostil a disparut cu totul, in loc sa fie scurtat"
    assert "p" * 200 not in text and "v" * 200 not in text and "9" * 200 not in text


def test_antetul_numara_toate_severitatile_multimii(monkeypatch):
    """Pastilele de severitate trebuie sa se adune la totalul multimii.

    O severitate lipsa din lista pastilelor nu se vede pe gazda de azi (zero
    randuri `info`), dar in ziua in care apare unul, antetul spune un total mai
    mic decat lista de sub el — iar operatorul aduna pastilele si obtine alt
    numar decat ce vede. Suma, nu prezenta: asta e ce se poate falsifica.
    """
    sevs = ["info", "low", "medium", "high", "critical"]
    rows = [{**_FINDING, "id": 10 + i, "severity": sevs[i % 5],
             "priority": 50 - i} for i in range(15)]
    _Findings(rows).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    pastile = msg.sent[0].splitlines()[1]

    numere = [int(n) for n in re.findall(r"[⚪🔵🟡🟠🔴](\d+)", pastile)]
    assert sum(numere) == len(rows), (
        f"pastilele {pastile!r} insumeaza {sum(numere)} din {len(rows)} randuri")


def test_bugetul_se_masoara_in_unitati_utf16(monkeypatch):
    """Telegram numara unitati UTF-16; `len()` numara caractere Python.

    Un emoji din planurile suplimentare e 1 caracter si 2 unitati. Masurat pe o
    lista de etichete cu emoji: `len` 3350, UTF-16 4914 — peste 4096, deci
    mesajul e refuzat intreg si operatorul primeste eroarea generica a lui
    `_guard` in loc de raspuns. Un buget numarat in caractere nu vede asta.
    """
    rows = [{**_FINDING, "id": 700 + i, "scanner": "trivy_image",
             "location": "🧨" * 60, "package": "😀" * 60,
             "fixed_version": "🔥" * 60, "priority": 90 - i}
            for i in range(views.VULN_LIMIT)]
    _Findings(rows).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    text = msg.sent[0]

    assert _u16(text) <= views.MAX_MESSAGE, (
        f"{_u16(text)} unitati UTF-16 pentru len={len(text)}")
    assert _aratate(text) == len(_ID_IN_LIST.findall(text))
    assert _aratate(text) > 0, "bugetul in UTF-16 a taiat tot"


def test_cate_randuri_se_cer_e_cat_se_poate_arata(monkeypatch):
    """`VULN_LIMIT` trebuie sa fie plafonul care se atinge, nu unul decorativ.

    Pe randuri scurte, toate cele cerute trebuie sa incapa — altfel comanda
    cere bazei mai mult decat poate tipari vreodata si numarul din constanta nu
    descrie nimic. (Pe randurile reale ale gazdei incap 17 din 20, fiindca
    referintele de imagine si legaturile CVE sunt lungi; antetul spune 17.)
    """
    rows = [{**_FINDING, "id": i, "cve": None, "package": "p", "location": None,
             "fixed_version": "1", "priority": 100 - i, "scanner": "dnf"}
            for i in range(1, 3 * views.VULN_LIMIT)]
    _Findings(rows).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    text = msg.sent[0]
    assert _aratate(text) == views.VULN_LIMIT, (
        f"s-au cerut {views.VULN_LIMIT} randuri scurte si au incaput "
        f"{_aratate(text)}")


def test_filtrele_anuntate_sunt_exact_cele_intelese():
    """Ajutorul si coada listei ofera doar cuvinte pe care comanda le accepta.

    Si invers: fiecare categorie pe care `subject` o poate produce trebuie sa
    aiba un cuvant anuntat, altfel exista o categorie numarata in panou pe care
    botul n-o poate arata si despre care nu spune nimic.
    """
    from sentinel.scan import subject

    for word in views.FILTER_WORDS:
        f = views.parse_vuln_filter(word)
        assert f.warning is None, f"„{word}” e anuntat dar nu e inteles"
        assert f.filtered, f"„{word}” e anuntat dar nu filtreaza nimic"

    acoperite = {views.parse_vuln_filter(w).kind for w in views.FILTER_WORDS}
    assert set(subject.KINDS) <= acoperite, (
        f"categorii fara cuvant anuntat: {set(subject.KINDS) - acoperite}")

    linia = [ln for ln in views.HELP.splitlines()
             if ln.startswith("/vulnerabilitati")]
    assert len(linia) == 1
    oferite = linia[0].split("[")[1].split("]")[0].split("|")
    assert oferite == list(views.FILTER_WORDS), (
        f"/ajutor ofera {oferite}, comanda anunta {list(views.FILTER_WORDS)}")


def test_iesirea_scanerului_nu_poate_injecta_markup(monkeypatch):
    """`location` si `package` ajung acum pe rand prin doua drumuri noi.

    Amandoua vin din scanare: o cale sub un web root si un nume de pachet
    dintr-un manifest — adica text scris de cine incarca fisiere pe gazda.
    Mesajul e `parse_mode=HTML`; un `<b>` nescapat nu e doar urat, e un mesaj
    pe care Telegram il refuza intreg, deci o alerta care nu pleaca.
    """
    rows = [{**_FINDING, "id": 1, "scanner": "trivy_fs",
             "location": "html/<img src=x onerror=alert(1)>/composer.lock",
             "package": "<b>vendor/pkg</b>",
             "fixed_version": "<i>1.0</i>"}]
    _Findings(rows).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    text = msg.sent[0]
    assert "<img" not in text and "<b>vendor" not in text and "<i>1.0" not in text
    assert "&lt;img" in text and "&lt;b&gt;vendor" in text

    upd2, msg2 = _update()
    run(views.cmd_vuln(upd2, _ctx(None, ["1"])))
    assert "<img" not in msg2.sent[0] and "&lt;img" in msg2.sent[0]


def test_no_vulnerabilities_is_reported_as_good_news(monkeypatch):
    _Findings([]).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    assert "✅" in msg.sent[0] and "niciuna" in msg.sent[0]


def test_nimic_in_categorie_nu_e_acelasi_lucru_cu_nimic_deschis(monkeypatch):
    """„Nicio vulnerabilitate" cand gazda are 1055 e cea mai buna veste falsa.

    Categoria ceruta poate fi goala fara ca gazda sa fie curata, iar mesajul
    trebuie sa spuna care dintre cele doua e.
    """
    _productie().install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, ["necunoscut"])))
    text = msg.sent[0]
    assert "1055 deschise în total" in text, text


def test_vulns_list_points_at_planifica_not_at_patch(monkeypatch):
    """Aceeași greșeală, pe lista din care operatorul citește id-urile: coada
    mesajului îi spune ce să tasteze imediat după ce i-a arătat 20 de id-uri de
    vulnerabilitate. `/patch <id>` acolo înseamnă «ia id-ul ăsta și caută-l
    printre planuri»."""
    _Findings([_FINDING]).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    text = msg.sent[0]
    assert "/planifica" in text
    assert "/patch" not in text, text


@pytest.mark.parametrize("arg,kind", [
    ("sistem", "os"), ("os", "os"), ("container", "container"),
    ("containere", "container"), ("aplicatie", "app"), ("aplicație", "app"),
    ("app", "app"), ("necunoscut", "unknown"), ("SISTEM", "os"),
])
def test_argumentele_pe_categorie_duc_la_categoria_paginii(arg, kind):
    """Aceleasi categorii ca `?asociat=` din panou, in cuvintele tastate aici.

    Daca botul si pagina ar numi altfel aceleasi lucruri, operatorul care citeste
    „container" in panou si tasteaza „container" in chat ar primi altceva.
    """
    assert views.parse_vuln_filter(arg).kind == kind


@pytest.mark.parametrize("arg,severities,kev", [
    ("", None, False), ("critice", ("critical",), False),
    ("critical", ("critical",), False), ("mari", ("critical", "high"), False),
    ("high", ("critical", "high"), False), ("kev", None, True),
    ("exploatate", None, True),
])
def test_argumentele_de_severitate_raman_cele_stiute(arg, severities, kev):
    """Filtrele vechi continua sa insemne acelasi lucru dupa mutarea in SQL."""
    f = views.parse_vuln_filter(arg)
    assert (f.severities, f.kev_only) == (severities, kev)


# --- detaliul unei constatari ----------------------------------------------
def test_vuln_ajunge_la_o_constatare_din_afara_primelor_randuri(monkeypatch):
    """Ultimele 55 de constatari deschise nu se puteau deschide deloc.

    Comanda citea 1000 de randuri si cauta id-ul printre ele; pe gazda sunt 1055
    deschise. Pentru cele de dincolo de felie raspunsul era „inexistenta sau deja
    rezolvata" despre o vulnerabilitate deschisa — inclusiv pentru un id copiat
    dintr-o alerta.
    """
    corpus = _productie().install(monkeypatch)
    ultima = min(corpus.rows, key=lambda r: (r["priority"], r["id"]))

    async def _nu_lista(*a, **k):
        raise AssertionError("detaliul cauta inca printr-o lista taiata")

    monkeypatch.setattr(views.findings_repo, "list_open", _nu_lista)
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, [str(ultima["id"])])))
    assert f"#{ultima['id']}" in msg.sent[0]


def test_un_id_inexistent_si_unul_rezolvat_sunt_doua_raspunsuri(monkeypatch):
    """„Inexistenta sau deja rezolvata" amesteca doua fapte diferite.

    Operatorul care tocmai a cerut un plan pentru ea are nevoie de al doilea:
    „s-a reparat" inchide intrebarea, „nu exista" inseamna ca a citit gresit
    id-ul.
    """
    _Findings([{**_FINDING, "id": 42, "status": "resolved"}]).install(monkeypatch)

    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["42"])))
    rezolvata = msg.sent[0]
    assert "Nu mai e deschisă (stare: resolved)" in rezolvata
    assert "/planifica" not in rezolvata, (
        "se ofera un plan pentru ceva ce scanarea nu mai vede")

    upd2, msg2 = _update()
    run(views.cmd_vuln(upd2, _ctx(None, ["99999"])))
    assert "nu există" in msg2.sent[0]
    assert "nu există" not in rezolvata


def test_detaliul_spune_pe_ce_sta(monkeypatch):
    """Si in detaliu, nu doar in lista: `openssl` intr-o imagine si `openssl` pe
    gazda cer reparatii diferite (reconstructie de imagine vs `dnf update`)."""
    _Findings([{**_FINDING, "id": 7, "scanner": "trivy_image",
                "location": "docker.n8n.io/n8nio/n8n"}]).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["7"])))
    assert "Container · docker.n8n.io/n8nio/n8n" in msg.sent[0]


def test_detaliul_nu_e_inecat_de_o_locatie_uriasa(monkeypatch):
    """O `location` de cateva mii de caractere nu are voie sa impinga afara
    restul detaliului.

    `clamp` taie de la coada, iar coada e exact ce trebuie: legaturile catre
    NVD si Red Hat, si linia care spune cum se cere un plan. O eticheta
    nemarginita lasa in mesaj un singur rand — cel scris de scaner.
    """
    _Findings([{**_FINDING, "id": 42, "scanner": "trivy_image",
                "location": "registry.test/" + "n" * 5000}]).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["42"])))
    text = msg.sent[0]

    assert "n" * 200 not in text, "eticheta a intrat netaiata"
    assert "nvd.nist.gov" in text, "legaturile au fost impinse afara din mesaj"
    assert "/planifica 42" in text, "oferta de plan a fost impinsa afara"
    assert _u16(text) <= views.MAX_MESSAGE


def test_o_categorie_pe_care_clasificatorul_n_o_mai_produce_e_spusa(monkeypatch):
    """Aliasul duce la o categorie pe care `subject.categories` n-o mai da.

    Nu se poate intampla azi — `KINDS` le acopera pe toate — si tocmai de-aia
    linia defensiva era invizibila pentru suita: stearsa, nimeni n-ar fi
    observat, iar efectul stergerii ar fi 1055 de randuri aratate sub eticheta
    unei categorii anume, fara un cuvant ca filtrul n-a fost aplicat.
    """
    from sentinel.scan import subject

    corpus = _productie().install(monkeypatch)
    intregi = views.categories
    monkeypatch.setattr(
        views, "categories",
        lambda counts: [c for c in intregi(counts) if c.kind != subject.KIND_OS])

    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, ["sistem"])))
    text = msg.sent[0]

    assert "Categoria cerută nu mai există" in text, text[:200]
    assert corpus.calls[-1]["scanners"] is None, (
        "s-a filtrat pe o categorie despre care tocmai s-a spus ca nu exista")


def test_detaliul_pastreaza_epss(monkeypatch):
    """EPSS era pe ecran cand randul venea din `list_open`.

    `get_finding` selecteaza coloane pe nume: una uitata nu da eroare, doar
    dispare din mesaj. EPSS e cifra care spune cat de probabil e sa fie
    exploatata, adica de ce se uita cineva la ea inaintea alteia.
    """
    _Findings([{**_FINDING, "epss": 0.42}]).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["42"])))
    assert "EPSS 42%" in msg.sent[0]


def test_a_finding_without_a_fix_does_not_offer_a_patch_plan(monkeypatch):
    """The planner refuses these anyway; offering the command would spend a
    model call to be told no."""
    _Findings([{**_FINDING, "fixed_version": None}]).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["42"])))
    assert "/patch 42" not in msg.sent[0]
    assert "nu se poate genera" in msg.sent[0]


def test_vuln_detail_points_at_planifica_not_at_patch(monkeypatch):
    """`/patch <id>` citește id-uri de PLAN; aici id-ul e al unei
    VULNERABILITĂȚI. Măsurat pe gazda de producție pe 15 septembrie 2026: 4
    planuri, cu id-urile 2-5, și findinguri cu id-uri de la 1 la 29 434, dintre
    care exact 4 cad în intervalul 2-5. Linia asta trimitea deci operatorul fie
    la «Plan inexistent.», fie — pentru patru vulnerabilități — la planul
    ALTCUIVA, cu butoanele lui de aprobare, pentru alt pachet și alt asset.
    """
    _Findings([_FINDING]).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["42"])))
    text = msg.sent[0]
    assert "/planifica 42" in text, (
        "detaliul unei vulnerabilități nu mai spune cum se cere un plan pentru ea")
    assert "/patch" not in text, (
        "id-ul unei vulnerabilități e oferit unei comenzi care caută planuri: "
        f"{text!r}")


def test_vuln_detail_carries_all_three_sources(monkeypatch):
    _Findings([{**_FINDING, "kev": True}]).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["42"])))
    text = msg.sent[0]
    assert "access.redhat.com" in text and "nvd.nist.gov" in text and "cisa.gov" in text


def test_vuln_without_an_id_explains_itself(monkeypatch):
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, [])))
    assert "/vuln" in msg.sent[0]


# --- events -----------------------------------------------------------------
def test_events_filtered_by_ip_offers_the_block_command(monkeypatch):
    monkeypatch.setattr(views.events_repo, "summary", _async({"total": 0}))
    monkeypatch.setattr(views.events_repo, "recent", _async([
        {"ts": NOW, "source": "sshd", "action": "auth_fail",
         "src_ip": "203.0.113.9", "username": "root"}]))
    upd, msg = _update()
    run(views.cmd_events(upd, _ctx(None, ["203.0.113.9"])))
    assert "/block 203.0.113.9" in msg.sent[0]


def test_a_non_ip_argument_is_not_treated_as_a_filter(monkeypatch):
    """`/events '; DROP TABLE` must not reach a query as an address."""
    seen = {}

    async def _recent(db, **kw):
        seen.update(kw)
        return []

    monkeypatch.setattr(views.events_repo, "summary", _async({"total": 0}))
    monkeypatch.setattr(views.events_repo, "recent", _recent)
    upd, msg = _update()
    run(views.cmd_events(upd, _ctx(None, ["'; DROP TABLE raw_events --"])))
    assert seen["src_ip"] is None


@pytest.mark.parametrize("value,ok", [
    ("203.0.113.9", True), ("2001:db8::1", True),
    ("nu-i ip", False), ("", False), ("203.0.113.9; rm -rf /", False),
])
def test_ip_detection(value, ok):
    assert views._looks_like_ip(value) is ok


# --- autoverificare ---------------------------------------------------------
# Panoul spunea „33 verificări" din `selfcheck_runs` și desena linia roșie din
# `selfcheck_state`. Cele două tabele au divergat, iar cusătura vizibilă a fost
# 33 față de 34: un rând pe care nicio rulare nu-l mai producea de 26 de ore
# ținea antetul roșu peste 317 rulări verzi. Un ecran care se contrazice singur
# e mai rău decât unul care tace.
class _SelfcheckDB:
    def __init__(self, rows, *, checks_run=99, duration_ms=710, previous_run=None):
        self.rows = rows
        self.runs = [{"started_at": NOW, "worst_status": "ok",
                      "checks_run": checks_run, "checks_bad": 0,
                      "duration_ms": duration_ms}]
        if previous_run is not None:
            self.runs.append({"started_at": NOW, "worst_status": "ok",
                              "checks_run": previous_run, "checks_bad": 0,
                              "duration_ms": duration_ms})

    async def fetch(self, sql, *a):
        if "selfcheck_state" in sql:
            return self.rows
        return self.runs if "selfcheck_runs" in sql else []


def _state_row(key, status, title, *, stale=False, detail="", since=None):
    return {"key": key, "status": status, "title": title, "detail": detail,
            "since": since or NOW, "stale": stale}


def _selfcheck(rows, **kw):
    upd, msg = _update()
    run(views.cmd_selfcheck(upd, _ctx(_SelfcheckDB(rows, **kw))))
    return msg.sent[0]


def test_selfcheck_counts_the_rows_it_shows(monkeypatch):
    """Antetul și corpul trebuie să vină din același loc.

    Cu numărul luat din tabela de rulări și rândurile din tabela de stare, cele
    două pot spune lucruri diferite despre același moment — și au făcut-o timp
    de o zi și două ore, fără ca nimic să semnaleze diferența."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    rows = [_state_row(f"ok:{i}", "ok", f"Verificarea {i}") for i in range(34)]
    text = _selfcheck(rows, checks_run=33)
    assert "34 verificări" in text
    assert "33 verificări" not in text
    assert "În regulă (34)" in text


def test_a_check_that_could_not_look_is_not_reported_as_fine(monkeypatch):
    """Un rând `unknown` nu apărea nici la defecte, nici la „În regulă" — deci
    nu apărea deloc, iar operatorul citea un panou care nu-l pomenea. O
    verificare care n-a putut citi ce-i trebuie nu e o verificare trecută."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    text = _selfcheck([
        _state_row("ok:1", "ok", "Baza de date"),
        _state_row("nft:table", "unknown", "Nu pot citi regulile nftables",
                   detail="nu știu dacă blocarea funcționează sau nu"),
    ])
    assert "Nu pot citi regulile nftables" in text
    assert "nu tot s-a putut verifica" in text
    assert "Totul funcționează" not in text
    assert "În regulă (1)" in text


def test_an_old_row_says_its_age_is_the_age_of_the_finding(monkeypatch):
    """„de 27h 54m" lângă „🔴 Toate sursele au amuțit" se citește ca durata
    penei. Era vechimea unui rând pe care nimeni nu-l mai reevalua."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    old = NOW - timedelta(hours=27, minutes=54)
    text = _selfcheck([
        _state_row("ok:1", "ok", "Baza de date"),
        _state_row("ingest:all", "down", "Toate sursele au amuțit",
                   stale=True, since=old),
    ])
    assert "constatare veche de 27h 54m" in text
    assert "ultima constatare, nu starea de acum" in text
    assert "1 verificări · " in text and "1 neevaluate" in text


def test_an_empty_state_table_is_not_good_news(monkeypatch):
    """Zero rânduri înseamnă că nu se știe nimic, nu că e totul bine."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    text = _selfcheck([])
    assert "Nu știu dacă Sentinel funcționează" in text
    assert "Totul funcționează" not in text


def test_fewer_checks_than_last_time_is_said_out_loud(monkeypatch):
    """Acoperire pierdută în tăcere.

    O sursă care tace peste fereastra de 30 de zile a colectorului iese din
    interogare, iar dacă rândul ei era verde nimic nu anunță retragerea: panoul
    numără pur și simplu o verificare mai puțin decât ieri. Măsurat pe gazdă,
    `su` are un singur eveniment vechi de 7 zile — deci se întâmplă, cu dată
    cunoscută, dacă nimeni nu rulează `su`."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    rows = [_state_row(f"ok:{i}", "ok", f"Verificarea {i}") for i in range(32)]
    text = _selfcheck(rows, checks_run=32, previous_run=33)
    assert "cu 1 verificări mai puțin" in text
    assert "(33 → 32)" in text


def test_the_same_number_of_checks_says_nothing(monkeypatch):
    """Linia de mai sus apare doar când numărul chiar scade. O notă la fiecare
    rulare ar fi zgomot pe care operatorul învață să-l sară."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    rows = [_state_row(f"ok:{i}", "ok", f"Verificarea {i}") for i in range(33)]
    assert "mai puțin" not in _selfcheck(rows, checks_run=33, previous_run=33)
    # Și nici când crește.
    assert "mai puțin" not in _selfcheck(rows, checks_run=33, previous_run=32)


# --- registration -----------------------------------------------------------
# Cele patru teste de mai jos citeau TEXTUL SURSĂ al lui `build_application`,
# fiindcă acolo stăteau tabelele de comenzi. De când din același tabel se derivă
# și meniul publicat la Telegram, tabelele sunt la nivel de modul, iar testele
# citesc structura — care e și ce se înregistrează de fapt. Un `'"nume"' in src`
# trecea oricum și dacă numele apărea doar într-un comentariu.
def _names() -> set[str]:
    from sentinel.telegram import bot

    return {n for c in bot.COMMANDS for n in c.names}


def test_every_web_page_has_a_command():
    """The point of the exercise: nothing the dashboard shows should be
    reachable only from a browser."""
    names = _names()
    for name in ("dashboard", "incidente", "vulnerabilitati", "evenimente",
                 "servicii", "blocate", "patchuri"):
        assert name in names, f"no command for {name}"


def test_commands_have_romanian_names():
    """The interface language is Romanian. `/incidents` working and
    `/incidente` not is the kind of detail that makes a tool feel foreign."""
    names = _names()
    for ro, en in (("incidente", "incidents"), ("servicii", "services"),
                   ("evenimente", "events"), ("rezolva", "resolve")):
        assert ro in names and en in names


# Validarea numelor de comenzi s-a mutat în
# `tests/security/test_telegram_command_names.py`.
#
# Testul care stătea aici extrăgea numele cu două expresii regulate —
# `\("([^"]+)"` pentru primul alias și `"([^"]+)"\)` pentru ultimul. Aliasul din
# MIJLOCUL unui tuplu de trei nu era prins de niciuna, iar acolo era exact
# `(("stiu", "știu", "ack"), ...)`: testul a trecut verde pe codul care a doborât
# botul pentru o zi. Docstring-ul lui afirma totuși că validează toate numele.
#
# Nu l-am reparat, l-am înlocuit. Două teste care afirmă același lucru, unul cu
# punct orb, sunt mai rele decât unul corect: al doilea dă încrederea pe care
# primul n-o merită. Cel nou citește AST-ul și acoperă și înregistrările directe
# prin `CommandHandler(...)`, în afara tabelelor.


def test_help_lists_what_is_registered():
    """A help text that drifts from the handlers is worse than none."""
    registered = _names()
    checked = 0
    for line in views.HELP.splitlines():
        if not line.startswith("/"):
            continue
        name = line.split()[0].lstrip("/").split("&")[0].strip()
        assert name in registered, f"/{name} is in the help text but not registered"
        checked += 1
    # Fără asta, o schimbare de format în HELP ar goli bucla și testul ar trece
    # verde fără să compare nimic — tiparul „listă parametrizată ieșită goală".
    assert checked >= 15, f"am verificat doar {checked} comenzi din textul de ajutor"


def test_read_only_commands_are_separated_from_acting_ones():
    """Not cosmetic: the acting ones each re-check the operator role, and the
    split is what makes it obvious which ones must."""
    from sentinel.telegram import bot

    read_only = {n for c in bot.READ_ONLY for n in c.names}
    acting = {n for c in bot.ACTING for n in c.names}

    assert read_only and acting
    for name in ("block", "unblock", "panic", "resolve", "rezolva", "stiu", "mute"):
        assert name in acting, f"/{name} nu mai e în lista care verifică rolul"
        assert name not in read_only, f"/{name} a ajuns printre comenzile de citire"
    # Fiecare comandă e într-una singură dintre liste, și amândouă ajung în tabel.
    assert not (read_only & acting)
    assert read_only | acting == {n for c in bot.COMMANDS for n in c.names}
