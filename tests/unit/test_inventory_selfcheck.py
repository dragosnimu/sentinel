"""`check_inventory` — starea în care nu se poate ști ce ar trebui supravegheat.

Perechea, în autoverificare, a anunțului de retragere din `health_service`.
Retragerea e un EVENIMENT: se întâmplă o dată per editare și se spune o dată,
pe nume, acolo. Aici e STAREA de dedesubt, iar ea are nevoie de alt mecanism
dintr-un motiv concret: `sync` refuză să retragă ceva pe o listă goală — un
fișier trunchiat ar stinge altfel toate sondele gazdei deodată — și raportează
refuzul la FIECARE trecere, din 30 în 30 de secunde. Ca notificare ar fi 2880
de mesaje pe zi; ca linie de jurnal e exact locul în care cele patru servicii
roșii au stat optsprezece zile. Detecția de schimbare din `selfcheck/runner.py`
e ce transformă o stare care persistă într-un singur mesaj.

Panele pe care le previn testele de aici:

  * **Un `inventory.yaml` golit, cu sondele mergând mai departe.** Fișierul care
    decide ce se supraveghează nu mai confirmă niciun activ, iar supravegherea
    continuă pe o listă pe care o mai ține doar baza de date. Nimic pe gazdă nu
    arată altfel; fără verificarea asta nimic n-o spune.
  * **O instalare nouă raportată ca defect.** Un fișier gol pe o gazdă fără
    active e starea validă a unei instalări noi, iar o alarmă acolo e zgomotul
    care antrenează reflexul de a nu mai citi.
  * **Un YAML stricat înghițit.** `health_service` prinde excepția și sondează
    mai departe, deci nimic vizibil nu se schimbă când fișierul încetează să se
    mai aplice.
  * **O verificare care nu e în `CHECKS`.** Nu rulează niciodată, și absența ei
    se citește ca „nimic de raportat".
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sentinel.scan import inventory
from sentinel.selfcheck import checks

T0 = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


def _rand(i: int) -> dict:
    """Un rând de activ cu toate coloanele pe care le cere `_row_to_asset`."""
    return {
        "id": i + 1, "name": f"activ{i}", "kind": "service", "bind_addr": None,
        "port": 22, "is_internet_exposed": False, "criticality": 3,
        "systemd_unit": None, "container_id": None, "container_image": None,
        "vhost_file": None, "webroot": None, "stack": None, "databases": [],
        "protected": False, "confirmed_by_operator": False, "tags": [],
        "notes": None, "first_seen": T0, "last_seen": T0, "retired_at": None,
    }


class _DB:
    """Baza, cu atâtea active încă nesondate câte i se cer."""

    def __init__(self, active: int) -> None:
        self.active = active
        self.statements: list[str] = []

    async def fetch(self, sql: str, *args):
        self.statements.append(sql)
        assert "FROM assets" in sql, f"interogare neașteptată:\n{sql}"
        # Discriminatorul verificării e câte active sunt ÎNCĂ sondate. Dacă ar
        # număra și retrasele, o gazdă curățată corect ar apărea permanent
        # degradată.
        assert "retired_at IS NULL" in sql, (
            "verificarea numără și activele retrase, deci nu mai deosebește "
            "o instalare nouă de un fișier trunchiat")
        return [_rand(i) for i in range(self.active)]


def _inventar(monkeypatch, tmp_path, text: str):
    """Scrie fișierul și îl pune în locul celui din /etc.

    Se schimbă `inventory.INVENTORY_PATH`, nu variabila de mediu: verificarea
    citește constanta la fiecare rulare, exact ca să poată fi mutată de aici.
    """
    p = tmp_path / "inventory.yaml"
    p.write_text(text, encoding="utf-8")
    monkeypatch.setattr(inventory, "INVENTORY_PATH", p)
    return p


def test_an_emptied_inventory_with_live_assets_is_reported(monkeypatch, tmp_path):
    """Fișierul care decide ce se supraveghează nu mai confirmă nimic — și sondele merg.

    Pana pe care o previne: `inventory.yaml` golit de o editare eșuată sau de un
    disc plin. `sync` nu retrage nimic — corect, altfel ar stinge toate sondele
    deodată — și raportează asta ca `retire_skipped` la fiecare trecere, într-un
    jurnal. Panoul rămâne verde, sondele merg pe o listă pe care doar baza o mai
    ține, iar operatorul află abia când încearcă să adauge ceva în fișier și nu
    se întâmplă nimic.
    """
    _inventar(monkeypatch, tmp_path, "assets: []\n")

    (r,) = run(checks.check_inventory(_DB(active=11)))

    assert r.key == "inventory:assets"
    assert r.status == "degraded", (
        f"starea „nu se poate ști ce se supraveghează” a ieșit pe `{r.status}`; "
        f"doar `down` și `degraded` ajung la operator")
    assert r.bad, "constatarea nu e considerată defect, deci nu declanșează niciun mesaj"
    assert r.facts["active_in_fisier"] == 0
    assert r.facts["active_in_baza"] == 11
    assert "11" in r.detail
    assert r.action, "constatarea nu spune ce e de făcut"


def test_an_empty_inventory_on_a_host_with_no_assets_is_not_a_fault(
        monkeypatch, tmp_path):
    """O instalare nouă nu are voie să sune ca un fișier trunchiat.

    Pana pe care o previne: o alarmă permanentă pe o gazdă proaspăt instalată,
    unde fișierul gol e starea validă și documentată (vezi `inventory.load`).
    Alarma aia n-are cum să fie stinsă de nimic din ce face operatorul în ziua
    aia, și fix așa se pierde obiceiul de a citi galbenul.
    """
    _inventar(monkeypatch, tmp_path, "assets: []\n")

    (r,) = run(checks.check_inventory(_DB(active=0)))

    assert r.status == "ok", f"o instalare nouă a fost raportată ca defect: {r.detail}"
    assert not r.bad
    assert r.facts["active_in_baza"] == 0


def test_a_populated_inventory_is_ok_and_says_both_numbers(monkeypatch, tmp_path):
    """Cheia trebuie emisă și când e bine, altfel runner-ul o retrage din tabel.

    Pana pe care o previne: `selfcheck/runner.py` șterge din `selfcheck_state`
    cheile pe care o rulare completă nu le-a produs. O verificare care tace când
    e bine își retrage propria constatare și îi anunță operatorului o „nu se mai
    raportează" pentru un neeveniment — zgomot pentru nimic.
    """
    _inventar(monkeypatch, tmp_path,
              "assets:\n  - name: sshd\n    kind: service\n    port: 22\n")

    (r,) = run(checks.check_inventory(_DB(active=1)))

    assert r.key == "inventory:assets"
    assert r.status == "ok"
    assert r.facts["active_in_fisier"] == 1
    assert r.facts["active_in_baza"] == 1


def test_an_unparseable_inventory_is_reported_instead_of_swallowed(
        monkeypatch, tmp_path):
    """Un fișier care nu se încarcă încetează să se aplice, fără să se vadă nimic.

    Pana pe care o previne: `health_service` prinde excepția, o scrie în jurnal
    și sondează mai departe activele pe care le are deja. Comportamentul e
    corect — dar de afară gazda arată identic cu una sănătoasă: nimic nu e roșu,
    nimic nu lipsește, doar că nici o adăugare și nici o scoatere din fișier nu
    mai are efect, la nesfârșit.
    """
    _inventar(monkeypatch, tmp_path, "assets: [unu")

    (r,) = run(checks.check_inventory(_DB(active=4)))

    assert r.status == "degraded", (
        f"un inventar care nu se încarcă a ieșit pe `{r.status}`")
    assert r.facts["citit"] is False, (
        "verificarea pretinde că a citit un fișier pe care nu l-a putut încărca")
    assert r.action


def test_the_check_is_registered_so_it_actually_runs():
    """O verificare care nu e în `CHECKS` nu rulează niciodată.

    Pana pe care o previne: tot codul de mai sus există, e testat, și nu se
    execută pe gazdă nici o dată. Absența unei chei din `selfcheck_state` se
    citește ca „nimic de raportat" — adică exact minciuna pe care verificarea a
    fost scrisă s-o prevină.
    """
    assert ("inventory", checks.check_inventory) in checks.CHECKS
