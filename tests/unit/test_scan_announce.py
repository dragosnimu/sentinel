"""Anunțul de vulnerabilități noi: forma mesajului și când NU pleacă.

Eșecul pe care îl previne, în ansamblu: o scanare descoperă douăzeci de CVE-uri
exploatate activ și nimeni nu află până când cineva deschide panoul din proprie
inițiativă. Până pe 21 august 2026 exact asta se întâmpla — orchestratorul nu
atingea Telegram deloc, iar singura urmă era o linie `INFO` în jurnal.

Mesajul se probează prin `build_message`, care e o funcție PURĂ. Separarea nu e
de stil: forma unui mesaj e ce citește operatorul la 3 dimineața, iar un test
care are nevoie de un bot ca să verifice o virgulă nu se scrie niciodată.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from sentinel.scan import announce, orchestrator


def run(coro):
    """Aceeasi forma ca in `test_shipper.py`: `pytest-asyncio` nu e
    configurat in depozit, iar un test care depinde de un plugin absent
    e un test care nu ruleaza."""
    return asyncio.run(coro)


def _finding(**over):
    base = {
        "cve": "CVE-2026-0001", "severity": "high", "package": "openssl",
        "installed_version": "3.0.1", "fixed_version": "3.0.2",
        "kev": False, "priority": 50,
    }
    base.update(over)
    return base


def _working_channel(monkeypatch) -> list[str]:
    """Un canal Telegram care CHIAR ar livra, plus urma apelului.

    Fara asta, un test care cere `0` trece si cand garda a cazut: in mediul de
    test nu exista token, deci `announce` intoarce `0` din alt motiv, iar cele
    doua cazuri arata identic. Verificat prin falsificare pe 21 august 2026 —
    mutatia care ignora complet comutatorul NU a fost prinsa pana n-a existat
    functia asta.
    """
    calls: list[str] = []

    async def fake_send(token, chats, text, **kw):
        calls.append(text)
        return [SimpleNamespace(chat_id=c, ok=True, describe=lambda: "ok")
                for c in chats]

    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: {"TELEGRAM_BOT_TOKEN": "t"})
    monkeypatch.setattr("sentinel.telegram.direct.send_to_chats", fake_send)
    return calls


def test_the_exploited_ones_come_first_whatever_their_priority() -> None:
    """Dacă din tot mesajul se citește un singur rând, ăla trebuie să fie cel
    care se exploatează ACUM.

    Fixtura e construită împotriva unui scor combinat: constatarea KEV are
    prioritatea cea MAI MICĂ. Sortată pe un singur număr, ar ajunge ultima.
    """
    items = [
        _finding(cve="CVE-BANAL", priority=99, kev=False),
        _finding(cve="CVE-EXPLOATAT", priority=1, kev=True),
    ]
    message = announce.build_message(items, host="gazda")
    assert message.index("CVE-EXPLOATAT") < message.index("CVE-BANAL"), (
        "o constatare exploatată activ a ajuns sub una banală cu prioritate mare")
    # Numărul KEV e în TITLU: e singura cifră care schimbă ce face operatorul în
    # următoarele minute, iar îngropată în listă nu se vede pe un ecran de telefon.
    assert "1 se exploatează activ" in message


def test_a_long_scan_does_not_produce_an_unbounded_message() -> None:
    """Telegram taie mesajele lungi, iar ce se pierde e COADA — adică exact
    numărul total, care e informația cea mai importantă când sunt multe.

    Mărginit aici, coada e numărul, iar lista e vârful.
    """
    items = [_finding(cve=f"CVE-{i:04d}", priority=i) for i in range(40)]
    message = announce.build_message(items, host="gazda")

    listed = sum(1 for line in message.splitlines() if line.startswith(("•", "🔴")))
    assert listed == announce.MAX_LISTED, (
        f"{listed} constatări enumerate, plafonul e {announce.MAX_LISTED}")
    assert "40 vulnerabilități noi" in message, "totalul nu apare în titlu"
    assert f"încă {40 - announce.MAX_LISTED}" in message, (
        "restul nu e numărat, deci mesajul pare complet când nu e")


def test_a_package_name_with_markup_cannot_break_the_message() -> None:
    """Un `<` netratat rupe mesajul întreg și Telegram răspunde cu 400 — alarma
    s-ar pierde din cauza unui caracter dintr-un nume de pachet.

    Valorile vin din ieșirea unui scaner: nu din trafic, dar nici scrise de noi.
    """
    message = announce.build_message(
        [_finding(package="lib<script>x", cve="CVE-A&B")], host="gazda")
    assert "<script>" not in message
    assert "lib&lt;script&gt;x" in message
    assert "CVE-A&amp;B" in message


def test_an_unreadable_priority_is_not_treated_as_zero() -> None:
    """Zero ar trimite constatarea la coada listei ca și cum ar fi fost evaluată
    și găsită neimportantă. Se ridică la mijloc, ca să fie văzută și corectată.
    """
    assert announce._rank(_finding(priority=None)) == (0, 50)
    assert announce._rank(_finding(priority="nu-e-numar")) == (0, 50)
    assert announce._rank(_finding(priority=7)) == (0, 7)
    assert announce._rank(_finding(priority=7, kev=True)) == (1, 7)


def test_nothing_new_sends_nothing(monkeypatch) -> None:
    """O scanare care regăsește aceleași două sute de constatări nu trimite
    nimic. Un canal care repetă aceeași listă la fiecare rulare e unul pe care
    operatorul îl oprește — și atunci se pierde și alarma care conta.

    Canalul e funcțional dinadins: altfel `0` ar putea veni din lipsa tokenului.
    """
    calls = _working_channel(monkeypatch)
    cfg = SimpleNamespace(scan=SimpleNamespace(announce_new=True),
                          telegram=SimpleNamespace(allowed_chat_ids=[1]),
                          hostname="gazda")
    assert run(announce.announce(cfg, [])) == 0
    assert calls == [], "a plecat un mesaj fara nicio constatare noua"


def test_the_switch_is_obeyed(monkeypatch) -> None:
    """`scan.announce_new: false` chiar oprește canalul, cu constatări reale în
    mână ȘI cu un Telegram funcțional în spate.

    Canalul funcțional e tot testul: cu unul nefuncțional, `0` s-ar întoarce din
    lipsa tokenului, iar comutatorul ar putea fi ignorat complet fără ca nimeni
    să observe. Exact asta s-a întâmplat la prima falsificare.
    """
    calls = _working_channel(monkeypatch)
    cfg = SimpleNamespace(scan=SimpleNamespace(announce_new=False),
                          telegram=SimpleNamespace(allowed_chat_ids=[1]),
                          hostname="gazda")
    assert run(announce.announce(cfg, [_finding()])) == 0
    assert calls == [], "comutatorul e pe `false`, dar mesajul a plecat oricum"


def test_a_broken_telegram_does_not_fail_the_scan(monkeypatch) -> None:
    """Un anunț care oprește scanarea ar transforma un canal de informare
    într-un mod de eșec. Scanarea e treaba; anunțul e despre ea.
    """
    def boom(*_a, **_k):
        raise RuntimeError("rețeaua a căzut")

    monkeypatch.setattr("sentinel.config.get_secrets", boom)
    cfg = SimpleNamespace(scan=SimpleNamespace(announce_new=True),
                          telegram=SimpleNamespace(allowed_chat_ids=[1]))
    assert run(announce.announce(cfg, [_finding()])) == 0


def test_delivery_is_counted_per_chat_not_by_absence_of_an_exception(
        monkeypatch) -> None:
    """Un 400 de la Telegram — „chat not found", „bot was blocked by the user" —
    arată exact ca un succes dacă te uiți doar la faptul că apelul s-a întors.

    Aceeași regulă ca la alerta directă a autoverificării, și pentru același
    motiv: canalul ăsta e cel care trebuie să funcționeze când restul nu.
    """
    sent = {}

    async def fake_send(token, chats, text, **kw):
        sent["text"] = text
        return [SimpleNamespace(chat_id=1, ok=True, describe=lambda: "1 ok"),
                SimpleNamespace(chat_id=2, ok=False, describe=lambda: "2: blocat")]

    monkeypatch.setattr("sentinel.config.get_secrets", lambda: {"TELEGRAM_BOT_TOKEN": "t"})
    monkeypatch.setattr("sentinel.telegram.direct.send_to_chats", fake_send)

    cfg = SimpleNamespace(scan=SimpleNamespace(announce_new=True),
                          telegram=SimpleNamespace(allowed_chat_ids=[1, 2]),
                          hostname="gazda")
    delivered = run(announce.announce(cfg, [_finding(cve="CVE-X")]))
    assert delivered == 1, "un chat care a refuzat mesajul a fost numărat ca livrare"
    assert "CVE-X" in sent["text"]

# ---------------------------------------------------------------------------
# Cablajul. Un modul de anunt pe care nu-l cheama nimeni e chiar tiparul din
# `CLAUDE.md`: fisierul e pe disc, testele lui trec, si nu pleaca niciun mesaj.
# ---------------------------------------------------------------------------

def _wire(monkeypatch, results: dict) -> list[list[dict]]:
    """Inlocuieste scanerele si anuntul; intoarce loturile trimise la anunt."""
    sent: list[list[dict]] = []

    async def fake_announce(cfg, findings):
        sent.append(list(findings))
        return 1

    async def fake_kev(_db):
        return None

    async def fake_dnf(_db, _triggered_by):
        return results.get("dnf", {})

    async def fake_trivy(_db, _cfg, _triggered_by):
        return results.get("trivy_fs", {})

    async def fake_plans(_db, _cfg):
        return results.get("patch_plans", {})

    monkeypatch.setattr("sentinel.intel.kev.refresh", fake_kev)
    monkeypatch.setattr(orchestrator, "_run_os_packages", fake_dnf)
    monkeypatch.setattr(orchestrator, "_run_trivy_fs", fake_trivy)
    monkeypatch.setattr(orchestrator, "_draft_plans", fake_plans)
    monkeypatch.setattr(orchestrator.announce, "announce", fake_announce)
    return sent


def _cfg(**over):
    base = SimpleNamespace(
        # `filesystem` e scris explicit, chiar si cand e oprit: `run_all` il
        # citeste, iar un ciot caruia ii lipseste un steag pe care codul il
        # citeste nu esueaza pe „scanerul n-a rulat" — esueaza pe AttributeError,
        # adica pe altceva decat ce masoara testul.
        scan=SimpleNamespace(enabled=True, os_packages=True, filesystem=False,
                             announce_new=True),
        telegram=SimpleNamespace(allowed_chat_ids=[1]), hostname="gazda")
    for k, v in over.items():
        setattr(base.scan, k, v)
    return base


def test_a_scan_that_finds_something_new_actually_reaches_the_announcer(
        monkeypatch) -> None:
    """Cablajul, nu mesajul.

    Esecul pe care il previne: `announce.py` exista, testele lui trec, si niciun
    mesaj nu pleaca vreodata fiindca `run_all` nu-l cheama. Exact forma din
    tabelul lui `CLAUDE.md` — fisierul pe disc nu e dovada ca a fost incarcat.
    """
    item = _finding(cve="CVE-NOUA")
    sent = _wire(monkeypatch, {"dnf": {"new": 1, "new_items": [item]}})
    summary = run(orchestrator.run_all(object(), _cfg()))

    assert sent == [[item]], "constatarea noua n-a ajuns la anunt"
    assert summary["announced"] == {"chats": 1, "findings": 1}


def test_two_scanners_produce_one_message_not_two(monkeypatch) -> None:
    """Un operator cu trei scanere ar primi trei mesaje pentru aceeasi rulare,
    iar al treilea l-ar face sa opreasca notificarile — si atunci se pierde si
    alarma care conta.

    Fixtura pune constatari noi pe DOUA rezultate din sumar deodata.
    """
    a, b = _finding(cve="CVE-A"), _finding(cve="CVE-B")
    sent = _wire(monkeypatch, {"dnf": {"new_items": [a]},
                               "patch_plans": {"new_items": [b]}})
    run(orchestrator.run_all(object(), _cfg()))

    assert len(sent) == 1, f"{len(sent)} mesaje pentru o singura rulare"
    assert sent[0] == [a, b], "constatarile n-au fost adunate din ambele scanere"


def test_the_filesystem_scanner_reaches_the_same_single_announcement(
        monkeypatch) -> None:
    """Al doilea scaner real intra in acelasi mesaj, nu intr-al lui.

    Esecul pe care il previne: `trivy_fs` cablat in `run_all` fara sa fie cules
    de bucla de anunt — constatarile lui ar intra in baza si n-ar spune nimanui
    nimic, exact pana cand cineva deschide panoul. Sau, in cealalta directie,
    culese de un al doilea apel la `announce`: doua mesaje pentru o rulare, si
    operatorul opreste canalul.
    """
    a, b = _finding(cve="CVE-DNF"), _finding(cve="CVE-TRIVY")
    sent = _wire(monkeypatch, {"dnf": {"new_items": [a]},
                               "trivy_fs": {"new_items": [b]}})
    run(orchestrator.run_all(object(), _cfg(filesystem=True)))

    assert len(sent) == 1, f"{len(sent)} mesaje pentru o singura rulare"
    assert sent[0] == [a, b], "constatarile lui trivy n-au ajuns in anunt"


def test_a_scanner_that_reports_no_new_items_does_not_break_the_scan(
        monkeypatch) -> None:
    """Un scaner mai vechi, sau unul adaugat maine, care nu raporteaza deloc
    cheia `new_items`: scanarea merge mai departe si nu pleaca niciun anunt.
    """
    sent = _wire(monkeypatch, {"dnf": {"status": "completed", "findings": 12}})
    summary = run(orchestrator.run_all(object(), _cfg()))

    assert sent == [], "a plecat un anunt fara nicio constatare noua"
    assert "announced" not in summary
    assert summary["dnf"]["findings"] == 12, "scanarea n-a mai ajuns in sumar"


def test_scanning_disabled_never_touches_the_announcer(monkeypatch) -> None:
    """`scan.enabled: false` iese inaintea oricarui scaner. Fara cazul asta,
    o iesire timpurie mutata gresit ar chema anuntul cu un sumar gol."""
    sent = _wire(monkeypatch, {"dnf": {"new_items": [_finding()]}})
    summary = run(orchestrator.run_all(object(), _cfg(enabled=False)))

    assert sent == []
    assert summary == {"skipped": {"reason": "scan disabled"}}
