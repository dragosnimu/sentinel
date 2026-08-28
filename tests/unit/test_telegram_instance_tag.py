"""Fiecare mesaj de pe Telegram spune de pe ce mașină vine.

Eșecul pe care îl previne fișierul ăsta are un nume și o dată: **27 august
2026, două instanțe, opt ore de alerte despre mașina greșită.** Un Sentinel
instalat pe un VM de test a primit tokenul de Telegram al producției. Din 27
august 13:10 până pe 28 la 08:32, două instanțe au trimis alerte în același
chat. Operatorul a primit peste noapte zeci de mesaje ca

    🔴 Colector „sshd" a amuțit · de 4h 1m
    🟡 Servicii care rulează cod vechi · de 16h 5m

adevărate pe VM și false pe producție, și niciunul nu spunea despre care mașină
vorbește. Opt ore a crezut că producția e stricată. În tot timpul ăsta alertele
reale ale producției nu ajungeau nicăieri, fiindcă două lung-polling-uri pe
același token se omoară reciproc la `getUpdates`.

Testele de aici sunt împărțite în trei:

  * **căile** — fiecare drum pe care un mesaj poate ieși din proces ajunge
    numit, inclusiv cele care nu trec prin `_broadcast` și cele care nu trec
    deloc prin bot;
  * **ce scrie** — eticheta goală, identitatea necitibilă, și convenția, care
    trebuie să fie aceeași cu a panoului;
  * **lungimea** — antetul nu are voie să împingă un mesaj peste plafonul
    Telegram, fiindcă un mesaj peste 4096 e refuzat cu 400, adică pierdut.

`python-telegram-bot` nu e dependență de dezvoltare peste tot, deci fișierul se
sare unde lipsește și rulează în CI și pe gazdă, ca `test_telegram_push.py`.
"""

from __future__ import annotations

import asyncio
import datetime
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from telegram import CallbackQuery, Chat, Message, User  # noqa: E402
from telegram.constants import ParseMode  # noqa: E402
from telegram.ext import ExtBot  # noqa: E402

from sentinel.telegram import identity  # noqa: E402
from sentinel.telegram import views  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
ROUTE_TS = REPO / "aggregator" / "app" / "api" / "sentinel" / "check" / "route.ts"

# 32 de hexazecimale, exact ce scrie instalatorul cu `openssl rand -hex 16`.
FULL_ID = "a3f19c2b" + "5d4e" * 6
SHORT = "a3f19c2b"


def run(coro):
    """`pytest-asyncio` nu e configurat în depozit, iar un test care depinde de
    un plugin absent e un test care nu rulează."""
    return asyncio.run(coro)


@pytest.fixture
def identity_on_disk(tmp_path, monkeypatch):
    """O identitate care se poate citi, în locul celei de pe gazdă."""
    path = tmp_path / "instance_id"
    path.write_text(FULL_ID + "\n", encoding="utf-8")
    monkeypatch.setattr("sentinel.identity.INSTANCE_ID_PATH", path)
    return path


@pytest.fixture
def identity_missing(tmp_path, monkeypatch):
    """Fișierul de identitate lipsește — „nu știu", nu „nu e nimic de spus"."""
    monkeypatch.setattr("sentinel.identity.INSTANCE_ID_PATH",
                        tmp_path / "nu-exista" / "instance_id")


@pytest.fixture
def recorded_sends(monkeypatch) -> list[tuple]:
    """Ce a primit `python-telegram-bot`, nu ce credem noi că i-am dat.

    Se înlocuiesc metodele lui `ExtBot`, adică exact stratul de sub
    `StampingBot`: apelul `super()` din suprascriere ajunge aici, deci ce se
    vede în listă e textul cu care ar fi plecat cererea HTTP.
    """
    calls: list[tuple] = []

    async def fake(self, *args, **kwargs):
        calls.append((args, kwargs))
        return "trimis"

    monkeypatch.setattr(ExtBot, "send_message", fake)
    monkeypatch.setattr(ExtBot, "edit_message_text", fake)
    return calls


def _bot(label: str = ""):
    from sentinel.telegram.bot import StampingBot

    # Token deliberat scurt și fără formă de token, ca în
    # tests/security/test_telegram_command_names.py: un șir cu forma unui token
    # într-un depozit public nu se poate deosebi de unul adevărat.
    return StampingBot("0:test", label=label)


def _message(bot) -> Message:
    chat = Chat(id=7, type="private")
    msg = Message(message_id=1, chat=chat,
                  date=datetime.datetime.now(datetime.timezone.utc))
    msg.set_bot(bot)
    return msg


def _texts(calls: list[tuple]) -> list[str]:
    """Textul din fiecare apel, oriunde ar fi stat el în semnătură."""
    out = []
    for args, kwargs in calls:
        if "text" in kwargs:
            out.append(kwargs["text"])
        else:
            # `send_message(chat_id, text, ...)` și `edit_message_text(text, ...)`
            out.append(args[1] if isinstance(args[0], int) else args[0])
    return out


# ---------------------------------------------------------------------------
# Căile
# ---------------------------------------------------------------------------
def test_every_ptb_route_names_the_instance(identity_on_disk, recorded_sends):
    """Cele patru drumuri prin bibliotecă, verificate pe efect, nu pe intenție.

    `StampingBot` există pe premisa că `Message.reply_text`, `reply_html` și
    `CallbackQuery.edit_message_text` ajung toate la două metode ale botului.
    Premisa e o afirmație despre `python-telegram-bot`, nu despre codul nostru,
    deci se verifică: dacă biblioteca schimbă rutarea, jumătate din mesaje ar
    pleca din nou nenumite, iar noi am crede că le-am acoperit.
    """
    bot = _bot("prod")

    async def scenariu():
        await bot.send_message(7, "trimis direct", parse_mode=ParseMode.HTML)
        msg = _message(bot)
        await msg.reply_text("răspuns simplu")
        await msg.reply_html("răspuns html")
        cq = CallbackQuery(id="1", chat_instance="ci", message=msg,
                           from_user=User(id=1, first_name="o", is_bot=False))
        cq.set_bot(bot)
        await cq.edit_message_text("confirmare", parse_mode=ParseMode.HTML)

    run(scenariu())
    texts = _texts(recorded_sends)
    assert len(texts) == 4, "o cale nu a ajuns la bibliotecă deloc"
    for text in texts:
        assert SHORT in text, f"mesaj fără numele instanței: {text!r}"
        assert "prod" in text


def test_the_header_matches_the_parse_mode_of_the_message(
        identity_on_disk, recorded_sends):
    """Un `<i>` într-un mesaj trimis fără `parse_mode` e patru caractere în
    plus în fața alertei, nu cursive.

    Jumătate din răspunsurile din `bot.py` pleacă fără `parse_mode` — „Niciun
    incident deschis", „Anulat." — deci nu e un caz teoretic.
    """
    bot = _bot("prod")

    async def scenariu():
        await bot.send_message(7, "fără markup")
        await bot.send_message(7, "cu markup", parse_mode=ParseMode.HTML)

    run(scenariu())
    plain, html = _texts(recorded_sends)
    assert plain.startswith(f"{identity.PREFIX}prod ({SHORT})\n")
    assert "<i>" not in plain.splitlines()[0]
    assert html.startswith(f"<i>{identity.PREFIX}prod ({SHORT})</i>\n")


def test_broadcast_names_the_instance(identity_on_disk, recorded_sends):
    """Calea pe care au venit alertele din noaptea de 27 august: incidente,
    digest, rezultate de patch și coada generică — toate trec prin
    `_broadcast`."""
    from sentinel.telegram import bot as bot_mod

    app = SimpleNamespace(bot=_bot("prod"))
    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=[7, 8]))
    sent = run(bot_mod._broadcast(app, cfg, "🔴 <b>Colector „sshd\" a amuțit</b>",
                                  severity="critical"))
    assert sent == 2
    for text in _texts(recorded_sends):
        assert text.startswith(f"<i>{identity.PREFIX}prod ({SHORT})</i>\n")
        assert "amuțit" in text


def test_the_patch_plan_push_names_the_instance(
        identity_on_disk, recorded_sends, monkeypatch):
    """Calea despre care comentariul din `_push_plans` spune explicit că NU
    folosește `_broadcast`, fiindcă fiecare chat are nevoie de tokenul lui.

    O cale ratată e chiar mesajul care va confuza data viitoare, iar asta e
    singura care era deja documentată ca ocolind punctul comun.
    """
    from sentinel.db.repo import patches as patches_repo
    from sentinel.telegram import patch_flow

    async def fake_issue(db, **kwargs):
        return "jeton"

    monkeypatch.setattr("sentinel.db.repo.approvals.issue", fake_issue)
    row = patches_repo.PlanRow(
        id=3, plan_id=3, plan_hash="h", plan={"target": {"asset_name": "web"}},
        status="validated", risk_level="low", requires_reboot=False,
        reversible=True, estimated_downtime_s=5, asset_id=1,
        created_at=None, approved_by=None, approved_at=None,
        validation_errors=None)

    run(patch_flow.send_plan_for_approval(_bot("prod"), None, 7, row))
    text = _texts(recorded_sends)[0]
    assert text.startswith(f"<i>{identity.PREFIX}prod ({SHORT})</i>\n")
    assert "Plan de patch #3" in text


def test_the_selfcheck_direct_alert_names_the_instance(
        identity_on_disk, monkeypatch):
    """Mesajul care pleacă TOCMAI fiindcă botul e picat.

    Ocolește procesul botului, deci ocolește și `StampingBot`. E și mesajul cu
    cea mai mare nevoie de nume: sosește când nimic altceva nu merge, iar
    „pe care mașină" e prima întrebare la care trebuie să răspundă.
    """
    from sentinel.selfcheck import runner

    trimise: list[str] = []

    async def fake_send(token, chats, text, **kw):
        trimise.append(text)
        return [SimpleNamespace(chat_id=c, ok=True, describe=lambda: "ok")
                for c in chats]

    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: {"TELEGRAM_BOT_TOKEN": "t"})
    monkeypatch.setattr("sentinel.telegram.direct.send_to_chats", fake_send)
    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=[7]),
                          instance_label="prod")

    run(runner._send_direct(cfg, "🔴 Autoverificarea a găsit ceva"))
    assert trimise, "alerta directă nu a plecat deloc"
    assert trimise[0].startswith(f"<i>{identity.PREFIX}prod ({SHORT})</i>\n")
    assert "botul nu răspunde" in trimise[0]


def test_the_vulnerability_announcement_names_the_instance(
        identity_on_disk, monkeypatch):
    """A doua cale care nu trece prin bot: anunțul de după scanare."""
    from sentinel.scan import announce

    trimise: list[str] = []

    async def fake_send(token, chats, text, **kw):
        trimise.append(text)
        return [SimpleNamespace(chat_id=c, ok=True, describe=lambda: "ok")
                for c in chats]

    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: {"TELEGRAM_BOT_TOKEN": "t"})
    monkeypatch.setattr("sentinel.telegram.direct.send_to_chats", fake_send)
    cfg = SimpleNamespace(scan=SimpleNamespace(announce_new=True),
                          telegram=SimpleNamespace(allowed_chat_ids=[7]),
                          instance_label="prod", hostname="gazda")

    finding = {"cve": "CVE-2026-0001", "severity": "high", "package": "openssl",
               "installed_version": "3.0.1", "fixed_version": "3.0.2",
               "kev": True, "priority": 90}
    assert run(announce.announce(cfg, [finding])) == 1
    assert trimise[0].startswith(f"<i>{identity.PREFIX}prod ({SHORT})</i>\n")
    assert "CVE-2026-0001" in trimise[0]


def test_the_install_test_message_names_the_instance(identity_on_disk, monkeypatch):
    """A treia: `sentinel telegram --send-test`, la capătul unui deploy.

    E chiar momentul în care apare a doua instanță într-un chat — pe 27 august
    exact ăsta a fost primul mesaj al VM-ului, și nu spunea nimic despre cine
    e. Text simplu, fără markup: `parse_mode` e None pe calea asta dinadins
    (vezi `telegram/direct.py`), deci un `<i>` ar ajunge literal.
    """
    from sentinel.services import telegram_service

    trimise: list[str] = []

    async def fake_send(token, chats, text, **kw):
        trimise.append(text)
        return [SimpleNamespace(chat_id=c, ok=True, describe=lambda: "ok")
                for c in chats]

    monkeypatch.setattr("sentinel.telegram.direct.send_to_chats", fake_send)
    cfg = SimpleNamespace(
        telegram=SimpleNamespace(enabled=True, allowed_chat_ids=[7]),
        instance_label="prod")
    sec = SimpleNamespace(get=lambda k, d=None: "t")

    assert telegram_service._send_test(cfg, sec, None) == 0
    assert trimise[0].startswith(f"{identity.PREFIX}prod ({SHORT})\n")
    assert "<i>" not in trimise[0]


def test_the_application_is_built_with_the_stamping_bot():
    """Fără asta, tot ce e mai sus poate fi adevărat despre o clasă pe care
    procesul real nu o folosește niciodată."""
    from sentinel.config import Config
    from sentinel.telegram import bot as bot_mod

    secrets = SimpleNamespace(require=lambda k: "0:test",
                              has=lambda k: True, get=lambda k, d=None: None)
    app = bot_mod.build_application(Config(), secrets)
    assert isinstance(app.bot, bot_mod.StampingBot)


def _pool(request) -> tuple:
    """Câte conexiuni are voie să țină deschise un obiect de cerere al PTB.

    Se citește din httpx, prin atribute private, fiindcă nici PTB nici httpx nu
    expun valoarea. Dacă vreunul se schimbă, sondele întorc `None` și testul de
    mai jos pică zgomotos — nu trece verde pe o comparație între două `None`.
    """
    pool = getattr(request._client._transport, "_pool", None)
    return (getattr(pool, "_max_connections", None),
            getattr(pool, "_max_keepalive_connections", None))


def test_the_bot_is_configured_exactly_as_the_builder_would_have():
    """Botul propriu nu are voie să schimbe ALTCEVA decât textul mesajelor.

    `Application.builder().token(...)` nu doar transmite tokenul: construiește
    `ExtBot` cu două obiecte de cerere, unul cu 256 de conexiuni pentru tot ce
    trimite botul și unul cu o singură conexiune pentru lung-polling. Un
    `ExtBot(token)` gol ia valoarea implicită a lui `HTTPXRequest`, care e 1 —
    adică plafonul de trimitere ar fi scăzut de la 256 la o conexiune cu
    timeout de o secundă pe rezervarea din pool, ca efect secundar al adăugării
    unui rând de text. Exact tiparul din `CLAUDE.md`: schimbarea intenționată
    ar fi fost livrată împreună cu una neintenționată, invizibilă până la o
    rafală de alerte.

    Comparația e cu un bot pe care biblioteca l-a construit chiar ea, deci o
    schimbare a valorilor implicite ale PTB pică aici, nu pe gazdă.
    """
    from telegram.ext import Application

    from sentinel.config import Config
    from sentinel.telegram import bot as bot_mod

    secrets = SimpleNamespace(require=lambda k: "0:test",
                              has=lambda k: True, get=lambda k, d=None: None)
    al_nostru = bot_mod.build_application(Config(), secrets).bot
    referinta = Application.builder().token("0:test").build().bot

    for indice, care in ((0, "get_updates"), (1, "trimitere")):
        a, b = al_nostru._request[indice], referinta._request[indice]
        assert _pool(b) != (None, None), (
            "sonda pe pool-ul httpx nu mai citește nimic; comparația de mai jos "
            "ar trece pe două `None` fără să verifice nimic")
        assert _pool(a) == _pool(b), (
            f"pool-ul de conexiuni pentru {care} diferă de cel pe care l-ar fi "
            f"construit biblioteca: {_pool(a)} față de {_pool(b)}")
        assert a._client.timeout == b._client.timeout, (
            f"timeout-urile pentru {care} diferă de cele ale bibliotecii")
        assert a.http_version == b.http_version


# ---------------------------------------------------------------------------
# Ce scrie
# ---------------------------------------------------------------------------
def test_an_unreadable_identity_still_sends_and_says_it_does_not_know(
        identity_missing, recorded_sends):
    """Un mesaj fără identificator e mai bun decât niciun mesaj — dar trebuie
    să spună că nu știe, nu să tacă și nu să inventeze un nume.

    „Necunoscut" și „în regulă" sunt stări diferite; confundate, unealta minte.
    """
    async def scenariu():
        await _bot("prod").send_message(7, "alertă", parse_mode=ParseMode.HTML)
        await _bot("").send_message(7, "alertă", parse_mode=ParseMode.HTML)

    run(scenariu())
    cu_eticheta, fara_eticheta = _texts(recorded_sends)
    assert cu_eticheta.startswith(
        f"<i>{identity.PREFIX}prod ({identity.UNKNOWN_ID})</i>\n")
    assert fara_eticheta.startswith(f"<i>{identity.PREFIX}{identity.UNKNOWN}</i>\n")
    assert "alertă" in cu_eticheta and "alertă" in fara_eticheta


def test_an_empty_label_falls_back_to_the_short_id(identity_on_disk, recorded_sends):
    """Pe producție `instance_label` e probabil gol, și un antet gol nu
    identifică nimic. Rezerva e id-ul, niciodată șirul vid."""
    run(_bot("").send_message(7, "x", parse_mode=ParseMode.HTML))
    run(_bot("   ").send_message(7, "y", parse_mode=ParseMode.HTML))
    for text in _texts(recorded_sends):
        assert text.startswith(f"<i>{identity.PREFIX}{SHORT}</i>\n")
        assert "()" not in text


def test_the_short_id_is_a_prefix_of_the_real_one(identity_on_disk):
    """Scurtat, nu rezumat. Operatorul trebuie să poată lega ce vede în mesaj de
    `/etc/sentinel/instance_id` și de panou printr-un `grep`, nu printr-o
    tabelă de corespondență pe care nimeni nu o ține."""
    tag = identity.current_tag("")
    assert FULL_ID.startswith(tag)
    assert len(tag) == identity.SHORT_ID


def test_a_label_from_the_config_cannot_break_the_markup(identity_on_disk):
    """`instance_label` e scris de mână în `sentinel.yaml`. Un `<` netratat rupe
    markup-ul FIECĂRUI mesaj, Telegram răspunde 400, și alerta se pierde din
    cauza unui caracter dintr-un nume cosmetic."""
    head = identity.header(identity.instance_name(SHORT, "<b>x</b>&"))
    assert "<b>" not in head
    assert "&lt;b&gt;x&lt;/b&gt;&amp;" in head
    # În text simplu nu se escapează, fiindcă acolo nu înseamnă nimic.
    assert "<b>" in identity.header(identity.instance_name(SHORT, "<b>x</b>"),
                                    html=False)


def test_a_label_of_the_wrong_yaml_type_does_not_break_the_channel():
    """`instance_label: 01` e un int pentru YAML, `2026-08-12` o dată.

    Un `.strip()` peste ele ridică AttributeError. Argumentul e cel din
    `sentinel/report/beacon.py`: un câmp COSMETIC nu are voie să poată opri
    canalul — exact rezultatul împotriva căruia există fișierul ăsta.
    """
    assert identity.instance_name(SHORT, 1) == f"1 ({SHORT})"
    assert identity.instance_name(SHORT, datetime.date(2026, 8, 12)) == \
        f"2026-08-12 ({SHORT})"
    assert identity.instance_name(SHORT, None) == SHORT


def test_the_naming_convention_is_the_same_as_the_panel():
    """Panoul și Telegram trebuie să numească aceeași mașină la fel.

    Altfel „care e a3f1?" are două răspunsuri, iar operatorul care compară
    panoul cu telefonul crede că are trei instanțe. Convenția e a panoului —
    `nameOf` din `aggregator/app/api/sentinel/check/route.ts` — și testul
    citește TypeScript-ul, ca o schimbare acolo să pice aici în loc să treacă
    neobservată.
    """
    sursa = ROUTE_TS.read_text(encoding="utf-8")
    corp = re.search(r"function nameOf\s*\([^)]*\)\s*:\s*string\s*\{(.*?)\n\}",
                     sursa, re.S)
    assert corp, (
        f"`nameOf` nu mai există în {ROUTE_TS}. Convenția de afișare a "
        "instanțelor era acolo; dacă s-a mutat, mută și verificarea asta, "
        "fiindcă altfel Telegram și panoul pot diverge fără să spună nimeni.")
    text = " ".join(corp.group(1).split())

    assert "const label = inst.last?.label?.trim();" in text, (
        f"panoul nu mai taie spațiile din etichetă; {text!r}. "
        "`instance_name` o face, deci o etichetă „   " + '"' + " ar fi tratată "
        "diferit în cele două locuri.")
    assert "return label ? `${label} (${id})` : id;" in text, (
        f"panoul și-a schimbat convenția de afișare: {text!r}. "
        "Adu `sentinel/telegram/identity.instance_name` la aceeași formă, sau "
        "cele două vor numi aceeași mașină diferit.")

    # Aceleași trei cazuri, în Python.
    assert identity.instance_name("ID", "eticheta") == "eticheta (ID)"
    assert identity.instance_name("ID", "") == "ID"
    assert identity.instance_name("ID", "   ") == "ID"


# ---------------------------------------------------------------------------
# Lungimea
# ---------------------------------------------------------------------------
def test_a_clamped_message_at_the_limit_survives_the_header():
    """Un mesaj deja la plafonul intern, plus antetul, nu trece de 4096.

    Peste 4096 Telegram răspunde 400 și mesajul se pierde întreg. `clamp` taie
    la 3600 tocmai ca să rămână loc, iar antetul e acum unul dintre lucrurile
    pe care locul ăla le plătește — deci corpul nu are voie să fie atins.
    """
    linii = [f"<b>rândul {n}</b> " + "x" * 60 for n in range(400)]
    corp = views.clamp(linii, tail="\n/incidente")
    assert len(corp) > views.MAX_MESSAGE - 200, "fixtura nu ajunge la plafon"

    iesit = identity.stamp(corp, identity.instance_name(SHORT, "e" * identity.MAX_LABEL))
    assert len(iesit) <= identity.TELEGRAM_MAX
    assert iesit.endswith(corp), "corpul unui mesaj deja tăiat a fost tăiat din nou"


def test_an_oversized_message_is_trimmed_on_a_line_boundary_and_says_so():
    """Căile care NU trec prin `clamp` — corpul unei notificări din bază, de
    exemplu — nu au niciun plafon. Antetul nu are voie să fie motivul pentru
    care Telegram refuză mesajul.

    Se taie rânduri ÎNTREGI: un `<b>` rupt la jumătate face ca Telegram să
    răspundă 400, adică operatorul nu primește nimic în loc să primească un
    mesaj scurtat.

    Aserțiunea e că rândurile păstrate sunt un PREFIX exact al celor de la
    intrare. O verificare mai slabă — că `<b>` și `</b>` se numără la fel — a
    trecut verde peste o tăiere pe caractere, fiindcă tăietura nimerea în
    umplutura de după etichete. Numărătoarea rămâne, dar ca aserțiune a doua.
    """
    linii = [f"<b>rândul {n}</b> " + "y" * 80 for n in range(200)]
    corp = "\n".join(linii)
    assert len(corp) > identity.TELEGRAM_MAX

    iesit = identity.stamp(corp, identity.instance_name(SHORT, "prod"))
    assert len(iesit) <= identity.TELEGRAM_MAX
    assert iesit.startswith(f"<i>{identity.PREFIX}prod ({SHORT})</i>\n")

    randuri = iesit.split("\n")
    antet, pastrate, notita = randuri[0], randuri[1:-1], randuri[-1]
    assert "scurtat" in notita, "s-a tăiat în tăcere"
    assert len(pastrate) < len(linii), "fixtura nu a fost tăiată deloc"
    assert pastrate == linii[:len(pastrate)], (
        "rândurile păstrate nu sunt un prefix exact al celor de la intrare — "
        "s-a tăiat în mijlocul unui rând, deci se poate tăia în mijlocul unei "
        "etichete, iar Telegram refuză mesajul cu 400")
    assert iesit.count("<b>") == iesit.count("</b>"), "markup rupt la tăiere"
    assert antet.endswith("</i>")


def test_a_single_line_too_long_to_keep_still_names_the_instance():
    """Un formatator care produce un singur rând mai lung decât tot bugetul.

    Nimic din depozit nu face asta azi; e tratat fiindcă alternativa e markup
    tăiat în două și un mesaj pe care Telegram îl refuză — adică tăcere.
    """
    iesit = identity.stamp("z" * 9000, identity.instance_name(SHORT, "prod"))
    assert iesit.startswith(f"<i>{identity.PREFIX}prod ({SHORT})</i>\n")
    assert "panoul web" in iesit
    assert len(iesit) <= identity.TELEGRAM_MAX


def test_the_header_is_never_written_twice():
    """O cale care marchează explicit și apoi trece și prin bot ar spune de
    două ori de pe ce mașină vine — iar al doilea rând ar arăta ca o a doua
    instanță."""
    tag = identity.instance_name(SHORT, "prod")
    o_data = identity.stamp("alertă", tag)
    assert identity.stamp(o_data, tag) == o_data
