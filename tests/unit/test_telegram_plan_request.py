"""`/planifica` din `sentinel/telegram/bot.py` — calea prin care operatorul poate
CERE un plan de remediere.

Eșecul pe care fișierul ăsta îl previne, măsurat pe gazda de producție pe 15
septembrie 2026: 1028 de findinguri deschise, 857 cu versiune care le repară,
ultimul plan generat pe 3 august. `planner.generate_for_kev` redactează automat
doar pentru findingurile KEV cu remediere cunoscută — mulțimea aia e goală, deci
nu face nimic, corect. Docstring-ul lui spune că restul „pot aștepta să ceară un
om", iar `planner.generate` — funcția completă, cu poartă de asset protejat,
verificare de buget și buclă de reparare — nu era chemat din nicio comandă.
Operatorul n-avea pe unde să ceară. Sistemul de patch-uri arăta mort fiindcă
nimeni nu cerea niciodată nimic.

Ce verifică fiecare test e scris în docstring-ul lui, în termeni de ce se strică
pentru operator. Trei lucruri NU se pot verifica de aici, și niciun test din
fișier nu se preface că le acoperă:

  * că Telegram chiar acceptă `/planifica` în meniu — nu există token în suită;
  * că modelul produce un plan valid pentru un pachet anume — `planner.generate`
    e simulat aici, iar validatorul lui are testele lui;
  * că `python-telegram-bot` chiar procesează update-urile unul câte unul.
    Testul de mai jos dovedește doar că HANDLERUL se întoarce înainte ca modelul
    să termine, ceea ce e partea de care răspunde fișierul ăsta.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("telegram")

from sentinel.config import Config  # noqa: E402
from sentinel.db.repo import findings as findings_repo  # noqa: E402
from sentinel.db.repo import patches as patch_repo  # noqa: E402
from sentinel.patch import planner  # noqa: E402
from sentinel.telegram import bot, patch_flow, views  # noqa: E402

CHAT_ID = 1234567890  # substituent — vezi nota din tests/unit/test_telegram_errors.py
OTHER_CHAT = 1987654321
FINDING_ID = 7


def run(c):
    return asyncio.run(c)


class _Msg:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict]] = []

    async def reply_text(self, text, **kw):
        self.sent.append((text, kw))


class _Bot:
    """Doar `send_message`: exact ce folosește `_run_plan_request` ca să livreze
    rezultatul în afara handlerului."""

    def __init__(self) -> None:
        self.sent: list[tuple[int, str]] = []

    async def send_message(self, chat_id, text, **kw):
        self.sent.append((chat_id, text))


def _update():
    msg = _Msg()
    return SimpleNamespace(effective_chat=SimpleNamespace(id=CHAT_ID),
                           effective_message=msg, message=msg), msg


def _cfg(*, viewer: bool = False) -> Config:
    cfg = Config()
    cfg.telegram.allowed_chat_ids = [CHAT_ID]
    if viewer:
        # Rolurile configurate, iar chatul ăsta nu e niciunul dintre ele: exact
        # forma în care `_can_act` întoarce False.
        cfg.telegram.owner_chat_id = OTHER_CHAT
    return cfg


def _ctx(args=None, *, cfg=None):
    ctx = SimpleNamespace(bot_data={"db": object(), "cfg": cfg or _cfg()},
                          args=args if args is not None else [str(FINDING_ID)],
                          bot=_Bot())
    return ctx


def _finding(**over) -> dict[str, Any]:
    row = {"id": FINDING_ID, "cve": "CVE-2026-0001", "title": "ceva",
           "severity": "high", "cvss": 7.5, "kev": False, "priority": 60,
           "package": "curl", "installed_version": "8.0.1-1",
           "fixed_version": "8.0.1-2", "ecosystem": "rpm", "scanner": "dnf",
           "status": "open", "asset_name": "host"}
    row.update(over)
    return row


def _plan_row(plan_id: int = 14, *, status: str = "validated",
              validation_errors=None, plan=None) -> patch_repo.PlanRow:
    import uuid

    return patch_repo.PlanRow(
        id=plan_id, plan_id=uuid.uuid4(), plan_hash="h" * 8,
        plan=plan or {"target": {"asset_name": "host"}, "risk": {"level": "low"}},
        status=status, risk_level="low", requires_reboot=False, reversible=True,
        estimated_downtime_s=5, asset_id=1,
        created_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        approved_by=None, approved_at=None, validation_errors=validation_errors)


def _plan_cu_backup(*, reversibil: bool = True) -> dict[str, Any]:
    """Forma pe care o citește `window.evaluate`: un backup `path` real și
    declarația de reversibilitate a planului. Restul câmpurilor nu contează
    pentru poartă, deci nu sunt inventate aici."""
    return {"target": {"asset_name": "host"},
            "risk": {"level": "low", "reversible": reversibil},
            "backup": [{"kind": "path", "source": "/etc/nginx"}]}


@pytest.fixture(autouse=True)
def _curata_cererile():
    """Registrul cererilor în curs e stare de modul (ca `_pending_pins`). Un test
    care lasă o intrare în el ar face următorul să creadă că o generare e deja
    pornită — și l-ar trece verde din motivul greșit."""
    bot._plan_requests.clear()
    yield
    bot._plan_requests.clear()


@pytest.fixture
def cheie(monkeypatch):
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k, d=None: "sk-test"))


def _nu_chema_modelul(monkeypatch) -> list:
    """Înlocuiește `planner.generate` cu ceva care înregistrează apelul. Folosit
    și ca dovadă că NU a fost chemat: lista rămâne goală."""
    apeluri: list = []

    async def _generate(db, cfg, api_key, finding_id, *, generated_by="ai"):
        apeluri.append((finding_id, generated_by))
        return None, "nu s-ar fi ajuns aici"

    monkeypatch.setattr(planner, "generate", _generate)
    return apeluri


def _fara_plan_viu(monkeypatch) -> None:
    async def _none(db, finding_id):
        return None

    monkeypatch.setattr(patch_repo, "live_plan_for_finding", _none)


def _finding_este(monkeypatch, row) -> None:
    async def _get(db, finding_id):
        # Interogat pe id-ul cerut, nu „ce i s-a dat testului": un fals care
        # întoarce același rând indiferent de argument ar trece și peste o
        # comandă care citește alt finding decât cel tastat.
        return row if row is not None and row["id"] == finding_id else None

    monkeypatch.setattr(findings_repo, "get_finding", _get)


# --- înregistrarea ----------------------------------------------------------
def test_comanda_exista_si_e_descoperibila():
    """Fără asta, „nu există nicio cale prin care omul să ceară" rămâne adevărat
    chiar dacă handlerul e scris: o comandă neînregistrată nu e chemată de
    nimic, iar una absentă din meniu și din /ajutor nu e găsită de nimeni.

    Tot aici se apără `/patch 3`: dacă `planifica` ar fi ajuns printre numele
    grupului de patch-uri, `/patch` ar fi început să însemne altceva decât azi.
    """
    nume_acting = {n for c in bot.ACTING for n in c.names}
    nume_read_only = {n for c in bot.READ_ONLY for n in c.names}

    assert "planifica" in nume_acting, (
        "comanda care cheltuie un apel Opus trebuie să fie în lista care "
        "verifică rolul, nu printre cele de citire")
    assert "planifica" not in nume_read_only

    publicate = {c.command for c in bot.menu_commands()}
    assert "planifica" in publicate, "comanda nu ajunge în meniul Telegram"
    assert "/planifica" in views.HELP, "comanda nu apare în /ajutor"

    # `/patch <id>` înseamnă exact ce însemna: planul cu id-ul ăla.
    patchuri = next(c for c in bot.COMMANDS if c.handler is bot.cmd_patches)
    assert patchuri.names == ("patches", "patch", "patchuri")
    assert "planifica" not in patchuri.names and "genereaza" not in patchuri.names


def _fake_secrets():
    """Token deliberat fără formă de token — vezi nota din test_telegram_menu.py."""
    return SimpleNamespace(require=lambda k: "0:test", has=lambda k: True,
                           get=lambda k, d=None: None)


def _callback_inregistrat(nume: str):
    """Handler-ul pe care APLICAȚIA REALĂ l-a înregistrat pentru o comandă."""
    from telegram.ext import CommandHandler

    app = bot.build_application(_cfg(), _fake_secrets())
    for handlere in app.handlers.values():
        for h in handlere:
            if isinstance(h, CommandHandler) and nume in h.commands:
                return h.callback
    raise AssertionError(f"/{nume} nu e înregistrată în aplicația construită")


def test_comanda_trece_prin_garda_de_chat_nu_doar_prin_rol():
    """`_can_act` verifică ROLUL. Verificarea de chat-și-expeditor
    (`_authorized`) vine din `_guard`, iar `on_flush_callback` e precedentul din
    fișier: un handler care verificase doar rolul a rămas singurul buton pe care
    un membru nelistat al grupului îl mai putea apăsa după ce toate celelalte
    căi i-au fost închise.

    Verificat pe aplicația reală construită de `build_application`, nu pe
    apartenența la o listă: un update dintr-un chat NEAUTORIZAT nu trebuie să
    primească niciun răspuns — nici măcar refuzul, care ar confirma că botul
    există.
    """
    callback = _callback_inregistrat("planifica")
    msg = _Msg()
    update = SimpleNamespace(
        effective_chat=SimpleNamespace(id=OTHER_CHAT, type="private"),
        effective_message=msg, message=msg, effective_user=None)
    ctx = SimpleNamespace(bot_data={"cfg": _cfg()}, args=["7"],
                          bot=SimpleNamespace(username=None))

    run(callback(update, ctx))

    assert msg.sent == [], (
        "un chat neautorizat a primit un răspuns: comanda nu mai trece prin "
        "`_guard`, deci nici prin verificarea de chat și de expeditor")


def test_intr_un_grup_comanda_cere_mentiunea_botului():
    """§8 din docs/TELEGRAM.md: mai multe instanțe Sentinel pot împărți un grup.
    Un `/planifica 7` fără mențiune ar porni o generare — și o cheltuială — pe
    FIECARE gazdă care citește din grupul acela."""
    callback = _callback_inregistrat("planifica")
    msg = _Msg()
    msg.text = "/planifica 7"
    update = SimpleNamespace(
        effective_chat=SimpleNamespace(id=CHAT_ID, type="group"),
        effective_message=msg, message=msg, effective_user=None)
    ctx = SimpleNamespace(bot_data={"cfg": _cfg()}, args=["7"],
                          bot=SimpleNamespace(username="sentinel_test_bot"))

    run(callback(update, ctx))

    assert len(msg.sent) == 1 and "mențiunea botului" in msg.sent[0][0]


# --- autorizarea ------------------------------------------------------------
def test_un_viewer_nu_poate_cheltui_un_apel_opus(monkeypatch, cheie):
    """Un cont de vizualizare care poate porni o generare cheltuie bani reali din
    bugetul AI al gazdei și poate goli plafonul zilnic înaintea unui KEV. Rolul
    se verifică ÎNAINTE de orice citire și înaintea oricărui apel."""
    apeluri = _nu_chema_modelul(monkeypatch)

    async def _boom(db, finding_id):
        raise AssertionError("nu trebuia citit nimic pentru un viewer")

    monkeypatch.setattr(findings_repo, "get_finding", _boom)

    update, msg = _update()
    run(bot.cmd_planifica(update, _ctx(cfg=_cfg(viewer=True))))

    assert apeluri == []
    assert not bot._plan_requests
    assert "vizualizare" in msg.sent[0][0]


# --- parsarea argumentului ----------------------------------------------
def test_fara_argument_arata_folosirea_nu_pica(monkeypatch, cheie):
    apeluri = _nu_chema_modelul(monkeypatch)
    update, msg = _update()
    run(bot.cmd_planifica(update, _ctx(args=[])))
    assert apeluri == []
    assert "Folosire" in msg.sent[0][0]


def test_un_argument_nenumeric_arata_folosirea_nu_pica(monkeypatch, cheie):
    apeluri = _nu_chema_modelul(monkeypatch)
    update, msg = _update()
    run(bot.cmd_planifica(update, _ctx(args=["abc"])))
    assert apeluri == []
    assert "Folosire" in msg.sent[0][0]


def test_o_cifra_unicode_neZecimala_nu_omoara_handlerul(monkeypatch, cheie):
    """`'²'.isdigit()` e `True`, dar `int('²')` ridică `ValueError` —
    exact tiparul din nota de memorie despre `[0-9]` sub UTF-8: caracterul
    trece verificarea „arată ca o cifră" și pică la conversia reală. Înainte
    de fix, comanda asta arunca necaptat din `cmd_planifica`; acum trebuie să
    răspundă cu folosirea, la fel ca orice alt argument nenumeric."""
    apeluri = _nu_chema_modelul(monkeypatch)
    update, msg = _update()
    run(bot.cmd_planifica(update, _ctx(args=["²"])))
    assert apeluri == []
    assert len(msg.sent) == 1, msg.sent
    assert "Folosire" in msg.sent[0][0]


# --- refuzurile deterministe ------------------------------------------------
def test_un_finding_inexistent_nu_ajunge_la_model(monkeypatch, cheie):
    """`generate` ar fi întors „finding inexistent" — după ce pornea un task și
    după ce operatorul primise o confirmare. Răspunsul corect e pe loc."""
    apeluri = _nu_chema_modelul(monkeypatch)
    _finding_este(monkeypatch, None)
    _fara_plan_viu(monkeypatch)

    update, msg = _update()
    run(bot.cmd_planifica(update, _ctx()))

    assert apeluri == []
    assert "nu există" in msg.sent[0][0]


def test_un_finding_deja_rezolvat_nu_ajunge_la_model(monkeypatch, cheie):
    """5249 din findingurile gazdei sunt `resolved` (măsurat pe 15 septembrie
    2026). Un plan pentru unul dintre ele ar repara ceva ce scanarea nu mai
    vede, pe bani — și mesajul trebuie să spună că e rezolvat, nu că nu există.
    """
    apeluri = _nu_chema_modelul(monkeypatch)
    _finding_este(monkeypatch, _finding(status="resolved"))
    _fara_plan_viu(monkeypatch)

    update, msg = _update()
    run(bot.cmd_planifica(update, _ctx()))

    assert apeluri == []
    text = msg.sent[0][0]
    assert "resolved" in text and "deschisă" in text


def test_fara_versiune_care_repara_nu_se_plateste_nimic(monkeypatch, cheie):
    """171 dintre findingurile deschise n-au versiune care să le repare (1028
    deschise, 857 cu fix — măsurat pe 15 septembrie 2026). Pentru ele nu există
    ce aplica, deci nu există plan de cerut."""
    apeluri = _nu_chema_modelul(monkeypatch)
    _finding_este(monkeypatch, _finding(fixed_version=None))
    _fara_plan_viu(monkeypatch)

    update, msg = _update()
    run(bot.cmd_planifica(update, _ctx()))

    assert apeluri == []
    assert "nu are o versiune" in msg.sent[0][0]


def test_o_vulnerabilitate_pe_care_executorul_n_o_poate_repara_e_refuzata(monkeypatch, cheie):
    """Măsurat pe gazda de producție pe 15 septembrie 2026: din 857 de
    findinguri deschise cu versiune care repară, 407 NU sunt pachete ale gazdei
    (npm 185, alpine 82, go 80, composer 44, deb 16), iar toate primele 12 după
    prioritate sunt din categoria aia — adică exact cele pe care operatorul le
    vede primele în `/vulnerabilitati` și pe care le-ar cere primele.

    Fără refuzul ăsta, prima lui apăsare costă până la două apeluri Opus și se
    poate termina doar în `rejected_invalid`, sau într-un plan `dnf` plauzibil
    pentru un pachet Alpine dintr-o imagine de container, care pică abia la
    dry-run — pe o mașină de producție.
    """
    apeluri = _nu_chema_modelul(monkeypatch)
    _finding_este(monkeypatch, _finding(ecosystem="npm", scanner="trivy_fs",
                                        package="lodash"))
    _fara_plan_viu(monkeypatch)

    update, msg = _update()
    run(bot.cmd_planifica(update, _ctx()))

    assert apeluri == [], "s-a plătit un apel la model pentru un refuz sigur"
    assert not bot._plan_requests
    text = msg.sent[0][0]
    assert "npm" in text, "refuzul nu spune ce ecosistem a găsit"
    assert "rpm" in text, "refuzul nu spune ce SE POATE planifica"


def test_un_ecosistem_necunoscut_nu_e_tratat_ca_rpm(monkeypatch, cheie):
    """„Nu știu" și „e bine" sunt stări diferite. Un finding fără `ecosystem`
    nu e o dovadă că e pachet de sistem, iar ghicitul costă un apel la model ca
    să fie respins."""
    apeluri = _nu_chema_modelul(monkeypatch)
    _finding_este(monkeypatch, _finding(ecosystem=None))
    _fara_plan_viu(monkeypatch)

    update, msg = _update()
    run(bot.cmd_planifica(update, _ctx()))

    assert apeluri == []
    assert "ecosistem" in msg.sent[0][0]


def test_pe_o_gazda_debian_se_planifica_pachetele_deb(monkeypatch, cheie):
    """Poarta întreabă gazda, nu presupune AlmaLinux: `platform.family` decide
    ce ecosistem e „al gazdei". Măsurat pe 15 septembrie 2026, a doua gazdă
    Sentinel e Ubuntu 24.04 și are findinguri `deb` cu remediere cunoscută — un
    filtru scris „rpm" în cod le-ar fi refuzat pe toate, iar comanda n-ar fi
    existat acolo deloc.
    """
    apeluri = _nu_chema_modelul(monkeypatch)
    _finding_este(monkeypatch, _finding(ecosystem="deb", scanner="apt"))
    _fara_plan_viu(monkeypatch)

    cfg = _cfg()
    cfg.platform.family = "debian"

    async def scenariu():
        update, msg = _update()
        await bot.cmd_planifica(update, _ctx(cfg=cfg))
        task = bot._plan_requests.get(FINDING_ID)
        assert task is not None, (
            "un pachet `deb` pe o gazdă debian a fost refuzat: "
            f"{msg.sent[0][0] if msg.sent else 'niciun mesaj'}")
        # Așteptat, fiindcă `create_task` doar programează: fără asta,
        # `apeluri` ar fi gol și pentru un handler care chiar a pornit-o.
        await asyncio.wait_for(task, timeout=2)

    run(scenariu())

    assert apeluri == [(FINDING_ID, bot.MANUAL_PLAN_ORIGIN)]


def test_un_plan_viu_opreste_o_a_doua_redactare(monkeypatch, cheie):
    """`generate_for_kev` are garda asta în `NOT EXISTS`; `generate` NU are
    niciuna. Fără ea aici, a doua apăsare pe același finding plătește încă un
    apel Opus și lasă DOUĂ planuri vii pentru aceeași vulnerabilitate, fiecare
    cu propriile butoane de aprobare."""
    apeluri = _nu_chema_modelul(monkeypatch)
    _finding_este(monkeypatch, _finding())

    async def _live(db, finding_id):
        assert finding_id == FINDING_ID
        return _plan_row(12, status="approved")

    monkeypatch.setattr(patch_repo, "live_plan_for_finding", _live)

    update, msg = _update()
    run(bot.cmd_planifica(update, _ctx()))

    assert apeluri == [], "s-a cerut un plan nou peste unul viu"
    text = msg.sent[0][0]
    assert "#12" in text and "/patch 12" in text, (
        "refuzul trebuie să trimită la planul care există deja")
    assert "approved" in text


# --- concurența -------------------------------------------------------------
def _generate_care_asteapta(monkeypatch, poarta: asyncio.Event, rezultat=(None, "gata")):
    apeluri: list = []

    async def _generate(db, cfg, api_key, finding_id, *, generated_by="ai"):
        apeluri.append((finding_id, generated_by))
        await poarta.wait()
        return rezultat

    monkeypatch.setattr(planner, "generate", _generate)
    return apeluri


def test_comanda_raspunde_inainte_ca_modelul_sa_termine(monkeypatch, cheie):
    """`python-telegram-bot` procesează update-urile unul câte unul. Un apel Opus
    așteptat ÎN handler ar face botul mut zeci de secunde: nici /status, nici
    /unblock, nici butonul de deblocare de pe alerta care tocmai a sosit."""
    _finding_este(monkeypatch, _finding())
    _fara_plan_viu(monkeypatch)
    poarta = asyncio.Event()

    async def scenariu():
        apeluri = _generate_care_asteapta(monkeypatch, poarta)
        update, msg = _update()
        ctx = _ctx()
        # Mărginit: dacă handlerul așteaptă generarea, nu se mai întoarce
        # niciodată singur, iar testul trebuie să pice, nu să atârne.
        await asyncio.wait_for(bot.cmd_planifica(update, ctx), timeout=2)

        assert msg.sent, "operatorul n-a primit nicio confirmare"
        assert "Cer un plan" in msg.sent[0][0]
        task = bot._plan_requests.get(FINDING_ID)
        assert task is not None and not task.done(), (
            "generarea trebuia să ruleze în fundal, nu în handler")
        poarta.set()
        await task
        assert apeluri == [(FINDING_ID, bot.MANUAL_PLAN_ORIGIN)]
        assert FINDING_ID not in bot._plan_requests, (
            "cererea terminată trebuie să elibereze locul")

    run(scenariu())


def test_a_doua_apasare_in_timpul_generarii_nu_plateste_din_nou(monkeypatch, cheie):
    """Un operator, un finding, două atingeri. Plafonul de buget e un plafon de
    CHELTUIALĂ zilnică, nu de concurență: fără garda asta, zece atingeri pe
    același rând înseamnă zece apeluri Opus în paralel pentru același plan."""
    _finding_este(monkeypatch, _finding())
    _fara_plan_viu(monkeypatch)
    poarta = asyncio.Event()

    async def scenariu():
        apeluri = _generate_care_asteapta(monkeypatch, poarta)
        update, msg = _update()
        ctx = _ctx()
        # Mărginit, ca peste tot în fișierul ăsta: sub regresia pe care fișierul
        # o previne (așteptarea modelului ÎN handler), un apel nemărginit nu se
        # mai întoarce niciodată. Testul trebuie să devină ROȘU, nu să atârne —
        # în CI un test agățat e un job blocat, nu un eșec.
        await asyncio.wait_for(bot.cmd_planifica(update, ctx), timeout=2)
        await asyncio.wait_for(bot.cmd_planifica(update, ctx), timeout=2)

        # Numărat pe task-uri, nu pe apeluri: `create_task` doar programează, iar
        # corutina n-a apucat încă să pornească. Apelurile se numără mai jos,
        # după ce chiar au rulat — altfel testul ar trece și dacă handlerul n-ar
        # porni nimic deloc.
        assert len(bot._plan_requests) == 1, "a doua apăsare a mai pornit o generare"
        assert "Deja cer un plan" in msg.sent[1][0]
        poarta.set()
        await asyncio.wait_for(bot._plan_requests[FINDING_ID], timeout=2)
        assert apeluri == [(FINDING_ID, bot.MANUAL_PLAN_ORIGIN)]

    run(scenariu())


def test_peste_plafonul_de_concurenta_cererea_e_refuzata_vizibil(monkeypatch, cheie):
    """857 de findinguri cu remediere cunoscută înseamnă 857 de atingeri
    posibile. Fără plafon, o serie de atingeri pe rânduri DIFERITE pornește tot
    atâtea apeluri Opus deodată — iar refuzul trebuie spus, nu tăcut."""
    _fara_plan_viu(monkeypatch)
    poarta = asyncio.Event()

    async def _get(db, finding_id):
        return _finding(id=finding_id)

    monkeypatch.setattr(findings_repo, "get_finding", _get)

    async def scenariu():
        apeluri = _generate_care_asteapta(monkeypatch, poarta)
        update, msg = _update()
        for fid in range(1, bot.MAX_CONCURRENT_PLAN_REQUESTS + 2):
            # Mărginit: vezi nota din testul de mai sus — un handler care
            # așteaptă modelul ar agăța testul, nu l-ar face roșu.
            await asyncio.wait_for(
                bot.cmd_planifica(update, _ctx(args=[str(fid)])), timeout=2)

        assert len(bot._plan_requests) == bot.MAX_CONCURRENT_PLAN_REQUESTS
        assert "Se generează deja" in msg.sent[-1][0]
        poarta.set()
        for task in list(bot._plan_requests.values()):
            await asyncio.wait_for(task, timeout=2)
        # Chiar au ajuns la model, exact atâtea câte au avut voie: fără linia
        # asta, un handler care nu pornește nimic ar trece testul.
        assert len(apeluri) == bot.MAX_CONCURRENT_PLAN_REQUESTS

    run(scenariu())


# --- ce se întoarce de la model ---------------------------------------------
def _ruleaza_cu_rezultat(monkeypatch, rezultat, *, exceptie=None):
    """Pornește comanda și așteaptă task-ul de fundal. Întoarce (msg, ctx)."""
    _finding_este(monkeypatch, _finding())
    _fara_plan_viu(monkeypatch)

    async def _generate(db, cfg, api_key, finding_id, *, generated_by="ai"):
        if exceptie is not None:
            raise exceptie
        return rezultat

    monkeypatch.setattr(planner, "generate", _generate)

    rezultate: dict = {}

    async def scenariu():
        update, msg = _update()
        ctx = _ctx()
        await bot.cmd_planifica(update, ctx)
        task = bot._plan_requests.get(FINDING_ID)
        assert task is not None, "nu s-a pornit nicio generare"
        await task
        rezultate["msg"] = msg
        rezultate["ctx"] = ctx

    run(scenariu())
    return rezultate["msg"], rezultate["ctx"]


def test_planul_validat_ajunge_cu_butoane_si_nu_se_mai_impinge_o_data(monkeypatch, cheie):
    """Operatorul a cerut planul; răspunsul trebuie să fie chiar planul, cu
    butoanele lui. Și o singură dată: planul manual trece de filtrul
    `generated_by <> 'ai'` din `unnotified_plans`, deci fără marcarea de aici
    bucla de push i-l mai trimite o dată, cu încă un set de butoane, în cel mult
    15 secunde."""
    trimise: list = []
    marcate: list = []

    async def _send(bot_obj, db, chat_id, row, *, gate_note=None, allow_apply=True):
        trimise.append((chat_id, row.id))

    async def _get_plan(db, plan_db_id):
        return _plan_row(14)

    async def _mark(db, plan_db_id):
        marcate.append(plan_db_id)

    monkeypatch.setattr(patch_flow, "send_plan_for_approval", _send)
    monkeypatch.setattr(patch_repo, "get_plan", _get_plan)
    monkeypatch.setattr(patch_repo, "mark_plan_notified", _mark)

    _ruleaza_cu_rezultat(monkeypatch, (14, "validated"))

    assert trimise == [(CHAT_ID, 14)], "planul nu a ajuns cu butoane la cine l-a cerut"
    assert marcate == [14], "planul rămâne netrimis și bucla de push îl va dubla"


def _trimitere_captata(monkeypatch) -> list[dict]:
    """Înlocuiește `send_plan_for_approval` cu ceva care reține TOT ce i s-a dat
    — inclusiv verdictul și decizia despre butonul de aplicare."""
    captat: list[dict] = []

    async def _send(bot_obj, db, chat_id, row, *, gate_note=None, allow_apply=True):
        captat.append({"chat_id": chat_id, "plan": row.id,
                       "nota": gate_note, "aplicare": allow_apply})

    monkeypatch.setattr(patch_flow, "send_plan_for_approval", _send)
    return captat


def _dovada_de_arhiva(monkeypatch, valoare) -> None:
    async def _summary(db):
        return valoare

    monkeypatch.setattr(patch_repo, "latest_archive_drill_summary", _summary)


def test_planul_ajunge_cu_verdictul_de_intoarcere_langa_buton(monkeypatch, cheie):
    """Măsurat pe amândouă gazdele pe 15 septembrie 2026:
    `restore_drill_items` n-are niciun artefact-arhivă, deci
    `latest_archive_drill_summary` întoarce `None` și ORICE plan iese azi
    `UNPROVEN`. Butonul rămâne — altfel comanda ar fi inutilă din prima zi —
    dar tăcerea de lângă el ar fi însemnat că sistemul ȘTIE că întoarcerea nu e
    dovedită și n-o spune. Exact forma din CLAUDE.md: intenția confirmată în
    locul faptului.
    """
    captat = _trimitere_captata(monkeypatch)
    _dovada_de_arhiva(monkeypatch, None)

    async def _get_plan(db, plan_db_id):
        return _plan_row(14, plan=_plan_cu_backup())

    async def _mark(db, plan_db_id):
        return None

    monkeypatch.setattr(patch_repo, "get_plan", _get_plan)
    monkeypatch.setattr(patch_repo, "mark_plan_notified", _mark)

    _ruleaza_cu_rezultat(monkeypatch, (14, "validated"))

    assert len(captat) == 1, captat
    assert captat[0]["aplicare"] is True, (
        "butonul a fost retras la `UNPROVEN`, adică la fiecare plan de pe gazdele "
        "de azi — comanda ar fi inutilă din prima zi")
    nota = captat[0]["nota"] or ""
    assert "NEDOVEDITĂ" in nota, nota
    assert "exercițiu de restaurare" in nota, (
        "verdictul nu poartă MOTIVUL dat de `window.evaluate`, doar o etichetă")


def test_un_plan_fara_cale_de_intoarcere_nu_primeste_buton_de_aplicare(monkeypatch, cheie):
    """`risk.reversible: false` înseamnă că planul însuși spune că nu există
    pași de revenire. Un buton „Aplică" lângă el e o aprobare în două atingeri
    pentru o schimbare din care nu se mai iese — iar fereastra săptămânală
    refuză deja exact planurile astea. Dry-run și Respinge rămân: niciunul nu
    atinge mașina."""
    captat = _trimitere_captata(monkeypatch)
    _dovada_de_arhiva(monkeypatch, None)

    async def _get_plan(db, plan_db_id):
        return _plan_row(15, plan=_plan_cu_backup(reversibil=False))

    async def _mark(db, plan_db_id):
        return None

    monkeypatch.setattr(patch_repo, "get_plan", _get_plan)
    monkeypatch.setattr(patch_repo, "mark_plan_notified", _mark)

    _ruleaza_cu_rezultat(monkeypatch, (15, "validated"))

    assert len(captat) == 1, captat
    assert captat[0]["aplicare"] is False, (
        "un plan care se declară irevocabil a primit totuși butonul de aplicare")
    assert "RETRAS" in (captat[0]["nota"] or ""), captat[0]["nota"]


def test_o_stare_de_poarta_necunoscuta_nu_deschide_drumul(monkeypatch, cheie):
    """Poarta are azi trei stări. Dacă mai apare una, decizia despre buton nu
    are voie să cadă în ramura permisivă doar fiindcă e „altceva decât
    NOT_REVERSIBLE"."""
    from sentinel.patch import window

    captat = _trimitere_captata(monkeypatch)
    _dovada_de_arhiva(monkeypatch, None)
    monkeypatch.setattr(window, "evaluate",
                        lambda plan, dovada: window.GateResult("altceva", "stare nouă"))

    async def _get_plan(db, plan_db_id):
        return _plan_row(16, plan=_plan_cu_backup())

    async def _mark(db, plan_db_id):
        return None

    monkeypatch.setattr(patch_repo, "get_plan", _get_plan)
    monkeypatch.setattr(patch_repo, "mark_plan_notified", _mark)

    _ruleaza_cu_rezultat(monkeypatch, (16, "validated"))

    assert captat[0]["aplicare"] is False
    assert "necunoscut" in (captat[0]["nota"] or "")


def test_daca_dovada_nu_poate_fi_citita_se_spune_nu_se_tace(monkeypatch, cheie):
    """O pană scurtă a bazei nu e un fapt despre plan. Verdictul devine
    „necunoscut", spus ca atare — nu un verdict inventat și nu tăcere."""
    captat = _trimitere_captata(monkeypatch)

    async def _summary(db):
        raise RuntimeError("conexiune pierdută")

    async def _get_plan(db, plan_db_id):
        return _plan_row(17, plan=_plan_cu_backup())

    async def _mark(db, plan_db_id):
        return None

    monkeypatch.setattr(patch_repo, "latest_archive_drill_summary", _summary)
    monkeypatch.setattr(patch_repo, "get_plan", _get_plan)
    monkeypatch.setattr(patch_repo, "mark_plan_notified", _mark)

    _ruleaza_cu_rezultat(monkeypatch, (17, "validated"))

    assert len(captat) == 1, "planul nu a mai ajuns deloc din cauza verdictului"
    assert captat[0]["aplicare"] is True
    assert "necunoscut" in (captat[0]["nota"] or "")


def test_butonul_retras_chiar_lipseste_din_tastatura():
    """Cealaltă jumătate a deciziei, verificată pe MESAJUL real, nu pe
    parametrul cu care a fost chemată funcția: fără asta, `allow_apply=False`
    ar fi putut fi un argument pe care nimeni nu-l citește.

    Se verifică și că NU se mai emite token de aprobare: `on_stage1` consumă
    orice token i se dă, iar un token emis pentru un buton „ascuns" rămâne o
    aprobare validă pentru cine ajunge la el.
    """
    trimise: list = []
    emise: list = []

    class _Bot2:
        async def send_message(self, chat_id, text, **kw):
            trimise.append((text, kw))

    async def _issue(db, **kw):
        emise.append(kw)
        return "tok"

    async def scenariu():
        import sentinel.telegram.patch_flow as pf

        real_issue = pf.approvals.issue
        pf.approvals.issue = _issue
        try:
            await pf.send_plan_for_approval(
                _Bot2(), object(), CHAT_ID, _plan_row(18, plan=_plan_cu_backup()),
                gate_note="⛔ <b>Fără cale de întoarcere</b> — motivul",
                allow_apply=False)
        finally:
            pf.approvals.issue = real_issue

    run(scenariu())

    text, kw = trimise[0]
    butoane = [b.callback_data for rand in kw["reply_markup"].inline_keyboard
               for b in rand]
    assert not any(b.startswith("pap1:") for b in butoane), butoane
    assert any(b.startswith("pdry:") for b in butoane), "dry-run a dispărut și el"
    assert any(b.startswith("prej:") for b in butoane), "respingerea a dispărut"
    assert emise == [], "s-a emis totuși un token de aprobare pentru un buton absent"
    assert "Fără cale de întoarcere" in text, "verdictul nu apare în mesaj"


def test_refuzul_validatorului_vine_cu_erorile_lui(monkeypatch, cheie):
    """`rejected_invalid` înseamnă două apeluri Opus plătite. Ce a produs
    refuzul — lista de erori din `patch_plans.validation_errors` — e singurul
    lucru de valoare rămas: spune dacă e vina promptului, a modelului sau a unui
    pachet care chiar nu se poate repara aici. Un „a eșuat" generic o aruncă,
    cu ea stând scrisă în bază."""
    erori = [{"path": "apply[0].argv", "code": "binary_not_allowed",
              "message": "binar nepermis: rm"},
             {"path": "preflight", "code": "no_blocking_check",
              "message": "nicio verificare blocantă"}]

    async def _get_plan(db, plan_db_id):
        return _plan_row(21, status="rejected_invalid", validation_errors=erori)

    monkeypatch.setattr(patch_repo, "get_plan", _get_plan)

    msg, ctx = _ruleaza_cu_rezultat(monkeypatch, (21, "rejected_invalid"))

    text = ctx.bot.sent[-1][1]
    assert "binar nepermis: rm" in text
    assert "nicio verificare blocantă" in text
    assert "apply[0].argv" in text
    assert "/patch 21" in text, "planul respins se păstrează ca dovadă; spune unde"


def test_un_plan_respins_fara_erori_nu_e_raportat_ca_si_cum_ar_fi_avut(monkeypatch, cheie):
    """„Nu știu de ce" și „iată de ce" sunt stări diferite. Dacă lista lipsește
    din bază, mesajul trebuie să spună asta, nu să tacă și să arate un refuz
    fără motiv."""
    async def _get_plan(db, plan_db_id):
        return _plan_row(22, status="rejected_invalid", validation_errors=None)

    monkeypatch.setattr(patch_repo, "get_plan", _get_plan)

    msg, ctx = _ruleaza_cu_rezultat(monkeypatch, (22, "rejected_invalid"))

    text = ctx.bot.sent[-1][1]
    assert "nu poartă nicio listă de erori" in text


def test_refuzul_de_buget_spune_cifrele_lui(monkeypatch, cheie):
    """Un „a eșuat" generic trimite operatorul să caute o pană inexistentă. Un
    plafon de buget atins e o decizie a sistemului, cu cifre, iar operatorul
    trebuie să vadă că poate fi ridicat — nu reparat."""
    msg, ctx = _ruleaza_cu_rezultat(
        monkeypatch, (None, "buget: daily cap reached ($5.00/$5.00)"))

    text = ctx.bot.sent[-1][1]
    assert "daily cap reached ($5.00/$5.00)" in text
    assert "buget" in text


def test_un_asset_protejat_spune_ca_e_protejat(monkeypatch, cheie):
    """Poarta de asset protejat e o decizie de proiectare, nu o defecțiune: un
    plan automat pentru el e respins din principiu. Operatorul trebuie să afle
    că trebuie să aplice manual, nu că s-a stricat ceva."""
    motiv = ("asset protejat (n8n) — patch-urile automate sunt interzise pentru "
             "el prin design; aplică manual")
    msg, ctx = _ruleaza_cu_rezultat(monkeypatch, (None, motiv))

    text = ctx.bot.sent[-1][1]
    assert "asset protejat (n8n)" in text
    assert "aplică manual" in text


def test_o_exceptie_in_task_ajunge_la_operator(monkeypatch, cheie):
    """Un task de fundal care moare cu o excepție NU trece prin
    `add_error_handler`-ul lui PTB. Fără plasa asta, operatorul rămâne cu
    confirmarea „cer un plan" și cu tăcere — la nesfârșit."""
    msg, ctx = _ruleaza_cu_rezultat(monkeypatch, None,
                                    exceptie=RuntimeError("conexiune pierdută"))

    text = ctx.bot.sent[-1][1]
    assert "RuntimeError" in text and "conexiune pierdută" in text


def test_o_cadere_pe_prima_linie_a_task_ului_ajunge_tot_la_operator(monkeypatch, cheie):
    """Găsit la revizuire (runda 2): importurile, `int(finding["id"])` și
    eticheta stăteau ÎN AFARA lui `try`. O cădere pe liniile alea omora task-ul
    înainte de plasă — operatorul rămânea cu „🧠 Cer un plan…" și cu tăcere,
    `log.error("plan request failed")` nu rula niciodată, iar singura urmă era
    „Task exception was never retrieved", în jurnalul lui `asyncio`, nu al lui
    Sentinel.

    Aici cade chiar `int(finding["id"])`, cu un rând al cărui id nu e un număr.
    Chemat direct, nu prin handler: handlerul nu poate fabrica un asemenea rând,
    dar task-ul primește orice îi dă baza.
    """
    bot_fals = _Bot()

    run(bot._run_plan_request(bot_fals, object(), _cfg(), "sk-test",
                              chat_id=CHAT_ID,
                              finding={"id": "nu-e-numar", "package": "curl"}))

    assert bot_fals.sent, ("task-ul a murit fără să spună nimic — operatorul "
                           "rămâne cu confirmarea și cu tăcere")
    text = bot_fals.sent[-1][1]
    assert "ValueError" in text
    assert "curl" in text, "mesajul nu spune despre ce vulnerabilitate vorbește"


def test_un_import_care_nu_merge_nu_lasa_operatorul_in_tacere(monkeypatch, cheie):
    """Declanșatorul realist: o gazdă livrată pe jumătate, unde
    `from sentinel.telegram import patch_flow` cade. Importurile stăteau
    deasupra lui `try`, deci exact cazul ăsta producea tăcere — și tot prin
    handler, adică fix drumul pe care îl parcurge operatorul.
    """
    import sys

    import sentinel.telegram as pachet

    _finding_este(monkeypatch, _finding())
    _fara_plan_viu(monkeypatch)
    monkeypatch.delattr(pachet, "patch_flow", raising=False)
    monkeypatch.setitem(sys.modules, "sentinel.telegram.patch_flow", None)

    async def scenariu():
        update, msg = _update()
        ctx = _ctx()
        await bot.cmd_planifica(update, ctx)
        assert "Cer un plan" in msg.sent[0][0]
        await asyncio.wait_for(bot._plan_requests[FINDING_ID], timeout=2)
        return ctx

    ctx = run(scenariu())

    assert ctx.bot.sent, "nicio vorbă despre cererea care tocmai a murit"
    text = ctx.bot.sent[-1][1]
    # `ModuleNotFoundError` e subclasa de ImportError pe care o ridică chiar
    # importul ăsta; ce contează e că mesajul NUMEȘTE ce a lipsit, ca operatorul
    # să știe că gazda e livrată pe jumătate, nu că modelul a refuzat ceva.
    assert "patch_flow" in text and "Error" in text, text


def test_registrul_se_elibereaza_si_cand_task_ul_moare(monkeypatch, cheie):
    """Locul din registru trebuie eliberat oricum ar ieși generarea, altfel
    findingul rămâne blocat („Deja cer un plan…") până la repornirea botului.
    Verificat pe un task care moare, nu pe unul care reușește."""
    _finding_este(monkeypatch, _finding())
    _fara_plan_viu(monkeypatch)

    async def _generate(db, cfg, api_key, finding_id, *, generated_by="ai"):
        raise RuntimeError("cade")

    monkeypatch.setattr(planner, "generate", _generate)

    async def scenariu():
        update, _msg = _update()
        await bot.cmd_planifica(update, _ctx())
        await asyncio.wait_for(bot._plan_requests[FINDING_ID], timeout=2)

    run(scenariu())

    assert FINDING_ID not in bot._plan_requests


def test_o_cadere_a_plasei_insesi_ajunge_in_jurnalul_lui_sentinel(caplog):
    """Plasa de sub plasă. `_run_plan_request` își prinde singur eșecurile, dar
    dacă însuși blocul `except` de acolo cade, tot ce mai rămânea era mesajul
    lui `asyncio` — „Task exception was never retrieved", în jurnalul lui
    `asyncio`, nu al lui Sentinel, la o oră nedeterminată, când colectorul de
    gunoi ajunge la task. Operatorul care caută în `journalctl -u
    sentinel-telegram` n-ar fi găsit nimic despre cererea lui.
    """
    import logging

    async def scenariu():
        async def _moare():
            raise RuntimeError("a căzut și plasa")

        task = asyncio.create_task(_moare())
        try:
            await task
        except RuntimeError:
            pass
        bot._cerere_incheiata(FINDING_ID, CHAT_ID, task)

    with caplog.at_level(logging.ERROR, logger="sentinel.telegram.bot"):
        run(scenariu())

    mesaje = [r.getMessage() for r in caplog.records]
    assert any("plan request task died" in m for m in mesaje), mesaje


def test_cererea_manuala_nu_e_etichetata_ca_output_automat(monkeypatch, cheie):
    """`generated_by` decide, în `unnotified_plans` și în
    `unnotified_window_gated_plans`, dacă planul e output nesupravegheat al
    planner-ului automat. Etichetat `'ai'`, planul cerut de operator ar primi, la
    15 secunde după ce i-a ajuns cu butoane, și anunțul „fereastra nu l-a
    eliberat" — o contrazicere pe telefon."""
    vazut: list = []

    async def _generate(db, cfg, api_key, finding_id, *, generated_by="ai"):
        vazut.append(generated_by)
        return None, "oprit aici"

    _finding_este(monkeypatch, _finding())
    _fara_plan_viu(monkeypatch)
    monkeypatch.setattr(planner, "generate", _generate)

    async def scenariu():
        update, _msg = _update()
        await bot.cmd_planifica(update, _ctx())
        await bot._plan_requests[FINDING_ID]

    run(scenariu())

    assert vazut == [bot.MANUAL_PLAN_ORIGIN]
    assert bot.MANUAL_PLAN_ORIGIN != "ai"
