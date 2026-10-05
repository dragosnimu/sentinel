"""Un rând `sent` trebuie să poarte dovada că Telegram a primit mesajul.

Plângerea operatorului, 5 octombrie 2026: «alerta de sesiune a apărut doar după
restart server». Rândul din `notifications` spunea `state='sent'`, `attempts=1`,
`error` gol — iar `message_id` era NULL, ca pe TOATE rândurile, inclusiv pe cel
care a ajuns. Deci din bază nu se putea deosebi un mesaj livrat de unul doar
presupus livrat, iar „a fost trimis" era o afirmație fără nimic în spate.

(Ce s-a MĂSURAT pe gazdă în aceeași zi, ca să nu se confunde cu ce se
dovedește aici: jurnalul botului are linia `notification pushed` pentru id 471,
la 09:53:09 ora locală, cu `chats: 1`. Telegram a primit deci mesajul. Ce n-a
putut spune nimeni era unde anume a ajuns — și asta repară testele de mai jos.)

Două feluri de dovadă:

* testele cu `_NotifDB` și un dublu de bot probează DECIZIA — ce se scrie în
  rând pentru fiecare răspuns posibil;
* testele cu `FakeTelegramApi` pornesc un server HTTP local și trec mesajul
  prin `StampingBot` — clasa chiar folosită pe gazdă —, deci probează și
  transportul: formularul pe care PTB îl trimite, răspunsul pe care îl parsează.

**Ce NU dovedește nimic de aici, spus pe față:** că un chat REAL a primit
mesajul. Nu există un bot viu în harness, iar un mesaj trimis operatorului
dintr-un test ar fi exact zgomotul pe care canalul nu-l poate suporta. Dublul
de server confirmă că cererea e cea pe care API-ul o așteaptă (`chat_id`,
`text`, `parse_mode`, `reply_markup`) și că răspunsul lui e citit corect; nu
confirmă ce face Telegram cu ea.
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest

pytest.importorskip("telegram")

import sentinel.config as sentinel_config  # noqa: E402
from sentinel.detect import logins as detect_logins  # noqa: E402
from sentinel.telegram import bot  # noqa: E402

CHAT_A, CHAT_B = -1009999000001, -1009999000002
NOW = datetime(2026, 10, 5, 6, 52, 54, tzinfo=timezone.utc)
TZ = "Europe/Bucharest"
HMAC = "notification-delivery-test-key-not-real"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _hmac_key(monkeypatch):
    """Fără cheie, butonul «Nu sunt eu» nu se emite — vezi `logins._buttons`."""
    monkeypatch.setattr(sentinel_config, "get_secrets",
                        lambda: SimpleNamespace(
                            get=lambda n, d=None: HMAC if n == "TELEGRAM_CALLBACK_HMAC_KEY" else d))


# ---------------------------------------------------------------------------
# Un «Telegram» local
# ---------------------------------------------------------------------------
class FakeTelegramApi:
    """Server HTTP care vorbește metoda `sendMessage` a Bot API.

    Ține fiecare cerere primită (`chat_id`, `text`, `reply_markup` decodate) și
    răspunde cum e configurat per chat: `ok` cu un `message_id` pe care îl
    alege el, sau o eroare în formatul API-ului (`{"ok": false, ...}`).
    """

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.refuse: dict[int, tuple[int, str]] = {}
        self._next_id = 4700
        api = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 — numele cerut de stdlib
                body = self.rfile.read(int(self.headers.get("content-length", 0)))
                form = {k: v[0] for k, v in parse_qs(body.decode("utf-8")).items()}
                chat = int(form.get("chat_id", "0"))
                api.requests.append({
                    "path": self.path, "chat_id": chat,
                    "text": form.get("text", ""),
                    "parse_mode": form.get("parse_mode"),
                    "reply_markup": json.loads(form["reply_markup"])
                    if "reply_markup" in form else None,
                })
                if chat in api.refuse:
                    code, why = api.refuse[chat]
                    out, status = {"ok": False, "error_code": code, "description": why}, code
                else:
                    api._next_id += 1
                    out, status = {"ok": True, "result": {
                        "message_id": api._next_id, "date": 1760000000,
                        "chat": {"id": chat, "type": "group", "title": "g"},
                        "text": form.get("text", "")}}, 200
                raw = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_a) -> None:  # tăcut: nu poluează raportul
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "FakeTelegramApi":
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._server.shutdown()
        self._server.server_close()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/bot"


def _real_bot(api: FakeTelegramApi):
    """`StampingBot` — clasa de pe gazdă —, îndreptat spre serverul local."""
    from telegram.request import HTTPXRequest

    return bot.StampingBot(
        "123456:test-token-not-real", label="test", base_url=api.base_url,
        request=HTTPXRequest(connection_pool_size=4),
        get_updates_request=HTTPXRequest(connection_pool_size=1))


def _cfg(*chats: int):
    return SimpleNamespace(telegram=SimpleNamespace(
        allowed_chat_ids=list(chats), quiet_hours=None, timezone=TZ))


# ---------------------------------------------------------------------------
# O bază care poartă tot lanțul: logare -> coadă -> trimitere
# ---------------------------------------------------------------------------
class _ChainDB:
    """Dublu pentru `announce_new_sessions` ȘI `_push_notifications`.

    Cele două jumătăți ale lanțului scriu și citesc același tabel `notifications`;
    un dublu pentru fiecare ar fi lăsat o cusătură netestată chiar între ele — adică
    exact locul în care rândul poate ajunge `sent` fără să fi ajuns nicăieri.
    """

    def __init__(self, sessions: list[dict]) -> None:
        self.sessions = sessions
        self.notifications: list[dict] = []
        self.updates: list[tuple[str, tuple]] = []
        self.fail_sent_update = False
        self.sent_update_status = "UPDATE 1"

    async def fetch(self, sql, *a):
        if "FROM login_sessions" in sql:
            assert "alerted_at IS NULL" in sql and "interactive = true" in sql, sql
            cols = [c.strip().rsplit(" AS ", 1)[-1].strip()
                    for c in sql.split("SELECT", 1)[1].split("FROM", 1)[0].split(",")]
            return [{c: s.get(c) for c in cols} for s in self.sessions
                    if s.get("alerted_at") is None and s.get("interactive")]
        if "FROM notifications WHERE state = 'queued'" in sql:
            return [dict(n) for n in self.notifications if n["state"] == "queued"][:5]
        raise AssertionError(f"fetch nerecunoscut: {sql}")

    async def fetchval(self, sql, *a):
        assert "min(first_seen)" in sql, sql
        return None

    async def fetchrow(self, sql, *a):
        assert "INSERT INTO login_baseline" in sql, sql
        return {"seen_count": 1, "inserted": True}

    async def execute(self, sql, *a):
        if "INSERT INTO notifications" in sql:
            self.notifications.append({
                "id": 471, "severity": a[0], "kind": a[1], "dedup_key": a[2],
                "title": a[3], "body": a[4], "buttons": a[5], "state": "queued",
                "enqueued_at": NOW, "attempts": 0, "error": None, "message_id": None,
                "sent_at": None, "channel": "telegram"})
            return "INSERT 0 1"
        if "UPDATE login_sessions SET alerted_at" in sql:
            for s in self.sessions:
                if s["id"] == a[0]:
                    s["alerted_at"] = NOW
            return "UPDATE 1"
        if "UPDATE notifications SET" in sql:
            self.updates.append((sql, a))
            row = next(n for n in self.notifications if n["id"] == a[0])
            if "state = 'sent'" in sql:
                if self.fail_sent_update:
                    raise ConnectionError("baza a căzut după trimitere")
                # Se aplică CHIAR ce spune instrucțiunea: un `UPDATE` fără
                # `message_id` în `SET` lasă coloana NULL și testul vede.
                row["state"] = "sent"
                row["attempts"] += 1
                if "message_id = $2" in sql:
                    row["message_id"] = a[1]
                if "error = $3" in sql:
                    row["error"] = a[2]
                return self.sent_update_status
            if "state = 'failed'" in sql:
                row.update(state="failed", attempts=a[1], error=a[2])
            else:
                row.update(attempts=a[1], error=a[2])
            return "UPDATE 1"
        raise AssertionError(f"execute nerecunoscut: {sql}")


def _session(**over) -> dict:
    base = {"id": 46797, "session_key": "455", "username": "operator",
            "src_ip": "198.51.100.7", "terminal": "pts0", "interactive": True,
            "opened_at": NOW, "closed_at": None, "command_count": 0,
            "sudo_count": 0, "alerted_at": None}
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# Lanțul întreg, prin transportul real
# ---------------------------------------------------------------------------
def test_a_login_alert_reaches_the_chat_and_the_row_carries_the_proof():
    """Plângerea: alerta de logare n-a ajuns la operator, iar rândul nu spunea
    nimic care s-o dovedească sau s-o infirme.

    Lanțul rulează întreg, cu cod real: `announce_new_sessions` pune rândul în
    coadă, `_push_notifications` îl trimite prin `StampingBot` către un server HTTP
    local, iar rândul trebuie să iasă `sent` cu EXACT `message_id`-ul pe care l-a
    ales serverul. Dacă `message_id` ar fi rămas NULL, operatorul n-ar fi putut
    căuta mesajul în chat — nici pentru a-l găsi, nici pentru a vedea că lipsește.
    """
    db = _ChainDB([_session()])
    assert run(detect_logins.announce_new_sessions(db, tz_name=TZ)) == 1

    with FakeTelegramApi() as api:
        app = SimpleNamespace(bot=_real_bot(api), bot_data={})
        run(bot._push_notifications(app, _cfg(CHAT_A), db, quiet_chats=set()))

    assert len(api.requests) == 1, "alerta trebuia să plece exact o dată"
    sent = api.requests[0]
    assert sent["path"].endswith("/sendMessage")
    assert sent["chat_id"] == CHAT_A
    assert sent["parse_mode"] == "HTML"
    assert "Logare pe server" in sent["text"]
    assert "operator" in sent["text"] and "198.51.100.7" in sent["text"]
    # Butoanele ajung la Telegram ca tastatură inline, nu se pierd pe drum.
    texte = [b["text"] for rand in sent["reply_markup"]["inline_keyboard"] for b in rand]
    assert texte == ["✔️ Am văzut", "🚨 Nu sunt eu"]

    row = db.notifications[0]
    assert row["state"] == "sent"
    assert row["message_id"] == 4701, (
        "rândul e `sent`, dar nu poartă numărul mesajului pe care l-a dat Telegram "
        f"(a primit {row['message_id']!r}) — exact lipsa care a făcut imposibil de "
        "spus dacă alerta a ajuns")
    assert row["error"] is None


def test_telegram_refusing_the_chat_never_marks_the_row_sent():
    """Telegram răspunde `400 chat not found` (grupul a fost migrat, botul a fost
    scos). `send_message` aruncă `BadRequest`, iar rândul NU are voie să devină
    `sent`: ar fi o alertă de securitate dată drept trimisă și pierdută.
    """
    db = _ChainDB([_session()])
    run(detect_logins.announce_new_sessions(db, tz_name=TZ))

    with FakeTelegramApi() as api:
        api.refuse[CHAT_A] = (400, "Bad Request: chat not found")
        app = SimpleNamespace(bot=_real_bot(api), bot_data={})
        run(bot._push_notifications(app, _cfg(CHAT_A), db, quiet_chats=set()))

    row = db.notifications[0]
    assert row["state"] == "queued", "rămâne în coadă, ca să se reîncerce"
    assert row["message_id"] is None
    assert row["attempts"] == 1
    assert row["error"] == "trimitere eșuată — se reîncearcă"


# ---------------------------------------------------------------------------
# Decizia, pe fiecare răspuns posibil
# ---------------------------------------------------------------------------
class _Bot:
    """Dublu de bot cu un răspuns configurat PER CHAT: un `Message`, `None`, sau
    o excepție."""

    def __init__(self, per_chat: dict) -> None:
        self.per_chat = per_chat

    async def send_message(self, chat_id, text, **_kw):
        out = self.per_chat[chat_id]
        if isinstance(out, Exception):
            raise out
        return out


def _queued_db() -> _ChainDB:
    db = _ChainDB([])
    db.notifications.append({
        "id": 471, "severity": "info", "kind": "login", "dedup_key": "login:455",
        "title": "Logare pe server", "body": "corp", "buttons": "[]",
        "state": "queued", "enqueued_at": NOW, "attempts": 0, "error": None,
        "message_id": None, "sent_at": None, "channel": "telegram"})
    return db


def test_a_call_that_returns_without_a_message_id_is_not_a_delivery():
    """`send_message` care nu aruncă NU e dovadă. Dacă transportul ar fi înlocuit
    sau stricat astfel încât să întoarcă `None`, rândul vechi devenea `sent` — chiar
    forma plângerii: «trimis» fără nimic care să arate că a ajuns.

    Acum rămâne `queued`, cu un `error` care spune de ce (nu «eșec de rețea»,
    fiindcă reîncercarea poate dubla mesajul și cine citește rândul trebuie să știe).
    """
    db = _queued_db()
    app = SimpleNamespace(bot=_Bot({CHAT_A: None}), bot_data={})
    run(bot._push_notifications(app, _cfg(CHAT_A), db, quiet_chats=set()))

    row = db.notifications[0]
    assert row["state"] == "queued"
    assert row["message_id"] is None
    assert "fără message_id" in row["error"]


@pytest.mark.parametrize("answer", [True, 0, -5, "4711", 4711.0])
def test_only_a_positive_integer_counts_as_a_message_id(answer):
    """`True` e un `int` pentru Python și ar trece drept mesajul numărul 1.
    Un `message_id` șir sau float nu vine de la Bot API."""
    db = _queued_db()
    app = SimpleNamespace(bot=_Bot({CHAT_A: SimpleNamespace(message_id=answer)}),
                          bot_data={})
    run(bot._push_notifications(app, _cfg(CHAT_A), db, quiet_chats=set()))
    assert db.notifications[0]["state"] == "queued", (
        f"{answer!r} a fost luat drept dovadă de livrare")


def test_the_unconfirmed_row_gives_up_loudly_after_the_attempt_cap():
    """Dacă răspunsul fără număr se repetă, rândul nu rămâne veșnic `queued` și nu
    devine `sent`: ajunge `failed`, cu un motiv care nu spune «n-a primit-o
    nimeni» despre un mesaj pe care Telegram l-a acceptat."""
    db = _queued_db()
    db.notifications[0]["attempts"] = bot.MAX_NOTIFICATION_ATTEMPTS - 1
    db.notifications[0]["enqueued_at"] = datetime.now(timezone.utc) - timedelta(hours=1)
    app = SimpleNamespace(bot=_Bot({CHAT_A: None}), bot_data={})
    run(bot._push_notifications(app, _cfg(CHAT_A), db, quiet_chats=set()))

    row = db.notifications[0]
    assert row["state"] == "failed"
    assert "confirmat" in row["error"]


def test_a_partial_delivery_stays_sent_but_says_who_missed_it():
    """Două chaturi, unul refuză. Rândul rămâne `sent` — a-l reîncerca ar dubla
    mesajul în chatul care l-a primit —, dar `error` spune ce chat a lipsit. Un
    rând `sent` cu `error` gol ar afirma «a ajuns peste tot»."""
    db = _queued_db()
    app = SimpleNamespace(bot=_Bot({CHAT_A: SimpleNamespace(message_id=88),
                                    CHAT_B: RuntimeError("Forbidden: bot was kicked")}),
                          bot_data={})
    run(bot._push_notifications(app, _cfg(CHAT_A, CHAT_B), db, quiet_chats=set()))

    row = db.notifications[0]
    assert row["state"] == "sent"
    assert row["message_id"] == 88
    assert "1 din 2" in row["error"]
    assert str(CHAT_B) in row["error"] and "kicked" in row["error"]


def test_the_journal_line_exists_even_when_the_database_fails_right_after():
    """Livrarea e ireversibilă. Dacă `UPDATE`-ul pică imediat după, rândul rămâne
    `queued` și mesajul se retrimite — iar jurnalul trebuie să arate că PRIMA
    copie a existat, cu numărul ei, ca dublura să se poată explica."""
    db = _queued_db()
    db.fail_sent_update = True
    app = SimpleNamespace(bot=_Bot({CHAT_A: SimpleNamespace(message_id=321)}),
                          bot_data={})
    records: list[logging.LogRecord] = []

    class _Grab(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Grab(level=logging.DEBUG)
    bot.log.addHandler(handler)
    try:
        with pytest.raises(ConnectionError):
            run(bot._push_notifications(app, _cfg(CHAT_A), db, quiet_chats=set()))
    finally:
        bot.log.removeHandler(handler)

    pushed = [r for r in records if r.getMessage() == "notification pushed"]
    assert pushed and pushed[0].message_id == 321, (
        "livrarea s-a întâmplat și jurnalul n-are nicio urmă a ei")


def test_a_row_that_is_no_longer_queued_is_reported_not_overwritten():
    """`UPDATE … WHERE state = 'queued'` care nu atinge niciun rând (`UPDATE 0`)
    înseamnă că altcineva a schimbat rândul între citire și scriere. Mesajul a
    plecat oricum; ce nu se poate e tăcerea."""
    db = _queued_db()
    db.sent_update_status = "UPDATE 0"
    app = SimpleNamespace(bot=_Bot({CHAT_A: SimpleNamespace(message_id=5)}),
                          bot_data={})
    records: list[logging.LogRecord] = []

    class _Grab(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Grab(level=logging.DEBUG)
    bot.log.addHandler(handler)
    try:
        run(bot._push_notifications(app, _cfg(CHAT_A), db, quiet_chats=set()))
    finally:
        bot.log.removeHandler(handler)

    assert any(r.getMessage() == "notification delivered but its row was no longer queued"
               for r in records)
    sql = db.updates[0][0]
    assert "AND state = 'queued'" in sql, (
        "fără condiția de stare, un rând deja `failed` sau `suppressed` ar fi "
        "rescris ca `sent`")


# ---------------------------------------------------------------------------
# `_broadcast` rămâne ce era pentru ceilalți apelanți
# ---------------------------------------------------------------------------
def test_broadcast_still_counts_accepted_calls_for_its_other_callers():
    """Incidentele, planurile și rezumatele cheamă `_broadcast` și așteaptă un
    număr. Schimbarea de aici nu are voie să le schimbe contractul: un `None` de la
    un dublu rămâne «a plecat», ca până acum."""
    app = SimpleNamespace(bot=_Bot({CHAT_A: None, CHAT_B: SimpleNamespace(message_id=7)}),
                          bot_data={})
    assert run(bot._broadcast(app, _cfg(CHAT_A, CHAT_B), "text")) == 2
    app = SimpleNamespace(bot=_Bot({CHAT_A: RuntimeError("x"),
                                    CHAT_B: SimpleNamespace(message_id=7)}),
                          bot_data={})
    assert run(bot._broadcast(app, _cfg(CHAT_A, CHAT_B), "text")) == 1
