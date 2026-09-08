"""T3 din audit: o alertă a cărei trimitere a eșuat era PIERDUTĂ, nu ținută.

Trei defecte separate, măsurate pe o gazdă de producție pe 5 septembrie 2026
(20 de rânduri din `notifications`, 13 critice, pierdute definitiv):

* `_push_incidents`/`_push_incident_digest` marcau `mark_notified` INDIFERENT
  de câți `chat_id` chiar au primit mesajul — `_broadcast` întorcea 0, iar
  incidentul dispărea din coadă oricum;
* `_push_notifications` marca `failed` după O SINGURĂ încercare eșuată,
  fără nicio a doua șansă;
* `RetryAfter` (limitare de rată Telegram, 429) era tratat identic cu orice
  altă excepție, deși e singurul caz în care Telegram spune exact cât să
  aștepți.

Testele astea verifică EFECTUL: ce se scrie în baza de date (simulată) și ce
se cheamă mai departe, nu doar că funcțiile rulează fără să arunce.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.db.repo.incidents import IncidentRow  # noqa: E402
from sentinel.telegram import bot  # noqa: E402

KEY = b"test-fixture-hmac-key"
CHAT_A, CHAT_B = 700000001, 700000002
NOW = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)


def run(c):
    return asyncio.run(c)


def _incident(id_=1, severity="high") -> IncidentRow:
    return IncidentRow(
        id=id_, fingerprint=f"f{id_}", status="open", severity=severity,
        title="t", summary=None, actor_key="203.0.113.7", detection_count=1,
        first_detection_at=NOW, last_detection_at=NOW, ai_severity=None,
        notified_at=None, auto_action=None)


def _cfg():
    return SimpleNamespace(
        telegram=SimpleNamespace(allowed_chat_ids=[CHAT_A, CHAT_B], min_severity="medium",
                                 digest_threshold=10, callback_ttl_s=600),
        response=SimpleNamespace(auto_block=SimpleNamespace(default_ttl_s=86400)))


class _FakeBot:
    """`send_message` configurabil per test: fie reușește pe toate chat-urile,
    fie eșuează pe toate — exact granularitatea de care au nevoie testele de
    mai jos."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.sent: list[int] = []

    async def send_message(self, chat_id, text, **_kw):
        if self.fail:
            raise RuntimeError("simulated send failure")
        self.sent.append(chat_id)


def _app(fail: bool = False):
    return SimpleNamespace(bot=_FakeBot(fail=fail), bot_data={"callback_hmac_key": KEY})


# ---------------------------------------------------------------------------
# _push_incidents: marcat doar dacă a chiar ajuns undeva
# ---------------------------------------------------------------------------
async def _unnotified_one(db, **kw):
    return [_incident()]


def test_an_incident_reaching_nobody_is_not_marked_notified(monkeypatch):
    marked = []

    async def _mark(db, inc_id):
        marked.append(inc_id)

    monkeypatch.setattr(bot.inc_repo, "unnotified", _unnotified_one)
    monkeypatch.setattr(bot.inc_repo, "mark_notified", _mark)

    app = _app(fail=True)  # toate trimiterile eșuează
    run(bot._push_incidents(app, _cfg(), db=SimpleNamespace(), quiet_chats=set()))

    assert marked == [], (
        "incidentul a fost marcat notificat deși NICIUN chat n-a primit mesajul "
        "— exact pierderea măsurată pe 5 septembrie 2026")


def test_an_incident_that_reaches_at_least_one_chat_is_marked(monkeypatch):
    marked = []

    async def _mark(db, inc_id):
        marked.append(inc_id)

    monkeypatch.setattr(bot.inc_repo, "unnotified", _unnotified_one)
    monkeypatch.setattr(bot.inc_repo, "mark_notified", _mark)

    app = _app(fail=False)
    run(bot._push_incidents(app, _cfg(), db=SimpleNamespace(), quiet_chats=set()))

    assert marked == [1], "contra-proba: un incident livrat TREBUIE marcat"


def test_only_the_delivered_incident_is_marked_in_a_mixed_batch(monkeypatch):
    """Lotul de liniște amestecat, cerut explicit în audit: ambele chat-uri
    sunt în fereastra de liniște, dar un incident CRITIC trece oricum
    (`passes_anyway`) iar unul obișnuit nu — un singur apel spre
    `_push_incidents` trebuie să marcheze DOAR incidentul care chiar a ajuns
    undeva, nu tot lotul deodată."""
    async def _unnotified_two(db, **kw):
        return [_incident(id_=1, severity="critical"), _incident(id_=2, severity="high")]

    marked = []

    async def _mark(db, inc_id):
        marked.append(inc_id)

    monkeypatch.setattr(bot.inc_repo, "unnotified", _unnotified_two)
    monkeypatch.setattr(bot.inc_repo, "mark_notified", _mark)

    app = _app(fail=False)
    both_chats_quiet = {CHAT_A, CHAT_B}
    run(bot._push_incidents(app, _cfg(), db=SimpleNamespace(), quiet_chats=both_chats_quiet))

    assert marked == [1], (
        f"doar incidentul critic (#1) trecea peste liniște — marcat: {marked}")


# ---------------------------------------------------------------------------
# _push_notifications: reținut, nu eșuat, cât mai are încercări
# ---------------------------------------------------------------------------
class _NotifDB:
    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows
        self.updates: list[tuple] = []

    async def fetch(self, sql, *a):
        return list(self.rows)

    async def execute(self, sql, *a):
        self.updates.append((sql, a))
        return "UPDATE 1"


def _row(**over):
    base = {"id": 1, "severity": "medium", "title": "t", "body": "corp",
            "kind": "selfcheck", "buttons": "[]", "enqueued_at": NOW, "attempts": 0}
    base.update(over)
    return base


def test_a_failed_send_is_not_marked_failed_after_one_attempt():
    """Pierdut pe 5 septembrie: 20 de rânduri, 13 critice, `failed` după o
    singură încercare, niciodată reîncercate."""
    db = _NotifDB([_row()])
    app = _app(fail=True)
    run(bot._push_notifications(app, _cfg(), db, quiet_chats=set()))

    states = [u for u in db.updates if "state = 'failed'" in u[0]]
    assert not states, "un singur eșec nu are voie să marcheze failed"
    attempted = [u for u in db.updates if "attempts = $2" in u[0]]
    assert attempted and attempted[0][1] == (1, 1, "trimitere eșuată — se reîncearcă")


def test_a_row_gives_up_only_after_the_attempt_cap():
    """Contra-proba plafonului: la a cincea încercare (MAX_NOTIFICATION_ATTEMPTS),
    rândul chiar trebuie marcat `failed`, cu ultima eroare — altfel un rând
    stricat rămâne veșnic `queued`, reîncercat la infinit."""
    db = _NotifDB([_row(attempts=bot.MAX_NOTIFICATION_ATTEMPTS - 1,
                        enqueued_at=datetime.now(timezone.utc) - timedelta(hours=1))])
    app = _app(fail=True)
    run(bot._push_notifications(app, _cfg(), db, quiet_chats=set()))

    failed = [u for u in db.updates if "state = 'failed'" in u[0]]
    assert failed, "trebuia să renunțe după plafonul de încercări"
    assert failed[0][1][1] == bot.MAX_NOTIFICATION_ATTEMPTS


def test_a_successful_send_marks_sent_not_failed():
    db = _NotifDB([_row()])
    app = _app(fail=False)
    run(bot._push_notifications(app, _cfg(), db, quiet_chats=set()))

    sent = [u for u in db.updates if "state = 'sent'" in u[0]]
    assert sent and sent[0][1] == (1,)


def test_a_row_not_yet_due_for_retry_is_left_alone():
    """Ritmul exponențial: imediat după primul eșec, rândul nu trebuie
    reîncercat la FIECARE ciclu de 15s — altfel o pană scurtă e lovită la
    fiecare tick în loc să aștepte, exact zgomotul pe care backoff-ul
    există să-l evite.

    `enqueued_at` e „acum" REAL (timpul de execuție al testului), nu o dată
    fixă — pragul de 15s la prima reîncercare (`attempts=1`) nu are cum să fi
    trecut deja între linia asta și apelul de mai jos.
    """
    just_now = datetime.now(timezone.utc)
    db = _NotifDB([_row(attempts=1, enqueued_at=just_now)])  # abia eșuat o dată
    app = _app(fail=True)

    run(bot._push_notifications(app, _cfg(), db, quiet_chats=set()))

    assert db.updates == [], "rândul nu era încă scadent pentru reîncercare"


def test_a_row_due_after_the_backoff_window_is_retried():
    """Contra-proba: după ce pragul chiar a trecut, reîncercarea are loc."""
    long_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    db = _NotifDB([_row(attempts=1, enqueued_at=long_ago)])
    app = _app(fail=False)

    run(bot._push_notifications(app, _cfg(), db, quiet_chats=set()))

    assert any("state = 'sent'" in u[0] for u in db.updates)


# ---------------------------------------------------------------------------
# RetryAfter: onorat, nu tratat ca orice altă eroare
# ---------------------------------------------------------------------------
def test_retry_after_is_honoured_with_one_extra_attempt(monkeypatch):
    """Fostul comportament: `RetryAfter` cădea în `except Exception`, ca orice
    alt eșec — rândul pierdea exact fereastra pe care Telegram i-o oferise."""
    from telegram.error import RetryAfter

    calls = {"n": 0}

    class _RateLimitedBot:
        async def send_message(self, chat_id, text, **_kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RetryAfter(1)  # o so
            return None

    sleeps = []

    async def _fast_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr(bot.asyncio, "sleep", _fast_sleep)

    app = SimpleNamespace(bot=_RateLimitedBot(), bot_data={"callback_hmac_key": KEY})
    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=[CHAT_A]))
    sent = run(bot._broadcast(app, cfg, "text"))

    assert sent == 1, "trimiterea trebuia să reușească la a doua încercare"
    assert sleeps, "trebuia să aștepte, nu doar să reîncerce imediat"
