"""Token accounting and the hard spend cap.

Before every model call the worker asks `allowed()`; after every call it
`record()`s the usage. Once the day's or month's estimated spend crosses the
configured cap, `allowed()` returns False and the model is simply not called —
the deterministic verdict stands and the incident is left for the next window.
An event storm therefore costs a bounded amount, never an open-ended one.

Costs are ESTIMATED from published per-token pricing. A cap does not need to be
billing-accurate; it needs to stop spending near the right number, which this does.
"""

from __future__ import annotations

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# USD per token (input, output, cached-input). Matched by tier substring so the
# exact dated model id still resolves. Approximate — the cap is a safety net.
_PRICING = {
    "haiku": (1.00e-6, 5.00e-6, 0.10e-6),
    "sonnet": (3.00e-6, 15.00e-6, 0.30e-6),
    "opus": (15.00e-6, 75.00e-6, 1.50e-6),
}
_DEFAULT = _PRICING["sonnet"]


def _rates(model: str) -> tuple[float, float, float]:
    m = model.lower()
    for tier, rates in _PRICING.items():
        if tier in m:
            return rates
    return _DEFAULT


def estimate_cost(model: str, input_tokens: int, output_tokens: int,
                  cached_tokens: int = 0) -> float:
    r_in, r_out, r_cache = _rates(model)
    fresh_in = max(0, input_tokens - cached_tokens)
    return fresh_in * r_in + cached_tokens * r_cache + output_tokens * r_out


async def record(db: Database, *, purpose: str, model: str, input_tokens: int,
                 output_tokens: int, cached_tokens: int = 0, cache_write_tokens: int = 0,
                 transport: str = "api", duration_ms: int | None = None) -> float:
    """Write one usage row into the ai_usage table (schema from 0006). `purpose`
    is stored as `kind`, cached reads as `cache_read_tokens`."""
    cost = estimate_cost(model, input_tokens, output_tokens, cached_tokens)
    await db.execute(
        """
        INSERT INTO ai_usage
            (kind, transport, model, input_tokens, output_tokens,
             cache_read_tokens, cache_write_tokens, cost_usd, duration_ms)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        purpose, transport, model, input_tokens, output_tokens,
        cached_tokens, cache_write_tokens, cost, duration_ms)
    return cost


async def spent_today(db: Database) -> float:
    return float(await db.fetchval(
        "SELECT COALESCE(sum(cost_usd), 0) FROM ai_usage WHERE at::date = CURRENT_DATE") or 0)


# Începutul lunii, scris O SINGURĂ DATĂ: plafonul lunar (`spent_month`) și contorul din
# bara laterală (`usage_totals`) răspund la „cât s-a cheltuit luna asta", iar două copii ale
# predicatului ar ajunge să însemne două luni — contorul ar arăta 12 $ în timp ce plafonul,
# care decide dacă mai pleacă un apel, ar socoti 40.
MONTH_START_SQL = "date_trunc('month', CURRENT_DATE)"


async def spent_month(db: Database) -> float:
    return float(await db.fetchval(
        "SELECT COALESCE(sum(cost_usd), 0) FROM ai_usage "
        f"WHERE at >= {MONTH_START_SQL}") or 0)


async def usage_totals(db: Database) -> dict[str, float | int]:
    """Ce a costat modelul și de câte ori a fost chemat: luna asta și de la început.

    Citit din `ai_usage`, adică din ce a ÎNREGISTRAT `record()` — un apel care nu și-a scris
    rândul nu e numărat aici, iar contorul nu pretinde altceva. O linie = un apel la model,
    chiar dacă răspunsul n-a putut fi folosit: s-a plătit oricum.

    Luna e cea a plafonului (`MONTH_START_SQL`); „de la început" e suma pe tot tabelul. O
    singură interogare, ca cele două perechi să vină din același instantaneu.
    """
    row = await db.fetchrow(
        f"""
        SELECT count(*)                                           AS runs,
               COALESCE(sum(cost_usd), 0)                         AS cost,
               count(*) FILTER (WHERE at >= {MONTH_START_SQL})    AS month_runs,
               COALESCE(sum(cost_usd) FILTER (WHERE at >= {MONTH_START_SQL}), 0)
                                                                  AS month_cost
        FROM ai_usage
        """)
    return {"runs": int(row["runs"]), "cost": float(row["cost"]),
            "month_runs": int(row["month_runs"]), "month_cost": float(row["month_cost"])}


async def allowed(db: Database, cfg: Config) -> tuple[bool, str]:
    """May we spend on another call? Returns (allowed, reason-if-not)."""
    if not cfg.ai.enabled:
        return False, "ai disabled"
    day = await spent_today(db)
    if day >= cfg.ai.daily_budget_usd:
        return False, f"daily cap reached (${day:.2f}/${cfg.ai.daily_budget_usd:.2f})"
    month = await spent_month(db)
    if month >= cfg.ai.monthly_budget_usd:
        return False, f"monthly cap reached (${month:.2f}/${cfg.ai.monthly_budget_usd:.2f})"
    return True, ""
