"""High-level block / unblock / flush, tying the executor to the DB record.

The executor is the authority on WHAT may be blocked — it re-checks its own
never-block policy on every request, so nothing here can widen it. This layer
adds three things the executor deliberately does not: a friendly early rejection
for the obvious cases (so the operator sees "that's your own network" instead of
a bare refusal), the durable history row, and the audit entry.

The executor client is a blocking socket call; it runs in a thread so a slow or
stuck executor cannot freeze the web or the bot's event loop.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from sentinel.db.engine import Database
from sentinel.db.repo import audit as audit_repo
from sentinel.db.repo import blocklist as blocklist_repo
from sentinel.errors import ExecutorRejected, ExecutorUnavailable
from sentinel.logging_setup import get_logger
from sentinel.respond.executor_client import ExecutorClient

log = get_logger(__name__)

_client = ExecutorClient()


class BlockRefused(Exception):
    """A block the caller should not even attempt — loopback, own network, bad IP."""


def _validate_target(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise BlockRefused(f"'{ip}' nu este o adresă IP validă") from exc
    if addr.is_loopback:
        raise BlockRefused("nu se blochează loopback (127.0.0.1/::1)")
    if addr.is_private:
        raise BlockRefused("nu se blochează o adresă privată (RFC1918) — ar putea fi rețeaua ta")
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        raise BlockRefused("adresă rezervată/multicast — nu se blochează")
    return addr


async def block(
    db: Database,
    ip: str,
    *,
    ttl: int | None,
    reason: str,
    by: str,
    incident_id: int | None = None,
    actor_key: str | None = None,
) -> dict[str, Any]:
    """Block one address. Raises BlockRefused / ExecutorRejected / ExecutorUnavailable."""
    _validate_target(ip)  # fast, friendly precheck; the executor is the real gate
    result = await asyncio.to_thread(_client.block_ip, ip, ttl, reason, incident_id)

    await blocklist_repo.record_block(
        db, ip=ip, reason=reason, created_by=by, ttl_seconds=ttl,
        incident_id=incident_id, actor_key=actor_key,
    )
    await audit_repo.record(
        db, actor=by, source="respond", operation="block_ip", target=ip,
        params={"ttl": ttl, "reason": reason, "incident_id": incident_id}, result="ok",
    )
    log.info("ip blocked", extra={"ip": ip, "ttl": ttl, "by": by})
    return result


class SelfLockoutRefused(Exception):
    """Adresa e a operatorului. Blocarea ei l-ar închide pe el afară."""


async def is_allowlisted(db: Database, ip: str) -> bool:
    """Adresa e în allowlist — adică declarată a ta.

    `>>=` e operatorul de apartenență al lui PostgreSQL: „rețeaua asta conține
    adresa asta". Allowlist-ul ține CIDR-uri, nu adrese: un `=` ar rata un
    `198.51.100.0/24` pus acolo tocmai fiindcă adresa de acasă se schimbă în
    interiorul lui. Iar o gardă de auto-încuiere care ratează exact cazul pentru
    care a fost scrisă e mai rea decât una absentă.
    """
    return bool(await db.fetchval(
        """
        SELECT 1 FROM allowlist
         WHERE confirmed = true
           AND (expires_at IS NULL OR expires_at > now())
           AND cidr >>= $1::inet
         LIMIT 1
        """,
        ip))


async def block_and_terminate(db: Database, ip: str, session_key: str, *,
                              by: str, reason: str) -> dict[str, Any]:
    """Blochează adresa ȘI închide sesiunea deschisă. Butonul «nu sunt eu».

    Ordinea contează și e cea aleasă dinadins: întâi blocarea, apoi închiderea.
    Invers, cine e închis se poate reconecta în secunda dintre cele două — iar
    fereastra aia e exact cât îi trebuie cuiva care se uită la ecran.

    ## Garda de auto-încuiere

    O adresă din allowlist NU se blochează, oricât ar fi apăsat butonul. Sentinel
    are deja lista aia cu peer-ul SSH al operatorului, iar butonul ăsta e cel mai
    ușor de apăsat greșit din tot sistemul: sosește pe telefon, la ora la care
    tocmai te-ai logat, cu textul «cineva s-a logat pe server».

    Costul, spus pe față: dacă cineva chiar intră de pe adresa ta, butonul nu-l
    scoate. Rămân `/block` — care nu are garda asta — și consola VPS-ului.

    Sesiunea SE ÎNCHIDE oricum, chiar dacă adresa e a ta: închiderea nu te lasă
    pe dinafară, doar te deconectează, iar dacă chiar altcineva folosește
    adresa ta, aia e jumătatea care contează.
    """
    protejata = await is_allowlisted(db, ip)
    rezultat: dict[str, Any] = {"ip": ip, "session_key": session_key,
                                "blocked": False, "terminated": False,
                                "allowlisted": protejata}

    if not protejata:
        await block(db, ip, ttl=None, reason=reason, by=by)
        rezultat["blocked"] = True

    inchisa = await asyncio.to_thread(_client.terminate_session, session_key)
    rezultat["terminated"] = bool(inchisa.get("terminated"))

    await audit_repo.record(
        db, actor=by, source="respond", operation="block_and_terminate", target=ip,
        params={"session_key": session_key, "reason": reason,
                "allowlisted": protejata},
        result="ok" if rezultat["terminated"] else "partial",
    )
    log.info("session terminated", extra=rezultat)
    return rezultat


async def unblock(db: Database, ip: str, *, by: str, reason: str = "manual") -> dict[str, Any]:
    result = await asyncio.to_thread(_client.unblock_ip, ip)
    n = await blocklist_repo.mark_unblocked(db, ip, by=by, reason=reason)
    await audit_repo.record(
        db, actor=by, source="respond", operation="unblock_ip", target=ip,
        params={"rows": n, "reason": reason}, result="ok",
    )
    log.info("ip unblocked", extra={"ip": ip, "by": by, "rows": n})
    return result


async def allow(db: Database, ip: str, *, by: str) -> dict[str, Any]:
    _validate_target  # noqa: B018 - allow accepts anything; validation is the executor's
    result = await asyncio.to_thread(_client.allow_ip, ip)
    await audit_repo.record(
        db, actor=by, source="respond", operation="allow_ip", target=ip, params={}, result="ok",
    )
    log.info("ip allowlisted", extra={"ip": ip, "by": by})
    return result


async def flush(db: Database, *, by: str, reason: str) -> dict[str, Any]:
    result = await asyncio.to_thread(_client.flush_blocklist, reason)
    n = await blocklist_repo.mark_all_unblocked(db, by=by, reason=reason)
    await audit_repo.record(
        db, actor=by, source="respond", operation="flush_blocklist", target="*",
        params={"rows": n, "reason": reason}, result="ok",
    )
    log.warning("blocklist flushed", extra={"by": by, "reason": reason, "rows": n})
    return result


async def live_count() -> int:
    """The element count the executor actually has in nftables, or -1 if unknown."""
    try:
        return await asyncio.to_thread(_client.blocklist_size)
    except (ExecutorRejected, ExecutorUnavailable):
        return -1


async def live_blocked() -> set[str] | None:
    """WHICH addresses the kernel is actually dropping, or None if unknown.

    None and an empty set mean different things and must not be confused: one
    is "the executor did not answer", the other is "nothing is blocked". A
    reconciler that treated the first as the second would mark every block in
    the database as released the moment the executor hiccupped.
    """
    from sentinel.respond.executor_client import _nft_elements

    try:
        sets = await asyncio.to_thread(_client.list_sets)
    except (ExecutorRejected, ExecutorUnavailable):
        return None
    out: set[str] = set()
    for name in ("blocklist_v4", "blocklist_v6"):
        data = sets.get(name)
        if isinstance(data, dict) and "error" not in data:
            out.update(_nft_elements(data))
    return out
