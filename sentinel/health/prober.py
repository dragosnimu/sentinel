"""Probe each asset for availability and record the result.

One probe per asset per tick. The probe method follows the asset's kind:

* **http**   — an HTTP request to the app through loopback; 2xx/3xx is up, a
               response with >=400 is degraded (reachable but unhealthy), no
               response is down.
* **tcp**    — a plain TCP connect; connected is up, refused/timeout is down.
* **systemd**— `systemctl is-active`; active is up, anything else down.
* **docker** — `docker inspect` running state.

A run of `down_after_failures` down samples opens an outage record; the first up
sample closes it. Availability is computed from the samples themselves
(health repo), so this module only has to be honest about each single probe.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

import httpx

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import assets as assets_repo
from sentinel.db.repo import health as health_repo
from sentinel.logging_setup import get_logger
from sentinel.util import shellsafe

log = get_logger(__name__)


@dataclass
class ProbeResult:
    status: str            # up | degraded | down | unknown
    probe: str
    latency_ms: int | None = None
    http_status: int | None = None
    error: str | None = None


async def _probe_http(asset: assets_repo.Asset, timeout_s: int) -> ProbeResult:
    # Probe the app directly on loopback, not through the public hostname: this
    # measures the service, not nginx, DNS or the network path — and it works
    # even while a certificate is being renewed.
    #
    # Probe "/" rather than a health endpoint: a third-party app (Snipe-IT, n8n,
    # Webmin, qdrant) has no /healthz, and asking for one would 404 and read as
    # degraded. Any answer below 500 means the server is serving — a 301/302/401/
    # 404 is a normal response, not an outage — so up is `< 500` and degraded is a
    # 5xx (the server is there but erroring). Try the likely scheme first and fall
    # back to the other, so a service on a non-standard TLS port (Webmin on 10000)
    # is still probed correctly without per-asset configuration.
    host = asset.bind_addr or "127.0.0.1"
    port = asset.port or 80
    primary = "https" if port in (443, 4443, 8443, 9443) else "http"
    schemes = (primary, "http" if primary == "https" else "https")

    last_error = "no scheme answered"
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}/"
        loop = asyncio.get_running_loop()
        start = loop.time()
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout_s, follow_redirects=False) as client:
                resp = await client.get(url)
        except httpx.HTTPError as exc:
            last_error = str(exc)[:200]
            continue
        latency = int((loop.time() - start) * 1000)
        status = "up" if resp.status_code < 500 else "degraded"
        return ProbeResult(status=status, probe="http", latency_ms=latency, http_status=resp.status_code)
    return ProbeResult(status="down", probe="http", error=last_error)


async def _probe_tcp(asset: assets_repo.Asset, timeout_s: int) -> ProbeResult:
    host = asset.bind_addr or "127.0.0.1"
    port = asset.port
    if not port:
        return ProbeResult(status="unknown", probe="tcp", error="no port to probe")
    loop = asyncio.get_running_loop()
    start = loop.time()
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_s)
        latency = int((loop.time() - start) * 1000)
        return ProbeResult(status="up", probe="tcp", latency_ms=latency)
    except (OSError, asyncio.TimeoutError) as exc:
        return ProbeResult(status="down", probe="tcp", error=str(exc)[:300])
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def _probe_systemd(asset: assets_repo.Asset, timeout_s: int) -> ProbeResult:
    unit = asset.systemd_unit
    if not unit:
        return ProbeResult(status="unknown", probe="systemd", error="no unit")
    res = await shellsafe.run_async(["systemctl", "is-active", unit], timeout_s=timeout_s)
    state = res.stdout.strip()
    if state == "active":
        return ProbeResult(status="up", probe="systemd")
    if state in ("activating", "reloading"):
        return ProbeResult(status="degraded", probe="systemd", error=state)
    return ProbeResult(status="down", probe="systemd", error=state or "inactive")


async def _probe_docker(asset: assets_repo.Asset, timeout_s: int) -> ProbeResult:
    ref = asset.container_id or asset.name
    res = await shellsafe.run_async(
        ["docker", "inspect", "-f", "{{.State.Running}} {{.State.Health.Status}}", ref],
        timeout_s=timeout_s,
    )
    if not res.ok:
        return ProbeResult(status="down", probe="docker", error=(res.stderr or "not found")[:200])
    parts = res.stdout.strip().split()
    running = parts[0] if parts else "false"
    health = parts[1] if len(parts) > 1 else ""
    if running != "true":
        return ProbeResult(status="down", probe="docker", error="not running")
    if health in ("unhealthy", "starting"):
        return ProbeResult(status="degraded", probe="docker", error=health)
    return ProbeResult(status="up", probe="docker")


async def probe(asset: assets_repo.Asset, cfg: Config) -> ProbeResult:
    kind = asset.probe_kind
    timeout = cfg.health.http_timeout_s
    try:
        if kind == "http":
            return await _probe_http(asset, timeout)
        if kind == "systemd":
            return await _probe_systemd(asset, timeout)
        if kind == "docker":
            return await _probe_docker(asset, timeout)
        if kind == "tcp":
            return await _probe_tcp(asset, timeout)
        return ProbeResult(status="unknown", probe=kind, error="no probe method for this asset")
    except Exception as exc:  # noqa: BLE001 - a probe must never take the loop down
        log.warning("probe raised", extra={"asset": asset.name, "detail": str(exc)})
        return ProbeResult(status="unknown", probe=kind, error=str(exc)[:300])


async def probe_all(db: Database, cfg: Config) -> dict[str, int]:
    """Probe every asset once, record the sample, and open/close outages.

    Probes run concurrently but bounded, so a host with many assets does not open
    a hundred sockets at once. Returns a small tally for the log line.
    """
    assets = await assets_repo.list_all(db)
    sem = asyncio.Semaphore(8)

    async def one(asset: assets_repo.Asset) -> str:
        async with sem:
            result = await probe(asset, cfg)
        await health_repo.record_sample(
            db,
            asset_id=asset.id,
            status=result.status,
            latency_ms=result.latency_ms,
            http_status=result.http_status,
            error=result.error,
            probe=result.probe,
        )
        # Outage bookkeeping: a sustained run of failures opens one; recovery closes it.
        if result.status == "up":
            await health_repo.close_outage(db, asset.id)
        elif result.status in ("down", "unknown"):
            fails = await health_repo.consecutive_failures(db, asset.id)
            if fails >= cfg.health.down_after_failures:
                await health_repo.open_outage(db, asset.id, cause=result.error)
        return result.status

    statuses = await asyncio.gather(*(one(a) for a in assets))
    tally = {s: statuses.count(s) for s in set(statuses)}
    log.info("availability probed", extra={"assets": len(assets), **{f"n_{k}": v for k, v in tally.items()}})
    return tally
