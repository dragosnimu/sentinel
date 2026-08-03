"""Geo/ASN enrichment from local MMDB databases.

Two sources work, because both write the same MaxMind-DB format and the same
record keys:

  * **MaxMind GeoLite2** — needs a free account and a license key.
  * **DB-IP lite** — no registration, direct monthly download, CC-BY.

DB-IP is what `deploy/geoip/refresh.sh` installs, since a deployment that needs
someone to go and create an account tends to ship without geo data at all. Both
naming conventions are accepted, so dropping either family into the directory
works.

Entirely optional. If no .mmdb is present, enrichment is a no-op and events are
stored without a country or ASN — a missing map is not a reason to drop the
event. Lookups never touch the network: the point of a local database is that
resolving a hostile address does not phone home and tip anyone off.
"""

from __future__ import annotations

import os

from sentinel.logging_setup import get_logger
from sentinel.model.event import Event

log = get_logger(__name__)

GEOIP_DIR = os.environ.get("SENTINEL_GEOIP_DIR", "/var/lib/sentinel/geoip")


class GeoEnricher:
    def __init__(self, geoip_dir: str = GEOIP_DIR):
        self._city = None
        self._asn = None
        try:
            import maxminddb  # noqa: PLC0415
        except ImportError:
            return
        # Both vendors, most specific first: a City database also answers the
        # country question, so it wins over a Country-only file when present.
        for attr, names in (
            ("_city", ("GeoLite2-City.mmdb", "GeoIP2-City.mmdb",
                       "dbip-city-lite.mmdb", "dbip-country-lite.mmdb")),
            ("_asn", ("GeoLite2-ASN.mmdb", "GeoIP2-ASN.mmdb",
                      "dbip-asn-lite.mmdb")),
        ):
            for name in names:
                path = os.path.join(geoip_dir, name)
                if os.path.isfile(path):
                    try:
                        setattr(self, attr, maxminddb.open_database(path))
                    except Exception as exc:  # noqa: BLE001
                        log.warning("could not open geoip db", extra={"path": path, "detail": str(exc)})
                    break

    @property
    def available(self) -> bool:
        return self._city is not None or self._asn is not None

    def enrich(self, event: Event) -> None:
        ip = event.src_ip
        if not ip or (self._city is None and self._asn is None):
            return
        try:
            if self._city is not None:
                rec = self._city.get(ip)
                if rec:
                    country = (rec.get("country") or {}).get("iso_code")
                    if country:
                        event.geo_country = country
            if self._asn is not None:
                rec = self._asn.get(ip)
                if rec:
                    event.geo_asn = rec.get("autonomous_system_number")
                    event.geo_as_org = rec.get("autonomous_system_organization")
        except (ValueError, KeyError):
            # A private or malformed address is simply not in the database.
            return

    def close(self) -> None:
        for db in (self._city, self._asn):
            if db is not None:
                try:
                    db.close()
                except Exception:  # noqa: BLE001
                    pass
