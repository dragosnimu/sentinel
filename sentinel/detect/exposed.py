"""Ce ascultă pe internet, și ce anume e fiecare lucru care ascultă.

Sentinel enumera porturile de la instalare. Le-a enumerat corect: 21 de porturi
în ascultare, într-o listă pe care operatorul a citit-o o dată. Printre ele era
un panou de administrare cu drepturi de root, expus public, cu autentificare
doar prin parolă. A stat acolo săptămâni, monitorizat ca orice altceva.

Diferența dintre a raporta și a fi util e exact asta. „21 de porturi în
ascultare" e un fapt. „Unul dintre ele e un panou root pe internet, și e cea mai
mare țintă de pe serverul tău" e o constatare. Prima nu cere nimic de la
cititor; a doua îl obligă să decidă.

## Ce face, concret

Citește socketurile în LISTEN direct din `/proc/net/tcp{,6}` — fișiere lizibile
de oricine, deci fără privilegii și fără comenzi externe — și clasifică fiecare
port public după CE e serviciul: panou de administrare, bază de date, API de
containere, coadă de mesaje, acces la distanță.

## Trei limite, spuse aici ca să nu fie descoperite la nevoie

**Clasificarea e după port, nu după proces.** Ca să afli ce proces deține un
socket trebuie să citești `/proc/<pid>/fd`, iar asta cere root pentru procesele
altcuiva; serviciul rulează ca `sentinel`. Un panou de administrare mutat pe un
port neobișnuit nu va fi recunoscut. Ce e în catalog e sigur; ce nu e, tace.

**Un bind pe 0.0.0.0 nu dovedește accesibilitatea.** Firewallul providerului
poate face socketul inaccesibil din internet. Alerta spune „legat pe toate
interfețele", nu „accesibil din internet", iar textul cere verificarea din
afară — fiindcă noi, de pe gazdă, nu putem trece prin firewallul din fața ei.

**Doar TCP.** Un panou de administrare pe UDP nu există în practică; un
colector de syslog da, dar acela nu e o suprafață de comandă.

## Cadența

O expunere e o stare, nu un eveniment. Alertează la prima observare și apoi cel
mult o dată la șapte zile cât timp persistă — destul cât să nu fie uitată, rar
cât să nu devină zgomot. Operatorul poate marca o expunere drept intenționată,
iar atunci tace definitiv: rămâne în profil, vizibilă ca decizie umană.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import Any, NamedTuple

from sentinel.db.engine import Database
from sentinel.detect.spec import DetectionSpec
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

PROC_TCP = ("/proc/net/tcp", "/proc/net/tcp6")
TCP_LISTEN = "0A"

DIM_SEEN = "exposed_service"        # ce am observat; aici stă și `acknowledged`
DIM_ALERTED = "exposed_service_alert"   # când am alertat ultima dată

RENAG_DAYS = 7


class ServiceClass(NamedTuple):
    """Ce e serviciul, cât de grav e public, și de ce."""
    name: str
    severity: str
    why: str


ADMIN = "panou de administrare"
DB = "bază de date"
CONTAINER = "infrastructură de containere"
QUEUE = "coadă de mesaje"
SEARCH = "motor de căutare / analiză"
VECTOR = "bază de date vectorială"
REMOTE = "acces la distanță"
AGENT = "agent de monitorizare"

# Doar porturile unde inferența e puternică. Un catalog lacom ar produce
# afirmații despre servicii pe care nu le-am identificat, iar o clasificare
# greșită într-o alertă critică e mai rea decât absența ei.
CATALOGUE: dict[int, ServiceClass] = {
    # Panouri de administrare: control asupra întregii gazde, de obicei ca root.
    10000: ServiceClass(f"{ADMIN} (Webmin)", "critical",
                        "control complet asupra gazdei, de regulă ca root"),
    9090:  ServiceClass(f"{ADMIN} (Cockpit)", "critical",
                        "control complet asupra gazdei, de regulă ca root"),
    8006:  ServiceClass(f"{ADMIN} (Proxmox)", "critical",
                        "control asupra tuturor mașinilor virtuale și al gazdei care le rulează"),
    2087:  ServiceClass(f"{ADMIN} (WHM)", "critical",
                        "control asupra întregului server și al tuturor conturilor de pe el"),
    2083:  ServiceClass(f"{ADMIN} (cPanel)", "critical",
                        "control asupra conturilor găzduite, fișierelor și bazelor lor"),
    7080:  ServiceClass(f"{ADMIN} (LiteSpeed)", "critical",
                        "control asupra serverului web și al conținutului servit"),

    # Baze de date: datele, direct, iar mai multe dintre ele pornesc fără parolă.
    3306:  ServiceClass(f"{DB} (MySQL/MariaDB)", "critical",
                        "citire și scriere în date, plus ghicirea parolelor fără limită de rată"),
    5432:  ServiceClass(f"{DB} (PostgreSQL)", "critical",
                        "citire și scriere în date; `COPY ... PROGRAM` execută comenzi ca utilizatorul bazei"),
    27017: ServiceClass(f"{DB} (MongoDB)", "critical",
                        "implicit fără autentificare — cea mai răscumpărată bază de date de pe internet"),
    6379:  ServiceClass(f"{DB} (Redis)", "critical",
                        "implicit fără parolă, iar `CONFIG SET` permite scrierea de fișiere"),
    11211: ServiceClass(f"{DB} (memcached)", "critical",
                        "fără autentificare prin proiectare; folosit și pentru amplificare DDoS"),
    5984:  ServiceClass(f"{DB} (CouchDB)", "critical",
                        "interfața de administrare e chiar API-ul; a fost exploatată pentru minat"),
    9042:  ServiceClass(f"{DB} (Cassandra)", "critical",
                        "implicit acceptă orice utilizator; datele întregului cluster"),
    1433:  ServiceClass(f"{DB} (SQL Server)", "critical",
                        "citire și scriere în date; `xp_cmdshell` execută comenzi pe gazdă"),

    # Containere și orchestrare: echivalent root pe gazdă.
    2375:  ServiceClass(f"{CONTAINER} (Docker, necriptat)", "critical",
                        "API-ul Docker fără TLS înseamnă root pe gazdă, fără parolă"),
    2376:  ServiceClass(f"{CONTAINER} (Docker, TLS)", "critical",
                        "API-ul Docker înseamnă root pe gazdă, chiar și cu TLS dacă certificatele scapă"),
    2379:  ServiceClass(f"{CONTAINER} (etcd)", "critical",
                        "starea întregului cluster, inclusiv secretele stocate în clar"),
    10250: ServiceClass(f"{CONTAINER} (kubelet)", "critical",
                        "execuție de comenzi în orice container de pe nod, adesea neautentificat"),
    6443:  ServiceClass(f"{CONTAINER} (API Kubernetes)", "high",
                        "planul de control al clusterului; expus deliberat de obicei, dar merită știut"),

    # Cozi și motoare de căutare: date și, adesea, execuție.
    15672: ServiceClass(f"{QUEUE} (RabbitMQ, panou)", "high",
                        "control asupra cozilor; parola implicită guest/guest e des uitată"),
    5672:  ServiceClass(f"{QUEUE} (AMQP)", "high",
                        "citirea și injectarea de mesaje în fluxul aplicației"),
    9092:  ServiceClass(f"{QUEUE} (Kafka)", "high",
                        "citirea și injectarea de mesaje; implicit fără autentificare"),
    9200:  ServiceClass(f"{SEARCH} (Elasticsearch)", "critical",
                        "indexul complet; multe instalări nu au autentificare"),
    8123:  ServiceClass(f"{SEARCH} (ClickHouse)", "high",
                        "interogare completă; utilizatorul implicit `default` nu are parolă"),

    6333:  ServiceClass(f"{VECTOR} (Qdrant)", "high",
                        "colecțiile de vectori și metadatele lor"),
    6334:  ServiceClass(f"{VECTOR} (Qdrant, gRPC)", "high",
                        "colecțiile de vectori și metadatele lor"),

    # Așteptate. În catalog pentru inventar complet, la `info`: nu sună telefonul,
    # dar apar în panou, iar o dispariție a lor devine vizibilă.
    22:    ServiceClass(f"{REMOTE} (SSH)", "info", "așteptat pe un server administrat de la distanță"),
    3389:  ServiceClass(f"{REMOTE} (RDP)", "high",
                        "rar intenționat pe un server Linux; țintă constantă de brute-force"),
    5900:  ServiceClass(f"{REMOTE} (VNC)", "high",
                        "adesea fără criptare, cu parolă scurtă și fără limită de încercări"),
    10050: ServiceClass(f"{AGENT} (Zabbix)", "medium",
                        "dezvăluie configurația gazdei celui care întreabă"),
    10051: ServiceClass(f"{AGENT} (Zabbix server)", "medium",
                        "primește date de la agenți; poate fi hrănit cu date false"),
    9100:  ServiceClass(f"{AGENT} (node_exporter)", "medium",
                        "metrici detaliate despre gazdă, fără autentificare"),
}


class Listener(NamedTuple):
    proto: str          # tcp | tcp6
    addr: str           # adresa de legare, deja formatată
    port: int
    public: bool        # legat pe toate interfețele


def _ipv4(hex_addr: str) -> str:
    """`0100007F` -> `127.0.0.1`. Little-endian, cum îl scrie nucleul."""
    return socket.inet_ntoa(struct.pack("<I", int(hex_addr, 16)))


def _ipv6(hex_addr: str) -> str:
    """32 de caractere hex, în grupuri de patru octeți little-endian."""
    groups = [hex_addr[i:i + 8] for i in range(0, 32, 8)]
    packed = b"".join(struct.pack("<I", int(g, 16)) for g in groups)
    return socket.inet_ntop(socket.AF_INET6, packed)


def _read_listeners() -> list[Listener]:
    out: list[Listener] = []
    for path in PROC_TCP:
        try:
            with open(path, encoding="ascii") as fh:
                next(fh, None)          # antetul
                for line in fh:
                    parts = line.split()
                    if len(parts) < 4 or parts[3] != TCP_LISTEN:
                        continue
                    local, _, port_hex = parts[1].partition(":")
                    port = int(port_hex, 16)
                    if len(local) == 8:
                        addr, proto = _ipv4(local), "tcp"
                    elif len(local) == 32:
                        addr, proto = _ipv6(local), "tcp6"
                    else:
                        continue
                    out.append(Listener(proto, addr, port,
                                        public=addr in ("0.0.0.0", "::")))
        except (OSError, ValueError, struct.error) as exc:
            # Un /proc ilizibil nu e o alertă de securitate, e o gazdă pe care
            # verificarea asta nu funcționează. Spus o dată, nu la fiecare pas.
            log.debug("nu pot citi %s: %s", path, exc)
    return out


async def _profile(db: Database, dimension: str) -> dict[str, Any]:
    rows = await db.fetch(
        "SELECT key, last_seen, acknowledged FROM behaviour_profiles WHERE dimension = $1",
        dimension)
    return {r["key"]: r for r in rows}


async def _remember(db: Database, dimension: str, keys: set[str]) -> None:
    for key in keys:
        await db.execute(
            """
            INSERT INTO behaviour_profiles (dimension, key) VALUES ($1, $2)
            ON CONFLICT (dimension, key) DO UPDATE SET
                last_seen = now(),
                observations = behaviour_profiles.observations + 1
            """,
            dimension, key)


async def exposed_services(db: Database, cursor: int) -> list[DetectionSpec]:
    """Servicii cu profil de risc, legate pe toate interfețele.

    `cursor` e ignorat: regula nu citește evenimente. Semnătura o păstrează
    fiindcă motorul apelează toate regulile la fel, iar o excepție ar fi o
    ramură în plus exact în bucla care trebuie să rămână simplă.
    """
    listeners = await asyncio.to_thread(_read_listeners)
    if not listeners:
        return []

    seen = await _profile(db, DIM_SEEN)
    alerted = await _profile(db, DIM_ALERTED)

    now_rows = await db.fetch(
        "SELECT now() - ($1::int * interval '1 day') AS cutoff", RENAG_DAYS)
    cutoff = now_rows[0]["cutoff"] if now_rows else None

    out: list[DetectionSpec] = []
    fresh_seen: set[str] = set()
    fresh_alert: set[str] = set()

    # Pe o gazdă cu IPv4 și IPv6, același serviciu apare de două ori. Un singur
    # incident per port: operatorul repară serviciul, nu familia de adrese.
    by_port: dict[int, list[Listener]] = {}
    for listener in listeners:
        if listener.public:
            by_port.setdefault(listener.port, []).append(listener)

    for port, group in sorted(by_port.items()):
        klass = CATALOGUE.get(port)
        if klass is None:
            # Necunoscut înseamnă necunoscut. A alerta pe „port deschis pe care
            # nu-l recunosc" ar produce o alertă per port pe orice gazdă reală,
            # iar valoarea regulii ăsteia stă tocmai în a nu face asta.
            continue

        key = f"tcp/{port}"
        fresh_seen.add(key)

        row = seen.get(key)
        if row is not None and row["acknowledged"]:
            continue

        last = alerted.get(key)
        if last is not None and cutoff is not None and last["last_seen"] > cutoff:
            continue        # alertat recent; o stare nu se raportează la minut

        families = ", ".join(sorted({listener.proto for listener in group}))
        first_time = row is None
        out.append(DetectionSpec(
            rule_id=f"exposure.public_service.{port}",
            rule_family="exposure",
            severity=klass.severity,
            src_ip=None,
            actor_key="host",
            fingerprint=f"exposure.public_service:{port}",
            title=f"{klass.name} expus public pe portul {port}",
            summary=(
                f"Portul {port}/{families} e legat pe toate interfețele. "
                f"Miza: {klass.why}. "
                + ("Prima observare. " if first_time else
                   f"Persistă de la {row['last_seen']:%d.%m.%Y}. ")
                + "Un bind pe toate interfețele nu dovedește accesibilitatea — "
                  "firewallul providerului poate să-l blocheze. Verifică din afara "
                  f"rețelei: `nc -vz <adresa-publica> {port}`. "
                  "Dacă e intenționat, marchează-l și nu mai revine."),
            evidence={
                "port": port,
                "service_class": klass.name,
                "severity_reason": klass.why,
                "bindings": [f"{listener.proto} {listener.addr}:{listener.port}"
                             for listener in group],
                "classified_by": "port",
                "first_seen": None if first_time else row["first_seen"].isoformat()
                if "first_seen" in row else None,
            },
            event_ids=[],
        ))
        fresh_alert.add(key)

    if fresh_seen:
        await _remember(db, DIM_SEEN, fresh_seen)
    if fresh_alert:
        await _remember(db, DIM_ALERTED, fresh_alert)
    return out


EXPOSURE_RULES = (exposed_services,)


# ---------------------------------------------------------------------------
# Marcajul operatorului
# ---------------------------------------------------------------------------
# `behaviour_profiles.acknowledged` exista de la migrația 0018, cu un comentariu
# care îi descria rostul, era citit aici și în `novelty.py` — și nu îl scria
# nimic. Alerta promitea „dacă e intenționat, marchează-l", iar promisiunea n-avea
# acoperire în cod.
#
# O funcționalitate pe jumătate construită e mai rea decât una absentă: absența se
# vede, iar jumătatea se citește ca întreg până în ziua în care cineva chiar
# încearcă să o folosească.


async def list_exposures(db: Database) -> list[dict[str, Any]]:
    """Ce am observat, cu starea marcajului. Pentru `/expuneri`."""
    rows = await db.fetch(
        """
        SELECT key, first_seen, last_seen, acknowledged
        FROM behaviour_profiles WHERE dimension = $1 ORDER BY key
        """,
        DIM_SEEN)
    out = []
    for r in rows:
        port = int(r["key"].split("/")[-1])
        klass = CATALOGUE.get(port)
        out.append({**dict(r), "port": port,
                    "service": klass.name if klass else "neclasificat",
                    "severity": klass.severity if klass else "info"})
    return out


async def acknowledge(db: Database, key: str, *, on: bool = True) -> bool:
    """Marchează o expunere drept intenționată. Reversibil.

    Reversibil dinadins: un marcaj definitiv ar face ca o decizie luată într-o
    zi aglomerată să nu mai poată fi revizuită, iar expunerile se schimbă când
    se schimbă serverul.
    """
    updated = await db.fetch(
        """
        UPDATE behaviour_profiles SET acknowledged = $3
        WHERE dimension = $1 AND key = $2
        RETURNING key
        """,
        DIM_SEEN, key, on)
    if updated and on:
        # Ștergem marcajul de alertare, ca o eventuală de-marcare ulterioară să
        # raporteze imediat, nu peste încă șapte zile.
        await db.execute(
            "DELETE FROM behaviour_profiles WHERE dimension = $1 AND key = $2",
            DIM_ALERTED, key)
    return bool(updated)
