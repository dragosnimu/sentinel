"""Scrie oglinda identității în baza de date, o dată, fără să suprascrie.

`/etc/sentinel/instance_id` e autoritatea; rândul din `instance_identity` e
oglinda (vezi `sentinel/db/migrations/0022_instance_identity.sql`). Migrația a
creat locul și n-a scris nimic în el dinadins — „oglinda se scrie de codul care
citește fișierul, care poate fi testat". Ăsta e codul acela.

## De ce aici și nu la pornirea serviciilor

Șase unități pornesc la fiecare instalare, iar oricare dintre ele ar fi putut
scrie rândul. Trei motive pentru care nu o face niciuna:

1. **Ordinea ar fi o presupunere, nu un fapt.** Oglinda nu poate fi scrisă
   înainte ca migrația să fi rulat. Dintr-un serviciu, „tabela există" e o
   speranță despre altă comandă, rulată altcândva; de aici e ceva ce tocmai s-a
   întâmplat în ACELAȘI proces, pe ACEEAȘI conexiune, cu două linii mai sus.
2. **Un serviciu care scrie identitatea e un serviciu care o poate bifurca.** Cu
   cât mai puține procese ating valoarea asta, cu atât mai puține moduri în care
   ea se poate schimba fără ca cineva să fi cerut.
3. `sentinel migrate` rulează la FIECARE instalare — e în `ALWAYS_STEPS`
   (`deploy/lib/common.sh`), pasul 28 — și rulează DUPĂ pasul 27, care e singurul
   scriitor al fișierului. Deci scriitorul de aici vede fișierul din aceeași
   rulare care l-a creat.

Rămâne idempotent oricum, fiindcă `sentinel migrate` se rulează și de mână, de
oricâte ori: `ON CONFLICT DO NOTHING` face din a doua rulare o operație nulă.

## Ce se întâmplă când baza spune ALTCEVA

Nu se suprascrie. Nepotrivirea dintre fișier și rând E constatarea pe care o
păzește tot mecanismul — simptomul unui backup luat pe o gazdă și restaurat pe
o clonă a alteia — iar a o „repara" scriind ar șterge exact dovada. Se
înregistrează în jurnal la ERROR, se tipărește (instalatorul rulează comanda
asta cu operatorul uitându-se la ieșire), și rămâne pe seama lui
`check_instance_identity`, care o raportează `degraded` la fiecare rulare de
autodiagnostic până se rezolvă de un om.

**Și nu oprește migrarea.** `install.sh` face `die` dacă `sentinel migrate`
întoarce non-zero, deci un diagnostic care eșuează ar bloca instalări — o pană
mai mare decât lucrul diagnosticat.

## De ce se înregistrează ÎNCERCAREA, nu doar rezultatul

Fără urma asta, „rândul lipsește" ar însemna în același timp „scriitorul n-a
rulat încă" (normal, pe o gazdă care tocmai s-a actualizat) și „scriitorul a
rulat și n-a reușit" (defect). `check_instance_identity` le-ar raporta pe
amândouă `ok` — adică tăcere în formă de sănătate, fix în verificarea scrisă ca
s-o elimine.

Urma stă în `collector_cursors`, sub `identity:mirror`: `cursor` e rezultatul
ultimei încercări, `updated_at` e momentul ei. Tabela aia e deja locul în care
procesele de fundal își țin semnul de carte durabil — beaconul își ține acolo
secvența — și nu cere o migrație nouă pentru trei coloane care există.

Se scrie ULTIMA, cu rezultatul adevărat, inclusiv pe eșec. Dacă nici ea nu se
poate scrie, baza de date e căzută, iar asta se aude oricum mai tare.
"""

from __future__ import annotations

from typing import Any, Protocol

from sentinel.identity import IdentityError, read_instance_id
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# Numele urmei în `collector_cursors`. Prefixul `identity:` îl ține departe de
# numele de colectoare, care sunt surse de evenimente.
MIRROR_MARKER = "identity:mirror"

# Vocabularul rezultatelor. Îl citește `check_instance_identity`, deci e un
# contract între două fișiere și e fixat de test — un șir schimbat aici și
# necitit acolo ar face verificarea să raporteze „scriitor stricat" pentru o
# scriere perfect reușită.
WRITTEN = "written"        # rândul nu exista; l-am scris noi
MATCHED = "matched"        # rândul exista deja și spune același lucru
CONFLICT = "conflict"      # rândul exista și spune ALTCEVA — nu s-a atins
UNREADABLE = "unreadable"  # nu s-a putut citi /etc/sentinel/instance_id
FAILED = "failed"          # interogarea a eșuat (tabelă lipsă, drepturi, ...)


class _Conn(Protocol):
    """Doar ce se folosește, ca să meargă și cu `asyncpg.Connection`, și cu
    `Database`, și cu un dublu de test care nu pretinde că e vreuna dintre ele."""

    async def fetchval(self, sql: str, *args: Any) -> Any: ...
    async def execute(self, sql: str, *args: Any) -> Any: ...


async def mirror_instance_id(conn: _Conn) -> str:
    """Oglindește identitatea. Întoarce unul dintre rezultatele de mai sus.

    Nu ridică niciodată: apelantul e runner-ul de migrații, iar o instalare nu
    are voie să cadă din cauza unui diagnostic.
    """
    try:
        file_id = read_instance_id()
    except IdentityError as exc:
        log.error("cannot mirror the instance identity",
                  extra={"detail": str(exc)[:220]})
        print(f"identitatea instalării nu se poate citi: {exc}")
        await _record(conn, UNREADABLE)
        return UNREADABLE

    try:
        # `RETURNING` întoarce un rând DOAR când INSERT-ul a inserat efectiv,
        # deci `None` înseamnă „exista deja" — fără o a doua interogare care să
        # întrebe altceva decât ce s-a întâmplat. `DO NOTHING`, nu
        # `DO UPDATE`: rândul existent nu se atinge, oricare ar fi el.
        inserted = await conn.fetchval(
            "INSERT INTO instance_identity (only_row, instance_id) "
            "VALUES (true, $1) ON CONFLICT (only_row) DO NOTHING "
            "RETURNING instance_id",
            file_id)
        if inserted is not None:
            log.info("instance identity mirrored", extra={"prefix": file_id[:8]})
            await _record(conn, WRITTEN)
            return WRITTEN

        existing = await conn.fetchval("SELECT instance_id FROM instance_identity")
    except Exception as exc:  # noqa: BLE001
        log.error("mirroring the instance identity failed",
                  extra={"detail": str(exc)[:220]})
        await _record(conn, FAILED)
        return FAILED

    if str(existing or "") == file_id:
        await _record(conn, MATCHED)
        return MATCHED

    # Prefixele, nu valorile întregi: mesajul ajunge în jurnal și pe ecranul
    # instalatorului, iar opt caractere sunt de-ajuns ca să se vadă că sunt două
    # lucruri diferite și ca să fie căutate amândouă.
    log.error("instance identity mismatch — the mirror was NOT overwritten",
              extra={"file": file_id[:8], "db": str(existing or "")[:8]})
    print("ATENȚIE: identitatea din baza de date nu e cea a gazdei "
          f"(fișier {file_id[:8]}…, bază {str(existing or '')[:8]}…). "
          "Rândul NU a fost rescris. Semn de bază restaurată pe altă mașină; "
          "vezi docs/OPERARE.md, „Identitatea instalării\".")
    await _record(conn, CONFLICT)
    return CONFLICT


async def _record(conn: _Conn, outcome: str) -> None:
    """Urma încercării. Eșecul ei se loghează și se înghite — dacă nici asta nu
    se poate scrie, ce era de spus se spune oricum mai tare, prin baza căzută."""
    try:
        await conn.execute(
            """
            INSERT INTO collector_cursors (name, cursor, updated_at)
            VALUES ($1, $2, now())
            ON CONFLICT (name) DO UPDATE
                SET cursor = EXCLUDED.cursor, updated_at = now()
            """,
            MIRROR_MARKER, outcome)
    except Exception as exc:  # noqa: BLE001
        log.error("cannot record the identity mirror attempt",
                  extra={"detail": str(exc)[:220]})
