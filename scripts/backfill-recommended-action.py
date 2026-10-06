#!/usr/bin/env python3
"""Aduce în `incidents.ai_verdict.recommended_action` istoricul scris strâmb.

Pe 6 octombrie 2026, din 791 de verdicte ale modelului, exact 169 aveau valoarea
`unknown` și 622 una dintre 12 ortografii ale celor cinci cuvinte din enum —
dintre care doar 20 chiar cuvântul corect. Restul:

    blocheaz + backslash + u0103      316   ← text de 6 caractere, nu litera ă
    investigheaz + backslash + u0103   90
    monitorizeaz + backslash + u0103    9
    investigheaz                        76   ← lipsește ă de la sfârșit
    blocheaz                            25
    ignor                                3
    monitorizeaz                         1
    investigheaza, blocheaza,
    monitorizeaza, ignora               82   ← fără diacritice

Toate sunt scrise ÎNAINTE ca `_normalise_action` să existe (15 septembrie 2026),
deci s-au păstrat verbatim. De atunci, un răspuns pe care normalizatorul nu-l
poate plasa devine `unknown` și valoarea brută se aruncă — rândurile de aici sunt
singura dovadă care a rămas.

## Regula: aceeași ca a plasei, nu o a doua

Decizia vine din `sentinel.ai.triage._normalise_action`, nu e rescrisă aici. Două
reguli care s-ar abate una de alta ar face ca un rând vechi și unul nou să
însemne lucruri diferite. Din ea rezultă și ce NU se atinge:

  * `unknown` — răspunsul brut s-a pierdut; nu există din ce să se deducă nimic,
    deci rămâne `unknown`. Sunt 169, și nimic din ce se face aici nu le schimbă;
  * orice valoare pe care regula n-o poate plasa fără ambiguitate (un prefix care
    ar potrivi două acțiuni, ceva mai scurt de 4 litere, text străin);
  * un rând fără `recommended_action` șir (lipsă, număr, listă): se numără și se
    spune, nu se ghicește.

«Nu ghicește» are o definiție verificabilă: după `--apply`, aceeași interogare de
candidați rulează din nou și trebuie să dea ZERO. Dacă dă altceva, scriptul
iese cu cod 1 și o spune — codul de retur al `UPDATE`-ului spune ce a raportat
serverul, renumărarea spune ce s-a întâmplat.

## Ce se scrie în rând

    recommended_action      = cuvântul din enum (blochează, investighează, …)
    recommended_action_raw  = ce era scris înainte (randat, nu brut)

Cheia soră e aceeași pe care o scrie `triage._clean` când plasa lucrează pe un
răspuns: prezența ei înseamnă «valoarea asta a fost dedusă, nu primită». Pe
rândurile din acest script ține și locul unui fișier de anulare: valoarea
veche e în rând. Randarea (`triage._render_raw`) dublează un backslash, ca o
literă adevărată și o scriere literală a ei să nu arate la fel.

## Re-rulabil, fără efect a doua oară

După prima rulare, `recommended_action` e cuvântul din enum, deci rândul nu mai
e candidat. A doua rulare numără zero și nu scrie nimic. Fiecare `UPDATE` e
compare-and-set (`WHERE ai_verdict->>'recommended_action' = valoarea citită`):
dacă între citire și scriere un triaj nou a rescris rândul, `UPDATE` nu
potrivește nimic și se numără ca «schimbat între timp», nu se suprascrie.

## Uscat implicit — și uscat de-adevăratelea

Fără `--apply`, sesiunea se deschide `default_transaction_read_only = on`: nu
«n-am scris nimic», ci «serverul ar refuza orice scriere». Un mod uscat care
doar se abține poate fi stricat de o modificare viitoare fără ca nimeni să
observe până la prima rulare reală.

## Copia din `incident_timeline` — se MĂSOARĂ, nu se atinge

`set_ai_verdict` scrie verdictul în DOUĂ locuri: pe rândul incidentului și ca o
intrare `kind = 'ai_verdict'` în `incident_timeline` (măsurat pe 6 octombrie
2026: 791 de intrări, cu aceeași valoare stricată). Scriptul corectează doar
primul loc. Intrările de cronologie rămân cum au fost scrise, din trei motive:

  * cronologia e append-only la sursă — nimic din `sentinel/` nu face UPDATE pe
    ea, iar o intrare spune ce a fost scris atunci;
  * fluxul ei către agregator merge pe `id` (`TIMELINE_STREAM`): un rând
    modificat nu mai trece de `WHERE id > cursor`, deci corectarea locală NU ar
    ajunge niciodată la replică — am avea două copii care se contrazic, în loc
    de una veche;
  * rescrierea unui jurnal e o decizie a operatorului, nu a unui script.

Raportul tipărește câte intrări de cronologie poartă valoarea stricată, ca
alegerea să se facă pe un număr și nu pe o bănuială. Consecința se vede în pagina
unui incident: antetul zice «blochează», iar intrarea «verdict AI» din
cronologie, pentru același incident, rămâne cea veche.

## Ce face asta aplicațiilor care citesc `ai_verdict`

`incidents` are un declanșator BEFORE UPDATE (`set_updated_at`, 0023): fiecare
rând atins primește `updated_at = now()`. Expeditorul merge pe `(updated_at, id)`
și retrimite rândul ÎNTREG, deci agregatorul primește valorile corectate la
runda următoare de expediere — fără nimic de făcut acolo, DACĂ upsert-ul lui
înlocuiește `ai_verdict`. Asta NU se poate afirma de aici: scriptul nu atinge
agregatorul și nu l-a citit. Ce se vede de aici e doar că rândurile pleacă.

Efectul lateral, spus în loc de ascuns: pe producție 602 de incidente vechi
capătă `updated_at` de azi. Orice ordonare sau filtrare după `incidents.updated_at`
le va vedea ca «tocmai schimbate».

## Cum se rulează

Pe gazdă NU există `scripts/` și nici o copie a depozitului: instalarea pune
sub `/opt/sentinel` doar pachetul (`/opt/sentinel/lib`) și mediul virtual. Iar
mediul virtual, singur, nu găsește pachetul — unitățile systemd îl găsesc
fiindcă au `Environment=PYTHONPATH=/opt/sentinel/lib`, și același lucru trebuie
spus aici. Deci: se copiază scriptul pe gazdă și se dă `PYTHONPATH`.

Fără `PYTHONPATH`, scriptul cade cu `ModuleNotFoundError: No module named
'sentinel'` ÎNAINTE de orice conexiune (măsurat pe producție, 6 octombrie 2026:
`sudo -u sentinel /opt/sentinel/venv/bin/python -c "import sentinel"` dă aceeași
eroare). E zgomotos, nu periculos — dar o comandă documentată care nu poate
merge costă operatorul douăzeci de minute.

Pe FIECARE gazdă (comanda e aceeași; vezi mai jos de ce):

    # de pe mașina de lucru
    scp scripts/backfill-recommended-action.py GAZDA:/tmp/

    # pe gazdă — uscat, implicit
    sudo -u sentinel env PYTHONPATH=/opt/sentinel/lib \\
         /opt/sentinel/venv/bin/python /tmp/backfill-recommended-action.py

    # pe gazdă — scrie, doar după ce numerele din rularea uscată sunt cele așteptate
    sudo -u sentinel env PYTHONPATH=/opt/sentinel/lib \\
         /opt/sentinel/venv/bin/python /tmp/backfill-recommended-action.py --apply

    # pe gazdă — scriptul nu mai e de folos
    rm /tmp/backfill-recommended-action.py

Scriptul nu primește gazdă sau port: se conectează la ce spune configurația
GAZDEI pe care rulează (`get_config()` + `database_dsn`, adică `database.port`
din `/etc/sentinel/sentinel.yaml`, sau `SENTINEL_DB_DSN` din secrets.env dacă e
setat). De aceea n8n, unde PostgreSQL ascultă pe 5433, folosește aceeași
comandă ca producția (5432) — nu se dă nicio opțiune de port. Pe producție
s-a verificat (6 octombrie 2026) că, cu `PYTHONPATH` dat, importurile,
`get_config()` și DSN-ul `127.0.0.1:5432/sentinel` se rezolvă pentru
utilizatorul `sentinel`, cu asyncpg 0.30.0. Pe n8n DSN-ul NU a fost citit de
aici: dovada că scriptul vorbește cu baza potrivită e rularea uscată, nu portul
din text.

Dovada că rulează pe baza potrivită: numerele din raportul uscat. Măsurat pe 6
octombrie 2026: producția 602 de rânduri de schimbat (din 791 de verdicte), n8n
14 (din 24). Un alt total înseamnă altă bază sau alt moment — se oprește și se
întreabă, nu se trece la `--apply`.

Nu necesită migrație.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import Counter
from pathlib import Path
from typing import Any, NamedTuple

# Scriptul stă în `scripts/`, lângă pachet, nu în el — vezi
# `purge-automation-commands.py`, același motiv.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import asyncpg  # noqa: E402

from sentinel.ai import triage  # noqa: E402
from sentinel.config import Config, database_dsn, get_config  # noqa: E402

TABLE = "incidents"

#: Valorile pe care scriptul NU le atinge niciodată, citite din aceeași sursă ca
#: normalizatorul: cuvintele din enum, ids-urile ASCII cerute modelului, și
#: `unknown`. Rândurile astea sunt deja în starea finală, sau nu mai au din ce
#: să fie deduse.
FINAL_VALUES = sorted({*triage._ACTION_ENUM, *triage._ACTION_WIRE, "unknown"})

#: Candidații: rânduri cu verdict, al căror `recommended_action` e un ȘIR care nu
#: e într-o stare finală. `jsonb_typeof` înaintea lui `->>`: un `null` JSON sau un
#: număr ar ieși din `->>` ca NULL sau text, și ar arăta ca o valoare.
CANDIDATES_SQL = f"""
SELECT id, ai_verdict->>'recommended_action' AS value
  FROM {TABLE}
 WHERE ai_verdict IS NOT NULL
   AND jsonb_typeof(ai_verdict->'recommended_action') = 'string'
   AND ai_verdict->>'recommended_action' <> ALL($1::text[])
 ORDER BY id
"""

#: Cum arată baza, în afară de candidați — ca raportul să poată spune «din câte».
SURVEY_SQL = f"""
SELECT count(*) FILTER (WHERE ai_verdict IS NOT NULL) AS with_verdict,
       count(*) FILTER (WHERE ai_verdict IS NOT NULL
                          AND jsonb_typeof(ai_verdict->'recommended_action')
                              IS DISTINCT FROM 'string') AS unreadable,
       count(*) FILTER (WHERE ai_verdict->>'recommended_action' = 'unknown')
                                                          AS unknown,
       count(*) FILTER (WHERE ai_verdict->>'recommended_action' = ANY($1::text[])
                          AND ai_verdict->>'recommended_action' <> 'unknown')
                                                          AS already_final
  FROM {TABLE}
"""

#: Câte intrări de cronologie poartă o valoare ne-finală, pe valoare. Doar se
#: numără: scriptul nu scrie niciodată aici (vezi docstring-ul modulului).
TIMELINE_SQL = """
SELECT detail->>'recommended_action' AS value, count(*) AS n
  FROM incident_timeline
 WHERE kind = 'ai_verdict'
   AND jsonb_typeof(detail->'recommended_action') = 'string'
   AND detail->>'recommended_action' <> ALL($1::text[])
 GROUP BY 1
"""

#: Compare-and-set. `||` pe jsonb înlocuiește cheile de la primul nivel și le
#: păstrează pe restul (severity, summary_ro, …) neatinse.
UPDATE_SQL = f"""
UPDATE {TABLE}
   SET ai_verdict = ai_verdict || jsonb_build_object(
           'recommended_action', $2::text,
           'recommended_action_raw', $3::text)
 WHERE id = $1
   AND ai_verdict->>'recommended_action' = $4::text
"""


class Decision(NamedTuple):
    new: str
    kind: str      # escape | prefix | folded


def decide(value: str) -> Decision | None:
    """Ce ar deveni valoarea, sau None dacă scriptul n-o atinge.

    Delegă plasarea la `triage._normalise_action`; aici se adaugă doar ETICHETA
    felului în care a fost plasată, pentru raport. Eticheta nu influențează
    decizia.
    """
    if value in FINAL_VALUES:
        return None
    new = triage._normalise_action(value)
    if new not in triage._ACTION_ENUM:
        return None
    if triage._decode_unicode_escapes(value) != value:
        kind = "escape"
    elif triage._fold(value) in triage._ACTION_BY_FOLD:
        kind = "folded"
    else:
        kind = "prefix"
    return Decision(new, kind)


def _n(value: int) -> str:
    return f"{value:,}".replace(",", " ")


async def _plan(conn: Any) -> tuple[list[tuple[int, str, Decision]], Counter]:
    """Citește candidații și îi împarte în «de schimbat» și «rămân»."""
    rows = await conn.fetch(CANDIDATES_SQL, FINAL_VALUES)
    changes: list[tuple[int, str, Decision]] = []
    staying: Counter = Counter()
    for r in rows:
        d = decide(r["value"])
        if d is None:
            staying[r["value"]] += 1
        else:
            changes.append((int(r["id"]), r["value"], d))
    return changes, staying


async def backfill(conn: Any, *, apply: bool, out: Any = None) -> dict[str, int]:
    """Raportează ce s-ar schimba; schimbă doar dacă `apply`.

    `out` se ia la APEL, nu ca valoare implicită legată la definire — altfel
    raportul ar pleca spre `sys.stdout`-ul de la import (vezi
    `purge-automation-commands.py`).
    """
    out = out if out is not None else sys.stdout

    survey = await conn.fetchrow(SURVEY_SQL, FINAL_VALUES)
    changes, staying = await _plan(conn)

    print(f"tabela    : {TABLE}.ai_verdict.recommended_action", file=out)
    print(f"verdicte  : {_n(int(survey['with_verdict']))}", file=out)
    print(f"  deja finale (cuvânt din enum)    : {_n(int(survey['already_final']))}",
          file=out)
    print(f"  `unknown` (răspunsul s-a pierdut): {_n(int(survey['unknown']))}",
          file=out)
    print(f"  fără `recommended_action` șir    : {_n(int(survey['unreadable']))}",
          file=out)
    print(f"  de schimbat                      : {_n(len(changes))}", file=out)
    print(f"  rămân, neplasabile fără ghicit   : {_n(sum(staying.values()))}",
          file=out)

    by_map: Counter = Counter()
    by_kind: Counter = Counter()
    for _id, old, d in changes:
        by_map[(old, d.new, d.kind)] += 1
        by_kind[d.kind] += 1
    if changes:
        print("\nce se schimbă (valoare veche → nouă, felul plasării; un "
              "backslash literal e afișat dublat):", file=out)
        for (old, new, kind), n in sorted(by_map.items(), key=lambda kv: -kv[1]):
            print(f"  {_n(n):>6}  {triage._render_raw(old):<22} → {new:<14} [{kind}]",
                  file=out)
        print("  pe fel: " + ", ".join(f"{k} {_n(v)}" for k, v in
                                       sorted(by_kind.items())), file=out)
    if staying:
        print("\nrămân neatinse (nu se pot plasa fără ghicit):", file=out)
        for val, n in staying.most_common(20):
            print(f"  {_n(n):>6}  {triage._render_raw(val)}", file=out)
    if survey["unknown"]:
        print(f"\nCele {_n(int(survey['unknown']))} de `unknown` rămân `unknown`: "
              f"valoarea brută nu s-a păstrat, deci nu există din ce să se "
              f"deducă ceva.", file=out)

    # Copiile din cronologie: numărate, neatinse. Câte din ele ar fi plasate de
    # aceeași regulă = câte intrări contrazic antetul după `--apply`.
    in_timeline = sum(int(r["n"]) for r in await conn.fetch(TIMELINE_SQL, FINAL_VALUES)
                      if decide(r["value"]) is not None)
    if in_timeline:
        print(f"\nincident_timeline: {_n(in_timeline)} intrări «verdict AI» poartă "
              f"aceeași valoare stricată și NU se ating (istoric append-only; "
              f"fluxul lor e pe id, deci o corectare locală n-ar ajunge la "
              f"agregator). Decizia e a operatorului.", file=out)

    result = {"candidates": len(changes) + sum(staying.values()),
              "planned": len(changes), "changed": 0, "raced": 0,
              "left": sum(staying.values()), "remaining": len(changes),
              "timeline_stale": in_timeline}

    if not apply:
        print("\n[uscat] nu s-a scris nimic (sesiunea e read-only).", file=out)
        print("        Rulează din nou cu --apply ca să scrie.", file=out)
        return result

    changed = raced = 0
    async with conn.transaction():
        for incident_id, old, d in changes:
            tag = await conn.execute(UPDATE_SQL, incident_id, d.new,
                                     triage._render_raw(old), old)
            if int(str(tag).rsplit(" ", 1)[-1]) == 1:
                changed += 1
            else:
                raced += 1

    # Faptul, nu intenția: se reia interogarea de candidați. Zero înseamnă că
    # nimic din ce regula știe să plaseze nu mai e în starea veche.
    after_changes, _ = await _plan(conn)
    result.update(changed=changed, raced=raced, remaining=len(after_changes))

    print(f"\nscrise    : {_n(changed)} rânduri", file=out)
    if raced:
        print(f"schimbate între timp (CAS n-a potrivit): {_n(raced)} — un triaj "
              f"nou le-a rescris; nu s-au atins.", file=out)
    print(f"mai sunt plasabile după scriere: {_n(len(after_changes))}"
          + ("" if not after_changes else "  ← NU e zero; rulează din nou"),
          file=out)
    if changed:
        print(f"\n{_n(changed)} de incidente au acum `updated_at = now()` "
              f"(declanșatorul 0023); expeditorul le retrimite la runda "
              f"următoare.", file=out)
    return result


async def _connect(cfg: Config, *, read_only: bool) -> Any:
    conn = await asyncpg.connect(
        database_dsn(cfg),
        server_settings={"application_name": "sentinel-backfill-action",
                         "statement_timeout": "120000"})
    if read_only:
        # La nivel de SESIUNE, nu doar «nu apelez UPDATE»: serverul însuși
        # refuză orice scriere din modul uscat.
        await conn.execute("SET default_transaction_read_only = on")
    return conn


async def _main(args: argparse.Namespace) -> int:
    cfg = get_config()
    conn = await _connect(cfg, read_only=not args.apply)
    try:
        result = await backfill(conn, apply=args.apply)
    finally:
        await conn.close()
    return 0 if (not args.apply or result["remaining"] == 0) else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="backfill-recommended-action.py",
        description="Plasează în enum valorile vechi ale lui "
                    "ai_verdict.recommended_action care se pot plasa fără "
                    "ghicit. Implicit uscat.")
    p.add_argument("--apply", action="store_true",
                   help="chiar scrie. Fără el, scriptul doar raportează.")
    args = p.parse_args(argv)
    return asyncio.run(_main(args))


if __name__ == "__main__":
    raise SystemExit(main())
