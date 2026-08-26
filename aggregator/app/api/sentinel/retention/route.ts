/**
 * `GET /api/sentinel/retention` — taie ce a expirat din replică.
 *
 * O rută API rulează doar când primește o cerere, deci cineva trebuie să o
 * cheme periodic. Pe găzduirea asta, cronul din panoul Hostinger:
 *
 *     0 4 * * *  curl -sS "https://<domeniu>/api/sentinel/retention?key=<secret>"
 *
 * Aceeași formă ca `/api/sentinel/check`, și cu ACELAȘI secret: sunt amândouă
 * declanșatoare de mentenanță, iar un al treilea secret de ținut minte e unul
 * pe care cineva îl pune în clar undeva.
 *
 * ## De ce e nevoie de ea
 *
 * Măsurat pe 25 august 2026, la câteva ore după ce fluxul de comenzi a pornit:
 * `session_command_entries` = **253 MB**, din 468 MB cât avea toată baza. Crește
 * cu ~17 000 de rânduri la fiecare deploy.
 *
 * Găzduirea e partajată și are cotă. O bază plină nu înseamnă „tabela e mare" —
 * înseamnă **ingestia refuzată pentru toate cele douăsprezece fluxuri**.
 *
 * ## De ce nu e o operație distructivă „ascunsă"
 *
 * Ce se taie e scris explicit în `lib/retention.ts`, iar răspunsul SPUNE ce s-a
 * șters, pe tabelă. `audit_entries` și `incident_entries` nu sunt în listă și nu
 * se ating niciodată: prima e o arhivă înlănțuită prin hash, a doua e un set de
 * decizii, iar deciziile nu expiră.
 */

import { NextResponse } from "next/server";
import { getPool } from "@/lib/db";
import { POLICIES, pruneExpired } from "@/lib/retention";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

const NO_STORE = { "Cache-Control": "no-store, no-cache, must-revalidate" };

export async function GET(req: Request) {
  const expected = process.env.SENTINEL_CHECK_SECRET;
  const given = new URL(req.url).searchParams.get("key")
    || req.headers.get("x-sentinel-check-key");
  // Fără secret configurat, ruta e ÎNCHISĂ, nu deschisă. Un implicit permisiv
  // pe o rută care șterge rânduri ar fi cel mai scurt drum către o replică goală.
  if (!expected || given !== expected) {
    return NextResponse.json({ error: "refuzat" }, { status: 401, headers: NO_STORE });
  }

  try {
    const results = await pruneExpired(getPool());
    const total = results.reduce((a, r) => a + r.deleted, 0);
    // `more` spune că plafonul de tranșe s-a atins și au mai rămas rânduri
    // vechi. Fără el, o restanță mare ar arăta identic cu o bază curată — iar
    // cronul următor ar continua fără ca nimeni să știe că a fost nevoie.
    const more = results.some((r) => r.more);
    return NextResponse.json(
      { ok: true, deleted: total, tables: results, more,
        policies: POLICIES.map((p) => ({ table: p.table, days: p.days })) },
      { headers: NO_STORE });
  } catch (err) {
    // Se raportează, nu se înghite: o retenție care eșuează în tăcere lasă baza
    // să crească până se umple, iar simptomul de atunci e ingestia refuzată
    // pentru tot — cel mai greu de legat de cauză.
    return NextResponse.json(
      { ok: false, error: String(err).slice(0, 200) },
      { status: 500, headers: NO_STORE });
  }
}
