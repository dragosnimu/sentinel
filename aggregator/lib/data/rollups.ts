/**
 * Contorul orar replicat. Sursa paginii `/panel/rapoarte`.
 *
 * Ora vine gata însumată de pe server. Aici NU se reagregă nimic peste ea:
 * `uniq_src` e un MAXIM peste minute, nu o sumă — o subestimare cunoscută,
 * aleasă acolo —, iar o recalculare de aici ar deveni un al doilea răspuns la
 * aceeași întrebare, cu altă valoare și fără nimic care să spună care e bun.
 *
 * ## De ce însumarea pe oră se face în TypeScript și nu în SQL
 *
 * Pagina arată o linie per oră, deci rândurile per sursă trebuie strânse. Asta
 * se putea cere bazei, cu `GROUP BY` și `SUM()`. Nu se cere, din două motive:
 *
 *   * volumul e minuscul prin construcție — un contor ORAR, câteva zeci de
 *     rânduri pe oră —, deci nu se câștiga nimic;
 *   * `SUM()` peste `BIGINT` întoarce ȘIRURI la driver, iar o adunare făcută pe
 *     ele ar concatena în loc să adune. Aceeași capcană ca `Boolean("0")`, în
 *     alt loc: rezultatul e absurd, dar nu pică nimic.
 *
 * `instanceId` e un FILTRU peste domeniu, nu un domeniu; vezi nota lungă din
 * `lib/data/detections.ts`.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

export type HourRow = {
  bucket: string;
  events: number;
  uniqSources: number;
  bytesIn: number;
  bytesOut: number;
  /** Cele mai active surse din ora aia, cu numărul lor. */
  top: { source: string; action: string; events: number }[];
};

/** Câte ore ÎNTREGI se arată. O pagină, nu o arhivă. */
export const HOURS_SHOWN = 48;

/** Câte surse se numesc într-o oră înainte de restul. */
export const TOP_PER_HOUR = 4;

/**
 * Câte rânduri se citesc. Generos față de `HOURS_SHOWN × surse`, dinadins.
 *
 * Plafonul e pe RÂNDURI fiindcă asta mărginește citirea, dar ce se arată sunt
 * ORE — iar ora de la marginea plafonului poate fi tăiată pe la mijloc. Aia se
 * ARUNCĂ, nu se afișează: un total pe oră mai mic decât cel real e un raport
 * care minte liniștit, spre deosebire de o oră lipsă, care se vede.
 */
export const MAX_ROWS_READ = 5_000;

export async function listHours(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
): Promise<HourRow[]> {
  if (seesNothing(allowedInstanceIds)) return [];

  const rows = await db.all(
    "SELECT bucket, source, action, n, uniq_src, bytes_in, bytes_out " +
    "  FROM event_rollup_1h_entries " +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? " +
    " ORDER BY bucket DESC LIMIT ?",
    [...allowedInstanceIds.allowedInstanceIds, instanceId, MAX_ROWS_READ]);

  const byBucket = new Map<string, HourRow>();
  for (const row of rows) {
    const bucket = String(row.bucket);
    const hour = byBucket.get(bucket) ?? {
      bucket, events: 0, uniqSources: 0, bytesIn: 0, bytesOut: 0, top: [],
    };
    // `Number(...)` pe fiecare: driverul întoarce coloanele întregi ca ȘIRURI
    // când sunt mari, iar `"10" + "5"` e `"105"`, nu 15.
    const events = Number(row.n);
    hour.events += events;
    // MAXIM, nu sumă: valoarea de pe server e deja un maxim peste minute, iar
    // suma unor maxime nu răspunde la nicio întrebare.
    hour.uniqSources = Math.max(hour.uniqSources, Number(row.uniq_src));
    hour.bytesIn += Number(row.bytes_in);
    hour.bytesOut += Number(row.bytes_out);
    hour.top.push({ source: String(row.source), action: String(row.action), events });
    byBucket.set(bucket, hour);
  }

  const hours = [...byBucket.values()].sort((a, b) => (a.bucket < b.bucket ? 1 : -1));

  // Ora cea mai veche se aruncă DOAR dacă plafonul a fost atins — atunci și
  // numai atunci poate fi tăiată. Aruncată necondiționat, s-ar pierde o oră
  // bună pe fiecare gazdă liniștită.
  if (rows.length >= MAX_ROWS_READ && hours.length > 0) hours.pop();

  for (const hour of hours) {
    hour.top.sort((a, b) => b.events - a.events);
    hour.top = hour.top.slice(0, TOP_PER_HOUR);
  }
  return hours.slice(0, HOURS_SHOWN);
}
