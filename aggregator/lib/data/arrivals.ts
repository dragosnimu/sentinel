/**
 * Ce a SOSIT efectiv, pe instanță și pe flux.
 *
 * Panoul are pagini pentru fluxuri care încă nu se expediază. Întrebarea „ce
 * scrie pagina asta când nu are date?" are două răspunsuri, și diferența dintre
 * ele e tot ce contează:
 *
 *   * „nimic de arătat" — fluxul curge, dar nu există rânduri. E o informație
 *     despre SERVER: nu s-a întâmplat nimic;
 *   * „fluxul n-a fost expediat niciodată" — e o informație despre CONDUCTĂ, iar
 *     reparația e cu totul alta.
 *
 * Confundate, un operator care se uită la o pagină goală de blocklist crede că
 * nu e nimeni blocat, când de fapt nimeni nu i-a trimis lista. Aia e exact
 * clasa de raport care minte liniștit.
 *
 * ## De ce se citește, și nu se scrie într-o listă
 *
 * Prima formă la care m-am gândit era o listă de fluxuri „încă neaduse", scrisă
 * în cod. Ar fi funcționat azi și ar fi mințit în ziua în care aduc unul și uit
 * s-o editez — iar minciuna aia e invizibilă: pagina spune „nu se expediază"
 * peste rânduri care chiar sosesc.
 *
 * `sync_cursors` are un rând per (instanță, flux), scris de ruta de ingestie la
 * PRIMUL lot acceptat. Prezența rândului e deci un fapt observabil despre ce s-a
 * întâmplat, nu o declarație despre ce ar trebui să se întâmple. În ziua în care
 * un flux începe să curgă, paginile lui încetează singure să spună că lipsește.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

export type Arrival = {
  stream: string;
  /** Câte rânduri au intrat de la prima sosire încoace. Poate fi 0. */
  rowsIngested: number;
  firstSeenAt: string | null;
  updatedAt: string | null;
};

/**
 * Fluxurile care au sosit vreodată de la o instanță anume.
 *
 * `instanceId` NU e o autorizație: filtrul pe domeniu rămâne pe loc, iar ăsta se
 * adaugă peste el. Un identificator inventat nu lărgește nimic — se intersectează
 * cu o mulțime din care nu face parte și întoarce zero rânduri. Vezi nota lungă
 * din `lib/data/detections.ts` pentru de ce forma asta e preferată unui domeniu
 * reconstruit.
 */
export async function arrivalsFor(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
): Promise<Map<string, Arrival>> {
  const out = new Map<string, Arrival>();
  if (seesNothing(allowedInstanceIds)) return out;

  const rows = await db.all(
    "SELECT stream, rows_ingested, first_seen_at, updated_at FROM sync_cursors " +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? " +
    " ORDER BY stream",
    [...allowedInstanceIds.allowedInstanceIds, instanceId]);

  for (const row of rows) {
    const stream = String(row.stream);
    out.set(stream, {
      stream,
      // `bigNumberStrings` face ca numerele mari să sosească drept șiruri.
      // `Number(...)` peste `null` ar da 0, care s-ar citi ca „au sosit zero
      // rânduri" în loc de „nu știu" — de-aia nu există `?? 0` aici.
      rowsIngested: Number(row.rows_ingested),
      firstSeenAt: row.first_seen_at === null || row.first_seen_at === undefined
        ? null : String(row.first_seen_at),
      updatedAt: row.updated_at === null || row.updated_at === undefined
        ? null : String(row.updated_at),
    });
  }
  return out;
}
