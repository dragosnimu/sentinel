/**
 * Autodiagnosticul replicat. Sursa paginii `/panel/servicii`.
 *
 * Tabela de pe server ține O SINGURĂ stare per verificare — rândurile se
 * compară, nu se acumulează —, deci identitatea aici e `(instance_id, check_key)`
 * și nu există `source_id`. Fluxul e primul cu filigran TEXT din tot protocolul.
 *
 * `instanceId` e un FILTRU peste domeniu, nu un domeniu; vezi nota lungă din
 * `lib/data/detections.ts`.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

export type CheckState = {
  checkKey: string;
  status: string;
  title: string;
  detail: string;
  since: string;
  lastSeen: string;
  lastAlertAt: string | null;
  stale: boolean;
};

const COLUMNS =
  "check_key, status, title, detail, since, last_seen, last_alert_at, stale";

/** Ordinea în care le vrei pe ecran: ce e rupt, întâi. */
const SEVERITY = new Map([["down", 0], ["degraded", 1], ["unknown", 2], ["ok", 3]]);

export async function listChecks(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
): Promise<CheckState[]> {
  if (seesNothing(allowedInstanceIds)) return [];

  const rows = await db.all(
    `SELECT ${COLUMNS} FROM selfcheck_state_entries ` +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? " +
    " ORDER BY check_key",
    [...allowedInstanceIds.allowedInstanceIds, instanceId]);

  const out = rows.map((row) => ({
    checkKey: String(row.check_key),
    status: String(row.status),
    title: String(row.title),
    detail: String(row.detail),
    since: String(row.since),
    lastSeen: String(row.last_seen),
    lastAlertAt: row.last_alert_at === null || row.last_alert_at === undefined
      ? null : String(row.last_alert_at),
    // `=== 1`, nu adevăr: `Boolean("0")` e ADEVĂRAT, iar coloana e `TINYINT(1)`.
    // Diferența contează pe ecran: „verificarea spune ok" și „verificarea n-a
    // putut rula și îți arăt ce știam data trecută" nu sunt același lucru, iar
    // a doua citită ca prima e chiar un raport care minte liniștit.
    stale: Number(row.stale) === 1,
  }));

  // Sortarea pe severitate se face AICI, nu în SQL, și e o alegere: vocabularul
  // e închis și mic, dar `status` e `TEXT` fără `CHECK` la receptor — dinadins,
  // ca o valoare nouă de pe server să nu fie refuzată la ingestie. Un `ORDER BY
  // FIELD(...)` ar pune tăcut valorile necunoscute la un capăt; aici ele cad
  // între „unknown" și „ok", vizibile, fiindcă lipsa din hartă dă un rang
  // intermediar în loc de unul inventat.
  return out.sort((a, b) =>
    (SEVERITY.get(a.status) ?? 2.5) - (SEVERITY.get(b.status) ?? 2.5));
}
