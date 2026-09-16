/**
 * Rulările de scanare replicate. Dă paginii de vulnerabilități VÂRSTA cifrei.
 *
 * Eșecul pe care îl previne, măsurat pe 21 august 2026: pagina arăta 31 de
 * vulnerabilități neaplicate, iar pe server `dnf update` nu găsea nimic. Numărul
 * nu era greșit — era măsurat la 03:23, iar pachetele fuseseră reparate la 09:14.
 * Între cele două a mai rulat o scanare și A EȘUAT cu `timeout`; reușită, ar fi
 * închis toate cele 31.
 *
 * Deci pagina nu minte despre număr, ci prin omisiune despre vârstă. Iar când
 * încercarea de reîmprospătare cade, tăcerea e mai rea: operatorul se uită la o
 * cifră care nu se mai mișcă și n-are de unde ști de ce.
 *
 * De aceea funcția asta întoarce DOUĂ lucruri, nu unul: ultima rulare ÎNCHEIATĂ
 * cu succes (de la care vine vârsta cifrei) și ultima rulare oricare (de la care
 * vine „a eșuat"). Contopite într-una singură, un eșec ar ascunde momentul
 * ultimei măsurători bune, sau invers.
 *
 * `instanceId` e un FILTRU peste domeniu, nu un domeniu; vezi nota lungă din
 * `lib/data/detections.ts`.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

export type ScanRun = {
  sourceId: number;
  scanner: string;
  status: string;
  startedAt: string;
  finishedAt: string | null;
  findings: number;
  resolved: number;
  error: string | null;
  triggeredBy: string;
};

export type ScanHealth = {
  /** Ultima rulare care s-a încheiat cu bine. De la ea vine vârsta cifrei. */
  lastGood: ScanRun | null;
  /** Ultima rulare, oricare ar fi ea. De la ea vine „a eșuat". */
  latest: ScanRun | null;
};

const COLUMNS =
  "source_id, scanner, status, started_at, finished_at, findings_count, " +
  "resolved_findings, error, triggered_by";

function toRun(row: Record<string, unknown>): ScanRun {
  return {
    // `Number(...)`: driverul întoarce coloanele întregi ca ȘIRURI când sunt
    // mari, iar o comparație pe șiruri ar pune „9" după „10".
    sourceId: Number(row.source_id),
    scanner: String(row.scanner),
    status: String(row.status),
    startedAt: String(row.started_at),
    finishedAt: row.finished_at === null || row.finished_at === undefined
      ? null : String(row.finished_at),
    findings: Number(row.findings_count),
    resolved: Number(row.resolved_findings),
    error: row.error === null || row.error === undefined ? null : String(row.error),
    triggeredBy: String(row.triggered_by),
  };
}

/**
 * Starea scanării pentru un scaner anume — implicit `dnf`, cel care alimentează
 * pagina de vulnerabilități pe AlmaLinux.
 */
export async function scanHealth(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
  scanner = "dnf",
): Promise<ScanHealth> {
  if (seesNothing(allowedInstanceIds)) return { lastGood: null, latest: null };

  const scope = scopePlaceholders(allowedInstanceIds);
  const params = [...allowedInstanceIds.allowedInstanceIds, instanceId, scanner];

  // `started_at DESC`, nu `source_id DESC`: ordinea în care s-au petrecut e ce
  // citește operatorul. Sunt aceeași ordine azi, dar a doua o spune pe față.
  const latest = await db.all(
    `SELECT ${COLUMNS} FROM scan_entries ` +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? AND scanner = ? ` +
    " ORDER BY started_at DESC LIMIT 1",
    params);

  const good = await db.all(
    `SELECT ${COLUMNS} FROM scan_entries ` +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? AND scanner = ? ` +
    "   AND status = 'completed' " +
    " ORDER BY started_at DESC LIMIT 1",
    params);

  return {
    lastGood: good.length ? toRun(good[0]) : null,
    latest: latest.length ? toRun(latest[0]) : null,
  };
}
