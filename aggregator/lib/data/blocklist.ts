/**
 * Blocările replicate. Sursa paginii `/panel/blocari`.
 *
 * `hit_count` e citit din contorul nftables de pe gazdă și e singurul răspuns
 * cinstit la întrebarea dacă blocarea a oprit ceva: o blocare cu zero lovituri
 * n-a oprit nimic. Se afișează de aceea lângă fiecare rând, nu ascuns într-un
 * detaliu.
 *
 * Deblocarea nu există aici și nu poate exista: agregatorul e o replică, iar
 * canalul de comandă rămâne Telegram.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

export type BlockSummary = {
  id: number;
  sourceId: number;
  ip: string;
  prefixLen: number | null;
  reason: string;
  ruleId: string | null;
  incidentSourceId: number | null;
  blockedAt: string;
  expiresAt: string | null;
  hitCount: number;
  lastHitAt: string | null;
  createdBy: string;
  active: boolean;
  unblockedAt: string | null;
  unblockedBy: string | null;
};

const COLUMNS =
  "id, source_id, ip, prefix_len, reason, rule_id, incident_source_id, " +
  "blocked_at, expires_at, hit_count, last_hit_at, created_by, active, " +
  "unblocked_at, unblocked_by";

const MAX_PAGE = 200;

function text(v: unknown): string | null {
  return v === null || v === undefined ? null : String(v);
}

export async function listBlocks(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
  options: { limit?: number } = {},
): Promise<BlockSummary[]> {
  if (seesNothing(allowedInstanceIds)) return [];
  const limit = Math.min(options.limit ?? MAX_PAGE, MAX_PAGE);

  const rows = await db.all(
    `SELECT ${COLUMNS} FROM blocklist_entries ` +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? " +
    // Active întâi — sunt cele care contează acum —, apoi cele mai recente.
    // `id DESC` la final e departajarea stabilă.
    " ORDER BY active DESC, blocked_at DESC, id DESC LIMIT ?",
    [...allowedInstanceIds.allowedInstanceIds, instanceId, limit]);

  return rows.map((row) => ({
    id: Number(row.id),
    sourceId: Number(row.source_id),
    ip: String(row.ip),
    prefixLen: row.prefix_len === null || row.prefix_len === undefined
      ? null : Number(row.prefix_len),
    reason: String(row.reason),
    ruleId: text(row.rule_id),
    incidentSourceId: row.incident_source_id === null
      || row.incident_source_id === undefined
      ? null : Number(row.incident_source_id),
    blockedAt: String(row.blocked_at),
    expiresAt: text(row.expires_at),
    hitCount: Number(row.hit_count),
    lastHitAt: text(row.last_hit_at),
    createdBy: String(row.created_by),
    // `=== 1`, nu adevăr. O blocare expirată arătată ca activă e o apărare
    // inventată; una activă arătată ca expirată trimite pe cineva s-o refacă.
    active: Number(row.active) === 1,
    unblockedAt: text(row.unblocked_at),
    unblockedBy: text(row.unblocked_by),
  }));
}
