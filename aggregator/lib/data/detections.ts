/**
 * Detecțiile replicate. Sursa paginii `/panel/evenimente`.
 *
 * ## De ce nu e o pagină de evenimente brute
 *
 * Panoul de pe server are `/events`, care răsfoiește liber `raw_events`. Aici nu
 * există și nu poate exista: granița de date decisă pe 12 august 2026 spune că
 * `raw_events` nu pleacă în bloc de pe gazdă — pleacă doar rândurile la care
 * trimit detecțiile expediate, și nici alea încă (au nevoie de sub-rânduri în
 * protocol). Planul numește pierderea asta pe nume, ca pe una asumată.
 *
 * Ce se pune în loc, la cererea operatorului: aceeași pagină, construită peste
 * `detections`. Nu e același lucru și n-are voie să pretindă că e — o detecție e
 * o interpretare a mai multor evenimente, nu un eveniment.
 *
 * ## `instanceId` nu e o autorizație
 *
 * Panoul arată un singur server odată, ales de operator. Selecția aia vine din
 * URL, deci e controlată de client — iar interogările de mai jos o tratează ca
 * pe un FILTRU peste domeniu, nu ca pe un domeniu.
 *
 * Concret: `WHERE instance_id IN (<domeniu>) AND instance_id = ?`. A doua clauză
 * pare redundantă lângă prima și e chiar proprietatea care contează: orice ar
 * pune cineva în URL, mulțimea rezultată e o SUBMULȚIME a domeniului. Nu se
 * poate lărgi, doar îngusta — inclusiv până la mulțimea vidă, care e răspunsul
 * corect pentru o instanță pe care contul n-o vede.
 *
 * Alternativa — să reconstruiesc un domeniu cu o singură instanță — ar fi cerut
 * un al doilea loc care fabrică `InstanceScope`, iar recensământul din
 * `tests/panel-authz.test.ts` există tocmai fiindcă al doilea loc e cel care
 * scapă. Aici nu se fabrică niciunul.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

export type DetectionSummary = {
  id: number;
  sourceId: number;
  ts: string;
  ruleId: string;
  ruleFamily: string;
  severity: string;
  score: string | null;
  actorKey: string | null;
  srcIp: string | null;
  dstPort: number | null;
  incidentSourceId: number | null;
  suppressed: boolean;
  suppressReason: string | null;
};

const SUMMARY_COLUMNS =
  "id, source_id, ts, rule_id, rule_family, severity, score, actor_key, " +
  "src_ip, dst_port, incident_source_id, suppressed, suppress_reason";

/** Cât se citește dintr-o dată. Aceeași margine ca la incidente. */
const MAX_PAGE = 200;

function pageSize(limit: number | undefined): number {
  if (limit === undefined) return MAX_PAGE;
  if (!Number.isSafeInteger(limit) || limit <= 0) return MAX_PAGE;
  return Math.min(limit, MAX_PAGE);
}

function text(value: unknown): string | null {
  return value === null || value === undefined ? null : String(value);
}

/**
 * Cele mai recente detecții ale unei instanțe.
 *
 * `ORDER BY ts DESC, id DESC`: a doua coloană nu e decorativă. Mai multe
 * detecții pot avea aceeași secundă — chiar e cazul obișnuit la un val de
 * autentificări eșuate —, iar fără o departajare stabilă ordinea diferă de la o
 * cerere la alta și paginarea sare rânduri.
 */
export async function listDetections(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
  options: { limit?: number } = {},
): Promise<DetectionSummary[]> {
  if (seesNothing(allowedInstanceIds)) return [];
  const limit = pageSize(options.limit);

  const rows = await db.all(
    `SELECT ${SUMMARY_COLUMNS} FROM detection_entries ` +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? " +
    " ORDER BY ts DESC, id DESC LIMIT ?",
    [...allowedInstanceIds.allowedInstanceIds, instanceId, limit]);

  return rows.map((row) => ({
    id: Number(row.id),
    sourceId: Number(row.source_id),
    ts: String(row.ts),
    ruleId: String(row.rule_id),
    ruleFamily: String(row.rule_family),
    severity: String(row.severity),
    score: text(row.score),
    actorKey: text(row.actor_key),
    srcIp: text(row.src_ip),
    dstPort: row.dst_port === null || row.dst_port === undefined
      ? null : Number(row.dst_port),
    incidentSourceId: row.incident_source_id === null
      || row.incident_source_id === undefined
      ? null : Number(row.incident_source_id),
    // `=== 1`, nu adevăr: coloana e `TINYINT(1)` și sosește ca număr sau ca șir,
    // iar `Boolean("0")` e ADEVĂRAT. Aceeași capcană numită la `pending_totp` și
    // la `disabled`. O detecție suprimată arătată ca activă e o alarmă
    // inventată; una activă arătată ca suprimată e una ascunsă.
    suppressed: Number(row.suppressed) === 1,
    suppressReason: text(row.suppress_reason),
  }));
}
