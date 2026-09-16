/**
 * Planurile de patch, replicate. Sursa paginii `/panel/patch-uri`.
 *
 * Pagina e o listă, nu un detaliu, și diferența are un motiv: detaliul de pe
 * server arată execuțiile și pașii lor — `patch_executions` și `patch_steps` —,
 * iar niciunul nu se expediază încă. `patch_steps.argv` e `text[]`, deci cere
 * sub-rânduri în protocol, exact ca `detection_events`.
 *
 * Ce se vede totuși e suficient pentru întrebarea obișnuită: ce planuri există,
 * în ce stare sunt, cât de riscante, dacă cer repornire și dacă sunt
 * reversibile. Ce NU se vede e ce a executat fiecare, și asta e scris pe pagină,
 * nu doar aici.
 *
 * Agregatorul nu execută niciodată nimic dintr-un plan. Coloana `plan` din
 * migrație poartă chiar comentariul ăsta.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

export type PlanSummary = {
  id: number;
  sourceId: number;
  planUuid: string;
  status: string;
  riskLevel: string | null;
  blastRadius: string | null;
  requiresReboot: boolean;
  reversible: boolean;
  estimatedDowntimeS: number | null;
  confidence: string | null;
  createdAt: string;
  approvedBy: string | null;
  approvedAt: string | null;
  rejectedBy: string | null;
  rejectedReason: string | null;
};

const COLUMNS =
  "id, source_id, plan_uuid, status, risk_level, blast_radius, requires_reboot, " +
  "reversible, estimated_downtime_s, confidence, created_at, approved_by, " +
  "approved_at, rejected_by, rejected_reason";

const MAX_PAGE = 200;

function text(v: unknown): string | null {
  return v === null || v === undefined ? null : String(v);
}

export async function listPlans(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
  options: { limit?: number } = {},
): Promise<PlanSummary[]> {
  if (seesNothing(allowedInstanceIds)) return [];
  const limit = Math.min(options.limit ?? MAX_PAGE, MAX_PAGE);

  const rows = await db.all(
    `SELECT ${COLUMNS} FROM patch_plan_entries ` +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? " +
    " ORDER BY created_at DESC, id DESC LIMIT ?",
    [...allowedInstanceIds.allowedInstanceIds, instanceId, limit]);

  return rows.map((row) => ({
    id: Number(row.id),
    sourceId: Number(row.source_id),
    planUuid: String(row.plan_uuid),
    status: String(row.status),
    riskLevel: text(row.risk_level),
    blastRadius: text(row.blast_radius),
    // `=== 1`, nu adevăr. „Cere repornire" arătat greșit e diferența dintre un
    // patch aplicat la miezul nopții și unul aplicat acum, în plin trafic.
    requiresReboot: Number(row.requires_reboot) === 1,
    // Iar „reversibil" arătat greșit e cea mai scumpă: cineva aprobă ceva ce
    // crede că poate anula.
    reversible: Number(row.reversible) === 1,
    estimatedDowntimeS: row.estimated_downtime_s === null
      || row.estimated_downtime_s === undefined
      ? null : Number(row.estimated_downtime_s),
    confidence: text(row.confidence),
    createdAt: String(row.created_at),
    approvedBy: text(row.approved_by),
    approvedAt: text(row.approved_at),
    rejectedBy: text(row.rejected_by),
    rejectedReason: text(row.rejected_reason),
  }));
}
