/**
 * Instanțele, așa cum le vede un cont anume.
 *
 * Prima dintre funcțiile de acces la date ale panoului, și cea care dă forma
 * tuturor: **primul parametru e baza, al doilea e `allowedInstanceIds`, iar
 * interogarea poartă `WHERE instance_id IN (…)`.** Nu există varianta fără
 * domeniu, nici cu domeniu opțional — un parametru opțional e un parametru care
 * într-o zi lipsește, iar atunci întoarce tot.
 *
 * `lib/instances.ts` e altceva și nu se confundă cu ăsta: acolo se caută cheia
 * de expediere a unui EXPEDITOR, pe drumul de ingestie, unde nu există niciun
 * utilizator și nicio autorizare de citit. Aici se răspunde la „ce are voie să
 * vadă omul ăsta".
 *
 * ## Ce NU se întoarce
 *
 * `ship_secret_enc`. Nu fiindcă ar fi în clar — e cifrat —, ci fiindcă un blob
 * ajuns într-un JSON servit panoului e un blob care trece prin cache-uri, prin
 * jurnale de proxy și prin istoricul unui browser. Proiecția e scrisă coloană cu
 * coloană dinadins; un `SELECT *` ar fi adus-o odată cu următoarea coloană
 * adăugată în `instances`, tăcut.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

export type VisibleInstance = {
  instanceId: string;
  label: string | null;
  enabled: boolean;
  /** Rolul contului PE instanța asta, din `user_instances`. */
  role: string;
  firstSeenAt: string | null;
  lastBatchAt: string | null;
};

/**
 * Numele e lung dinadins: `COLUMNS` era deja luat de `lib/auth/session.ts`, iar
 * recensământul de constante din `tests/unit/test_shipper.py` e pe NUME, nu pe
 * fișier. Două constante cu același nume ar fi însemnat că a doua se ascunde în
 * spatele motivului scris pentru prima.
 */
const INSTANCE_COLUMNS = "instance_id, label, enabled, first_seen_at, last_batch_at";

/**
 * Instanțele pe care contul le poate vedea. Lista goală e un răspuns valid.
 *
 * Un cont proaspăt creat primește zero rânduri aici, și asta e starea corectă:
 * drepturile se dau explicit, cu `npm run user -- grant`. Dacă lista ar fi
 * „toate" până la prima restricție, greșeala n-ar produce nicio eroare — s-ar
 * vedea abia când cineva citește incidentele altui server.
 */
export async function visibleInstances(
  db: AuthDb, allowedInstanceIds: InstanceScope,
): Promise<VisibleInstance[]> {
  // Înainte de orice: `seesNothing` cheamă `assertScope`, deci un domeniu
  // fabricat aruncă AICI, nu ajunge la o interogare.
  if (seesNothing(allowedInstanceIds)) return [];

  const rows = await db.all(
    `SELECT ${INSTANCE_COLUMNS} FROM instances ` +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    " ORDER BY instance_id",
    [...allowedInstanceIds.allowedInstanceIds]);

  return rows.map((row) => {
    const id = String(row.instance_id);
    return {
      instanceId: id,
      label: row.label === null || row.label === undefined ? null : String(row.label),
      // `=== 1`, nu adevăr: „nu știu ce e în coloană" nu e „pornită". Aceeași
      // regulă ca în `lib/instances.ts`.
      enabled: Number(row.enabled) === 1,
      role: allowedInstanceIds.roles.get(id) ?? "viewer",
      firstSeenAt: text(row.first_seen_at),
      lastBatchAt: text(row.last_batch_at),
    };
  });
}

function text(value: unknown): string | null {
  return value === null || value === undefined ? null : String(value);
}
