/**
 * Constatările scanerelor, replicate. Sursa paginii `/panel/vulnerabilitati`.
 *
 * Ordinea e cea din panoul serverului și nu e decorativă: `priority` e scorul
 * calculat acolo, care combină severitatea, EPSS-ul și faptul că e sau nu în
 * catalogul KEV. Reordonate după CVSS, listele arată complet altfel — CVSS e
 * prost la prezis ce se atacă efectiv, iar EPSS e mult mai bun. Replica nu
 * recalculează nimic; afișează ce a decis serverul.
 *
 * `instanceId` e un FILTRU peste domeniu, nu un domeniu — vezi nota lungă din
 * `lib/data/detections.ts`.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";
import { GROUPS } from "../finding-groups";
import type { FindingGroup } from "../finding-groups";

export type FindingSummary = {
  id: number;
  sourceId: number;
  scanner: string;
  cve: string | null;
  title: string | null;
  severity: string;
  cvss: string | null;
  epss: string | null;
  kev: boolean;
  kevDueDate: string | null;
  packageName: string | null;
  installedVersion: string | null;
  fixedVersion: string | null;
  priority: number;
  status: string;
  firstSeen: string;
  lastSeen: string;
};

const COLUMNS =
  "id, source_id, scanner, cve, title, severity, cvss, epss, kev, kev_due_date, " +
  "package, installed_version, fixed_version, priority, status, first_seen, last_seen";

const MAX_PAGE = 200;

function text(v: unknown): string | null {
  return v === null || v === undefined ? null : String(v);
}

/**
 * Câte constatări are fiecare grupă. O singură interogare, nu trei.
 *
 * Numerele stau pe filtrele din pagină, iar un filtru fără număr e o întrebare:
 * „dacă apăs, o să văd ceva?". Cu numărul, întrebarea nu se pune — și se vede
 * dintr-o privire dacă restanța crește.
 */
export async function countByGroup(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
): Promise<Record<FindingGroup, number> & { total: number }> {
  const out = { neaplicate: 0, rezolvate: 0, inchise: 0, total: 0 };
  if (seesNothing(allowedInstanceIds)) return out;

  const rows = await db.all(
    "SELECT status, COUNT(*) AS n FROM finding_entries " +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? GROUP BY status",
    [...allowedInstanceIds.allowedInstanceIds, instanceId]);

  for (const row of rows) {
    const status = String(row.status);
    const n = Number(row.n);
    out.total += n;
    // O stare pe care serverul o inventează mâine nu cade în nicio grupă, DELIBERAT:
    // suma grupelor devine mai mică decât totalul, iar diferența se vede pe
    // pagină. Clasificată tăcut într-una dintre ele, ar fi o afirmație pe care
    // n-a făcut-o nimeni.
    for (const [group, statuses] of Object.entries(GROUPS)) {
      if ((statuses as readonly string[]).includes(status)) {
        out[group as FindingGroup] += n;
      }
    }
  }
  return out;
}

export async function listFindings(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
  options: { limit?: number; group?: FindingGroup } = {},
): Promise<FindingSummary[]> {
  if (seesNothing(allowedInstanceIds)) return [];
  const limit = Math.min(options.limit ?? MAX_PAGE, MAX_PAGE);

  // Filtrul pe grupă se construiește din VOCABULARUL declarat, nu dintr-un șir
  // primit. Grupa vine din URL, deci de la client: interpolată, ar fi o
  // injecție; comparată cu `status LIKE`, ar potrivi stări viitoare pe care
  // nimeni nu le-a clasificat. Aici, o valoare necunoscută nu ajunge până aici
  // — `isGroup` o oprește în rută — iar stările pe care le-ar putea inventa
  // serverul mâine nu cad tăcut în nicio grupă: nu apar în niciuna, ceea ce se
  // vede ca o listă mai scurtă decât totalul, nu ca o clasificare inventată.
  const statuses = options.group === undefined ? [] : [...GROUPS[options.group]];
  const filter = statuses.length === 0 ? "" :
    ` AND status IN (${statuses.map(() => "?").join(", ")}) `;

  const rows = await db.all(
    `SELECT ${COLUMNS} FROM finding_entries ` +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? " + filter +
    // `priority DESC` întâi, `id DESC` ca departajare stabilă: mai multe
    // constatări împart aceeași prioritate, iar fără a doua coloană ordinea
    // diferă de la o cerere la alta și paginarea sare rânduri.
    " ORDER BY priority DESC, id DESC LIMIT ?",
    [...allowedInstanceIds.allowedInstanceIds, instanceId, ...statuses, limit]);

  return rows.map((row) => ({
    id: Number(row.id),
    sourceId: Number(row.source_id),
    scanner: String(row.scanner),
    cve: text(row.cve),
    title: text(row.title),
    severity: String(row.severity),
    cvss: text(row.cvss),
    epss: text(row.epss),
    // `=== 1`, nu adevăr: coloana e `TINYINT(1)` și `Boolean("0")` e ADEVĂRAT.
    // „E în catalogul KEV" înseamnă „se exploatează chiar acum"; inventat, ar
    // urca o constatare oarecare în capul listei și ar îngropa una reală.
    kev: Number(row.kev) === 1,
    kevDueDate: text(row.kev_due_date),
    packageName: text(row.package),
    installedVersion: text(row.installed_version),
    fixedVersion: text(row.fixed_version),
    priority: Number(row.priority),
    status: String(row.status),
    firstSeen: String(row.first_seen),
    lastSeen: String(row.last_seen),
  }));
}
