/**
 * Constatările scanerelor, replicate. Sursa paginii `/panel/vulnerabilitati`.
 *
 * Ordinea e cea din panoul serverului și nu e decorativă: întâi constatările
 * NEAPLICATE (una rezolvată păstrează pe veci `priority`-ul vechi și, fără asta,
 * ar acoperi toată lista „Toate"), apoi `priority`, banda semaforului calculat
 * acolo (roșu, galben, gri, verde — decizia CISA SSVC, nu un prag), iar
 * `risk_score` (probabilitate × impact) ordonează în interiorul benzii. Reordonate după CVSS, listele arată complet altfel — CVSS e prost la
 * prezis ce se atacă efectiv. Replica nu recalculează nimic; afișează ce a decis
 * serverul, GAZDĂ cu gazdă: culoarea unui rând e verdictul gazdei lui, și nimic
 * de aici nu amestecă rândurile a două gazde (vezi `lib/finding-risk.ts`).
 *
 * `instanceId` e un FILTRU peste domeniu, nu un domeniu — vezi nota lungă din
 * `lib/data/detections.ts`.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";
import { GROUPS } from "../finding-groups";
import type { FindingGroup } from "../finding-groups";
import { COLORS, countColors, riskView } from "../finding-risk";
import type { RiskColor, RiskView } from "../finding-risk";

export type FindingSummary = {
  id: number;
  sourceId: number;
  scanner: string;
  cve: string | null;
  title: string | null;
  severity: string;
  cvss: string | null;
  epss: string | null;
  epssPercentile: string | null;
  kev: boolean;
  kevDueDate: string | null;
  packageName: string | null;
  installedVersion: string | null;
  fixedVersion: string | null;
  priority: number;
  /** Semaforul gazdei: culoare, decizie, motiv. Vezi `lib/finding-risk.ts`. */
  risk: RiskView;
  /** `probabilitate × impact`, 0..1, ca șir (DECIMAL la sursă); doar pentru ordine. */
  riskScore: string | null;
  status: string;
  firstSeen: string;
  lastSeen: string;
};

const COLUMNS =
  "id, source_id, scanner, cve, title, severity, cvss, epss, epss_percentile, kev, " +
  "kev_due_date, package, installed_version, fixed_version, priority, risk_color, " +
  "risk_decision, risk_score, risk, status, first_seen, last_seen";

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

/**
 * Câte constatări NEAPLICATE are fiecare culoare.
 *
 * Doar neaplicate, mereu: culoarea e o evaluare a ceea ce încă cere ceva. O
 * constatare rezolvată nu mai e evaluată pe server (`enrich.ASSESSED_STATUSES`) și
 * rămâne cu culoarea implicită, gri — numărată aici, ar umfla „fără date" cu
 * constatările închise (pe producție, ~6.700 de rânduri `dnf` rezolvate) și ar
 * face din cea mai importantă cifră a paginii un zgomot. Gri e mereu în rezultat,
 * și zero e un răspuns: „nimic fără date" e un fapt.
 *
 * O culoare necunoscută sosită de pe sârmă se numără ca GRI (`toColor`), nu se
 * pierde: suma pastilelor rămâne egală cu numărul de rânduri.
 */
export async function countByColor(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
): Promise<Record<RiskColor, number>> {
  if (seesNothing(allowedInstanceIds)) return countColors([]);
  const statuses = [...GROUPS.neaplicate];
  const rows = await db.all(
    "SELECT risk_color, COUNT(*) AS n FROM finding_entries " +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? " +
    (statuses.length === 0 ? "" :
      ` AND status IN (${statuses.map(() => "?").join(", ")}) `) +
    " GROUP BY risk_color",
    [...allowedInstanceIds.allowedInstanceIds, instanceId, ...statuses]);
  const out = countColors([]);
  for (const row of rows) {
    // O valoare pe care vocabularul nu o cunoaște -> gri, nu pierdută.
    const color = COLORS.includes(String(row.risk_color) as RiskColor)
      ? (String(row.risk_color) as RiskColor) : "grey";
    out[color] += Number(row.n);
  }
  return out;
}

export async function listFindings(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
  options: { limit?: number; group?: FindingGroup; color?: RiskColor } = {},
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
  // Pentru ORDINE, nu pentru filtru: vezi nota de la `ORDER BY`. Din vocabularul
  // declarat, ca filtrul, și legat ca parametru.
  const openStatuses = [...GROUPS.neaplicate];
  // Culoarea vine din URL, deci de la client: se compara cu un VOCABULAR inchis
  // (`COLORS`), la fel ca grupa, si ajunge in SQL ca parametru, nu interpolata.
  // Randurile sosite inainte de migratie au `DEFAULT 'grey'` (0017), deci filtrul
  // pe gri le include fara o ramura speciala pentru NULL.
  const colorFilter = options.color === undefined ? "" : " AND risk_color = ? ";
  const filter = (statuses.length === 0 ? "" :
    ` AND status IN (${statuses.map(() => "?").join(", ")}) `) + colorFilter;

  const rows = await db.all(
    `SELECT ${COLUMNS} FROM finding_entries ` +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? " + filter +
    // NEAPLICATELE ÎNTÂI, apoi `priority DESC`, `risk_score DESC`, `id DESC`.
    //
    // Prima cheie nu e decorativă. O constatare rezolvată nu mai e reexpediată
    // niciodată, deci rămâne pe veci cu `priority`-ul de la ultima expediere:
    // pe producție, 6.684 de rânduri rezolvate au `priority` ≥ 40 și 4.499 au
    // ≥ 80, pe când un rând deschis și verde are 0–20. Ordonată doar după
    // `priority`, vederea „Toate" (fără grupă, 200 de rânduri) ar fi fost 200 de
    // rânduri rezolvate și nicio constatare deschisă. Cheia asta face ca ce cere
    // ceva să stea înaintea a ce s-a închis, oricare ar fi numerele rămase.
    // `risk_score` e NULL pe cele rezolvate, iar MariaDB pune NULL ultimul la DESC.
    // `id DESC` e departajarea stabilă: fără ea ordinea diferă de la o cerere la
    // alta și paginarea sare rânduri.
    ` ORDER BY CASE WHEN status IN (${openStatuses.map(() => "?").join(", ")}) ` +
    "THEN 0 ELSE 1 END, priority DESC, risk_score DESC, id DESC LIMIT ?",
    [...allowedInstanceIds.allowedInstanceIds, instanceId, ...statuses,
     ...(options.color === undefined ? [] : [options.color]), ...openStatuses, limit]);

  return rows.map((row) => ({
    id: Number(row.id),
    sourceId: Number(row.source_id),
    scanner: String(row.scanner),
    cve: text(row.cve),
    title: text(row.title),
    severity: String(row.severity),
    cvss: text(row.cvss),
    epss: text(row.epss),
    epssPercentile: text(row.epss_percentile),
    // `=== 1`, nu adevăr: coloana e `TINYINT(1)` și `Boolean("0")` e ADEVĂRAT.
    // „E în catalogul KEV" înseamnă „se exploatează chiar acum"; inventat, ar
    // urca o constatare oarecare în capul listei și ar îngropa una reală.
    kev: Number(row.kev) === 1,
    kevDueDate: text(row.kev_due_date),
    packageName: text(row.package),
    installedVersion: text(row.installed_version),
    fixedVersion: text(row.fixed_version),
    priority: Number(row.priority),
    risk: riskView(row),
    riskScore: text(row.risk_score),
    status: String(row.status),
    firstSeen: String(row.first_seen),
    lastSeen: String(row.last_seen),
  }));
}
