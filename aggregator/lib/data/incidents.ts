/**
 * Incidentele replicate, filtrate de dreptul contului care întreabă.
 *
 * Aceeași formă ca `lib/data/instances.ts`: baza, apoi `allowedInstanceIds`,
 * apoi restul. Fiecare interogare de aici poartă `instance_id IN (…)`, inclusiv
 * cea care caută UN rând după id — și mai ales aia, fiindcă ea e cea care decide
 * dacă cineva află că un incident există pe un server pe care n-are voie să-l
 * vadă.
 *
 * ## 404, nu 403 — și de ce iese așa singur
 *
 * Un 403 pentru „incidentul 812 nu e al tău" spune că incidentul 812 EXISTĂ.
 * Cine numără codurile de stare peste un interval de id-uri capătă harta a ceea
 * ce are celălalt server, fără să vadă niciun rând. De-aia interogarea nu caută
 * rândul și apoi compară instanța: filtrul e ÎN `WHERE`, deci „nu există
 * nicăieri" și „există pe altă instanță" produc același rezultat gol, pe același
 * drum de cod. Egalitatea la octet dintre cele două răspunsuri nu e o grijă a
 * rutei, e o consecință a faptului că ruta nu poate deosebi cazurile.
 *
 * ## De ce timeline-ul e o A DOUA interogare și nu un JOIN
 *
 * Fiindcă un JOIN care uită `instance_id` în clauza lui `ON` amestecă tăcut
 * datele a două servere: `incident_timeline_entries.incident_source_id` e id-ul
 * incidentului DE PE SERVERUL LUI, iar două instanțe au aproape sigur incidente
 * cu același id acolo. Legate doar pe `source_id`, cronologia serverului B ar
 * apărea sub incidentul serverului A — corect ca SQL, fals ca informație, și
 * fără nicio eroare nicăieri. Două interogări, fiecare cu `instance_id IN (…)`
 * al ei, nu au unde greși; o îmbinare corectă ar avea nevoie de `instance_id` în
 * `ON`, iar asta e o linie pe care o poate șterge un refactor. Garda din
 * `tests/joins.test.ts` există pentru ziua în care cineva o scrie totuși.
 *
 * ## Care dintre cele două tabele are azi scriitor, și care nu
 *
 * **`incident_entries` are.** Fluxul `incidents` din `lib/streams.ts`, cu
 * geamănul lui `INCIDENT_STREAM` din `sentinel/report/shipper.py` (`STREAMS =
 * (AUDIT_STREAM, INCIDENT_STREAM)`). Ce se citește de aici chiar ajunge acolo
 * prin sincronizare.
 *
 * **`incident_timeline_entries` NU are.** Tabela e creată de
 * `migrations/0003_entities.sql` și pe serverul monitorizat există chiar
 * `incident_timeline`, scrisă la fiecare acțiune (`sentinel/db/repo/incidents.py`)
 * — dar niciun flux n-o expediază, nici la un capăt, nici la celălalt. Deci pe
 * gazdă `incidentTimeline` întoarce azi o listă goală pentru ORICE incident, iar
 * `MAX_TIMELINE`, `truncated` și filtrul `instance_id = ?` sunt corecte și nu
 * apără încă nimic: sunt scrise pentru ziua în care fluxul apare, ca atunci să
 * nu trebuiască scrise sub presiune.
 *
 * Scris pe față fiindcă altfel se citește invers: un panou care afișează o
 * cronologie mereu goală arată exact ca unul căruia i s-a stricat interogarea, și
 * cine caută defectul îl caută aici, unde nu e. Fluxul NU se construiește
 * aici — e o piesă separată, cu cursorul, filigranul și migrația ei.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

/**
 * Cât se întoarce dintr-o listă, cel mult.
 *
 * Mărginit AICI, nu în rută: o funcție de acces la date care acceptă orice
 * `limit` e o cerere prin care oricine autentificat poate cere un milion de
 * rânduri. Ce vine de la client se strânge la intervalul ăsta, nu se refuză —
 * un 400 pentru `limit=5000` ar fi o suprafață de mesaje în plus fără nimic
 * câștigat.
 */
export const MAX_PAGE = 200;
export const DEFAULT_PAGE = 50;

/**
 * Câte rânduri de cronologie se citesc, cel mult.
 *
 * Aceeași grijă ca `MAX_PAGE`, aplicată interogării care n-o avea: cronologia
 * nu are `?limit=`, deci fără plafon citea TOT ce e legat de incident. Un
 * incident de forță brută are cronologia cât detecțiile lui — zeci de mii de
 * rânduri pentru o singură cerere autentificată, materializate în memoria
 * procesului de pe găzduire înainte să ajungă undeva.
 *
 * Tăierea NU e tăcută: se cere un rând peste plafon tocmai ca să se poată ști
 * dacă a mai rămas ceva, iar `truncated` pleacă spre panou. O cronologie tăiată
 * care arată ca una întreagă e chiar felul în care un instrument de monitorizare
 * minte — operatorul ar citi „asta e tot ce s-a întâmplat" dintr-o listă din
 * care lipsește sfârșitul.
 */
export const MAX_TIMELINE = 500;

export type IncidentSummary = {
  /** Id-ul RÂNDULUI din agregator, nu `incidents.id` de pe server. Opac. */
  id: number;
  instanceId: string;
  sourceId: number;
  fingerprint: string;
  status: string;
  severity: string;
  aiSeverity: string | null;
  title: string;
  detectionCount: number;
  firstDetectionAt: string;
  lastDetectionAt: string;
};

export type IncidentDetail = IncidentSummary & {
  summary: string | null;
  actorKey: string | null;
  acknowledgedBy: string | null;
  acknowledgedAt: string | null;
  resolvedAt: string | null;
  resolutionNote: string | null;
};

const SUMMARY_COLUMNS =
  "id, instance_id, source_id, fingerprint, status, severity, ai_severity, title, " +
  "detection_count, first_detection_at, last_detection_at";

const DETAIL_COLUMNS =
  `${SUMMARY_COLUMNS}, summary, actor_key, acknowledged_by, acknowledged_at, ` +
  "resolved_at, resolution_note";

/**
 * Cele mai recente incidente de pe instanțele permise.
 *
 * `ORDER BY last_detection_at DESC, id DESC`: a doua coloană nu e decorativă —
 * mai multe incidente pot avea aceeași ultimă detecție, iar fără o departajare
 * stabilă ordinea diferă de la o cerere la alta și paginarea sare rânduri.
 */
export async function listIncidents(
  db: AuthDb, allowedInstanceIds: InstanceScope,
  options: { limit?: number; instanceId?: string } = {},
): Promise<IncidentSummary[]> {
  if (seesNothing(allowedInstanceIds)) return [];
  const limit = pageSize(options.limit);

  // `instanceId` e un FILTRU peste domeniu, niciodată un domeniu. Panoul arată
  // un singur server odată, iar alegerea vine din URL — adică de la client.
  // Clauza se ADAUGĂ la `IN (<domeniu>)`, deci orice s-ar cere acolo, mulțimea
  // rezultată e o submulțime a celei permise: se poate îngusta, nu lărgi.
  // Aceeași formă și același motiv ca în `lib/data/detections.ts`.
  const only = options.instanceId === undefined ? "" : " AND instance_id = ? ";
  const extra = options.instanceId === undefined ? [] : [options.instanceId];

  const rows = await db.all(
    `SELECT ${SUMMARY_COLUMNS} FROM incident_entries ` +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` + only +
    " ORDER BY last_detection_at DESC, id DESC LIMIT ?",
    [...allowedInstanceIds.allowedInstanceIds, ...extra, limit]);
  return rows.map(toSummary);
}

/**
 * UN incident, sau `null`.
 *
 * `null` acoperă amândouă cazurile — nu există nicăieri, sau există pe o
 * instanță pe care contul n-o vede — fiindcă interogarea nu le poate deosebi.
 * Vezi capul modulului.
 */
export async function incidentById(
  db: AuthDb, allowedInstanceIds: InstanceScope, id: number,
): Promise<IncidentDetail | null> {
  if (seesNothing(allowedInstanceIds)) return null;
  // Un id care nu e un întreg pozitiv nu ajunge la bază: ar fi un parametru pe
  // care MariaDB îl convertește după regulile ei, iar `'5x'` devine acolo `5`.
  if (!Number.isSafeInteger(id) || id <= 0) return null;

  const rows = await db.all(
    `SELECT ${DETAIL_COLUMNS} FROM incident_entries ` +
    " WHERE id = ? " +
    `   AND instance_id IN (${scopePlaceholders(allowedInstanceIds)})`,
    [id, ...allowedInstanceIds.allowedInstanceIds]);

  if (rows.length === 0) return null;
  if (rows.length > 1) {
    // `id` e cheia primară. Mai multe rânduri înseamnă că interogarea nu mai e
    // cea scrisă aici, iar a alege unul ar fi o ghicire despre ce vede cineva.
    throw new Error(
      `${rows.length} incidente cu id-ul ${id}: cheia primară a tabelei ` +
      "incident_entries nu mai e unică sau interogarea a fost schimbată");
  }
  const row = rows[0];
  return {
    ...toSummary(row),
    summary: text(row.summary),
    actorKey: text(row.actor_key),
    acknowledgedBy: text(row.acknowledged_by),
    acknowledgedAt: text(row.acknowledged_at),
    resolvedAt: text(row.resolved_at),
    resolutionNote: text(row.resolution_note),
  };
}

export type TimelineEntry = {
  id: number;
  at: string;
  kind: string;
  actor: string | null;
};

export type Timeline = {
  entries: TimelineEntry[];
  /** `true` = incidentul are mai multe rânduri decât `MAX_TIMELINE`, iar ce e
   *  mai jos nu s-a citit. Cine afișează lista TREBUIE s-o spună. */
  truncated: boolean;
};

/**
 * Cronologia unui incident, filtrată de aceleași drepturi.
 *
 * Cere instanța ȘI `source_id`-ul incidentului, nu id-ul de rând al
 * agregatorului: cronologia se leagă de incident prin id-ul DE PE SERVER. Cine
 * cheamă funcția asta trece întâi prin `incidentById`, care e cea care
 * transformă un id opac într-o pereche (instanță, `source_id`) — și care refuză
 * să facă transformarea aia pentru o instanță nepermisă.
 *
 * ## Două filtre, cu treburi diferite — și niciunul nu-l acoperă pe celălalt
 *
 * `instance_id = ?` alege cronologia ACESTUI incident: `incident_source_id` e
 * id-ul de pe serverul lui, iar două instanțe au aproape sigur rânduri cu
 * aceeași valoare acolo. Fără el, un cont care vede două servere — cazul normal
 * al unui agregator multi-instanță — citește sub un incident al lui A acțiunile,
 * notele și verdictele întâmplate pe B. Nicio eroare, nicăieri.
 *
 * `instance_id IN (…)` e filtrul de AUTORIZARE, ca la fiecare interogare de
 * aici. Rămâne deși perechea vine de la o interogare deja filtrată: fără el,
 * funcția ar fi corectă doar cât timp apelantul o folosește corect.
 *
 * Cel de-al doilea îl MASCHEAZĂ pe primul într-o probă făcută cu un cont care
 * are o singură instanță — acolo `IN (prod-a)` exclude oricum rândurile lui B,
 * deci scoaterea lui `instance_id = ?` nu se vede. De-aia proba din
 * `tests/panel-authz.test.ts` dă contului AMÂNDOUĂ instanțele.
 */
export async function incidentTimeline(
  db: AuthDb, allowedInstanceIds: InstanceScope,
  incident: { instanceId: string; sourceId: number },
): Promise<Timeline> {
  if (seesNothing(allowedInstanceIds)) return { entries: [], truncated: false };

  // Un rând peste plafon: e singura cale prin care se poate ști dacă a mai rămas
  // ceva. Cu exact `MAX_TIMELINE` rânduri citite, „atât era" și „atât am citit"
  // ar arăta la fel.
  const rows = await db.all(
    "SELECT id, at, kind, actor FROM incident_timeline_entries " +
    " WHERE instance_id = ? AND incident_source_id = ? " +
    `   AND instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    " ORDER BY at, id LIMIT ?",
    [incident.instanceId, incident.sourceId,
     ...allowedInstanceIds.allowedInstanceIds, MAX_TIMELINE + 1]);

  return {
    entries: rows.slice(0, MAX_TIMELINE).map((row) => ({
      id: count(row.id, "incident_timeline_entries.id"),
      at: String(row.at),
      kind: String(row.kind),
      actor: text(row.actor),
    })),
    truncated: rows.length > MAX_TIMELINE,
  };
}

// ---------------------------------------------------------------------------
function pageSize(asked: number | undefined): number {
  if (asked === undefined) return DEFAULT_PAGE;
  if (!Number.isSafeInteger(asked) || asked <= 0) return DEFAULT_PAGE;
  return Math.min(asked, MAX_PAGE);
}

function toSummary(row: Record<string, unknown>): IncidentSummary {
  return {
    id: count(row.id, "incident_entries.id"),
    instanceId: String(row.instance_id),
    sourceId: count(row.source_id, "incident_entries.source_id"),
    fingerprint: String(row.fingerprint),
    status: String(row.status),
    severity: String(row.severity),
    aiSeverity: text(row.ai_severity),
    title: String(row.title),
    detectionCount: count(row.detection_count, "incident_entries.detection_count"),
    firstDetectionAt: String(row.first_detection_at),
    lastDetectionAt: String(row.last_detection_at),
  };
}

function text(value: unknown): string | null {
  return value === null || value === undefined ? null : String(value);
}

/** `BIGINT` vine ca ȘIR (`bigNumberStrings` în `lib/db.ts`), deci nu se
 *  presupune tipul — și un id necitibil ARUNCĂ, nu devine 0. */
function count(value: unknown, column: string): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(
      `${column} nu e un întreg citibil (${String(value)}); o valoare pe care ` +
      "nu o pot citi nu se rotunjește la 0");
  }
  return parsed;
}
