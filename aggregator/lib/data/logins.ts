/**
 * Sesiunile de login și istoricul de comenzi, citite pentru panou.
 *
 * `instanceId` e un FILTRU peste domeniu, nu un domeniu; vezi nota lungă din
 * `lib/data/detections.ts`.
 *
 * ## Ce face pagina asta altfel decât celelalte
 *
 * E singura care arată date de volum foarte mare. Măsurat pe gazdă pe 24 august
 * 2026: **~630 de comenzi pentru o singură logare interactivă** — un shell de login
 * sursează `/etc/profile.d/*`, iar fiecare script de acolo pornește zeci de
 * procese — și **~405 000 pentru un deploy**.
 *
 * Deci lista implicită e de SESIUNI, nu de comenzi. Comenzile se deschid pentru
 * o sesiune anume, PE PAGINI. O pagină care ar începe cu zece mii de rânduri de
 * `grep` și `basename` nu răspunde la nicio întrebare — dar nici una care arată
 * 500 din 22 000 și trimite restul „pe gazdă" nu răspunde la «ce a rulat în
 * sesiunea asta»: de aceea comenzile sunt paginate, nu plafonate.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import { AUTOMATION_DAYS, POLICIES } from "../retention";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

export type LoginSession = {
  sourceId: number;
  sessionKey: string;
  username: string | null;
  srcIp: string | null;
  terminal: string | null;
  interactive: boolean;
  openedAt: string | null;
  closedAt: string | null;
  closedInferred: boolean;
  commandCount: number;
  sudoCount: number;
  /**
   * Câte comenzi ale sesiunii a șters curățarea DIN ARHIVA ASTA.
   *
   * Nu vine de pe gazdă și nu e o parte din `commandCount`: aia e câte rânduri
   * are gazda, asta e câte am șters noi de aici. Citite împreună, spun și ce a
   * rulat sesiunea, și de ce tabelul de comenzi e mai scurt decât numărul de
   * deasupra lui.
   */
  commandsPurged: number;
};

export type SessionCommand = {
  ts: string | null;
  username: string | null;
  exe: string | null;
  argv: string;
  ppid: number | null;
  success: boolean | null;
};

/** Câte sesiuni se arată pe pagină. */
export const SESSIONS_SHOWN = 60;

/**
 * Câte comenzi încap pe O pagină a unei sesiuni.
 *
 * Nu mai e un plafon: până pe 5 octombrie 2026 era, iar o sesiune de 22 368 de
 * comenzi arăta primele 500 și trimitea restul «în baza de pe gazdă» — adică
 * operatorul nu mai putea vedea ce s-a rulat, exact întrebarea pentru care
 * pagina există. Acum sesiunea se citește pe pagini de atâtea rânduri, iar
 * pagina spune ce parte din total e cea de față.
 */
export const COMMANDS_SHOWN = 500;

/** Pagina cerută, adusă la o valoare care există: `abc`, `0`, `-3` → prima. */
function clampPage(requested: number, pages: number): number {
  if (!Number.isSafeInteger(requested) || requested < 1) return 1;
  return Math.min(requested, Math.max(1, pages));
}

/**
 * De ce lipsesc comenzi din tabelul unei sesiuni, atât cât se poate ști de aici.
 *
 *   * `retention` — sesiunea e mai veche decât fereastra de retenție care o
 *     privește (14 zile fără terminal, 180 cu), deci TOATE comenzile ei sunt în
 *     afara ferestrei: lipsa e explicată de politică;
 *   * `unknown` — sesiunea e mai nouă. Lipsa poate veni din curățarea
 *     automatizărilor, din comenzi care n-au ajuns încă sau n-au putut fi
 *     legate de sesiune (vezi `lib/session-links.ts`), iar de aici nu se poate
 *     alege între ele. «Nu știu» e un răspuns, și pagina îl dă ca atare.
 */
export type MissingWhy = "retention" | "unknown";

export type SessionDetail = {
  session: LoginSession | null;
  commands: SessionCommand[];
  /** `true` când mai sunt comenzi pe paginile următoare. */
  truncated: boolean;
  /** Pagina arătată, de la 1. */
  page: number;
  pages: number;
  /** Câte comenzi ale sesiunii SUNT în arhivă, pe toate paginile. */
  stored: number;
  /** Numărul de ordine (de la 1) al primei și ultimei comenzi de pe pagină. */
  from: number;
  to: number;
  /**
   * Câte din comenzile pe care gazda le-a numărat NU sunt în tabelul de aici și
   * nu sunt nici dintre cele șterse de curățare. Zero când totul se explică.
   */
  missing: number;
  /** Doar când `missing > 0`. */
  missingWhy: MissingWhy | null;
  /** Zilele ferestrei care a explicat lipsa, când `missingWhy` e `retention`. */
  retentionDays: number | null;
};

function num(v: unknown): number {
  // Driverul întoarce contoarele ca ȘIRURI când sunt mari; `"9" > "10"` pe
  // șiruri, iar o adunare devine concatenare.
  return Number(v ?? 0);
}

function bool(v: unknown): boolean {
  // `TINYINT(1)` sosește ca `"0"` sau `"1"`, iar `Boolean("0")` e `true`.
  return Number(v ?? 0) === 1;
}

function text(v: unknown): string | null {
  return v === null || v === undefined ? null : String(v);
}

function toSession(r: Record<string, unknown>): LoginSession {
  return {
    sourceId: num(r.source_id),
    sessionKey: String(r.session_key),
    username: text(r.username),
    srcIp: text(r.src_ip),
    terminal: text(r.terminal),
    interactive: bool(r.interactive),
    openedAt: text(r.opened_at),
    closedAt: text(r.closed_at),
    closedInferred: bool(r.closed_inferred),
    commandCount: num(r.command_count),
    sudoCount: num(r.sudo_count),
    commandsPurged: num(r.commands_purged),
  };
}

const COLUMNS =
  "source_id, session_key, username, src_ip, terminal, interactive, " +
  "opened_at, closed_at, closed_inferred, command_count, sudo_count, " +
  "commands_purged";

/**
 * Sesiunile, cele mai noi întâi.
 *
 * `onlyHumans` filtrează la cele cu terminal. E implicit ADEVĂRAT pe pagină,
 * fiindcă raportul măsurat e 557 de sesiuni de automatizare la 29 de om pe
 * șapte zile — iar o listă în care ce cauți e unul din douăzeci nu se citește.
 */
export async function listSessions(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
  opts: { onlyHumans?: boolean } = {},
): Promise<LoginSession[]> {
  if (seesNothing(allowedInstanceIds)) return [];

  const filtru = opts.onlyHumans === false ? "" : " AND interactive = 1 ";
  const rows = await db.all(
    `SELECT ${COLUMNS} FROM login_session_entries ` +
    ` WHERE instance_id IN (${scopePlaceholders(allowedInstanceIds)}) ` +
    "   AND instance_id = ? " + filtru +
    " ORDER BY opened_at DESC LIMIT ?",
    [...allowedInstanceIds.allowedInstanceIds, instanceId, SESSIONS_SHOWN]);
  return rows.map(toSession);
}

/** Fereastra de retenție care privește comenzile unei sesiuni, în zile. */
function retentionDaysFor(interactive: boolean): number {
  if (!interactive) return AUTOMATION_DAYS;
  // Politica generală pe comenzi, cea fără condiție suplimentară: aceeași
  // valoare ca în `lib/retention.ts`, citită de acolo, nu rescrisă aici.
  const general = POLICIES.find((p) => p.table === "session_command_entries"
                                       && p.extra === undefined);
  return general?.days ?? 180;
}

/**
 * O sesiune și comenzile ei, o pagină odată.
 *
 * `page` începe de la 1 și e adusă la o valoare care există. Pagina se citește cu
 * `LIMIT … OFFSET …` peste indexul `(instance_id, session_source_id, source_id)`,
 * deci o pagină târzie costă o parcurgere de index, nu o sortare.
 *
 * Totalul se numără ÎNAINTE de pagină, ca să se poată spune «pagina 3 din 45» și,
 * mai ales, ca să se poată compara cu ce a numărat gazda: `command_count` e câte
 * rânduri are gazda, `stored` câte are replica, iar diferența — minus ce a șters
 * curățarea (`commands_purged`) — e ce lipsește fără explicație. Fără
 * comparația asta, o sesiune cu 300 de comenzi din 22 000 arăta ca o sesiune cu
 * 300 de comenzi.
 *
 * `now` e parametru ca un test să nu depindă de ziua în care rulează.
 */
export async function sessionDetail(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
  sourceId: number, page = 1, now: () => number = Date.now,
): Promise<SessionDetail> {
  const empty: SessionDetail = {
    session: null, commands: [], truncated: false, page: 1, pages: 1,
    stored: 0, from: 0, to: 0, missing: 0, missingWhy: null, retentionDays: null,
  };
  if (seesNothing(allowedInstanceIds)) return empty;
  const scope = scopePlaceholders(allowedInstanceIds);
  const ids = [...allowedInstanceIds.allowedInstanceIds, instanceId];

  const [row] = await db.all(
    `SELECT ${COLUMNS} FROM login_session_entries ` +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? AND source_id = ?`,
    [...ids, sourceId]);
  if (row === undefined) return empty;
  const session = toSession(row);

  const [counted] = await db.all(
    "SELECT COUNT(*) AS n FROM session_command_entries " +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? ` +
    "   AND session_source_id = ?",
    [...ids, sourceId]);
  const stored = num(counted?.n);
  const pages = Math.max(1, Math.ceil(stored / COMMANDS_SHOWN));
  const shown = clampPage(page, pages);

  const rows = stored === 0 ? [] : await db.all(
    "SELECT ts, username, exe, argv, ppid, success " +
    "  FROM session_command_entries " +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? ` +
    "   AND session_source_id = ? " +
    " ORDER BY source_id LIMIT ? OFFSET ?",
    [...ids, sourceId, COMMANDS_SHOWN, (shown - 1) * COMMANDS_SHOWN]);

  const missing = Math.max(0, session.commandCount - stored - session.commandsPurged);
  let missingWhy: MissingWhy | null = null;
  let retentionDays: number | null = null;
  if (missing > 0) {
    const days = retentionDaysFor(session.interactive);
    // Cea mai NOUĂ activitate a sesiunii: închiderea, sau deschiderea dacă n-a
    // fost închisă. Dacă și aceea e în afara ferestrei, nicio comandă a ei nu
    // mai e în fereastră, iar lipsa se explică prin politică. Altfel „nu știu".
    const last = Date.parse((session.closedAt ?? session.openedAt ?? "")
                              .replace(" ", "T") + "Z");
    const old = Number.isFinite(last) && last < now() - days * 86_400_000;
    missingWhy = old ? "retention" : "unknown";
    retentionDays = old ? days : null;
  }

  return {
    session,
    commands: rows.map((r) => ({
      ts: text(r.ts),
      username: text(r.username),
      exe: text(r.exe),
      argv: String(r.argv ?? ""),
      ppid: r.ppid === null || r.ppid === undefined ? null : num(r.ppid),
      success: r.success === null || r.success === undefined ? null : bool(r.success),
    })),
    truncated: shown < pages,
    page: shown, pages, stored,
    from: stored === 0 ? 0 : (shown - 1) * COMMANDS_SHOWN + 1,
    to: stored === 0 ? 0 : (shown - 1) * COMMANDS_SHOWN + rows.length,
    missing, missingWhy, retentionDays,
  };
}
