/**
 * Sesiunile de login și istoricul de comenzi, citite pentru panou.
 *
 * `instanceId` e un FILTRU peste domeniu, nu un domeniu; vezi nota lungă din
 * `lib/data/detections.ts`.
 *
 * ## Ce face pagina asta altfel decât celelalte
 *
 * E singura care arată date de volum foarte mare. Măsurat pe gazdă pe 24 august
 * 2026: **~630 de comenzi pentru o singură logare interactivă** — un shell de
 * login sursează `/etc/profile.d/*`, iar fiecare script de acolo pornește zeci
 * de procese — și **~405 000 pentru un deploy**.
 *
 * Deci lista implicită e de SESIUNI, nu de comenzi. Comenzile se deschid pentru
 * o sesiune anume, tăiate la un plafon care se SPUNE. O pagină care ar începe cu
 * zece mii de rânduri de `grep` și `basename` nu răspunde la nicio întrebare.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
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
 * Câte comenzi se arată pentru o sesiune.
 *
 * 500 dintr-un deploy de ~405 000. Tăierea se SPUNE pe pagină — vezi `truncated`:
 * un plafon tăcut arată exact ca «atât s-a rulat», iar aici diferența e între
 * «n-a mai făcut nimic» și «restul nu ți l-am arătat».
 */
export const COMMANDS_SHOWN = 500;

export type SessionDetail = {
  session: LoginSession | null;
  commands: SessionCommand[];
  /** `true` când s-au rulat mai multe comenzi decât cele arătate. */
  truncated: boolean;
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

/**
 * O sesiune și comenzile ei.
 *
 * Se cer `COMMANDS_SHOWN + 1` rânduri, ca să se poată deosebi «atât a rulat» de
 * «atât ți-am arătat». Fără rândul în plus, cele două arată identic — iar prima
 * e o informație despre server, a doua despre pagină.
 */
export async function sessionDetail(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
  sourceId: number,
): Promise<SessionDetail> {
  if (seesNothing(allowedInstanceIds)) {
    return { session: null, commands: [], truncated: false };
  }
  const scope = scopePlaceholders(allowedInstanceIds);
  const ids = [...allowedInstanceIds.allowedInstanceIds, instanceId];

  const [row] = await db.all(
    `SELECT ${COLUMNS} FROM login_session_entries ` +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? AND source_id = ?`,
    [...ids, sourceId]);
  if (row === undefined) return { session: null, commands: [], truncated: false };

  const rows = await db.all(
    "SELECT ts, username, exe, argv, ppid, success " +
    "  FROM session_command_entries " +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? ` +
    "   AND session_source_id = ? " +
    " ORDER BY source_id LIMIT ?",
    [...ids, sourceId, COMMANDS_SHOWN + 1]);

  const truncated = rows.length > COMMANDS_SHOWN;
  return {
    session: toSession(row),
    commands: rows.slice(0, COMMANDS_SHOWN).map((r) => ({
      ts: text(r.ts),
      username: text(r.username),
      exe: text(r.exe),
      argv: String(r.argv ?? ""),
      ppid: r.ppid === null || r.ppid === undefined ? null : num(r.ppid),
      success: r.success === null || r.success === undefined ? null : bool(r.success),
    })),
    truncated,
  };
}
