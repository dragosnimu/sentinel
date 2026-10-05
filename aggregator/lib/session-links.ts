/**
 * Legătura dintre o comandă și sesiunea ei, refăcută la receptor.
 *
 * ## Eșecul pe care îl repară
 *
 * Măsurat pe 5 octombrie 2026: din 502 242 de rânduri în `session_command_entries`,
 * **265 220 (53 %) aveau `session_source_id` NULL**, repartizate pe 8 645 de
 * chei de sesiune și pe toată perioada, 24 august → azi. Pentru fiecare dintre
 * ele, pagina de detaliu a sesiunii — care caută comenzile după
 * `session_source_id` — nu putea arăta nimic, deși rândurile erau în tabelă.
 *
 * ## De ce era NULL
 *
 * Pe gazdă, `session_commands.session_id` se scrie NULL când comanda sosește
 * înaintea sesiunii ei, și se completează MAI TÂRZIU (`_attach_orphans`, la
 * logare sau la ieșire; vezi `sentinel/db/repo/logins.py`). Fluxul `session_commands`
 * e însă append-only: cursorul merge pe `id`, un rând pleacă o singură dată, în
 * starea de atunci, iar completarea de după nu-l mai atinge. Receptorul primea
 * deci NULL pentru totdeauna.
 *
 * Cifrele care îl dovedesc: gazda are azi 151 661 de rânduri NULL (orfane care
 * chiar n-au sesiune — de dinaintea proiecției, sau ale unor joburi fără
 * sesiune), iar replica 265 220. Diferența, ~113 500, sunt rânduri pe care gazda
 * le-a legat după ce le expediase.
 *
 * ## Ce face de acum
 *
 * Aceeași regulă ca pe gazdă, aplicată aici din ce are replica deja:
 *
 *     comanda aparține sesiunii cu ACEEAȘI `session_key` al cărei interval
 *     [deschidere − 1 min, închidere + 1 min] îi conține `ts`
 *     (închidere lipsă = fără margine superioară)
 *
 * Marginea de un minut și forma intervalului sunt cele din `_find_session` și
 * `_attach_orphans`, nu o alegere nouă: replica nu poate fi mai isteață decât
 * gazda despre ce înseamnă „aceeași sesiune", și nici mai nepăsătoare.
 *
 * `session_key` (`ses` din nucleu) se renumerotează la fiecare pornire a
 * gazdei, deci aceeași cheie apare, în luni diferite, la sesiuni diferite. De
 * aceea cheia SINGURĂ nu leagă nimic — fereastra de timp e jumătate din regulă.
 *
 * ## Ce NU se leagă
 *
 * **Ambiguitatea nu se rezolvă prin alegere.** Dacă două sesiuni cu aceeași cheie
 * au intervale care se suprapun, comanda din suprapunere ar putea fi a oricăreia;
 * gazda ia „cea mai recent deschisă", replica nu are dreptul să ghicească. Ambele
 * sesiuni rămân nelegate și se raportează, iar legarea se face de la sine când
 * una dintre ele se închide și intervalele nu se mai ating. Măsurat pe gazdă:
 * 6 perechi din 2 636 de sesiuni, toate din prima zi (24 august), duplicate
 * create la o secundă distanță.
 *
 * Un rând care are DEJA `session_source_id` nu se atinge niciodată: gazda știe
 * mai bine decât orice derivare de aici, iar condiția `IS NULL` din instrucțiune
 * e ce face operația repetabilă — a doua rulare nu are ce schimba.
 *
 * ## Unde rulează
 *
 *   1. `relinkAfterIngest`, după fiecare lot care a adus sesiuni sau comenzi:
 *      sesiunile din lot se leagă pe tot intervalul lor (o sesiune tocmai
 *      închisă e momentul în care orfanele ei devin atribuibile), iar comenzile
 *      din lot rămase NULL se leagă de sesiunea care le conține, dacă există;
 *   2. `backfill`, o singură dată pentru istoric, din `bin/relink-session-commands.ts`.
 *
 * ## Ce nu se poate dovedi de aici
 *
 * Nu există MariaDB pe mașina de dezvoltare. Testele rulează instrucțiunile
 * pe un dublu care evaluează chiar condițiile din text (`tests/session-links.test.ts`),
 * deci probează logica de selecție a intervalelor și forma instrucțiunilor, nu
 * că serverul le acceptă sau cât durează pe 500 000 de rânduri. Prima rulare pe
 * baza reală trebuie făcută cu `--dry-run`.
 */

import type { Db } from "./migrate";

/** Marginea de ceas între înregistrări, în milisecunde — cea de pe gazdă. */
export const MARGIN_MS = 60_000;

/** Câte valori într-un `IN (...)`. Sub limita de parametri a driverului. */
const CHUNK = 500;

/** O sesiune, cât trebuie ca să i se poată calcula intervalul. */
export type SessionWindow = {
  sourceId: number;
  sessionKey: string;
  openedAt: string;
  closedAt: string | null;
  interactive?: boolean;
};

/** Un interval de comenzi atribuibile unei sesiuni. `hi` e `Infinity` pe una deschisă. */
export type LinkWindow = { session: SessionWindow; lo: number; hi: number };

export type Plan = {
  link: LinkWindow[];
  /** Sesiuni cu cheia și intervalul suprapuse peste ale alteia: nu se leagă. */
  ambiguous: SessionWindow[];
  /** Sesiuni a căror dată nu se poate citi: „nu știu" nu e „n-are comenzi". */
  unreadable: SessionWindow[];
};

const DATETIME = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z?$/;

/** `DATETIME(6)` primit ca șir (`dateStrings: true`) → milisecunde UTC, sau `null`. */
export function parseDatetime(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const m = DATETIME.exec(value.trim());
  if (m === null) return null;
  const frac = m[7] === undefined ? 0 : Number(m[7].padEnd(3, "0").slice(0, 3));
  const ms = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]),
                      Number(m[4]), Number(m[5]), Number(m[6]), frac);
  return Number.isFinite(ms) ? ms : null;
}

/** Milisecunde UTC → `YYYY-MM-DD HH:MM:SS.mmm`, forma pe care o primește un DATETIME. */
export function formatDatetime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace("Z", "");
}

/**
 * Ce sesiuni se pot lega fără ghicit.
 *
 * Funcție pură: nu atinge baza, ca regula să se poată proba pe cazuri scrise de
 * mână. Ambiguitatea se hotărăște pe CHEIE: două sesiuni cu cheia diferită nu se
 * pot confunda, oricât de aproape ar fi în timp.
 */
export function planLinks(sessions: readonly SessionWindow[]): Plan {
  const plan: Plan = { link: [], ambiguous: [], unreadable: [] };
  const byKey = new Map<string, LinkWindow[]>();

  for (const session of sessions) {
    const opened = parseDatetime(session.openedAt);
    const closed = session.closedAt === null ? null : parseDatetime(session.closedAt);
    if (opened === null || (session.closedAt !== null && closed === null)) {
      plan.unreadable.push(session);
      continue;
    }
    const window: LinkWindow = {
      session, lo: opened - MARGIN_MS,
      hi: closed === null ? Number.POSITIVE_INFINITY : closed + MARGIN_MS,
    };
    const group = byKey.get(session.sessionKey);
    if (group === undefined) byKey.set(session.sessionKey, [window]);
    else group.push(window);
  }

  for (const group of byKey.values()) {
    for (const window of group) {
      const clash = group.some((other) => other !== window
        && other.lo <= window.hi && window.lo <= other.hi);
      if (clash) plan.ambiguous.push(window.session);
      else plan.link.push(window);
    }
  }
  return plan;
}

function marks(count: number): string {
  return Array.from({ length: count }, () => "?").join(", ");
}

function chunks<T>(items: readonly T[], size: number = CHUNK): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

function num(value: unknown): number {
  // BIGINT vine ca ȘIR (`bigNumberStrings`).
  return Number(value ?? 0);
}

/**
 * `UPDATE`-ul unei ferestre. Singura instrucțiune care scrie legătura.
 *
 * `session_source_id IS NULL` e condiția care o face repetabilă și care apără ce
 * a legat deja gazda. `instance_id` e în fiecare instrucțiune: `source_id` și
 * `session_key` se repetă între gazde, iar o legătură scrisă peste instanța
 * greșită ar pune comenzile unui server în sesiunea altuia.
 */
export function relinkSql(bounded: boolean): string {
  return "UPDATE session_command_entries SET session_source_id = ? " +
         "WHERE instance_id = ? AND session_source_id IS NULL " +
         "AND session_key = ? AND ts >= ?" + (bounded ? " AND ts <= ?" : "");
}

async function applyWindow(
  db: Db, instanceId: string, window: LinkWindow, lo: number, hi: number,
): Promise<void> {
  const bounded = Number.isFinite(hi);
  const params: unknown[] = [window.session.sourceId, instanceId,
                             window.session.sessionKey, formatDatetime(lo)];
  if (bounded) params.push(formatDatetime(hi));
  await db.run(relinkSql(bounded), params);
}

async function sessionsOfKeys(
  db: Db, instanceId: string, keys: readonly string[],
): Promise<SessionWindow[]> {
  const out: SessionWindow[] = [];
  for (const part of chunks(keys)) {
    const rows = await db.all(
      "SELECT source_id, session_key, interactive, opened_at, closed_at " +
      "FROM login_session_entries " +
      `WHERE instance_id = ? AND session_key IN (${marks(part.length)})`,
      [instanceId, ...part]);
    for (const r of rows) {
      out.push({
        sourceId: num(r.source_id), sessionKey: String(r.session_key),
        interactive: Number(r.interactive ?? 0) === 1,
        openedAt: String(r.opened_at),
        closedAt: r.closed_at === null || r.closed_at === undefined
          ? null : String(r.closed_at),
      });
    }
  }
  return out;
}

export type RelinkReport = {
  /** Câte chei de sesiune au fost examinate. */
  keys: number;
  /** Câte instrucțiuni de legare au rulat. */
  windows: number;
  /** Din comenzile LOTULUI rămase NULL înainte, câte au încetat să fie NULL. */
  linked: number;
  /** Din comenzile LOTULUI, câte au rămas NULL după. Normal să fie >0: orfane reale. */
  stillUnlinked: number;
  ambiguous: number[];
  unreadable: number[];
};

async function countUnlinked(
  db: Db, instanceId: string, commandIds: readonly number[],
): Promise<number> {
  let total = 0;
  for (const part of chunks(commandIds)) {
    const rows = await db.all(
      "SELECT COUNT(*) AS n FROM session_command_entries " +
      "WHERE instance_id = ? AND session_source_id IS NULL " +
      `AND source_id IN (${marks(part.length)})`,
      [instanceId, ...part]);
    total += num(rows[0]?.n);
  }
  return total;
}

/**
 * Se cheamă DUPĂ ce un lot cu sesiuni sau comenzi a intrat.
 *
 * `sessionIds` și `commandIds` sunt `source_id`-urile din lot. Ce se citește de
 * aici înainte vine din BAZĂ, nu din payload: rândurile au trecut deja prin
 * validarea de ingestie, iar un câmp luat din corpul cererii ar fi o a doua
 * cale de a pune o valoare în `WHERE`.
 *
 * Nu aruncă pe un rând ciudat: aruncă numai când baza refuză. Apelantul prinde
 * și SCRIE eroarea — rândurile sunt deja în arhivă, iar legătura se poate
 * reface oricând (`backfill`), deci o eroare aici nu are voie să blocheze
 * ecoul unui lot valid, dar nici să treacă fără urmă.
 */
export async function relinkAfterIngest(
  db: Db, instanceId: string,
  batch: { sessionIds: readonly number[]; commandIds: readonly number[] },
): Promise<RelinkReport> {
  const touchedSessions = new Set<number>();
  const keys = new Set<string>();

  for (const part of chunks(batch.sessionIds)) {
    const rows = await db.all(
      "SELECT source_id, session_key FROM login_session_entries " +
      `WHERE instance_id = ? AND source_id IN (${marks(part.length)})`,
      [instanceId, ...part]);
    for (const r of rows) {
      touchedSessions.add(num(r.source_id));
      keys.add(String(r.session_key));
    }
  }

  // Fereastra comenzilor din lot, per cheie: o sesiune găsită doar prin ele se
  // leagă DOAR în ea, nu pe tot intervalul. Altfel fiecare lot dintr-un deploy
  // mare ar reciti, pentru aceeași cheie, tot intervalul sesiunii.
  const narrow = new Map<string, { lo: number; hi: number }>();
  const before = await countUnlinked(db, instanceId, batch.commandIds);
  for (const part of chunks(batch.commandIds)) {
    const rows = await db.all(
      "SELECT session_key, MIN(ts) AS lo, MAX(ts) AS hi " +
      "FROM session_command_entries " +
      "WHERE instance_id = ? AND session_source_id IS NULL " +
      `AND source_id IN (${marks(part.length)}) GROUP BY session_key`,
      [instanceId, ...part]);
    for (const r of rows) {
      const lo = parseDatetime(r.lo);
      const hi = parseDatetime(r.hi);
      if (lo === null || hi === null) continue;
      const key = String(r.session_key);
      keys.add(key);
      const seen = narrow.get(key);
      narrow.set(key, seen === undefined ? { lo, hi }
        : { lo: Math.min(seen.lo, lo), hi: Math.max(seen.hi, hi) });
    }
  }

  const report: RelinkReport = {
    keys: keys.size, windows: 0, linked: 0, stillUnlinked: 0,
    ambiguous: [], unreadable: [],
  };
  if (keys.size === 0) return report;

  const plan = planLinks(await sessionsOfKeys(db, instanceId, [...keys]));
  report.ambiguous = plan.ambiguous.map((s) => s.sourceId);
  report.unreadable = plan.unreadable.map((s) => s.sourceId);

  for (const window of plan.link) {
    let { lo, hi } = window;
    if (!touchedSessions.has(window.session.sourceId)) {
      const range = narrow.get(window.session.sessionKey);
      if (range === undefined) continue;
      lo = Math.max(lo, range.lo);
      hi = Math.min(hi, range.hi);
      if (lo > hi) continue;
    }
    await applyWindow(db, instanceId, window, lo, hi);
    report.windows += 1;
  }

  report.stillUnlinked = await countUnlinked(db, instanceId, batch.commandIds);
  report.linked = Math.max(0, before - report.stillUnlinked);
  return report;
}

// ---------------------------------------------------------------------------
// Istoricul
// ---------------------------------------------------------------------------
export type BackfillOptions = {
  /** Doar instanța asta; altfel toate. */
  instanceId?: string;
  /** Fără `apply`, doar se numără ce ar fi legat. */
  apply: boolean;
  /** Pragul de retenție pentru sesiunile fără terminal, în zile. */
  automationDays: number;
  /** Ceasul, ca un test să nu depindă de ziua în care rulează. */
  now?: () => number;
};

export type BackfillReport = {
  instanceId: string;
  unlinkedBefore: number;
  unlinkedAfter: number;
  /** Ce ar lega (uscat) sau ce a legat (cu `apply`), după numărătoarea ferestrelor. */
  wouldLink: number;
  /** Din ele, câte aparțin sesiunilor FĂRĂ terminal mai vechi decât retenția. */
  prunableByRetention: number;
  sessions: number;
  ambiguous: number[];
  unreadable: number[];
  applied: boolean;
};

async function countInstanceUnlinked(db: Db, instanceId: string): Promise<number> {
  const rows = await db.all(
    "SELECT COUNT(*) AS n FROM session_command_entries " +
    "WHERE instance_id = ? AND session_source_id IS NULL", [instanceId]);
  return num(rows[0]?.n);
}

async function countWindow(
  db: Db, instanceId: string, window: LinkWindow,
): Promise<number> {
  const bounded = Number.isFinite(window.hi);
  const rows = await db.all(
    "SELECT COUNT(*) AS n FROM session_command_entries " +
    "WHERE instance_id = ? AND session_source_id IS NULL " +
    "AND session_key = ? AND ts >= ?" + (bounded ? " AND ts <= ?" : ""),
    [instanceId, window.session.sessionKey, formatDatetime(window.lo),
     ...(bounded ? [formatDatetime(window.hi)] : [])]);
  return num(rows[0]?.n);
}

/**
 * Leagă istoricul. Sigur de repetat: nu atinge decât rânduri cu legătura NULL.
 *
 * Verificarea efectului nu e codul de întoarcere al instrucțiunilor: rândurile
 * NULL ale instanței se numără ÎNAINTE și DUPĂ, iar raportul spune ce a găsit
 * baza, nu ce a cerut scriptul. `wouldLink` și `unlinkedBefore − unlinkedAfter`
 * trebuie să coincidă după `apply`; dacă nu, ceva s-a schimbat în timpul rulării
 * (un lot nou) sau instrucțiunile n-au făcut ce se credea, iar operatorul vede
 * diferența în loc s-o presupună zero.
 */
export async function backfill(db: Db, opts: BackfillOptions): Promise<BackfillReport[]> {
  const now = (opts.now ?? Date.now)();
  const ids = opts.instanceId !== undefined
    ? [opts.instanceId]
    : (await db.all("SELECT DISTINCT instance_id FROM login_session_entries", []))
        .map((r) => String(r.instance_id));

  const reports: BackfillReport[] = [];
  for (const instanceId of ids) {
    const rows = await db.all(
      "SELECT source_id, session_key, interactive, opened_at, closed_at " +
      "FROM login_session_entries WHERE instance_id = ?", [instanceId]);
    const sessions: SessionWindow[] = rows.map((r) => ({
      sourceId: num(r.source_id), sessionKey: String(r.session_key),
      interactive: Number(r.interactive ?? 0) === 1,
      openedAt: String(r.opened_at),
      closedAt: r.closed_at === null || r.closed_at === undefined
        ? null : String(r.closed_at),
    }));
    const plan = planLinks(sessions);
    const unlinkedBefore = await countInstanceUnlinked(db, instanceId);

    let wouldLink = 0;
    let prunable = 0;
    for (const window of plan.link) {
      const n = await countWindow(db, instanceId, window);
      if (n === 0) continue;
      wouldLink += n;
      const opened = parseDatetime(window.session.openedAt) ?? now;
      if (window.session.interactive === false
          && opened < now - opts.automationDays * 86_400_000) {
        prunable += n;
      }
      if (opts.apply) await applyWindow(db, instanceId, window, window.lo, window.hi);
    }

    reports.push({
      instanceId, unlinkedBefore,
      unlinkedAfter: opts.apply ? await countInstanceUnlinked(db, instanceId)
                                : unlinkedBefore,
      wouldLink, prunableByRetention: prunable, sessions: sessions.length,
      ambiguous: plan.ambiguous.map((s) => s.sourceId),
      unreadable: plan.unreadable.map((s) => s.sourceId),
      applied: opts.apply,
    });
  }
  return reports;
}
