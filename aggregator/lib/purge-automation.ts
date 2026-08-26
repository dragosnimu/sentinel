/**
 * Curățarea istoricului deja replicat al automatizărilor.
 *
 * Perechea de pe gazdă e `scripts/purge-automation-commands.py`. Sunt două
 * scripturi și nu unul cu două moduri fiindcă cele două baze n-au nimic în
 * comun în afară de REGULĂ: acolo PostgreSQL, cu `asyncpg` și cu parola din
 * `/etc/sentinel/secrets.env`; aici MariaDB, cu driverul declarat în
 * `lib/db.ts` și cu variabilele de mediu ale găzduirii — care nu există pe
 * gazdă și n-au API prin care să fie citite de altundeva. Un singur script ar
 * fi trebuit să care un client MariaDB în venv-ul agentului și să primească
 * parola replicii în linia de comandă.
 *
 * ## Ce se șterge
 *
 * Aceeași regulă ca filtrul care oprește scrierea rândurilor noi pe gazdă
 * (`sentinel/db/repo/logins.py`, `is_dropped_command`):
 *
 *     contul e unul de automatizare  ȘI  comanda n-a avut terminal real
 *
 * Se citește din CHIAR RÂNDUL de comandă (`username`, `tty`), nu din sesiunea
 * lui. Retenția de 14 zile din `lib/retention.ts` face altceva și rămâne acolo
 * unde e: aia se uită la `login_session_entries.interactive`, adică la o
 * proprietate a SESIUNII, și taie după vârstă. Asta taie după cont, indiferent
 * de vârstă. Prima e o politică de spațiu, a doua e „rândurile astea n-ar fi
 * trebuit trimise niciodată".
 *
 * `login_session_entries` NU se atinge: «s-a deschis o sesiune de deploy» e
 * faptul cu valoare de securitate, și sunt câteva sute de rânduri.
 *
 * ## De ce aici se OFERĂ `OPTIMIZE TABLE`, iar pe gazdă `VACUUM FULL` nu
 *
 * Asimetria e voită. Pe gazdă, un fișier mare nu costă nimic — 91 GB liberi —,
 * iar rescrierea tabelei ar bloca ingestia unui agent de securitate viu. Aici,
 * fișierul mare E chiar problema: găzduirea are cotă, iar o bază plină
 * înseamnă ingestia refuzată pentru toate cele douăsprezece fluxuri. Ce se
 * pierde cât durează rescrierea e o replică ce recuperează oricum din cursoare.
 *
 * Chiar și așa, pasul e opțional și explicit: `--optimize`. InnoDB rescrie
 * tabela și are nevoie de încă o dată dimensiunea ei liberă pe disc — pe o cotă
 * aproape plină, exact ce lipsește.
 */

import type { Queryable } from "./db";

/** Tabela replicată cu istoricul de comenzi. Singura pe care o atinge fișierul. */
export const TABLE = "session_command_entries";

/**
 * Terminalul real, ca tipar pentru MariaDB.
 *
 * ACELAȘI ȘIR ca `REAL_TTY_SQL` din `sentinel/db/repo/logins.py`, caracter cu
 * caracter — nu „echivalent", identic. Se citește de acolo în
 * `tests/unit/test_purge_automation_commands.py`, care decodează literalul ăsta
 * ca pe un șir JavaScript înainte să-l compare; scris altfel, testul ar compara
 * două scrieri ale aceleiași intenții, nu două reguli.
 *
 * Ce a fost reparat pe 25 august 2026, măsurat pe cele trei motoare:
 *
 *   | tty        | filtrul viu | curățarea pe PG | replica de aici |
 *   |------------|-------------|-----------------|-----------------|
 *   | `' pts0'`  | păstrat     | ȘTERS           | păstrat         |
 *   | `'pts0\n'` | păstrat     | ȘTERS           | păstrat         |
 *
 * `is_interactive` făcea `.strip()`, niciun predicat SQL nu-l făcea. Marginile
 * sunt acum în TIPAR, deci le vede fiecare motor. Clasa e scrisă cu caracterele
 * ei și nu ca `\s`, fiindcă `\s` e Unicode în Python și ASCII în PCRE — aceeași
 * despărțire, mutată cu un pas mai încolo. `[0-9]` și nu `\d`, din același
 * motiv plus faptul că aici `\` trece printr-un literal de șir.
 *
 * Rămâne o a treia divergență, pe care tiparul singur n-o poate închide:
 * `REGEXP` și `IN` sunt NESENSIBILE la majuscule sub colația `utf8mb4_unicode_ci`
 * a coloanei, deci `'PTS0'` era ARUNCAT de filtrul viu și PĂSTRAT aici. De-aia
 * predicatul poartă `COLLATE utf8mb4_bin` — și de-aia colația nu e crezută pe
 * cuvânt, ci probată pe server înainte de orice ștergere: vezi `COLLATION_PROBE`.
 */
export const REAL_TTY =
  "^[ \\t\\n\\r\\f\\v]*(pts[0-9]+|tty[0-9]+)[ \\t\\n\\r\\f\\v]*$";

/**
 * Colația sub care se face comparația, în loc de cea a coloanei.
 *
 * `utf8mb4_unicode_ci` face `username IN (?)` insensibil și la majuscule și la
 * spațiile de umplere de la sfârșit, iar `REGEXP` insensibil la majuscule.
 * PostgreSQL și Python nu fac niciuna, deci replica ștergea MAI MULT pe un capăt
 * și MAI PUȚIN pe celălalt — pe aceleași date.
 */
export const COLLATION = "utf8mb4_bin";

/**
 * Câte rânduri într-o instrucțiune. Aceeași valoare ca retenția replicii: un
 * `DELETE` de sute de mii de rânduri ține un lock lung pe InnoDB și poate face
 * ingestia să expire în timpul lui.
 */
export const BATCH = 5000;

export type PurgeOptions = {
  /** Modul pe cont. Exclusiv cu `sessionIds`. */
  accounts?: string[];
  /** Modul pe sesiune: instanța CUI sunt identificatorii. */
  instanceId?: string;
  /** `login_sessions.id` DE PE GAZDĂ, adică `source_id` aici. */
  sessionIds?: number[];
  apply: boolean;
  batch?: number;
  optimize?: boolean;
  log?: (line: string) => void;
};

export type PurgeResult = {
  matching: number;
  deleted: number;
  /** Câte MAI potrivesc regula după ștergere — faptul, nu codul de retur. */
  remaining: number;
  rowsBefore: number;
  rowsAfter: number;
  bytesBefore: number;
  bytesAfter: number;
  optimised: boolean;
  /** Câte sesiuni au avut rânduri șterse, deci câte contoare s-au atins. */
  sessionsTouched: number;
  /** Adevărat când garda a oprit ștergerea. Nu e „gata", e „n-am făcut nimic". */
  refused: boolean;
};

/**
 * Proba de colație: regula chiar deosebește majusculele PE SERVERUL ĂSTA?
 *
 * `COLLATE utf8mb4_bin` e scris în predicat, dar scris nu înseamnă aplicat: o
 * versiune de MariaDB care ignoră colația pe operandul stâng al lui `REGEXP`, o
 * bază cu altă colație implicită, un driver care rescrie interogarea — oricare
 * dintre ele ar face predicatul să se comporte ca înainte, în tăcere, iar
 * singurul semn ar fi un număr de rânduri șterse ușor altul decât pe gazdă.
 *
 * `CLAUDE.md` numește chiar tiparul ăsta: «un cod de ieșire nu e dovadă de
 * efect». Deci înainte de orice ștergere se ÎNTREABĂ serverul, cu chiar
 * construcția din predicat, iar dacă răspunsul nu e cel al gazdei, ștergerea nu
 * se face deloc.
 *
 * Ce NU dovedește, spus aici ca să nu fie descoperit mai târziu: proba
 * folosește LITERALI marcați cu `COLLATE`, nu coloanele tabelei.
 * Coercibilitatea unei expresii marcate explicit e aceeași în ambele cazuri,
 * deci e aceeași CONSTRUCȚIE — dar e aceeași construcție, nu aceeași
 * interogare.
 */
export const COLLATION_PROBE_SQL =
  `SELECT (? COLLATE ${COLLATION}) NOT REGEXP ? AS upper_not_tty, ` +
  `(? COLLATE ${COLLATION}) NOT REGEXP ? AS lower_not_tty, ` +
  `(? COLLATE ${COLLATION}) NOT REGEXP ? AS padded_not_tty, ` +
  `(? COLLATE ${COLLATION}) IN (?) AS upper_is_account`;

export const COLLATION_PROBE_PARAMS: unknown[] = [
  "PTS0", REAL_TTY,          // majusculă: pe gazdă NU e terminal real, deci cade
  "pts0", REAL_TTY,          // terminal real: se păstrează
  " pts0", REAL_TTY,         // cu spațiu în față: tot terminal real (vezi REAL_TTY)
  "SENTINEL-DEPLOY", "sentinel-deploy", // alt cont, dacă majusculele contează
];

/** Ce răspunde gazda la aceleași patru întrebări. */
export const COLLATION_PROBE_EXPECTED: Record<string, number> = {
  upper_not_tty: 1,
  lower_not_tty: 0,
  padded_not_tty: 0,
  upper_is_account: 0,
};

/**
 * Un 0/1 venit de la server, citit STRICT.
 *
 * `Number(...)` singur are o gaură care lasă proba să treacă exact când n-ar
 * trebui: `Number(null)` e `0`, iar trei din cele patru răspunsuri sunt
 * așteptate `0`. Deci o coloană care vine `null` — driver care nu recunoaște
 * construcția, versiune de MariaDB care întoarce `NULL` pentru `COLLATE` pe un
 * operand marcat, coloană redenumită — ar fi citită ca «serverul e de acord».
 * Azi proba pică închis din NOROC: `upper_not_tty` așteaptă `1`, iar `null` nu e
 * `1`. Norocul ăla ține de ce numere s-au ales, nu de vreo regulă.
 *
 * `null` înseamnă „nu e un număr", nu „zero": apelantul refuză.
 */
function numarDeLaServer(v: unknown): number | null {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "bigint") return Number(v);
  // Unele drivere întorc DECIMAL/BIGINT ca șir. Numai cifre, nimic altceva:
  // `Number(" ")` e 0, `Number(true)` e 1, `Number([])` e 0.
  if (typeof v === "string" && /^-?[0-9]+$/.test(v.trim())) return Number(v.trim());
  return null;
}

export async function assertRuleMatchesTheHost(db: Queryable): Promise<void> {
  const [rows] = await db.query(COLLATION_PROBE_SQL, COLLATION_PROBE_PARAMS);
  if (!Array.isArray(rows) || rows.length === 0) {
    throw new Error(
      "proba de colație n-a întors niciun rând: nu pot dovedi că regula de aici " +
      "șterge aceleași rânduri ca gazda. Nu șterg nimic.");
  }
  const got = rows[0] as Record<string, unknown>;
  const rele: string[] = [];
  for (const [cheie, astept] of Object.entries(COLLATION_PROBE_EXPECTED)) {
    const val = numarDeLaServer(got[cheie]);
    if (val === null) {
      rele.push(`${cheie}: ${JSON.stringify(got[cheie]) ?? "undefined"} nu e ` +
                `un număr, deci nu pot spune dacă serverul e de acord`);
    } else if (val !== astept) {
      rele.push(`${cheie}: ${String(got[cheie])} în loc de ${astept}`);
    }
  }
  if (rele.length > 0) {
    throw new Error(
      "regula NU se comportă pe serverul ăsta ca pe gazdă: " + rele.join("; ") +
      ". Ștergerea ar cădea pe alte rânduri decât filtrul viu, deci nu o fac. " +
      "Vezi COLLATION în lib/purge-automation.ts.");
  }
}

/**
 * Condiția pe cont, o singură dată, pentru numărare și pentru ștergere.
 *
 * `COLLATE` e INTERPOLAT, iar asta e în regulă doar fiindcă valoarea e o
 * constantă din fișierul ăsta: numele unei colații nu poate fi legat ca
 * parametru în MariaDB. Conturile rămân legate — ele vin din linia de comandă.
 */
function whereAccounts(accounts: string[]): { sql: string; params: unknown[] } {
  // `IN (?, ?, …)`: fiecare cont e un parametru propriu. Interpolat, un nume de
  // cont ar fi injecție — și numele vine dintr-un argument de linie de comandă.
  const semne = accounts.map(() => "?").join(", ");
  return {
    sql: `(username COLLATE ${COLLATION}) IN (${semne}) ` +
         `AND (tty IS NULL OR (tty COLLATE ${COLLATION}) NOT REGEXP ?)`,
    params: [...accounts, REAL_TTY],
  };
}

/**
 * Modul pe sesiune: TOATE comenzile sesiunilor numite, indiferent de cont și de
 * terminal.
 *
 * `instance_id` e obligatoriu și nu are implicit. `session_source_id` e
 * `login_sessions.id` DE PE GAZDĂ, iar el se renumerotează de la 1 pe fiecare
 * instanță: fără instanță, `--sessions 2521` ar șterge sesiunea 2521 a fiecărui
 * server din arhivă.
 */
function whereSessions(instanceId: string, ids: number[]): { sql: string; params: unknown[] } {
  const semne = ids.map(() => "?").join(", ");
  return {
    sql: `instance_id = ? AND session_source_id IN (${semne})`,
    params: [instanceId, ...ids],
  };
}

function whereOf(opts: PurgeOptions): { sql: string; params: unknown[]; sessions: boolean } {
  const peConturi = opts.accounts !== undefined && opts.accounts.length > 0;
  const peSesiuni = opts.sessionIds !== undefined && opts.sessionIds.length > 0;
  if (peConturi === peSesiuni) {
    // Gol NU e „nimic de curățat", e „nu știu pe cine". Un raport «0 rânduri»
    // ar arăta identic cu o replică deja curată. Amândouă deodată ar da un
    // raport din care nu se mai poate citi ce a căzut și de ce.
    throw new Error(
      "dă exact unul: --accounts <a,b> sau --sessions <id,id> --instance <id>");
  }
  if (peSesiuni) {
    if (!opts.instanceId) {
      throw new Error("--sessions cere și --instance: identificatorii de sesiune " +
                      "se renumerotează pe fiecare instanță");
    }
    return { ...whereSessions(opts.instanceId, opts.sessionIds as number[]), sessions: true };
  }
  return { ...whereAccounts(opts.accounts as string[]), sessions: false };
}

export function countSql(accounts: string[]): { sql: string; params: unknown[] } {
  const w = whereAccounts(accounts);
  return { sql: `SELECT COUNT(*) AS n FROM ${TABLE} WHERE ${w.sql}`, params: w.params };
}

/**
 * O tranșă.
 *
 * `LIMIT` e interpolat, ca în `lib/retention.ts`, fiindcă MariaDB nu acceptă un
 * parametru acolo în toate versiunile — și tocmai de aceea valoarea e verificată
 * aici, nu presupusă: e singurul loc din fișier unde ceva intră în SQL fără să
 * fie legat.
 */
export function deleteSql(accounts: string[], batch: number): { sql: string; params: unknown[] } {
  const w = whereAccounts(accounts);
  return {
    sql: `DELETE FROM ${TABLE} WHERE ${w.sql} LIMIT ${checkedBatch(batch)}`,
    params: w.params,
  };
}

/** Tranșa, verificată. Vezi `deleteSql` pentru de ce nu e legată. */
export function checkedBatch(batch: number): number {
  if (!Number.isSafeInteger(batch) || batch < 1 || batch > 100000) {
    throw new Error(`tranșă invalidă: ${batch}`);
  }
  return batch;
}

/**
 * Mărimea tabelei, din `information_schema`.
 *
 * E o ESTIMARE a InnoDB, nu o măsurătoare exactă — de-asta raportul o dă în
 * MB, nu în octeți, și de-asta se citește înainte ȘI după: ce contează e dacă
 * s-a schimbat, nu cifra în sine.
 */
export const SIZE_SQL =
  "SELECT data_length + index_length AS bytes FROM information_schema.tables " +
  "WHERE table_schema = DATABASE() AND table_name = ?";

/** Tabela sesiunilor. Se CITEȘTE și i se ating contoarele; nu se șterge din ea. */
export const SESSIONS_TABLE = "login_session_entries";

/**
 * Câte rânduri ar cădea din fiecare sesiune. Se cere și în modul uscat: e chiar
 * ce trebuie să vadă operatorul înainte să hotărască.
 */
export function touchedSql(where: string): string {
  return `SELECT instance_id, session_source_id, COUNT(*) AS n FROM ${TABLE} ` +
         `WHERE session_source_id IS NOT NULL AND ${where} ` +
         `GROUP BY instance_id, session_source_id`;
}

/**
 * Contorul sesiunii, după ștergere.
 *
 * NUMAI `commands_purged`, dinadins. `command_count` de aici e o afirmație A
 * GAZDEI, adusă de expediere (`lib/streams.ts`) și rescrisă la fiecare lot: pus
 * pe zero de aici, l-ar readuce următoarea expediere, iar panoul ar oscila
 * între două cifre fără ca vreuna să fie greșită. Ce știm de aici, și numai de
 * aici, e câte rânduri am șters NOI — deci asta scriem.
 *
 * Cifra din `command_count` nu mai minte odată citită lângă `commands_purged`:
 * «558 079 comenzi, 558 079 șterse din arhiva asta» spune și ce a rulat
 * sesiunea, și de ce tabelul de dedesubt e gol.
 *
 * Contra-cazul, scris aici fiindcă e minciuna în direcția opusă și nu are încă
 * nicio reparație: dacă se curăță GAZDA și nu replica, gazda renumără
 * `command_count` din tabela ei (`_refresh_counters`) și expediază cifra nouă
 * încoace, unde rândurile sunt toate la locul lor. Panoul arată atunci «0
 * comenzi (0 șterse)» deasupra unui tabel plin — adică exact eșecul pe care
 * coloana asta îl repară, doar că pe partea cealaltă. Ce l-ar închide e o
 * afirmație a replicii despre PROPRIILE rânduri, nu una a gazdei; deocamdată nu
 * există, iar cine vede cifrele astea trebuie să știe că nu există.
 */
export const PURGED_SQL =
  `UPDATE ${SESSIONS_TABLE} SET commands_purged = commands_purged + ? ` +
  `WHERE instance_id = ? AND source_id = ?`;

/**
 * Sesiunile fără terminal, cele mai grase întâi.
 *
 * `interactive` e proprietatea SESIUNII, pusă pe gazdă la prima comandă cu `tty`
 * real, deci o sesiune de om cu shell nu apare aici deloc. Numărul arătat e cel
 * RENUMĂRAT din tabelă, fiindcă `command_count` e al gazdei și poate descrie
 * rânduri care aici au fost deja șterse.
 *
 * O SUB-INTEROGARE corelată, nu un `JOIN`, ca în `lib/retention.ts` și din
 * același motiv: corelarea poartă `instance_id` prin construcție. `source_id` e
 * id-ul rândului PE SERVERUL LUI, deci două instanțe au aceleași valori, iar o
 * îmbinare legată numai pe el ar număra comenzile altui server sub sesiunea
 * asta. Vezi `tests/joins.test.ts`.
 */
export function listSessionsSql(limit: number): string {
  return `
SELECT s.instance_id, s.source_id, s.session_key, s.username, s.opened_at,
       s.command_count, s.commands_purged,
       (SELECT COUNT(*) FROM ${TABLE} c
         WHERE c.instance_id = s.instance_id
           AND c.session_source_id = s.source_id) AS rows_now
  FROM ${SESSIONS_TABLE} s
 WHERE s.interactive = 0
 ORDER BY rows_now DESC, s.opened_at DESC
 LIMIT ${checkedBatch(limit)}`;
}

/** Sesiunile cerute care există, cu fanionul lor. Ce lipsește se vede din diferență. */
export function knownSessionsSql(ids: number[]): string {
  const semne = ids.map(() => "?").join(", ");
  return `SELECT source_id, username, interactive, opened_at FROM ${SESSIONS_TABLE} ` +
         `WHERE instance_id = ? AND source_id IN (${semne}) ORDER BY source_id`;
}

async function scalar(db: Queryable, sql: string, params: unknown[]): Promise<number> {
  const [rows] = await db.query(sql, params);
  if (!Array.isArray(rows) || rows.length === 0) {
    // „Nu știu" nu e „zero": o tabelă care nu există încă, sau o interogare
    // care n-a întors rânduri, nu are voie să fie raportată ca o tabelă goală.
    throw new Error(`interogarea nu a întors niciun rând: ${sql}`);
  }
  const value = Object.values(rows[0] as Record<string, unknown>)[0];
  return Number(value ?? 0);
}

async function randuri(
  db: Queryable, sql: string, params: unknown[],
): Promise<Record<string, unknown>[]> {
  const [rows] = await db.query(sql, params);
  return Array.isArray(rows) ? (rows as Record<string, unknown>[]) : [];
}

export type SessionLine = {
  instanceId: string; sourceId: number; sessionKey: string;
  username: string | null; openedAt: string; commandCount: number;
  commandsPurged: number; rowsNow: number;
};

/**
 * Arată sesiunile fără terminal și nu șterge nimic.
 *
 * Nu codifică niciun prag: un deploy are 250 000–560 000 de comenzi, o sesiune
 * de diagnostic a unui om are sute. Diferența e de trei ordine de mărime și se
 * vede la citire; un prag scris aici ar fi o presupunere despre gazda altcuiva.
 */
export async function listSessions(
  db: Queryable, opts: { limit?: number; log?: (line: string) => void } = {},
): Promise<SessionLine[]> {
  const log = opts.log ?? ((line: string) => console.log(line));
  const limit = opts.limit ?? 40;
  const rows = await randuri(db, listSessionsSql(limit), []);
  const out: SessionLine[] = rows.map((r) => ({
    instanceId: String(r.instance_id),
    sourceId: Number(r.source_id),
    sessionKey: String(r.session_key),
    username: r.username === null || r.username === undefined ? null : String(r.username),
    openedAt: String(r.opened_at),
    commandCount: Number(r.command_count ?? 0),
    commandsPurged: Number(r.commands_purged ?? 0),
    rowsNow: Number(r.rows_now ?? 0),
  }));

  log(`Sesiuni FĂRĂ terminal, cele mai grase întâi (cel mult ${limit}):`);
  log("");
  log("instanță                 id     comenzi     șterse  cont                 deschisă");
  for (const r of out) {
    log(`${r.instanceId.padEnd(20)} ${String(r.sourceId).padStart(10)} ` +
        `${String(r.rowsNow).padStart(11)} ${String(r.commandsPurged).padStart(10)}  ` +
        `${(r.username ?? "—").padEnd(20)} ${r.openedAt.slice(0, 19)}`);
  }
  if (out.length === 0) {
    // Lista goală e o stare validă și trebuie citită ca atare, nu ca o
    // interogare care n-a mers.
    log("  (niciuna — nicio sesiune neinteractivă în arhivă)");
  }
  log("");
  log("Alege-le pe cele de șters și dă-le explicit:");
  log("    --instance <id> --sessions <id,id,…>            uscat");
  log("    --instance <id> --sessions <id,id,…> --apply    șterge");
  log("Coloana «șterse» e cât s-a curățat din sesiune până acum, DE AICI.");
  return out;
}

/**
 * Refuză identificatorii care nu descriu ce crede operatorul că descriu.
 *
 * Două stări separate, fiindcă cer lucruri diferite de la om: o sesiune care nu
 * există în arhiva instanței ăsteia (probabil o cifră greșită sau altă instanță)
 * și una interactivă — există, dar e a unui om la tastatură, adică exact
 * istoricul pe care nimic de aici n-are voie să-l ia.
 */
async function gardaSesiuni(
  db: Queryable, instanceId: string, ids: number[], log: (l: string) => void,
): Promise<boolean> {
  const rows = await randuri(db, knownSessionsSql(ids), [instanceId, ...ids]);
  const gasite = new Set(rows.map((r) => Number(r.source_id)));
  const lipsa = ids.filter((id) => !gasite.has(id));
  const umane = rows.filter((r) => Number(r.interactive) === 1);
  for (const id of lipsa) {
    log(`Sesiunea ${id} nu există pe instanța ${instanceId}.`);
  }
  for (const r of umane) {
    log(`Sesiunea ${Number(r.source_id)} e INTERACTIVĂ (cont ` +
        `${r.username === null ? "necunoscut" : String(r.username)}) — e a unui ` +
        "om la tastatură, nu o șterg.");
  }
  if (lipsa.length > 0 || umane.length > 0) {
    log("Nu s-a șters nimic. Verifică lista cu --list-sessions.");
    return false;
  }
  return true;
}

export async function purge(db: Queryable, opts: PurgeOptions): Promise<PurgeResult> {
  const log = opts.log ?? ((line: string) => console.log(line));
  const batch = checkedBatch(opts.batch ?? BATCH);
  const w = whereOf(opts);

  // Proba ÎNAINTE de numărătoare, nu doar înainte de ștergere.
  //
  // Era după întoarcerea din modul uscat, deci cifra pe care operatorul o
  // citește ca SĂ DECIDĂ era singura care nu trecea prin nicio verificare — pe
  // un server care ignoră colația, `potrivesc: N` numără alte rânduri decât ar
  // cădea pe gazdă. Ștergerea era în siguranță; decizia, nu.
  //
  // În modul uscat un refuz NU aruncă: o numărătoare inofensivă n-are voie să
  // devină o operație care eșuează. Se raportează, lângă cifră, că cifra nu e
  // de crezut. Cu `--apply` rămâne ce era: aruncă înainte să cadă vreun rând.
  let probaRea = "";
  if (!w.sessions) {
    try {
      await assertRuleMatchesTheHost(db);
    } catch (err) {
      probaRea = err instanceof Error ? err.message : String(err);
      if (opts.apply) throw err;
    }
  }

  const bytesBefore = await scalar(db, SIZE_SQL, [TABLE]);
  const rowsBefore = await scalar(db, `SELECT COUNT(*) AS n FROM ${TABLE}`, []);
  const matching = await scalar(
    db, `SELECT COUNT(*) AS n FROM ${TABLE} WHERE ${w.sql}`, w.params);

  if (w.sessions && !(await gardaSesiuni(db, opts.instanceId as string,
                                         opts.sessionIds as number[], log))) {
    return {
      matching: 0, deleted: 0, remaining: 0, rowsBefore, rowsAfter: rowsBefore,
      bytesBefore, bytesAfter: bytesBefore, optimised: false, sessionsTouched: 0,
      refused: true,
    };
  }

  log(`tabela   : ${TABLE}`);
  if (w.sessions) {
    log(`instanță : ${opts.instanceId}`);
    log(`sesiuni  : ${(opts.sessionIds as number[]).join(", ")}`);
    log("regula   : TOATE comenzile sesiunilor astea, indiferent de cont și de terminal");
  } else {
    log(`conturi  : ${(opts.accounts as string[]).join(", ")}`);
    log(`regula   : cont din listă ȘI tty care nu potrivește ${REAL_TTY}`);
    log(`colație  : ${COLLATION} (nu cea a coloanei; vezi COLLATION_PROBE_SQL)`);
  }
  log(`înainte  : ${rowsBefore} rânduri, ${mb(bytesBefore)}`);
  log(`potrivesc: ${matching} rânduri`);

  const atinse = await randuri(db, touchedSql(w.sql), w.params);
  if (atinse.length > 0) log(`sesiuni atinse: ${atinse.length}`);

  if (!opts.apply) {
    log("");
    if (probaRea) {
      log("ATENȚIE: cifra de mai sus NU e de crezut.");
      log(`  ${probaRea}`);
      log("  Numărătoarea folosește chiar regula pe care serverul n-o aplică, " +
          "deci potrivește alte rânduri decât filtrul de pe gazdă.");
      log("  `--apply` va refuza, nu va șterge.");
    }
    log("[uscat] nu s-a șters nimic. Rulează din nou cu --apply.");
    return {
      matching, deleted: 0, remaining: matching, rowsBefore, rowsAfter: rowsBefore,
      bytesBefore, bytesAfter: bytesBefore, optimised: false,
      sessionsTouched: atinse.length, refused: false,
    };
  }

  const dsql = `DELETE FROM ${TABLE} WHERE ${w.sql} LIMIT ${batch}`;
  let deleted = 0;
  for (;;) {
    const [res] = await db.query(dsql, w.params);
    const affected = (res as { affectedRows?: number }).affectedRows ?? 0;
    deleted += affected;
    if (affected > 0) log(`  … ${deleted} / ${matching}`);
    if (affected < batch) break;
  }

  // Contoarele, ÎNAINTE de OPTIMIZE: rescrierea tabelei poate dura minute, iar o
  // întrerupere la mijloc trebuie să lase panoul spunând adevărul, nu «558 079
  // comenzi» deasupra unui tabel gol.
  //
  // Se scade CE E ACUM din CE ERA, per sesiune — nu se crede planul. Expedierea
  // de pe gazdă merge în paralel, iar un rând sosit între cele două numărători
  // ar face un `commands_purged` prea mare.
  const dupa = await randuri(db, touchedSql(w.sql), w.params);
  const acum = new Map<string, number>();
  for (const r of dupa) {
    acum.set(`${String(r.instance_id)}/${Number(r.session_source_id)}`, Number(r.n));
  }
  let sessionsTouched = 0;
  for (const r of atinse) {
    const inst = String(r.instance_id);
    const sid = Number(r.session_source_id);
    const cazute = Math.max(Number(r.n) - (acum.get(`${inst}/${sid}`) ?? 0), 0);
    if (cazute === 0) continue;
    await db.query(PURGED_SQL, [cazute, inst, sid]);
    sessionsTouched += 1;
  }
  if (sessionsTouched > 0) {
    log(`contoare : ${sessionsTouched} sesiuni și-au primit commands_purged`);
    log("           (command_count rămâne al gazdei; îl rescrie expedierea)");
  }

  let optimised = false;
  if (opts.optimize) {
    log("OPTIMIZE TABLE … (rescrie tabela; poate dura)");
    await db.query(`OPTIMIZE TABLE ${TABLE}`, []);
    optimised = true;
  }

  // Faptul, nu codul de retur: se renumără ce mai potrivește regula.
  const remaining = await scalar(
    db, `SELECT COUNT(*) AS n FROM ${TABLE} WHERE ${w.sql}`, w.params);
  const rowsAfter = await scalar(db, `SELECT COUNT(*) AS n FROM ${TABLE}`, []);
  const bytesAfter = await scalar(db, SIZE_SQL, [TABLE]);

  log("");
  log(`șterse   : ${deleted} rânduri`);
  log(`rămase   : ${rowsAfter} rânduri, ${mb(bytesAfter)}`);
  log(`mai potrivesc regula: ${remaining}${remaining === 0 ? "" : "  ← NU e zero"}`);
  if (remaining > 0) {
    log("  Au apărut rânduri noi în timpul rulării (expedierea merge în " +
        "paralel) sau ștergerea a fost întreruptă. Rulează din nou.");
  }
  log(`mărime   : ${mb(bytesBefore)} → ${mb(bytesAfter)}`);
  if (!optimised) {
    log("`DELETE` nu întoarce spațiul sistemului de fișiere: InnoDB îl lasă " +
        "liber ÎN fișier, deci cota rămâne ocupată.");
    log(`Ce mai ai de rulat, dacă vrei spațiul înapoi:`);
    log(`    npm run purge-automation -- --accounts <conturi> --apply --optimize`);
    log("Rescrie tabela și are nevoie de încă o dată dimensiunea ei liberă pe " +
        "disc — pe o cotă aproape plină, exact ce lipsește.");
  }

  return {
    matching, deleted, remaining, rowsBefore, rowsAfter, bytesBefore, bytesAfter,
    optimised, sessionsTouched, refused: false,
  };
}

/** Octeți în MB, cu o zecimală. Raportul e citit de un om, nu de un script. */
export function mb(bytes: number): string {
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
