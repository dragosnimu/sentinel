/**
 * Un dublu de bază de date pentru primitivele de autentificare — și ce NU
 * dovedește.
 *
 * Aici nu există MariaDB. Deci ce urmează e un MODEL: ține rânduri în memorie,
 * EVALUEAZĂ instrucțiunile pe care le emit `lib/auth/session.ts`,
 * `lib/auth/totp.ts` și `lib/auth/users.ts`, și aplică asupra lor două reguli pe
 * care în producție le impune serverul:
 *
 *   1. **triggerele** `sessions_active_token_bi` / `_bu`, care pun
 *      `active_token_hash` pe `token_hash` cât timp rândul nu e revocat, și pe
 *      `NULL` altfel;
 *   2. **cheia unică** `uk_sessions_active_token`, care refuză un al doilea rând
 *      cu aceeași valoare NENULĂ și acceptă oricâte `NULL`.
 *
 * Modelul nu e crezut pe cuvânt: `assertTriggerModelMatchesSchema` citește
 * `migrations/0008_auth.sql` și cere ca expresia din trigger să fie chiar cea
 * implementată mai jos. Dacă migrația se schimbă și modelul nu, suita pică — și
 * invers.
 *
 * ## De ce EVALUEAZĂ instrucțiunea în loc s-o recunoască
 *
 * Prima versiune recunoștea fiecare instrucțiune după începutul ei și aplica
 * apoi o semantică scrisă de mână: `promote` punea `token_hash` din parametru,
 * `selectSessions` filtra expirarea, consumul de contor compara cu `>=`. Trei
 * mutații au trecut VERZI prin ea — `<` schimbat în `<=` în SQL, `token_hash`
 * scos din `SET`, filtrul de expirare șters din `WHERE` — fiindcă testele
 * probau modelul, nu instrucțiunea. Adică exact clasa de test care nu verifică
 * nimic, din `CLAUDE.md`.
 *
 * Acum `SET`-ul și `WHERE`-ul se citesc din textul REAL: o comparație schimbată
 * în `lib/auth/` schimbă ce face dublul, deci se vede. Gramatica acceptată e
 * mică dinadins, iar orice formă nerecunoscută e o EROARE, nu o operație nulă —
 * un dublu care înghite SQL necunoscut raportează verde pentru cod care în
 * producție n-ar face nimic.
 *
 * ## Dublul se pune ÎN LOCUL DRIVERULUI
 *
 * `query` implementează `Pool` din `lib/db.ts`, deci rutele îl primesc prin
 * `getPool(() => fake)` și cererea trece pe urmă prin `authDb`, prin
 * `lib/auth/*` și prin toată ruta — cod real. `all` și `write` rămân pentru
 * probele care vorbesc direct cu stratul de date. Un dublu pus mai sus (peste
 * `lib/auth/users.ts`) ar fi confirmat că ne-am chemat propria imitație.
 *
 * **Ce rămâne NEDOVEDIT de aici, spus pe față:** că MariaDB acceptă triggerele
 * și cheia, că evaluează aceleași condiții ca modelul ăsta, și că al doilea rând
 * activ e refuzat chiar cu ERROR 1062. Drumul prin care se dovedește e pe gazdă:
 * `npm run migrate -- --syntax-check` (care, măsurat pe MariaDB 11.8.8,
 * pregătește și `CREATE TRIGGER`), apoi proba prin efect din `README.md`.
 * „Modelul meu spune că merge" nu e „merge".
 *
 * ## Limitele modelului, enumerate — fiindcă „dublul zice da" nu e un argument
 *
 * Sondate una câte una pe 17 august 2026. Niciuna nu e azi un defect; fiecare e
 * un drum pe care o schimbare viitoare ar fi verde aici și moartă în producție,
 * deci se scriu ca să nu fie descoperite ca surprize:
 *
 *   * **niciun invariant al TABELEI.** Cheia primară, `NOT NULL`, `CHECK`-urile
 *     din `0008_auth.sql`, lățimile coloanelor și validitatea `INET6` nu există
 *     aici. Singura constrângere modelată e cheia unică pe `active_token_hash`.
 *     Un `INSERT` cu un `role` din afara vocabularului sau cu un `created_ip`
 *     care nu e adresă trece prin dublu și e refuzat de MariaDB. În particular:
 *     **că `INET6` acceptă un literal IPv4 punctat nu s-a măsurat nicăieri**,
 *     iar de-aia `lib/auth/client-ip.ts` scrie forma mapată `::ffff:…`;
 *   * **un `UPDATE` multi-rând care lovește 1062 lasă în urmă rândurile deja
 *     mutate.** MariaDB dă înapoi toată instrucțiunea (InnoDB), dublul nu.
 *     Contează dacă vreodată se scrie un `UPDATE` care atinge mai multe sesiuni
 *     și poate produce o coliziune de jeton activ;
 *   * **formatul timpului diferă în precizie.** Dublul dă `…T12:00:00.000`,
 *     driverul cu `dateStrings: true` dă `.000000`. Egal ca moment, diferit ca
 *     ȘIR — deci o comparație de forma `session.expiresAt === ceva` ar trece
 *     aici și ar pica pe gazdă. Timpii se compară ca timpi;
 *   * **fără tranzacții, fără concurență, fără lacăte de rând.** Cele două
 *     scrieri simultane pe care le apără contorul TOTP nu se pot reproduce aici;
 *     ce se probează e că instrucțiunea EMISĂ e cea condiționată;
 *   * **`COUNT(*)` numără rânduri în memorie, nu în MariaDB.** Ce se probează e
 *     că predicatul TRIMIS conține filtrul și fereastra; că `UTC_TIMESTAMP(6) -
 *     INTERVAL ? MINUTE` e chiar UTC (și nu fusul sesiunii, ca
 *     `CURRENT_TIMESTAMP`) se poate afirma doar despre TEXTUL instrucțiunii.
 *     Dublul întoarce numărul ca ȘIR, fiindcă `bigNumberStrings` chiar face asta
 *     — iar codul care ar presupune un număr trebuie să pice aici, nu pe gazdă.
 *
 * Adăugate pe 17 august 2026, odată cu autorizarea multi-instanță — aceeași
 * regulă, limite noi fiindcă gramatica a crescut:
 *
 *   * **nicio cheie unică în afară de `uk_sessions_active_token`.** `users`,
 *     `user_instances` și `instances` au și ele chei unice în schemă
 *     (`uk_users_username`, `uk_user_instances`, `uk_instances_instance_id`),
 *     iar dublul le ignoră. Consecința: un al doilea cont cu același nume, sau
 *     un al doilea drept pentru aceeași pereche, trece aici și e refuzat de
 *     MariaDB cu 1062. De-aia `lib/auth/accounts.ts` citește ÎNAINTE de scriere
 *     — mesajul omenesc e al codului, refuzul e al bazei;
 *   * **`ORDER BY` compară ca JavaScript, nu ca MariaDB.** Numerele se compară
 *     numeric, restul ca șiruri de unități UTF-16; serverul folosește colația
 *     coloanei. NULL sortează primul la ASC, ca la MariaDB, dar asta e modelat
 *     aici, nu măsurat acolo. O ordonare care depinde de diacritice sau de
 *     majuscule NU se poate proba din dublu;
 *   * **`AUTO_INCREMENT` e modelat ca `max(id) + 1`.** Suficient ca o citire
 *     înapoi să găsească rândul, dar nu e comportamentul serverului: acolo
 *     contorul nu se întoarce după o ștergere. Un test care s-ar sprijini pe
 *     REFOLOSIREA unui id ar fi verde aici și fals pe gazdă;
 *   * **un `SELECT` fără `WHERE` întoarce toate rândurile**, ca la MariaDB.
 *     Dinadins, nu ca scăpare: dacă ar fi o eroare a dublului, o interogare
 *     căreia i s-a pierdut `WHERE instance_id IN (…)` ar pica cu „gramatică
 *     nerecunoscută" în loc să întoarcă tot — adică proba de autorizare ar
 *     trece din alt motiv decât cel adevărat, iar pe gazdă efectul ar fi
 *     datele tuturor instanțelor.
 *
 * A treia limită era o capcană, și a fost ÎNCHISĂ: gramatica accepta `col < ?`
 * pe o coloană NULL și răspundea adevărat (`Number(null) === 0`), unde SQL dă
 * NULL, adică nicio potrivire. `consumeTotpCounter` scrie azi
 * `(totp_last_counter IS NULL OR totp_last_counter < ?)`, deci nu depindea de
 * ea — dar următoarea inegalitate pe o coloană NULL-abilă (`users.locked_until`,
 * `users.totp_confirmed_at`, amândouă în piesa 2) ar fi fost verde aici și
 * moartă în producție, iar dublul ar fi putut fi folosit ca argument pentru
 * scoaterea gărzii. Acum comparațiile urmează logica cu trei valori: orice
 * comparație cu NULL nu e ADEVĂRATĂ, deci rândul nu se potrivește.
 *
 * A patra e din aceeași familie, și a fost ÎNCHISĂ pe 17 august 2026: un
 * parametru `NaN` sau `Infinity` era comparat aici ca VALOARE — nu potrivea
 * nimic, deci „zero rânduri" — în timp ce driverul îl scrie în textul
 * instrucțiunii, iar MariaDB îl citește ca NUME DE COLOANĂ și refuză
 * instrucțiunea cu `ERROR 1054`. Vezi `assertBindable`: fără ea, o gardă de
 * formă scoasă din `lib/data/` ar fi fost verde aici și ar fi transformat pe
 * gazdă un 404 într-un 503 — adică chiar oracolul „id nevalid" / „id valid, dar
 * nu al tău" pe care ruta de incidente există să-l închidă.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

import { MIGRATIONS_DIR } from "../lib/migrate";
import type { AuthDb } from "../lib/auth/db";
import type { Pool, PooledConnection } from "../lib/db";

/** Regula pe care o implementează triggerele, scrisă o dată. */
const TRIGGER_EXPRESSION = "IF(NEW.revoked_at IS NULL, NEW.token_hash, NULL)";

export function authSchemaText(): string {
  return readFileSync(path.join(MIGRATIONS_DIR, "0008_auth.sql"), "utf8");
}

/**
 * Modelul de mai jos și schema livrată vorbesc despre aceeași regulă.
 *
 * Fără aserțiunea asta, testele de sesiune ar proba un model care poate să nu
 * mai semene cu ce se aplică pe gazdă — adică ar deveni verzi tocmai când
 * schema se strică.
 */
export function assertTriggerModelMatchesSchema(): void {
  const text = authSchemaText().replace(/\s+/g, " ");
  for (const when of ["BEFORE INSERT", "BEFORE UPDATE"]) {
    const expected =
      `CREATE TRIGGER sessions_active_token_${when === "BEFORE INSERT" ? "bi" : "bu"} ` +
      `${when} ON sessions FOR EACH ROW SET NEW.active_token_hash = ${TRIGGER_EXPRESSION}`;
    assert.ok(text.includes(expected),
              `migrations/0008_auth.sql nu conține triggerul ${when} în forma pe care ` +
              `o modelează dublul de test:\n  ${expected}`);
  }
}

export type SessionRow = {
  id: string;
  user_id: number;
  token_hash: string;
  active_token_hash: string | null;
  csrf_token: string;
  pending_totp: number;
  created_ip: string | null;
  user_agent: string | null;
  created_at: number;
  last_seen_at: number;
  expires_at: number;
  revoked_at: number | null;
  revoked_reason: string | null;
};

export type UserRow = {
  id: number;
  username: string;
  password_hash: string;
  role: string;
  disabled: number;
  totp_secret_enc: string | null;
  totp_confirmed_at: number | null;
  totp_last_counter: number | null;
  failed_attempts: number;
  locked_until: number | null;
  last_login_at: number | null;
  last_login_ip: string | null;
  password_changed_at: number;
  created_at: number;
};

export type AttemptRow = {
  at: number;
  username: string | null;
  ip: string | null;
  user_agent: string | null;
  result: string;
  stage: string | null;
  session_id: string | null;
  detail: string | null;
};

export type UserInstanceRow = {
  id: number;
  user_id: number;
  instance_id: string;
  role: string;
  granted_at: number;
  granted_by: string | null;
};

export type InstanceRow = {
  id: number;
  instance_id: string;
  label: string | null;
  enabled: number;
  first_seen_at: number | null;
  last_batch_at: number | null;
};

export type IncidentRow = {
  id: number;
  instance_id: string;
  source_id: number;
  fingerprint: string;
  status: string;
  severity: string;
  ai_severity: string | null;
  title: string;
  summary: string | null;
  actor_key: string | null;
  acknowledged_by: string | null;
  acknowledged_at: number | null;
  resolved_at: number | null;
  resolution_note: string | null;
  detection_count: number;
  created_at: number;
  first_detection_at: number;
  last_detection_at: number;
};

export type TimelineRow = {
  id: number;
  instance_id: string;
  source_id: number;
  incident_source_id: number;
  at: number;
  kind: string;
  actor: string | null;
};

type Row = Record<string, unknown>;

/**
 * Coloanele pe care un `SELECT` TREBUIE să le ceară, pe tabelă.
 *
 * Numai `sessions` e aici, și nu din întâmplare: `toSession` din
 * `lib/auth/session.ts` citește câmpurile fără să se întrebe dacă există, deci o
 * coloană scoasă din `SELECT` ar deveni tăcut `String(undefined)`. Pentru
 * `users`, garda e în cod (`present()` în `lib/auth/users.ts`), unde e mai bine —
 * acolo apără și în producție, nu doar în suită.
 */
const REQUIRED_PROJECTION = new Map<string, string[]>([
  ["sessions", ["id", "user_id", "pending_totp", "csrf_token", "created_at",
                "last_seen_at", "expires_at", "created_ip"]],
]);

// ---------------------------------------------------------------------------
// Gramatica mică pe care o înțelege dublul
// ---------------------------------------------------------------------------
type Cursor = { params: unknown[]; at: number };

function nextParam(cursor: Cursor): unknown {
  assert.ok(cursor.at < cursor.params.length,
            `dublul: instrucțiunea cere mai mulți parametri decât s-au dat ` +
            `(${cursor.params.length})`);
  const value = cursor.params[cursor.at++];
  assertBindable(value);
  return value;
}

/**
 * Un parametru pe care driverul NU-l poate lega ca număr.
 *
 * `mysql2` scrie un număr în textul instrucțiunii cu reprezentarea lui, deci
 * `NaN` pleacă spre server ca literalul `NaN`, iar `Infinity` ca `Infinity` —
 * amândouă citite acolo ca NUME DE COLOANĂ. Măsurat de verificator pe MariaDB
 * 10.5.29: `WHERE id = NaN` → `ERROR 1054 (42S22): Unknown column 'NaN' in
 * 'where clause'`.
 *
 * Dublul compara `NaN` cu valoarea din rând, nu potrivea nimic, și întorcea
 * liniștit zero rânduri. Diferența nu e academică: e chiar oracolul pe care
 * ruta incidentelor pretinde că îl închide. Cu garda de formă din
 * `lib/data/incidents.ts` scoasă, `/api/panel/incidents/abc` ar da **503**, iar
 * `/api/panel/incidents/999999` **404** — adică exact deosebirea dintre „id
 * nevalid" și „id valid, dar nu al tău", care spune cuiva unde să caute. Un
 * dublu mai îngăduitor decât serverul ar fi lăsat testul ăla verde peste
 * scoaterea gărzii.
 */
function assertBindable(value: unknown): void {
  if (typeof value === "number" && !Number.isFinite(value)) {
    const err = new Error(
      `ER_BAD_FIELD_ERROR: Unknown column '${String(value)}' in 'where clause'`);
    (err as Error & { errno: number }).errno = 1054;
    throw err;
  }
}

/**
 * Rândul-SONDĂ: orice coloană există și valorează 0.
 *
 * Există fiindcă verificarea de gramatică rulează ÎNAINTE de rândurile reale,
 * pe o tabelă care poate fi goală, iar formele noi (`col + 1`) au nevoie de o
 * valoare ca să nu arunce din alt motiv decât cel probat. Pe rândurile REALE,
 * o coloană inexistentă rămâne o eroare.
 */
const PROBE_ROW: Row = new Proxy({}, {
  get: () => 0,
  has: () => true,
}) as Row;

const INTERVAL_MS = { SECOND: 1000, MINUTE: 60_000, HOUR: 3_600_000 };

/** Valoarea din partea dreaptă a unei atribuiri sau comparații. */
function evalValue(text: string, cursor: Cursor, now: number, row: Row = PROBE_ROW): unknown {
  const value = text.trim();
  if (value === "?") return nextParam(cursor);
  if (value === "UTC_TIMESTAMP(6)") return now;
  if (value === "NULL") return null;
  if (/^-?\d+$/.test(value)) return Number(value);

  // Literal de șir. `result <> 'ok'` e singura formă folosită azi, dar un
  // literal e un literal: fără el, condiția ar fi „nerecunoscută”, adică o
  // eroare, adică o numărătoare care nu se poate scrie.
  const literal = /^'([^']*)'$/.exec(value);
  if (literal) return literal[1];

  // `UTC_TIMESTAMP(6) ± INTERVAL ? <unitate>`. Plus pentru expirări și blocări,
  // minus pentru ferestrele alunecătoare ale limitatorului.
  const interval = /^UTC_TIMESTAMP\(6\) ([+-]) INTERVAL \? (SECOND|MINUTE|HOUR)$/.exec(value);
  if (interval) {
    const amount = Number(nextParam(cursor)) * INTERVAL_MS[interval[2] as "SECOND" | "MINUTE" | "HOUR"];
    return interval[1] === "+" ? now + amount : now - amount;
  }

  // `col + <întreg>`: incrementul contorului de încercări. Se citește din rândul
  // REAL, ca la MariaDB — un increment scris ca `failed_attempts = 1` ar fi altă
  // instrucțiune și trebuie să se vadă că e alta.
  const arithmetic = /^(\w+) \+ (\d+)$/.exec(value);
  if (arithmetic) {
    const current = row[arithmetic[1]];
    assert.ok(current !== undefined,
              `dublul: coloana ${arithmetic[1]} nu există pe rândul atins`);
    return Number(current) + Number(arithmetic[2]);
  }

  throw new Error(`dublul nu recunoaște valoarea: „${value}”`);
}

/** `col = <valoare>, col2 = <valoare>` → ce se scrie în rând. */
function evalAssignments(
  text: string, cursor: Cursor, now: number, row: Row = PROBE_ROW,
): Row {
  const out: Row = {};
  for (const part of splitTop(text, ",")) {
    const [column, ...rest] = part.split("=");
    assert.ok(rest.length >= 1, `dublul: atribuire fără „=”: ${part}`);
    out[column.trim()] = evalValue(rest.join("="), cursor, now, row);
  }
  return out;
}

/** NULL-ul SQL, în amândouă felurile în care ajunge într-un rând al dublului. */
function isNull(value: unknown): boolean {
  return value === null || value === undefined;
}

/**
 * `A AND B AND …` → adevărat pentru rândul dat.
 *
 * Parametrii se consumă în ordinea din text, ca la driver: mai întâi cei din
 * `SET`, apoi cei din `WHERE`. O condiție pe care gramatica n-o cunoaște e o
 * eroare — altfel un `WHERE` lărgit din greșeală ar trece drept „fără condiții".
 *
 * Comparațiile urmează logica cu trei valori: dacă vreo parte e NULL, rezultatul
 * e NECUNOSCUT, iar `WHERE` păstrează doar ADEVĂRAT. Vezi limita închisă din
 * capul fișierului — fără asta, `Number(null) === 0` făcea `col < ?` adevărat pe
 * o coloană goală, exact invers față de MariaDB. Regula se aplică și lui `<>`:
 * `NULL <> 'ok'` nu potrivește, deși „e altceva decât ok" pare adevărat.
 */
function evalWhere(text: string, row: Row, cursor: Cursor, now: number): boolean {
  let matches = true;
  for (const raw of splitTop(text, " AND ")) {
    const part = raw.trim().replace(/^\((.*)\)$/s, "$1").trim();
    let ok: boolean;

    const isNullTest = /^(\w+) IS NULL$/.exec(part);
    const isNotNull = /^(\w+) IS NOT NULL$/.exec(part);
    const compare = /^(\w+) (=|<>|<=|>=|<|>) (.+)$/.exec(part);
    const nullOr = /^(\w+) IS NULL OR (\w+) (<|<=|>|>=) (.+)$/.exec(part);
    // `col IN (?, ?, …)` — filtrul de autorizare al fiecărei interogări de date.
    // Lista e mereu de semne de întrebare: `scopePlaceholders` o construiește
    // așa tocmai ca identificatorii de instanță să plece ca parametri. Un `IN`
    // cu valori lipite în text nu e recunoscut aici, deci ar fi o eroare — și
    // ăsta e răspunsul corect, fiindcă ar fi și o injecție.
    const inList = /^(\w+) IN \(([^)]*)\)$/.exec(part);

    if (inList) {
      // Parametrii se consumă în ordinea din text, ca la driver, chiar dacă
      // rândul nu se potrivește: altfel condiția următoare ar citi parametrul
      // greșit pentru rândurile care ies din listă.
      const values = splitTop(inList[2], ",").map(
        (entry) => evalValue(entry, cursor, now, row));
      const current = row[inList[1]];
      ok = !isNull(current)
        && values.some((value) => !isNull(value) && current === value);
    } else if (nullOr) {
      assert.equal(nullOr[1], nullOr[2], "dublul: condiție despre două coloane");
      const value = evalValue(nullOr[4], cursor, now, row);
      const current = row[nullOr[1]];
      ok = isNull(current)
        || (!isNull(value) && compareWith(nullOr[3], Number(current), Number(value)));
    } else if (isNullTest) {
      ok = isNull(row[isNullTest[1]]);
    } else if (isNotNull) {
      ok = !isNull(row[isNotNull[1]]);
    } else if (compare) {
      const value = evalValue(compare[3], cursor, now, row);
      const current = row[compare[1]];
      // Orice comparație cu NULL e NECUNOSCUT, nu ADEVĂRAT — inclusiv `=`.
      ok = isNull(current) || isNull(value) ? false
        : compare[2] === "="
          ? current === value
          : compare[2] === "<>"
            ? current !== value
            : compareWith(compare[2], Number(current), Number(value));
    } else {
      throw new Error(`dublul nu recunoaște condiția: „${part}”`);
    }
    matches = matches && ok;
  }
  return matches;
}

/**
 * `ORDER BY col [DESC][, col2 …]`, aplicat pe rândurile deja filtrate.
 *
 * Cheile se citesc din instrucțiunea REALĂ, ca peste tot aici: o ordonare
 * schimbată în `lib/data/` trebuie să schimbe ce vede testul. Comparația e
 * numerică pentru numere și lexicografică (UTF-16) pentru rest — vezi limita
 * scrisă în capul fișierului.
 */
function sortRows(rows: Row[], order: string): Row[] {
  const keys = splitTop(order, ",").map((entry) => {
    const parsed = /^(\w+)(?: (ASC|DESC))?$/.exec(entry.trim());
    if (!parsed) throw new Error(`dublul nu recunoaște ordonarea: „${entry.trim()}”`);
    return { column: parsed[1], desc: parsed[2] === "DESC" };
  });
  return [...rows].sort((left, right) => {
    for (const key of keys) {
      const order = compareValues(left[key.column], right[key.column]);
      if (order !== 0) return key.desc ? -order : order;
    }
    return 0;
  });
}

/** NULL primul la ASC, ca la MariaDB; numerele numeric, restul ca șiruri. */
function compareValues(left: unknown, right: unknown): number {
  if (isNull(left) && isNull(right)) return 0;
  if (isNull(left)) return -1;
  if (isNull(right)) return 1;
  if (typeof left === "number" && typeof right === "number") {
    return left < right ? -1 : left > right ? 1 : 0;
  }
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareWith(op: string, left: number, right: number): boolean {
  switch (op) {
    case "<": return left < right;
    case "<=": return left <= right;
    case ">": return left > right;
    case ">=": return left >= right;
    default: throw new Error(`dublul nu recunoaște operatorul „${op}”`);
  }
}

/**
 * Lista de coloane a unui `SELECT` → perechi (de unde se citește, cum se cheamă).
 *
 * Se citește din instrucțiunea REALĂ, nu dintr-o proiecție memorată aici:
 * altfel o coloană adăugată sau redenumită în `lib/auth/` ar ajunge tăcut în alt
 * câmp. Formele acceptate sunt trei — o coloană simplă, un `CAST(x AS CHAR) AS
 * y` (de care are nevoie `created_ip` ca să iasă din `INET6` ca text), și un
 * `(x IS NULL) AS y`, forma cu care `listAccounts` deosebește un cont fără
 * secret TOTP de unul cu înrolare neterminată.
 *
 * `isNull` întoarce 1 sau 0, nu `true`/`false`, fiindcă exact asta întoarce
 * MariaDB — iar codul care citește face `Number(...) === 1`. Un dublu care ar
 * da boolean ar ascunde chiar capcana `Boolean("0")` de care se ferește acolo.
 */
function projectionOf(
  selectList: string,
): { source: string; name: string; isNull?: boolean }[] {
  return splitTop(selectList, ",").map((entry) => {
    const text = entry.trim();
    const cast = /^CAST\((\w+) AS CHAR\) AS (\w+)$/.exec(text);
    if (cast) return { source: cast[1], name: cast[2] };
    const nul = /^\((\w+) IS NULL\) AS (\w+)$/.exec(text);
    if (nul) return { source: nul[1], name: nul[2], isNull: true };
    if (/^\w+$/.test(text)) return { source: text, name: text };
    throw new Error(`dublul nu recunoaște coloana selectată: „${text}”`);
  });
}

export class FakeAuthDb implements AuthDb, Pool {
  /** Ceas propriu, în milisecunde. Testele îl mișcă; nimic nu depinde de cel
   *  real, ca o expirare să se poată proba fără să aștepte nimeni cinci minute. */
  nowMs = Date.UTC(2026, 7, 16, 12, 0, 0);

  readonly sessions: SessionRow[] = [];
  readonly users: UserRow[] = [];
  readonly loginAttempts: AttemptRow[] = [];
  readonly userInstances: UserInstanceRow[] = [];
  readonly instances: InstanceRow[] = [];
  readonly incidentEntries: IncidentRow[] = [];
  readonly incidentTimelineEntries: TimelineRow[] = [];
  /**
   * `sync_cursors` — un rând per (instanță, flux), scris de ingestie la PRIMUL
   * lot acceptat. Panoul îl citește ca să deosebească „nimic de arătat" de
   * „fluxul n-a sosit niciodată", iar dublul trebuie să-l aibă altfel fiecare
   * pagină cade cu 503 pe o tabelă necunoscută.
   */
  readonly syncCursors: Row[] = [];
  /** Fiecare instrucțiune și parametrii ei, pentru probele care se uită la ce
   *  chiar a plecat spre bază (jetonul în clar, de pildă). */
  readonly statements: { sql: string; params: unknown[] }[] = [];

  constructor() {
    assertTriggerModelMatchesSchema();
  }

  /**
   * Un cont, cu toate coloanele pe care le are `users` în schemă.
   *
   * Implicitele descriu un cont care NU se poate autentifica încă (fără hash de
   * parolă, fără al doilea factor înrolat): un cont de test care ar putea intra
   * din greșeală e cum ajunge un test să treacă fără să probeze nimic.
   */
  addUser(id: number, over: Partial<UserRow> = {}): UserRow {
    const row: UserRow = {
      id,
      username: `u${id}`,
      password_hash: "",
      role: "viewer",
      disabled: 0,
      totp_secret_enc: null,
      totp_confirmed_at: null,
      totp_last_counter: null,
      failed_attempts: 0,
      locked_until: null,
      last_login_at: null,
      last_login_ip: null,
      password_changed_at: this.nowMs,
      created_at: this.nowMs,
      ...over,
    };
    this.users.push(row);
    return row;
  }

  /**
   * O instanță înregistrată. Implicit PORNITĂ, ca în schemă.
   *
   * Nu dă niciun drept nimănui: drepturile sunt rânduri în `user_instances`, iar
   * absența lor înseamnă „nicio instanță". Un ajutor care ar lega automat
   * instanța de un cont ar face ca testele de autorizare să treacă fără ca
   * nimeni să fi dat vreun drept.
   */
  addInstance(instanceId: string, over: Partial<InstanceRow> = {}): InstanceRow {
    const row: InstanceRow = {
      id: nextId(this.instances as unknown as Row[]),
      instance_id: instanceId,
      label: null,
      enabled: 1,
      first_seen_at: null,
      last_batch_at: this.nowMs,
      ...over,
    };
    this.instances.push(row);
    return row;
  }

  /** `detection_entries` — sursa paginii care ține locul lui `/events`. */
  readonly detectionEntries: Row[] = [];

  /**
   * Un rând de cursor: „fluxul ăsta A SOSIT de la instanța asta".
   *
   * `rowsIngested` poate fi 0 dinadins — e starea „fluxul curge, dar n-a adus
   * nimic", care e diferită de absența rândului și pe care panoul o scrie altfel.
   */
  addArrival(instanceId: string, stream: string, rowsIngested = 1): Row {
    const row: Row = {
      id: nextId(this.syncCursors), instance_id: instanceId, stream,
      last_source_id: rowsIngested, rows_ingested: rowsIngested,
      last_batch_seq: 1, first_seen_at: this.nowMs, updated_at: this.nowMs,
    };
    this.syncCursors.push(row);
    return row;
  }

  /** `finding_entries`, `blocklist_entries`, `patch_plan_entries`. */
  readonly findingEntries: Row[] = [];
  readonly blocklistEntries: Row[] = [];
  readonly patchPlanEntries: Row[] = [];

  /** O constatare replicată de pe instanța dată. */
  addFinding(instanceId: string, over: Partial<Row> = {}): Row {
    const row: Row = {
      id: nextId(this.findingEntries), instance_id: instanceId, source_id: 1,
      scanner: "trivy", cve: "CVE-2026-0001", title: "ceva",
      severity: "high", cvss: "7.5", epss: "0.1234", kev: 0,
      kev_due_date: null, package: "openssl", installed_version: "3.0.1",
      fixed_version: "3.0.2", priority: 70, status: "open",
      first_seen: this.nowMs, last_seen: this.nowMs,
      ...over,
    };
    this.findingEntries.push(row);
    return row;
  }

  /** O blocare replicată de pe instanța dată. */
  addBlock(instanceId: string, over: Partial<Row> = {}): Row {
    const row: Row = {
      id: nextId(this.blocklistEntries), instance_id: instanceId, source_id: 1,
      ip: "203.0.113.10", prefix_len: null, reason: "brute-force",
      rule_id: "auth.ssh_bruteforce", incident_source_id: null,
      blocked_at: this.nowMs, expires_at: null, hit_count: 12,
      last_hit_at: this.nowMs, created_by: "auto", active: 1,
      unblocked_at: null, unblocked_by: null,
      ...over,
    };
    this.blocklistEntries.push(row);
    return row;
  }

  /** Un plan de patch replicat de pe instanța dată. */
  addPlan(instanceId: string, over: Partial<Row> = {}): Row {
    const row: Row = {
      id: nextId(this.patchPlanEntries), instance_id: instanceId, source_id: 1,
      plan_uuid: "00000000-0000-0000-0000-000000000001", status: "draft",
      risk_level: "low", blast_radius: "un serviciu", requires_reboot: 0,
      reversible: 1, estimated_downtime_s: 30, confidence: "0.90",
      created_at: this.nowMs, approved_by: null, approved_at: null,
      rejected_by: null, rejected_reason: null,
      ...over,
    };
    this.patchPlanEntries.push(row);
    return row;
  }

  readonly selfcheckEntries: Row[] = [];

  /** O stare de autodiagnostic replicată de pe instanța dată. */
  addCheck(instanceId: string, over: Partial<Row> = {}): Row {
    const row: Row = {
      id: nextId(this.selfcheckEntries), instance_id: instanceId,
      check_key: "web", status: "ok", title: "Panoul", detail: "",
      since: this.nowMs, last_seen: this.nowMs, last_alert_at: null, stale: 0,
      ...over,
    };
    this.selfcheckEntries.push(row);
    return row;
  }

  readonly loginSessionEntries: Row[] = [];

  /** O sesiune de login replicată de pe instanța dată. */
  addLoginSession(instanceId: string, over: Partial<Row> = {}): Row {
    const row: Row = {
      id: nextId(this.loginSessionEntries), instance_id: instanceId,
      source_id: nextId(this.loginSessionEntries),
      session_key: "432", username: "operator", auid: "1000",
      src_ip: "198.51.100.7",
      // `pts0` si nu `ssh`: pe pagina se arata implicit numai sesiunile CU
      // terminal, iar un implicit fara ar face fiecare test sa para gol.
      terminal: "pts0", interactive: 1,
      opened_at: this.nowMs, closed_at: null, closed_inferred: 0,
      command_count: 0, sudo_count: 0, commands_purged: 0,
      updated_at: this.nowMs,
      ...over,
    };
    this.loginSessionEntries.push(row);
    return row;
  }

  readonly sessionCommandEntries: Row[] = [];

  /** O comandă replicată de pe instanța dată. */
  addSessionCommand(instanceId: string, over: Partial<Row> = {}): Row {
    const row: Row = {
      id: nextId(this.sessionCommandEntries), instance_id: instanceId,
      source_id: nextId(this.sessionCommandEntries),
      session_source_id: 1, session_key: "432", ts: this.nowMs,
      username: "operator", exe: "/usr/bin/ls", argv: "/usr/bin/ls -la",
      cwd: "/root", tty: "pts0", pid: 100, ppid: 99, success: 1,
      ...over,
    };
    this.sessionCommandEntries.push(row);
    return row;
  }

  readonly scanEntries: Row[] = [];

  /** O rulare de scanare, replicată de pe instanța dată. */
  addScan(instanceId: string, over: Partial<Row> = {}): Row {
    const row: Row = {
      id: nextId(this.scanEntries), instance_id: instanceId,
      source_id: nextId(this.scanEntries), scanner: "dnf", target: "os",
      asset_source_id: null, status: "completed",
      started_at: this.nowMs, finished_at: this.nowMs,
      duration_ms: 1000, exit_code: 0,
      // Şiruri, ca `bigNumberStrings`.
      findings_count: "0", new_findings: "0", resolved_findings: "0",
      db_version: null, error: null, triggered_by: "schedule",
      ...over,
    };
    this.scanEntries.push(row);
    return row;
  }

  readonly rollupEntries: Row[] = [];

  /** O oră de contor, replicată de pe instanța dată. */
  addRollupHour(instanceId: string, over: Partial<Row> = {}): Row {
    const row: Row = {
      id: nextId(this.rollupEntries), instance_id: instanceId,
      bucket: this.nowMs, asset_source_id: 1, source: "nginx", action: "req",
      // Şiruri, ca `bigNumberStrings`: codul care le adună trebuie să pice aici
      // dacă le concatenează, nu pe gazdă.
      n: "10", uniq_src: "3", bytes_in: "100", bytes_out: "200",
      p95_latency_ms: 7,
      ...over,
    };
    this.rollupEntries.push(row);
    return row;
  }

  /** O detecție replicată de pe instanța dată. */
  addDetection(instanceId: string, over: Partial<Row> = {}): Row {
    const row: Row = {
      id: nextId(this.detectionEntries), instance_id: instanceId,
      source_id: 1, ts: this.nowMs, rule_id: "auth.ssh_bruteforce",
      rule_family: "auth", severity: "medium", score: null, actor_key: null,
      src_ip: "203.0.113.10", dst_port: 22, incident_source_id: null,
      suppressed: 0, suppress_reason: null,
      ...over,
    };
    this.detectionEntries.push(row);
    return row;
  }

  /** Un incident replicat de pe instanța dată. */
  addIncident(instanceId: string, over: Partial<IncidentRow> = {}): IncidentRow {
    const row: IncidentRow = {
      id: nextId(this.incidentEntries as unknown as Row[]),
      instance_id: instanceId,
      source_id: 1,
      fingerprint: "amprenta",
      status: "open",
      severity: "high",
      ai_severity: null,
      title: "titlu",
      summary: null,
      actor_key: null,
      acknowledged_by: null,
      acknowledged_at: null,
      resolved_at: null,
      resolution_note: null,
      detection_count: 1,
      created_at: this.nowMs,
      first_detection_at: this.nowMs,
      last_detection_at: this.nowMs,
      ...over,
    };
    this.incidentEntries.push(row);
    return row;
  }

  private table(name: string): Row[] {
    if (name === "sessions") return this.sessions as unknown as Row[];
    if (name === "users") return this.users as unknown as Row[];
    if (name === "login_attempts") return this.loginAttempts as unknown as Row[];
    if (name === "user_instances") return this.userInstances as unknown as Row[];
    if (name === "instances") return this.instances as unknown as Row[];
    if (name === "incident_entries") return this.incidentEntries as unknown as Row[];
    if (name === "incident_timeline_entries") {
      return this.incidentTimelineEntries as unknown as Row[];
    }
    if (name === "sync_cursors") return this.syncCursors;
    if (name === "detection_entries") return this.detectionEntries;
    if (name === "finding_entries") return this.findingEntries;
    if (name === "blocklist_entries") return this.blocklistEntries;
    if (name === "patch_plan_entries") return this.patchPlanEntries;
    if (name === "selfcheck_state_entries") return this.selfcheckEntries;
    if (name === "event_rollup_1h_entries") return this.rollupEntries;
    if (name === "scan_entries") return this.scanEntries;
    if (name === "login_session_entries") return this.loginSessionEntries;
    if (name === "session_command_entries") return this.sessionCommandEntries;
    throw new Error(`dublul nu cunoaște tabela ${name}`);
  }

  /** Triggerele `sessions_active_token_bi` / `_bu`, modelate. */
  private applyTrigger(row: Row): void {
    row.active_token_hash = row.revoked_at === null || row.revoked_at === undefined
      ? row.token_hash : null;
  }

  /** Cheia unică `uk_sessions_active_token`, modelată: NULL-urile nu se ciocnesc. */
  private assertUnique(row: Row): void {
    if (row.active_token_hash === null) return;
    const clash = (this.sessions as unknown as Row[]).some(
      (other) => other !== row && other.active_token_hash === row.active_token_hash);
    if (clash) {
      const err = new Error(
        "ER_DUP_ENTRY: Duplicate entry for key 'uk_sessions_active_token'");
      (err as Error & { errno: number }).errno = 1062;
      throw err;
    }
  }

  /**
   * Gramatica se verifică pe un rând-SONDĂ, o dată, înainte de rândurile reale.
   *
   * Fără asta, docstring-ul de sus era fals cum e scris: condițiile și
   * atribuirile se evaluează per rând candidat, deci pe o tabelă GOALĂ nu se
   * evaluau deloc — o formă nerecunoscută devenea o operație nulă tăcută, exact
   * ce fișierul ăsta pretinde că refuză.
   *
   * Tot aici se cere și ca instrucțiunea să folosească TOȚI parametrii dați.
   * Verificarea exista doar pe ramura `INSERT`; un `UPDATE` căruia îi rămâne un
   * parametru nelegat e o condiție ștearsă din `WHERE` — la MariaDB ar fi o
   * eroare, iar în dublu ar fi trecut ca un `WHERE` mai larg, adică o revocare
   * care atinge mai multe sesiuni decât cea cerută.
   */
  private checkGrammar(params: unknown[], where: string, assignments?: string): void {
    const probe: Cursor = { params, at: 0 };
    if (assignments !== undefined) evalAssignments(assignments, probe, this.nowMs);
    evalWhere(where, PROBE_ROW, probe, this.nowMs);
    assert.equal(probe.at, params.length,
                 "dublul: au rămas parametri neconsumați");
  }

  // -------------------------------------------------------------------------
  // Driverul
  // -------------------------------------------------------------------------
  async end(): Promise<void> { /* nimic de închis */ }

  /**
   * Cârligul per conexiune al pool-ului. Dublul nu deschide nicio sesiune
   * MariaDB, deci n-are ce pune în mod strict — dar ȚINE tratantul, ca
   * `useAuthServer` să poată cere ca `getPool` chiar să-l fi înregistrat. Ce
   * TRIMITE tratantul se probează în `tests/db-strict-mode.test.ts`.
   */
  connectionHandler: ((connection: PooledConnection) => void) | null = null;

  on(_event: "connection", handler: (connection: PooledConnection) => void): unknown {
    this.connectionHandler = handler;
    return this;
  }

  async query(sql: string, params: unknown[] = []): Promise<[unknown, unknown]> {
    this.statements.push({ sql, params });
    const one = flat(sql);
    if (one.startsWith("SELECT ")) return [this.select(one, params), []];
    return [{ affectedRows: this.mutate(one, params) }, []];
  }

  async all(sql: string, params: unknown[] = []): Promise<Row[]> {
    const [rows] = await this.query(sql, params);
    assert.ok(Array.isArray(rows), `dublul: „${sql}” nu întoarce rânduri`);
    return rows as Row[];
  }

  async write(sql: string, params: unknown[] = []): Promise<number> {
    const [result] = await this.query(sql, params);
    const affected = (result as { affectedRows?: unknown }).affectedRows;
    assert.equal(typeof affected, "number",
                 `dublul: „${sql}” nu e o scriere`);
    return affected as number;
  }

  // -------------------------------------------------------------------------
  private select(one: string, params: unknown[]): Row[] {
    // Ceasul BAZEI, citit ca valoare. MariaDB acceptă un `SELECT` fără `FROM`;
    // gramatica de mai jos cere o tabelă, deci forma asta se recunoaște aici.
    // Rostul ei e să existe UN singur ceas: o fereastră tăiată în SQL și o
    // despărțire făcută pe ceasul procesului sunt două ceasuri, iar dublul
    // îngheață unul dintre ele — adică proba ar trece sau ar pica după cât de
    // departe e ziua de azi de data fixată în fixtură.
    if (/^SELECT UTC_TIMESTAMP\(6\) AS \w+$/.test(one.trim())) {
      assert.equal(params.length, 0, "dublul: citirea ceasului n-are parametri");
      return [{ acum: this.nowMs }];
    }
    const parsed = /^SELECT (.+?) FROM (\w+)((?: .*)?)$/.exec(one);
    if (!parsed) throw new Error(`dublul nu recunoaște interogarea: ${one}`);
    const [, selectList, table] = parsed;
    let tail = parsed[3];

    // `GROUP BY` se taie de la coada ÎNAINTE de parsarea lui `WHERE`, ca `LIMIT`:
    // lasat acolo, ar fi citit ca parte din ultima conditie, iar dubla ar cadea
    // cu „valoare nerecunoscuta" pe o instructiune perfect valida. Numele
    // coloanei se pastreaza — agregarea de mai jos il verifica.
    let groupBy: string | null = null;
    const groupAt = /\s+GROUP BY (\w+)$/.exec(tail);
    if (groupAt) {
      groupBy = groupAt[1];
      tail = tail.slice(0, groupAt.index);
    }

    // `LIMIT ?` se leagă ULTIMUL, după parametrii lui `WHERE` — ordinea în care
    // driverul consumă lista. Se taie de la coadă înainte de orice altceva.
    let limit: number | null = null;
    let whereParams = params;
    const limitAt = /\s+LIMIT (\?|\d+)$/.exec(tail);
    if (limitAt) {
      tail = tail.slice(0, limitAt.index);
      if (limitAt[1] === "?") {
        assert.ok(params.length >= 1, "dublul: `LIMIT ?` fără niciun parametru");
        limit = Number(params[params.length - 1]);
        whereParams = params.slice(0, -1);
      } else {
        limit = Number(limitAt[1]);
      }
      assert.ok(Number.isSafeInteger(limit) && limit >= 0,
                `dublul: LIMIT cu o valoare care nu e un întreg (${String(limit)})`);
    }

    let order: string | null = null;
    const orderAt = /\s+ORDER BY (.+)$/.exec(tail);
    if (orderAt) {
      tail = tail.slice(0, orderAt.index);
      order = orderAt[1];
    }

    const whereAt = /^\s+WHERE (.+)$/.exec(tail);
    if (tail.trim() !== "" && !whereAt) {
      throw new Error(`dublul nu recunoaște coada interogării: „${tail.trim()}”`);
    }
    const where = whereAt ? whereAt[1] : null;

    if (where === null) {
      // Fără `WHERE` — toate rândurile, ca la MariaDB. Vezi limita scrisă în
      // capul fișierului: o eroare aici ar face ca o interogare căreia i s-a
      // pierdut filtrul de instanțe să pice din alt motiv decât cel adevărat.
      assert.equal(whereParams.length, 0,
                   "dublul: interogare fără `WHERE`, dar cu parametri");
    } else {
      this.checkGrammar(whereParams, where);
    }

    // Un cursor per rând: condițiile se evaluează pentru fiecare rând pornind de
    // la primul parametru, ca la o instrucțiune preparată. Un cursor comun ar fi
    // consumat parametrii primului rând și ar fi rămas fără la al doilea — ceea
    // ce s-a și întâmplat, la primul test cu trei sesiuni.
    let rows = where === null
      ? [...this.table(table)]
      : this.table(table).filter(
        (row) => evalWhere(where, row, { params: whereParams, at: 0 }, this.nowMs));

    if (order !== null) rows = sortRows(rows, order);
    if (limit !== null) rows = rows.slice(0, limit);

    // `SELECT <coloana>, COUNT(*) AS n ... GROUP BY <coloana>` — agregarea pe
    // care o face `countByGroup`. Modelata AICI, nu ocolita: codul livrat chiar
    // grupeaza in baza, iar o dubla care ar cere codului sa citeasca toate
    // randurile ar proba alt cod decat cel care ruleaza.
    const grouped = /^(\w+), COUNT\(\*\) AS n$/.exec(selectList.trim());
    if (grouped && groupBy !== null) {
      const column = grouped[1];
      assert.equal(groupBy, column,
                   "dublul: se grupeaza dupa alta coloana decat cea selectata");
      const tally = new Map<string, number>();
      for (const row of rows) {
        const value = String(row[column]);
        tally.set(value, (tally.get(value) ?? 0) + 1);
      }
      // `n` ca SIR, ca `bigNumberStrings`: codul care presupune un numar trebuie
      // sa pice aici, nu pe gazda.
      return [...tally.entries()].map(([value, n]) => ({ [column]: value, n: String(n) }));
    }

    if (/^COUNT\(\*\) AS n$/.test(selectList.trim())) {
      // Șir, ca `bigNumberStrings`. Codul care presupune un număr trebuie să
      // pice AICI, nu pe gazdă.
      return [{ n: String(rows.length) }];
    }

    const projection = projectionOf(selectList);
    const required = REQUIRED_PROJECTION.get(table);
    for (const column of required ?? []) {
      assert.ok(projection.some((entry) => entry.name === column),
                `dublul: interogarea nu cere coloana ${column}, iar codul care ` +
                "citește rândul n-ar observa lipsa ei");
    }

    return rows.map((row) => Object.fromEntries(
      projection.map(({ source, name, isNull }) => {
        const value = row[source];
        if (isNull) return [name, value === undefined || value === null ? 1 : 0];
        if (value === undefined || value === null) return [name, null];
        return [name, isTime(name) ? iso(Number(value)) : value];
      })));
  }

  private mutate(one: string, params: unknown[]): number {
    const cursor: Cursor = { params, at: 0 };

    if (one.startsWith("INSERT INTO ")) {
      const affected = this.insert(one, cursor);
      assert.equal(cursor.at, params.length,
                   "dublul: au rămas parametri neconsumați");
      return affected;
    }

    // `DELETE FROM <tabelă> WHERE …`. Fără `WHERE` NU e acceptat, și asta e o
    // abatere DINADINS de la MariaDB: un `DELETE` fără condiție golește tabela,
    // iar `login_attempts` e starea celor trei limitatoare. Dublul nu trebuie să
    // fie drumul pe care cineva descoperă că merge.
    const remove = /^DELETE FROM (\w+) WHERE (.+)$/.exec(one);
    if (remove) {
      this.checkGrammar(params, remove[2]);
      const rows = this.table(remove[1]);
      let removed = 0;
      // De la coadă spre cap: ștergerea în timpul parcurgerii ar sări rândul de
      // după fiecare rând scos.
      for (let i = rows.length - 1; i >= 0; i--) {
        if (!evalWhere(remove[2], rows[i], { params, at: 0 }, this.nowMs)) continue;
        rows.splice(i, 1);
        removed++;
      }
      return removed;
    }

    const update = /^UPDATE (\w+) SET (.+?) WHERE (.+)$/.exec(one);
    if (!update) throw new Error(`dublul nu recunoaște instrucțiunea: ${one}`);
    const assignments = update[2];
    this.checkGrammar(params, update[3], assignments);
    let affected = 0;
    for (const row of this.table(update[1])) {
      // Un cursor per rând: parametrii se citesc de la capăt pentru fiecare
      // rând, ca la evaluarea reală a unei instrucțiuni preparate.
      const perRow: Cursor = { params, at: 0 };
      const values = evalAssignments(assignments, perRow, this.nowMs, row);
      if (!evalWhere(update[3], row, perRow, this.nowMs)) continue;
      Object.assign(row, values);
      if (update[1] === "sessions") {
        this.applyTrigger(row);
        this.assertUnique(row);
      }
      affected++;
    }
    return affected;
  }

  /**
   * `INSERT INTO <tabelă> (...) VALUES (...)`.
   *
   * Coloanele și valorile se citesc din instrucțiunea REALĂ, nu dintr-o ordine
   * memorată aici: altfel o coloană adăugată sau mutată în `session.ts` ar
   * ajunge tăcut în alt câmp, iar testele ar proba altceva decât ce se scrie.
   */
  private insert(sql: string, cursor: Cursor): number {
    const table = /^INSERT INTO (\w+) \(/.exec(sql)?.[1];
    assert.ok(table, `dublul: nu pot citi tabela din ${sql}`);
    const columns = groupAfter(sql, `INSERT INTO ${table} (`).split(",")
      .map((name) => name.trim());
    const values = splitTop(groupAfter(sql, "VALUES ("), ",");
    assert.equal(columns.length, values.length,
                 `dublul: ${columns.length} coloane și ${values.length} valori`);

    const row: Row = table === "sessions"
      ? { revoked_at: null, revoked_reason: null, active_token_hash: null }
      : {};
    for (let i = 0; i < columns.length; i++) {
      row[columns[i]] = evalValue(values[i], cursor, this.nowMs);
    }
    if (table === "sessions") return this.insertRow(row as unknown as SessionRow);

    // Se cere ca tabela să fie una cunoscută ÎNAINTE de a scrie: un `INSERT`
    // într-o tabelă pe care dublul n-o are ar fi altfel un rând pierdut în
    // tăcere, adică exact clasa de test care nu verifică nimic.
    const rows = this.table(table as string);
    if (AUTO_INCREMENT.has(table as string) && row.id === undefined) {
      row.id = nextId(rows);
    }
    rows.push(row);
    return 1;
  }

  /** Inserează un rând gata construit — pentru probele care au nevoie de o
   *  coliziune pe care codul livrat n-o poate produce singur. */
  insertRow(row: SessionRow): number {
    const stored = { ...row } as unknown as Row;
    this.applyTrigger(stored);
    this.assertUnique(stored);
    this.sessions.push(stored as unknown as SessionRow);
    return 1;
  }
}

/**
 * Tabelele al căror `id` îl pune serverul, nu instrucțiunea.
 *
 * `login_attempts` NU e aici, deși are și ea `AUTO_INCREMENT`: nimic din codul
 * livrat nu citește id-ul unui rând de încercare, iar `AttemptRow` nu are câmpul.
 * O coloană în plus pe rândurile alea ar schimba ce compară testele existente
 * fără să probeze nimic.
 */
const AUTO_INCREMENT = new Set([
  "users", "user_instances", "instances", "incident_entries",
  "incident_timeline_entries",
]);

/** `max(id) + 1`. Vezi limita despre `AUTO_INCREMENT` din capul fișierului. */
function nextId(rows: Row[]): number {
  let max = 0;
  for (const row of rows) {
    const id = Number(row.id);
    if (Number.isSafeInteger(id) && id > max) max = id;
  }
  return max + 1;
}

/** `at` singur e coloana de timp din `incident_timeline_entries`; restul sunt
 *  `*_at`. Fără primul, cronologia ar ieși din dublu ca număr, iar din driver ca
 *  șir de dată — două forme diferite pentru aceeași coloană. */
function isTime(column: string): boolean {
  return column === "at" || column.endsWith("_at");
}

function iso(ms: number): string {
  // Forma pe care o dă driverul cu `dateStrings: true`.
  return new Date(ms).toISOString().replace("T", " ").replace("Z", "");
}

/** Spațiile albe strânse la unul singur, ca în `splitStatements`. */
function flat(sql: string): string {
  return sql.replace(/\s+/g, " ").trim();
}

/**
 * Conținutul parantezei deschise de `start`, până la ÎNCHIDEREA EI.
 *
 * Numărarea parantezelor nu e pedanterie: lista de valori conține
 * `UTC_TIMESTAMP(6)`, iar o tăiere la primul `)` ar rupe instrucțiunea în
 * mijlocul unei funcții și ar face dublul să citească alte coloane decât cele
 * scrise.
 */
function groupAfter(text: string, start: string): string {
  const from = text.indexOf(start);
  assert.ok(from >= 0, `dublul: nu găsesc „${start}” în instrucțiune`);
  let depth = 1;
  let out = "";
  for (const ch of text.slice(from + start.length)) {
    if (ch === "(") depth++;
    if (ch === ")") {
      depth--;
      if (depth === 0) return out;
    }
    out += ch;
  }
  throw new Error(`dublul: paranteză neînchisă după „${start}”`);
}

/** Taie la separator, dar numai la nivelul de sus (parantezele rămân întregi). */
function splitTop(text: string, separator: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (depth === 0 && text.startsWith(separator, i)) {
      parts.push(current);
      current = "";
      i += separator.length - 1;
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts;
}
