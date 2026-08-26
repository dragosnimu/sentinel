/**
 * Runner de migrații pentru MariaDB: granular pe instrucțiune, idempotent.
 *
 * ## Eșecul pe care îl previne
 *
 * O migrație care moare la instrucțiunea 7 din 12 lasă baza într-o stare pe care
 * NICIUN număr de versiune nu o descrie. Rularea următoare are atunci două
 * variante, amândouă greșite: ori reia fișierul de la prima instrucțiune și
 * moare pe „tabela există deja" — migrație blocată, cu un mesaj care arată ca o
 * problemă de bază de date —, ori consideră fișierul aplicat și trece la N+1,
 * lăsând în urmă cinci instrucțiuni care n-au rulat niciodată. A doua e mai rea:
 * e tăcută, iar simptomul apare peste săptămâni, ca o coloană care lipsește.
 *
 * `sentinel/db/migrate.py:8-9` nu are problema asta fiindcă PostgreSQL are DDL
 * tranzacțional: un fișier, o tranzacție, iar un eșec nu lasă nimic pe jumătate.
 * **MariaDB nu are.** Fiecare instrucțiune DDL face commit implicit, inclusiv
 * peste o tranzacție deschisă. Deci garanția trebuie reconstruită altfel, iar
 * singura formă care ține e: **se înregistrează INSTRUCȚIUNI, nu fișiere**, și
 * fiecare are o pre-verificare independentă de registru.
 *
 * ## Cele două surse de adevăr, și de ce sunt amândouă necesare
 *
 * 1. **Registrul** (`schema_version`, un rând per instrucțiune) spune ce am
 *    consemnat că am aplicat.
 * 2. **Garda** (`-- @guard ...`, evaluată pe `information_schema`) spune ce
 *    există CHIAR ACUM în bază.
 *
 * Fereastra dintre ele e reală și nu se poate închide: DDL-ul face commit, apoi
 * scriem rândul în registru; o cădere între cele două lasă obiectul creat și
 * neconsemnat. De-aia garda se evaluează ÎNAINTE de execuție: dacă obiectul e
 * deja acolo, instrucțiunea nu se re-rulează, se consemnează cu
 * `note = 'reconciled'`. Ordinea execuție→consemnare e sigură TOCMAI fiindcă
 * există garda; inversată, o cădere ar lăsa consemnat ceva ce nu s-a întâmplat.
 *
 * **Și pe drumul CONSEMNAT, la fiecare rulare** (`auditLedger`). O primă
 * versiune aplica argumentul de mai sus doar instrucțiunilor necunoscute și
 * credea registrul pe cuvânt pentru restul — adică fix pe drumul care se
 * parcurge de aici încolo, mereu. O tabelă ștearsă după ce fusese consemnată
 * ieșea `skipped` și nu se mai întorcea niciodată, cu registrul spunând că
 * schema e la zi. Costul închiderii e un `SELECT COUNT(*)` per instrucțiune
 * consemnată, per rulare. Divergența OPREȘTE rularea și nu repară nimic —
 * argumentul e la `auditLedger`.
 *
 * ## Ce dovedește succesul
 *
 * Nu codul de retur al driverului. După fiecare instrucțiune, garda se
 * evaluează A DOUA OARĂ, iar dacă obiectul tot nu e acolo, rularea se oprește și
 * NU se consemnează nimic. Un `query()` care s-a întors fără excepție nu e o
 * dovadă că obiectul există — e dovada că serverul a acceptat cererea. Tabelul
 * din `CLAUDE.md` e făcut în întregime din diferența asta.
 *
 * `guard none` e cazul în care nu există nimic de confirmat. Se consemnează cu
 * `verified = 0`, ca registrul să deosebească „dovedit acolo" de „a rulat, n-am
 * putut verifica". Cele două n-au voie să arate la fel într-un registru.
 *
 * ## Filtrul pe `DATABASE()`
 *
 * Toate interogările de gardă poartă `TABLE_SCHEMA = DATABASE()`.
 * `information_schema` e la nivel de INSTANȚĂ: fără filtru, o tabelă cu același
 * nume din baza altcuiva ar face garda să spună „există", instrucțiunea s-ar
 * sări, registrul ar consemna-o aplicată, iar baza noastră ar rămâne fără ea.
 * Pe o găzduire partajată nu e un caz teoretic.
 *
 * ## Concurență
 *
 * Două rulări simultane ar putea trece amândouă de aceeași gardă. Se ia un
 * lacăt numit (`GET_LOCK`) la început; dacă nu se obține, rularea se OPREȘTE.
 * `GET_LOCK` întoarce `NULL` la eroare, iar `NULL` nu e „liber": e „nu știu",
 * deci tot refuz.
 *
 * ## Ce NU face
 *
 * Nu există migrații de întors. Motivul e cel din `sentinel/db/migrate.py`:
 * întoarcerea unei schimbări de schemă pe o bază vie e o fantezie, iar drumul
 * înapoi e instantaneul dinaintea publicării.
 */

import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { splitStatements } from "./sql-statements";
import type { Guard, Statement } from "./sql-statements";

export class MigrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MigrationError";
  }
}

/**
 * Interfața minimă cerută de la o conexiune.
 *
 * Deliberat mai îngustă decât mysql2: runner-ul nu trebuie să poată deschide
 * tranzacții (n-ar folosi la nimic pe DDL) și nu trebuie să cunoască driverul.
 * `lib/db.ts` face adaptarea. Un dublu de test implementează aceleași două
 * metode — vezi nota din `tests/migrate.test.ts` despre ce afirmă dublul și ce
 * nu poate afirma.
 */
export interface Db {
  all(sql: string, params?: unknown[]): Promise<Record<string, unknown>[]>;
  run(sql: string, params?: unknown[]): Promise<void>;
}

export const MIGRATIONS_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)), "..", "migrations");

export const BOOTSTRAP_FILE = "0000_bootstrap.sql";
const NAME_RE = /^(\d{4})_([a-z0-9_]+)\.sql$/;

/** Numele lacătului. Fix, nu derivat din baza de date: două aplicații pe aceeași
 *  bază trebuie să se excludă reciproc, iar `GET_LOCK` e la nivel de server. */
export const LOCK_NAME = "sentinel_aggregator_migrate";
const LOCK_TIMEOUT_S = 15;

export type Migration = { file: string; version: number; name: string; statements: Statement[] };

export type StatementOutcome =
  | "applied"      // a rulat acum, iar garda a confirmat efectul
  | "ran"          // a rulat acum; `guard none`, deci nimic de confirmat
  | "reconciled"   // obiectul era deja acolo, neconsemnat
  | "skipped"      // consemnat deja, sumă de control potrivită
  | "pending";     // doar la `--dry-run`

export type StatementReport = {
  migration: string;
  index: number;
  guardText: string;
  outcome: StatementOutcome;
  durationMs: number;
};

export type RunReport = { statements: StatementReport[]; dryRun: boolean };

// ---------------------------------------------------------------------------
// Descoperirea fișierelor
// ---------------------------------------------------------------------------
export function discover(dir: string = MIGRATIONS_DIR): Migration[] {
  const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  const found: Migration[] = [];
  const seen = new Map<number, string>();

  for (const file of files) {
    const match = NAME_RE.exec(file);
    if (!match) {
      // Nu se sare tăcut. Un fișier cu numele greșit e o migrație care nu se
      // aplică niciodată, iar aia se descoperă abia când lipsește o coloană.
      throw new MigrationError(
        `${file}: numele nu are forma NNNN_nume.sql, deci n-ar fi aplicat niciodată`);
    }
    if (file === BOOTSTRAP_FILE) continue;
    const version = Number(match[1]);
    const previous = seen.get(version);
    if (previous) {
      throw new MigrationError(
        `versiunea ${match[1]} apare de două ori: ${previous} și ${file}`);
    }
    seen.set(version, file);
    found.push({
      file,
      version,
      name: match[2],
      statements: splitStatements(readFileSync(path.join(dir, file), "utf8"), file),
    });
  }
  if (found.length === 0) {
    throw new MigrationError(`${dir}: nicio migrație în afară de bootstrap`);
  }
  return found;
}

// ---------------------------------------------------------------------------
// Gărzile: ce există CHIAR ACUM
// ---------------------------------------------------------------------------
/**
 * `true` / `false` / `null` — a treia valoare e „nu se poate ști".
 *
 * `null` nu se confundă cu `false`. O interogare pe `information_schema` care
 * nu întoarce niciun rând nu înseamnă „obiectul lipsește", înseamnă că n-am
 * primit răspunsul așteptat, iar tratarea ei ca „lipsește" ar re-rula o
 * instrucțiune deja aplicată.
 */
export async function guardPresent(db: Db, guard: Guard): Promise<boolean | null> {
  if (guard.kind === "none") return null;

  let sql: string;
  let params: unknown[];
  switch (guard.kind) {
    case "table":
      sql = "SELECT COUNT(*) AS n FROM information_schema.TABLES " +
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?";
      params = [guard.table];
      break;
    case "index":
      sql = "SELECT COUNT(*) AS n FROM information_schema.STATISTICS " +
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?";
      params = [guard.table, guard.name];
      break;
    case "column":
      sql = "SELECT COUNT(*) AS n FROM information_schema.COLUMNS " +
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?";
      params = [guard.table, guard.name];
      break;
    case "trigger":
      // TRIGGER_SCHEMA, nu TABLE_SCHEMA. Vederea asta NU are o coloană
      // `TABLE_SCHEMA` — are `TRIGGER_SCHEMA` și `EVENT_OBJECT_SCHEMA` —, deci
      // alegerea greșită ar fi o eroare „Unknown column", zgomotoasă, nu o
      // nepotrivire tăcută. (O versiune anterioară a comentariului ăstuia
      // descria o nepotrivire tăcută; era greșit, iar un comentariu greșit
      // despre o gardă e felul în care cineva „repară" garda. Lista de coloane
      // e de confirmat pe server — vezi raportul rundei.)
      sql = "SELECT COUNT(*) AS n FROM information_schema.TRIGGERS " +
            "WHERE TRIGGER_SCHEMA = DATABASE() AND TRIGGER_NAME = ?";
      params = [guard.name];
      break;
  }

  const rows = await db.all(sql, params);
  if (!rows.length || rows[0] == null || rows[0].n === undefined || rows[0].n === null) {
    return null;
  }
  // `Number(...)`: cu `bigNumberStrings` driverul întoarce COUNT(*) ca șir, iar
  // `"0" > 0` e fals dar `"0"` e adevărat ca boolean. Conversia explicită scoate
  // clasa asta de greșeală din discuție.
  const n = Number(rows[0].n);
  if (!Number.isFinite(n)) return null;
  return n > 0;
}

function describeGuard(guard: Guard): string {
  switch (guard.kind) {
    case "table": return `tabela ${guard.table}`;
    case "index": return `indexul ${guard.table}.${guard.name}`;
    case "column": return `coloana ${guard.table}.${guard.name}`;
    case "trigger": return `triggerul ${guard.name}`;
    case "none": return `nimic de verificat (${guard.reason})`;
  }
}

// ---------------------------------------------------------------------------
// Lacătul
// ---------------------------------------------------------------------------
export async function acquireLock(db: Db): Promise<void> {
  const rows = await db.all("SELECT GET_LOCK(?, ?) AS got", [LOCK_NAME, LOCK_TIMEOUT_S]);
  const got = rows.length ? rows[0].got : undefined;
  // 1 = l-am luat. 0 = expirat. NULL/altceva = eroare, adică „nu știu" — și
  // „nu știu" nu e permisiune.
  if (Number(got) !== 1) {
    throw new MigrationError(
      `nu am obținut lacătul ${LOCK_NAME} (GET_LOCK a întors ${String(got)}). ` +
      "Altă rulare de migrații e în curs, sau serverul n-a putut răspunde. " +
      "Două rulări simultane pot trece amândouă de aceeași gardă.");
  }
}

/**
 * Eliberarea nu are test, și asta e o alegere scrisă, nu o scăpare.
 *
 * `GET_LOCK` e legat de SESIUNE: MariaDB îl eliberează singură când conexiunea
 * se închide, iar `bin/migrate.ts` închide conexiunea într-un `finally` pe
 * fiecare drum. Deci un `RELEASE_LOCK` sărit nu produce niciun efect observabil
 * — un test pentru el ar afirma doar că linia există, ceea ce e chiar clasa de
 * aserțiune pe care `CLAUDE.md` o numește inutilă. Se cheamă oricum, fiindcă
 * ziua în care runner-ul primește o conexiune împrumutată de la un pool e ziua
 * în care contează.
 */
export async function releaseLock(db: Db): Promise<void> {
  await db.all("SELECT RELEASE_LOCK(?) AS released", [LOCK_NAME]);
}

// ---------------------------------------------------------------------------
// Bootstrap: tabela în care se consemnează tot restul
// ---------------------------------------------------------------------------
export async function bootstrap(db: Db, dir: string = MIGRATIONS_DIR): Promise<void> {
  const text = readFileSync(path.join(dir, BOOTSTRAP_FILE), "utf8");
  const statements = splitStatements(text, BOOTSTRAP_FILE);
  if (statements.length !== 1) {
    throw new MigrationError(
      `${BOOTSTRAP_FILE}: aștept exact o instrucțiune, am găsit ${statements.length}. ` +
      "Bootstrap-ul e singurul fișier care nu se poate consemna în registru, " +
      "deci e singurul care trebuie să rămână trivial.");
  }
  const [stmt] = statements;
  await db.run(stmt.sql);
  // `CREATE TABLE IF NOT EXISTS` iese cu succes și când n-a creat nimic, și —
  // dacă serverul refuză din alt motiv — tot un cod de retur dă. Faptul
  // observabil e rândul din `information_schema`.
  const present = await guardPresent(db, stmt.guard);
  if (present !== true) {
    throw new MigrationError(
      `după bootstrap, ${describeGuard(stmt.guard)} tot nu e vizibilă în ` +
      "information_schema. Fără registru nu se poate consemna nimic, deci nu " +
      "se aplică nimic.");
  }
}

// ---------------------------------------------------------------------------
// Registrul
// ---------------------------------------------------------------------------
type LedgerRow = { stmt_index: number; stmt_sha256: string };

async function ledgerFor(db: Db, migration: string): Promise<Map<number, LedgerRow>> {
  const rows = await db.all(
    "SELECT stmt_index, stmt_sha256 FROM schema_version WHERE migration = ?",
    [migration]);
  const out = new Map<number, LedgerRow>();
  for (const row of rows) {
    out.set(Number(row.stmt_index), {
      stmt_index: Number(row.stmt_index),
      stmt_sha256: String(row.stmt_sha256),
    });
  }
  return out;
}

async function record(db: Db, migration: string, stmt: Statement,
                      verified: boolean, note: string | null,
                      durationMs: number): Promise<void> {
  await db.run(
    "INSERT INTO schema_version " +
    "(migration, stmt_index, stmt_sha256, guard, verified, note, duration_ms) " +
    "VALUES (?, ?, ?, ?, ?, ?, ?)",
    [migration, stmt.index, stmt.sha256, stmt.guardText, verified ? 1 : 0,
     note, Math.round(durationMs)]);
}

// ---------------------------------------------------------------------------
// O migrație
// ---------------------------------------------------------------------------
/**
 * Prima trecere: fiecare instrucțiune CONSEMNATĂ e reverificată în bază.
 *
 * Fără ea, registrul era crezut pe cuvânt. Ăsta e drumul care se parcurge la
 * FIECARE rulare de aici înainte, iar pe el argumentul din capul modulului —
 * două surse de adevăr, fiindcă fereastra dintre ele e reală — nu se aplica
 * deloc: un rând în registru trimitea instrucțiunea la `skipped` fără să
 * întrebe baza nimic.
 *
 * Cazul nu e teoretic și e la o comandă distanță, chiar din proiectarea asta:
 * triggerele fac orice rând de probă din `audit_entries` permanent, deci
 * singurul mod de a curăța unul e `DROP TABLE audit_entries`. După aia,
 * registrul încă poartă instrucțiunile #2–#5, `npm run migrate` tipărește
 * `skipped=4`, iar tabela nu se mai întoarce niciodată — cu registrul spunând
 * că schema e la zi. E chiar al doilea mod de eșec pe care îl numește capul
 * modulului, și e cel tăcut.
 *
 * ## Se OPREȘTE, nu repară
 *
 * Alternativa evidentă e re-rularea instrucțiunii lipsă. E greșită aici, și
 * motivul e ce ține agregatorul: `audit_entries` e o ARHIVĂ. Recreată goală,
 * ingestia reia de la cursorul expeditorului, care e demult mai departe — deci
 * rândurile dispărute nu se mai întorc niciodată, iar reparația automată ar fi
 * chiar pierderea. Oprirea îi lasă operatorului fereastra în care poate reface
 * dintr-o copie ÎNAINTE ca ingestia să continue.
 *
 * Se raportează TOATE divergențele, nu prima: cine tocmai a pierdut o tabelă
 * vrea lista, nu un obiect pe rulare.
 */
async function auditLedger(
  db: Db, migration: Migration, ledger: Map<number, LedgerRow>,
): Promise<void> {
  const missing: string[] = [];
  const unreadable: string[] = [];

  for (const stmt of migration.statements) {
    const known = ledger.get(stmt.index);
    if (!known) continue;
    if (known.stmt_sha256 !== stmt.sha256) {
      // Istorie rescrisă. Aici NU se continuă: o instrucțiune consemnată ca
      // aplicată, al cărei text s-a schimbat, înseamnă că baza asta și fișierul
      // ăsta descriu lucruri diferite — și nu se poate ști care e adevărul fără
      // să se uite un om.
      throw new MigrationError(
        `${migration.file} #${stmt.index} (linia ${stmt.line}) e consemnată ca ` +
        `aplicată, dar textul ei s-a schimbat (registru ${known.stmt_sha256.slice(0, 12)}, ` +
        `fișier ${stmt.sha256.slice(0, 12)}). Migrațiile sunt imuabile odată ` +
        "aplicate — adaugă una nouă, nu o edita pe asta.");
    }
    // `guard none` n-a putut fi confirmată nici la aplicare (se consemnează cu
    // `verified = 0`), deci nu are ce fi reverificat. Nu se tace: registrul o
    // spune, și de-aia coloana există.
    if (stmt.guard.kind === "none") continue;

    const present = await guardPresent(db, stmt.guard);
    if (present === true) continue;
    const where = `#${stmt.index} ${describeGuard(stmt.guard)}`;
    if (present === null) unreadable.push(where);
    else missing.push(where);
  }

  if (missing.length || unreadable.length) {
    const parts: string[] = [];
    if (missing.length) {
      parts.push(`consemnate ca aplicate, dar ABSENTE din bază: ${missing.join(", ")}`);
    }
    if (unreadable.length) {
      // „Nu pot citi" și „lipsește" sunt stări diferite, și amândouă opresc —
      // dar operatorul trebuie să știe pe care o are.
      parts.push(`consemnate ca aplicate, dar NU SE POT CITI din information_schema: ` +
                 unreadable.join(", "));
    }
    throw new MigrationError(
      `${migration.file}: registrul și baza nu sunt de acord — ${parts.join(" · ")}. ` +
      "Nu se aplică nimic și NU se re-creează nimic automat: `audit_entries` e o " +
      "arhivă, iar recreată goală ar reporni ingestia de la un cursor mult mai " +
      "avansat, deci rândurile pierdute nu s-ar mai întoarce. Reface dintr-o copie, " +
      "sau — dacă pierderea e acceptată — șterge rândurile corespunzătoare din " +
      "schema_version și rulează din nou.");
  }
}

export async function applyMigration(
  db: Db, migration: Migration, dryRun: boolean,
  log: (line: string) => void = () => {},
): Promise<StatementReport[]> {
  const ledger = await ledgerFor(db, migration.file);
  // Întâi TOT ce e consemnat, apoi ce lipsește: nu se aplică instrucțiuni noi
  // peste o schemă despre care se știe deja că nu e ce spune registrul.
  await auditLedger(db, migration, ledger);
  const reports: StatementReport[] = [];

  for (const stmt of migration.statements) {
    if (ledger.has(stmt.index)) {
      reports.push({ migration: migration.file, index: stmt.index,
                     guardText: stmt.guardText, outcome: "skipped", durationMs: 0 });
      continue;
    }

    const before = await guardPresent(db, stmt.guard);
    if (before === null && stmt.guard.kind !== "none") {
      // „Nu pot citi" nu e „lipsește". Tratat ca lipsă, DDL-ul ar rula pe o
      // bază despre care nu știm nimic; verificarea de după l-ar opri, dar
      // abia după ce a rulat. Aici se oprește înainte.
      throw new MigrationError(
        `${migration.file} #${stmt.index} (linia ${stmt.line}): nu pot citi din ` +
        `information_schema dacă ${describeGuard(stmt.guard)} există. Nu rulez ` +
        "nimic pe o presupunere — „nu știu” și „lipsește” nu sunt același lucru.");
    }

    if (dryRun) {
      // `--dry-run` NU are voie să scrie, nici măcar urma încercării. E comanda
      // rulată de cineva care vrea să afle ce s-ar întâmpla.
      log(`${migration.file} #${stmt.index}: ar rula — ${describeGuard(stmt.guard)}` +
          (before === true ? " (există deja, s-ar reconcilia)" : ""));
      reports.push({ migration: migration.file, index: stmt.index,
                     guardText: stmt.guardText, outcome: "pending", durationMs: 0 });
      continue;
    }

    if (before === true) {
      // A rulat data trecută, dar procesul a murit înainte să consemneze.
      // Se consemnează acum; nu se re-rulează.
      await record(db, migration.file, stmt, true, "reconciled", 0);
      log(`${migration.file} #${stmt.index}: ${describeGuard(stmt.guard)} exista deja — consemnată`);
      reports.push({ migration: migration.file, index: stmt.index,
                     guardText: stmt.guardText, outcome: "reconciled", durationMs: 0 });
      continue;
    }

    const started = Date.now();
    await db.run(stmt.sql);
    const durationMs = Date.now() - started;

    if (stmt.guard.kind === "none") {
      await record(db, migration.file, stmt, false, null, durationMs);
      log(`${migration.file} #${stmt.index}: a rulat, NEVERIFICATĂ (${stmt.guard.reason})`);
      reports.push({ migration: migration.file, index: stmt.index,
                     guardText: stmt.guardText, outcome: "ran", durationMs });
      continue;
    }

    // Efectul, nu intenția: `run()` s-a întors fără excepție, ceea ce spune că
    // serverul a acceptat cererea. Dacă obiectul nu e acolo, nu s-a întâmplat.
    const after = await guardPresent(db, stmt.guard);
    if (after !== true) {
      throw new MigrationError(
        `${migration.file} #${stmt.index} (linia ${stmt.line}) a rulat fără eroare, dar ` +
        `${describeGuard(stmt.guard)} ${after === null ? "nu se poate citi din" : "tot lipsește din"} ` +
        "information_schema. Nu se consemnează nimic — o instrucțiune consemnată " +
        "fără efect e mai rea decât una neconsemnată.");
    }
    await record(db, migration.file, stmt, true, null, durationMs);
    log(`${migration.file} #${stmt.index}: aplicată — ${describeGuard(stmt.guard)} (${durationMs} ms)`);
    reports.push({ migration: migration.file, index: stmt.index,
                   guardText: stmt.guardText, outcome: "applied", durationMs });
  }
  return reports;
}

// ---------------------------------------------------------------------------
// Tot
// ---------------------------------------------------------------------------
export async function migrate(
  db: Db,
  { dryRun = false, dir = MIGRATIONS_DIR, log = (line: string) => console.log(line) } = {},
): Promise<RunReport> {
  const migrations = discover(dir);

  await acquireLock(db);
  try {
    if (dryRun) {
      // Nici bootstrap-ul nu se rulează la dry-run. Dacă registrul lipsește,
      // TOT ce urmează e „ar rula", iar `ledgerFor` ar cădea pe o tabelă
      // inexistentă — deci se spune asta, nu se creează tabela pe furiș.
      const present = await guardPresent(db, { kind: "table", table: "schema_version" });
      if (present !== true) {
        throw new MigrationError(
          "schema_version nu există (sau nu se poate citi), deci nu pot spune ce " +
          "e deja aplicat. Rulează fără --dry-run ca să se creeze registrul.");
      }
    } else {
      await bootstrap(db, dir);
    }

    const statements: StatementReport[] = [];
    for (const migration of migrations) {
      statements.push(...await applyMigration(db, migration, dryRun, log));
    }
    return { statements, dryRun };
  } finally {
    await releaseLock(db);
  }
}
