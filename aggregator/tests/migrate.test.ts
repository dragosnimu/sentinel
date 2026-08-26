/**
 * Runner-ul de migrații: reluare, reconciliere, verificarea efectului.
 *
 * ## CE AFIRMĂ DUBLUL DE MAI JOS, ȘI CE NU POATE AFIRMA — de citit înainte
 *
 * Testele astea rulează împotriva unui `FakeDb`, fiindcă pe mașina pe care s-au
 * scris nu există MariaDB. Dublul **nu modelează MariaDB** și nu se pretinde
 * echivalent cu ea. Tot ce face e:
 *
 *   * să RĂSPUNDĂ la interogările de gardă și de registru cu ce i se pune în
 *     mână de fiecare test;
 *   * să ȚINĂ MINTE ce SQL a primit, în ordine.
 *
 * Deci ce se dovedește aici e purtarea CODULUI NOSTRU: că nu re-execută o
 * instrucțiune consemnată, că se oprește pe o sumă de control schimbată, că
 * reia de la instrucțiunea la care a murit, că nu consemnează o instrucțiune al
 * cărei efect nu s-a putut confirma. Toate astea sunt decizii scrise în
 * `lib/migrate.ts`, nu proprietăți ale bazei.
 *
 * Ce NU se dovedește, și trebuie verificat pe gazdă:
 *
 *   * că `information_schema.TABLES` / `STATISTICS` / `COLUMNS` / `TRIGGERS` au
 *     coloanele pe care le interogăm;
 *   * că `GET_LOCK` întoarce 1 acolo;
 *   * că DDL-ul din `migrations/0001_core.sql` e acceptat de server.
 *
 * Pentru ultimul există `npm run migrate -- --syntax-check`, care cere chiar
 * serverului să analizeze fiecare instrucțiune.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  Db, MigrationError, applyMigration, bootstrap, discover, guardPresent, migrate,
} from "../lib/migrate";
import { splitStatements } from "../lib/sql-statements";

// ---------------------------------------------------------------------------
// Dublul. Vezi nota de sus: răspunde și înregistrează, nimic altceva.
// ---------------------------------------------------------------------------
type FakeOptions = {
  /** Obiectele care „există" la pornire, ca text de forma "table:instances". */
  present?: Set<string>;
  /** Rândurile din registru: cheie "fișier#index" -> sha256 consemnat. */
  ledger?: Map<string, string>;
  /** Instrucțiunea (după prefix) la care `run` aruncă, o singură dată. */
  failOn?: string;
  /**
   * Ce întoarce GET_LOCK: `true`/`false` = luat/expirat, `null` = eroare,
   * `"no-row"` = un răspuns fără rândul așteptat, un număr = orice altceva.
   * Ultimele două există fiindcă „nu înțeleg răspunsul" nu e permisiune.
   */
  lock?: boolean | null | "no-row" | number;
  /** Ce obiect devine vizibil după fiecare instrucțiune. Declarat de test. */
  appears?: Map<string, string>;
  /** Obiectele care rămân absente chiar și DUPĂ ce instrucțiunea lor a rulat. */
  neverAppears?: Set<string>;
  /**
   * `information_schema` nu răspunde cu nimic — nici „există", nici „lipsește".
   * `"except-bootstrap"` lasă `schema_version` citibilă, ca bootstrap-ul să
   * treacă și orbirea să lovească exact gărzile instrucțiunilor.
   */
  blind?: "all" | "except-bootstrap";
};

class FakeDb implements Db {
  readonly ran: string[] = [];
  readonly asked: string[] = [];
  /** Ce s-a scris efectiv în registru, pe câmpuri. */
  readonly recorded = new Map<string, { verified: unknown; note: unknown; guard: unknown }>();
  readonly present: Set<string>;
  readonly ledger: Map<string, string>;
  private readonly opts: FakeOptions;

  constructor(opts: FakeOptions = {}) {
    this.opts = opts;
    this.present = new Set(opts.present ?? []);
    this.ledger = new Map(opts.ledger ?? []);
  }

  async all(sql: string, params: unknown[] = []): Promise<Record<string, unknown>[]> {
    this.asked.push(sql);
    if (sql.includes("GET_LOCK")) {
      // `??` ar înghiți `null`, care e chiar valoarea de probat.
      const lock = this.opts.lock === undefined ? true : this.opts.lock;
      if (lock === "no-row") return [];
      if (typeof lock === "number") return [{ got: lock }];
      return [{ got: lock === null ? null : lock ? 1 : 0 }];
    }
    if (sql.includes("RELEASE_LOCK")) return [{ released: 1 }];
    if (sql.includes("FROM schema_version")) {
      const file = String(params[0]);
      const rows: Record<string, unknown>[] = [];
      for (const [key, sha] of this.ledger) {
        const [f, idx] = key.split("#");
        // Șiruri, nu numere: cu `bigNumberStrings` driverul chiar întoarce
        // șiruri, iar codul nu are voie să se bazeze pe tip.
        if (f === file) rows.push({ stmt_index: idx, stmt_sha256: sha });
      }
      return rows;
    }
    if (sql.includes("information_schema.")) {
      const blind = this.opts.blind;
      // Un răspuns gol e „nu știu": exact ce vede codul când vederea nu se
      // poate citi. Nu se întoarce `{n: 0}` — aia ar fi „lipsește".
      if (blind === "all") return [];
      if (blind === "except-bootstrap" && params[0] !== "schema_version") return [];
    }
    if (sql.includes("information_schema.TABLES")) {
      return [{ n: this.present.has(`table:${params[0]}`) ? "1" : "0" }];
    }
    if (sql.includes("information_schema.STATISTICS")) {
      return [{ n: this.present.has(`index:${params[0]}.${params[1]}`) ? "1" : "0" }];
    }
    if (sql.includes("information_schema.COLUMNS")) {
      return [{ n: this.present.has(`column:${params[0]}.${params[1]}`) ? "1" : "0" }];
    }
    if (sql.includes("information_schema.TRIGGERS")) {
      return [{ n: this.present.has(`trigger:${params[0]}`) ? "1" : "0" }];
    }
    throw new Error(`FakeDb: interogare neprevăzută: ${sql}`);
  }

  async run(sql: string, params: unknown[] = []): Promise<void> {
    if (sql.startsWith("INSERT INTO schema_version")) {
      this.ledger.set(`${params[0]}#${params[1]}`, String(params[2]));
      // Parametrii ÎNTREGI, nu doar suma: `verified` e o decizie, iar un test
      // care nu se poate uita la ea nu o poate apăra.
      this.recorded.set(`${params[0]}#${params[1]}`,
                        { verified: params[4], note: params[5], guard: params[3] });
      this.ran.push(`RECORD ${params[0]}#${params[1]}`);
      return;
    }
    if (this.opts.failOn && sql.startsWith(this.opts.failOn)) {
      this.opts.failOn = undefined;
      this.ran.push(`FAIL ${sql}`);
      throw new Error("serverul a refuzat instrucțiunea");
    }
    this.ran.push(sql);
    // Efectul pe care îl imităm: o instrucțiune care a rulat face obiectul ei
    // vizibil. Care obiect anume nu se ghicește din SQL — testul îl declară.
    const appear = (this.opts.appears ?? APPEARS).get(sql);
    if (appear && !(this.opts.neverAppears ?? new Set()).has(appear)) {
      this.present.add(appear);
    }
  }
}

/**
 * Ce obiect apare după fiecare instrucțiune de probă.
 *
 * Declarat aici, la încărcarea modulului, NU dedus din SQL: un dublu care ar
 * parsa SQL ar fi al doilea parser de întreținut, iar acordul lui cu MariaDB ar
 * fi tot o presupunere. Și nu populat din interiorul testelor — o hartă
 * completată lateral face ca un test să depindă de altul care a rulat înaintea
 * lui, iar rulat singur pică.
 */
const APPEARS = new Map<string, string>([
  ["CREATE TABLE IF NOT EXISTS schema_version (id INT)", "table:schema_version"],
  ...Array.from({ length: 12 }, (_, k) => k + 1).map(
    (i) => [`CREATE TABLE t${i} (id INT)`, `table:t${i}`] as [string, string]),
]);

function fixture(dir: string, file: string, body: string): void {
  writeFileSync(path.join(dir, file), body, { encoding: "utf8" });
}

function tmp(): string {
  return mkdtempSync(path.join(tmpdir(), "agg-migrate-"));
}

const BOOTSTRAP_BODY =
  "-- @guard table schema_version\nCREATE TABLE IF NOT EXISTS schema_version (id INT);\n";

/** Douăsprezece instrucțiuni, ca în eșecul pe care runner-ul îl previne. */
function twelve(): string {
  let body = "";
  for (let i = 1; i <= 12; i++) {
    body += `-- @guard table t${i}\nCREATE TABLE t${i} (id INT);\n`;
  }
  return body;
}

// ---------------------------------------------------------------------------

test("o migrație moartă la instrucțiunea 7 din 12 reia de la 7, nu de la 1", async () => {
  // ESTE eșecul pentru care runner-ul ăsta există. Cu înregistrare pe FIȘIER,
  // rularea următoare ori reia de la 1 și moare pe „tabela există deja" —
  // migrație blocată —, ori sare la fișierul următor și lasă cinci
  // instrucțiuni neaplicate, ceea ce se descoperă peste săptămâni ca o coloană
  // lipsă.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", twelve());

  const first = new FakeDb({ failOn: "CREATE TABLE t7 " });
  await assert.rejects(migrate(first, { dir, log: () => {} }));
  assert.equal(first.ledger.size, 6, "primele șase trebuie consemnate");

  // A doua rulare, pe aceeași bază.
  const second = new FakeDb({ present: first.present, ledger: first.ledger });
  const report = await migrate(second, { dir, log: () => {} });

  const created = second.ran.filter((s) => s.startsWith("CREATE TABLE t"));
  assert.deepEqual(created, [7, 8, 9, 10, 11, 12].map((i) => `CREATE TABLE t${i} (id INT)`),
                   "s-au re-rulat instrucțiuni deja aplicate");
  assert.equal(report.statements.filter((s) => s.outcome === "skipped").length, 6);
  assert.equal(report.statements.filter((s) => s.outcome === "applied").length, 6);
});

test("obiectul creat dar neconsemnat se reconciliază, nu se re-rulează", async () => {
  // Fereastra reală: DDL-ul face commit, apoi se scrie rândul de registru. O
  // cădere între ele lasă tabela creată și neconsemnată. Fără reconciliere,
  // rularea următoare ar re-rula `CREATE TABLE` și ar muri.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", twelve());

  const db = new FakeDb({ present: new Set(["table:t1", "table:t2"]) });
  const report = await migrate(db, { dir, log: () => {} });

  assert.equal(report.statements.filter((s) => s.outcome === "reconciled").length, 2);
  assert.ok(!db.ran.includes("CREATE TABLE t1 (id INT)"), "t1 a fost re-rulată");
  assert.equal(db.ledger.get("0001_core.sql#1") !== undefined, true);
});

test("o instrucțiune care a rulat fără eroare dar al cărei obiect NU apare " +
     "oprește migrația și nu se consemnează", async () => {
  // Chiar tiparul din CLAUDE.md: codul de retur nu e dovadă de efect.
  // Consemnată, instrucțiunea n-ar mai fi rulată niciodată, iar tabela ar
  // lipsi pentru totdeauna dintr-o bază despre care registrul spune că e la zi.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", twelve());

  const db = new FakeDb({ neverAppears: new Set(["table:t3"]) });
  await assert.rejects(migrate(db, { dir, log: () => {} }),
                       (err: unknown) => err instanceof MigrationError &&
                                         /tot lipsește/.test((err as Error).message));
  assert.equal(db.ledger.has("0001_core.sql#3"), false,
               "instrucțiunea neconfirmată a fost consemnată");
  assert.equal(db.ledger.size, 2);
});

test("o instrucțiune consemnată al cărei text s-a schimbat oprește totul", async () => {
  // Două instalări care aplică fișiere diferite sub același număr diverg tăcut.
  // Aici se oprește, cu ambele sume în mesaj.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", "-- @guard table t1\nCREATE TABLE t1 (id INT);\n");

  const db = new FakeDb({ ledger: new Map([["0001_core.sql#1", "a".repeat(64)]]) });
  await assert.rejects(migrate(db, { dir, log: () => {} }),
                       (err: unknown) => err instanceof MigrationError &&
                                         /imuabile/.test((err as Error).message));
});

test("`--dry-run` nu scrie nimic, nici măcar registrul", async () => {
  // Comanda pe care o rulează cineva ca să afle ce s-ar întâmpla, nu ca să facă
  // să se întâmple.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", twelve());

  const db = new FakeDb({ present: new Set(["table:schema_version"]) });
  const report = await migrate(db, { dryRun: true, dir, log: () => {} });

  assert.equal(report.statements.length, 12);
  assert.ok(report.statements.every((s) => s.outcome === "pending"));
  assert.deepEqual(db.ran, [], `dry-run a executat: ${db.ran.join(" | ")}`);
  assert.equal(db.ledger.size, 0);
});

test("`--dry-run` fără registru spune că nu poate ști, în loc să-l creeze", async () => {
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", twelve());
  const db = new FakeDb();
  await assert.rejects(migrate(db, { dryRun: true, dir, log: () => {} }),
                       (err: unknown) => err instanceof MigrationError &&
                                         /schema_version/.test((err as Error).message));
  assert.deepEqual(db.ran, []);
});

test("fără lacăt, nu se aplică nimic", async () => {
  // Două rulări simultane pot trece amândouă de aceeași gardă și pot executa
  // amândouă `CREATE TABLE`; a doua moare, iar operatorul rămâne cu o migrație
  // pe jumătate și un mesaj care nu spune de ce.
  //
  // Se probează patru răspunsuri, nu două. `0` și `NULL` singure nu deosebesc
  // regula corectă („doar 1 înseamnă luat") de una permisivă („doar 0 înseamnă
  // refuzat"): în JavaScript `Number(null)` E 0, deci un `=== 0` scris din
  // greșeală ar refuza și `NULL`, iar proba ar trece verde peste o regulă care
  // acceptă orice altă valoare — inclusiv un răspuns fără coloana așteptată.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", twelve());

  for (const lock of [false, null, "no-row" as const, 2]) {
    const db = new FakeDb({ lock });
    await assert.rejects(migrate(db, { dir, log: () => {} }),
                         (err: unknown) => err instanceof MigrationError &&
                                           /lacăt/.test((err as Error).message));
    assert.deepEqual(db.ran, [], `lock=${String(lock)} a executat ceva`);
  }
});

test("bootstrap-ul se dovedește din information_schema, nu din codul de retur", async () => {
  // `CREATE TABLE IF NOT EXISTS` iese cu succes și când n-a creat nimic. Fără
  // registru nu se poate consemna nimic, deci nu se aplică nimic — iar asta
  // trebuie spus, nu presupus.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  const db = new FakeDb({ neverAppears: new Set(["table:schema_version"]) });
  await assert.rejects(bootstrap(db, dir),
                       (err: unknown) => err instanceof MigrationError &&
                                         /information_schema/.test((err as Error).message));
});

test("gărzile filtrează pe DATABASE(), altfel o tabelă din altă bază le păcălește", async () => {
  // Pe găzduire partajată, `information_schema` e la nivel de INSTANȚĂ. Fără
  // filtru, o tabelă `instances` a altcuiva ar face garda să spună „există",
  // instrucțiunea s-ar sări, registrul ar consemna-o aplicată, iar baza noastră
  // ar rămâne fără ea. E o aserțiune pe interogarea TRIMISĂ — nu pe efectul ei,
  // fiindcă efectul îl poate arăta doar un server.
  const db = new FakeDb();
  await guardPresent(db, { kind: "table", table: "instances" });
  await guardPresent(db, { kind: "index", table: "audit_entries", name: "ix_a" });
  await guardPresent(db, { kind: "column", table: "instances", name: "label" });
  await guardPresent(db, { kind: "trigger", name: "t_no_update" });
  assert.equal(db.asked.length, 4);
  for (const sql of db.asked) {
    assert.ok(sql.includes("DATABASE()"), sql);
  }
  // Triggerele se filtrează pe TRIGGER_SCHEMA; `TABLE_SCHEMA` acolo ar fi altă
  // coloană, iar potrivirea ar fi o coincidență.
  assert.ok(db.asked[3].includes("TRIGGER_SCHEMA = DATABASE()"), db.asked[3]);
});

test("un răspuns de gardă fără rânduri e „nu știu”, nu „lipsește”", async () => {
  // Tratat ca „lipsește", ar re-rula o instrucțiune deja aplicată; tratat ca
  // „există", ar sări una neaplicată. Ambele sunt greșite, deci a treia
  // valoare trebuie să existe.
  const db: Db = {
    async all() { return []; },
    async run() { /* nimic */ },
  };
  assert.equal(await guardPresent(db, { kind: "table", table: "x" }), null);

  const nullish: Db = {
    async all() { return [{ n: null }]; },
    async run() { /* nimic */ },
  };
  assert.equal(await guardPresent(nullish, { kind: "table", table: "x" }), null);
});

test("`guard none` se consemnează cu verified=0, iar o gardă confirmată cu 1", async () => {
  // Coloana `verified` E decizia: „a rulat" și „e dovedit acolo" nu au voie să
  // arate la fel într-un registru, altfel nimeni nu mai poate spune, luni mai
  // târziu, ce anume a fost confirmat. O versiune anterioară a testului ăstuia
  // se uita doar la eticheta din raport (`outcome === "ran"`) și la SQL-ul
  // executat; scris `verified = 1` peste `guard none`, trecea verde.
  const stmts = splitStatements(
    "-- @guard none SET nu creează obiecte\nSET @x = 1;\n" +
    "-- @guard table t1\nCREATE TABLE t1 (id INT);\n", "0001_core.sql");
  const db = new FakeDb();
  const reports = await applyMigration(
    db, { file: "0001_core.sql", version: 1, name: "core", statements: stmts },
    false, () => {});

  assert.deepEqual(reports.map((r) => r.outcome), ["ran", "applied"]);
  assert.ok(db.ran.includes("SET @x = 1"));

  assert.equal(db.recorded.get("0001_core.sql#1")?.verified, 0,
               "`guard none` a fost consemnată ca dovedită");
  assert.equal(db.recorded.get("0001_core.sql#2")?.verified, 1,
               "o gardă confirmată a fost consemnată ca NEdovedită");
  // Și reconcilierea: obiectul era acolo, deci e dovedit — dar se vede din
  // `note` că nu noi l-am creat acum.
  const second = new FakeDb({ present: new Set(["table:t1"]) });
  await applyMigration(
    second, { file: "0001_core.sql", version: 1, name: "core",
              statements: splitStatements("-- @guard table t1\nCREATE TABLE t1 (id INT);\n",
                                          "0001_core.sql") },
    false, () => {});
  assert.equal(second.recorded.get("0001_core.sql#1")?.verified, 1);
  assert.equal(second.recorded.get("0001_core.sql#1")?.note, "reconciled");
});

test("o instrucțiune CONSEMNATĂ al cărei obiect a dispărut oprește rularea", async () => {
  // Drumul parcurs la FIECARE rulare de aici încolo, și cel pe care registrul
  // era crezut pe cuvânt. Scenariul e la o comandă distanță: triggerele fac
  // orice rând de probă din `audit_entries` permanent, deci singurul mod de a
  // curăța unul e `DROP TABLE audit_entries`. Fără verificarea asta, registrul
  // păstrează instrucțiunile, rularea următoare tipărește `skipped`, iar tabela
  // nu se mai întoarce niciodată — cu registrul spunând că schema e la zi.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", twelve());

  const first = new FakeDb();
  await migrate(first, { dir, log: () => {} });
  assert.equal(first.ledger.size, 12);

  // Cineva șterge două obiecte. Registrul rămâne intact.
  const after = new FakeDb({ present: first.present, ledger: first.ledger });
  after.present.delete("table:t3");
  after.present.delete("table:t9");

  const err = await migrate(after, { dir, log: () => {} }).then(
    () => null, (e: unknown) => e as Error);
  assert.ok(err instanceof MigrationError, "rularea nu s-a oprit");
  assert.match(err.message, /ABSENTE din baz/);
  // Toate divergențele, nu prima: cine tocmai a pierdut o tabelă vrea lista.
  assert.match(err.message, /#3 /);
  assert.match(err.message, /#9 /);

  // Și NU se repară automat: recreată goală, arhiva ar reporni ingestia de la
  // un cursor mult mai avansat, deci rândurile pierdute n-ar mai reveni.
  assert.ok(!after.ran.some((s) => s.startsWith("CREATE TABLE t3")),
            `a re-creat automat: ${after.ran.join(" | ")}`);
});

test("o migrație cu `guard none` se poate rula A DOUA OARĂ", async () => {
  // Eșecul pe care îl previne, și motivul pentru care testul ăsta trebuie să
  // existe ÎNAINTE ca cineva să folosească facilitatea:
  //
  // `guardPresent` întoarce `null` pentru `guard none` — corect, nu e nimic de
  // citit. Dar `auditLedger` tratează `null` drept „nu pot citi din
  // information_schema" și OPREȘTE rularea. Fără scutirea explicită de la
  // linia aia, prima migrație care folosește `guard none` — un `INSERT`, un
  // `SET`, orice al cărui efect nu se vede în `information_schema` — trece o
  // dată, iar de la a doua rulare încolo TOATE migrațiile se opresc definitiv,
  // cu un mesaj care acuză baza de date.
  //
  // Azi niciuna dintre cele șase instrucțiuni livrate n-are `guard none`, deci
  // capcana e nearmată. E armată de E3, care e chiar cazul pentru care a fost
  // scrisă ramura.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql",
          "-- @guard table t1\nCREATE TABLE t1 (id INT);\n" +
          "-- @guard none SET nu creează obiecte vizibile în information_schema\n" +
          "SET @x = 1;\n");

  const first = new FakeDb();
  const one = await migrate(first, { dir, log: () => {} });
  assert.deepEqual(one.statements.map((s) => s.outcome), ["applied", "ran"]);

  // A doua rulare, pe aceeași bază. Nimic nu s-a schimbat.
  const second = new FakeDb({ present: first.present, ledger: first.ledger });
  const two = await migrate(second, { dir, log: () => {} });
  assert.deepEqual(two.statements.map((s) => s.outcome), ["skipped", "skipped"]);
  // Bootstrap-ul rulează la fiecare invocare, prin proiectare (`IF NOT EXISTS`
  // + dovada din information_schema), deci se scoate din comparație. Ce nu are
  // voie să se repete sunt instrucțiunile MIGRAȚIEI.
  const rerun = second.ran.filter((s) => !s.startsWith("CREATE TABLE IF NOT EXISTS"));
  assert.deepEqual(rerun, [], `a re-executat ceva: ${rerun.join(" | ")}`);

  // Și a treia, fiindcă „se oprește definitiv" înseamnă de la a doua încolo.
  const third = new FakeDb({ present: second.present, ledger: second.ledger });
  const three = await migrate(third, { dir, log: () => {} });
  assert.deepEqual(three.statements.map((s) => s.outcome), ["skipped", "skipped"]);
});

test("`--dry-run` vede divergența, și tot nu scrie nimic", async () => {
  // E prima comandă pe care o rulează cineva pe o bază de producție, tocmai
  // fiindcă nu schimbă nimic. Dacă ea raportează liniștit `pending` peste o
  // schemă din care lipsește o tabelă, operatorul află abia la aplicare — adică
  // exact atunci când e cel mai scump.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", twelve());

  const first = new FakeDb();
  await migrate(first, { dir, log: () => {} });

  const after = new FakeDb({ present: first.present, ledger: first.ledger });
  after.present.delete("table:t5");
  const before = after.ran.length;

  await assert.rejects(migrate(after, { dryRun: true, dir, log: () => {} }),
                       (err: unknown) => err instanceof MigrationError &&
                                         /ABSENTE din baz/.test((err as Error).message));
  assert.equal(after.ran.length, before, `dry-run a scris: ${after.ran.join(" | ")}`);
});

test("dacă information_schema nu se poate citi, o instrucțiune consemnată " +
     "oprește rularea și se spune că nu s-a putut CITI", async () => {
  // „Lipsește" și „nu pot citi" opresc amândouă, dar operatorul trebuie să
  // știe pe care o are: prima cere o restaurare, a doua cere o bază care
  // răspunde.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", "-- @guard table t1\nCREATE TABLE t1 (id INT);\n");

  const db = new FakeDb();
  await migrate(db, { dir, log: () => {} });

  const blind = new FakeDb({ present: db.present, ledger: db.ledger,
                             blind: "except-bootstrap" });
  await assert.rejects(migrate(blind, { dir, log: () => {} }),
                       (err: unknown) => err instanceof MigrationError &&
                                         /NU SE POT CITI/.test((err as Error).message));
});

test("dacă garda nu se poate citi, instrucțiunea nouă NU se execută", async () => {
  // Tratat ca „lipsește", DDL-ul ar rula pe o bază despre care nu știm nimic.
  // Verificarea de după l-ar opri, dar abia DUPĂ ce a rulat — iar pe MariaDB
  // DDL-ul face commit, deci „după" e prea târziu.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", twelve());

  const db = new FakeDb({ blind: "except-bootstrap" });
  await assert.rejects(migrate(db, { dir, log: () => {} }),
                       (err: unknown) => err instanceof MigrationError &&
                                         /nu știu/.test((err as Error).message));
  assert.ok(!db.ran.some((s) => s.startsWith("CREATE TABLE t")),
            `a executat DDL pe o presupunere: ${db.ran.join(" | ")}`);
});

test("un fișier de migrație cu numele greșit e o eroare, nu un fișier sărit", async () => {
  // Un fișier care nu se aplică niciodată se descoperă abia când lipsește o
  // coloană din el.
  //
  // Directorul are ȘI o migrație validă, iar mesajul se potrivește pe nume.
  // Fără amândouă, testul trecea din alt motiv: cu doar bootstrap + fișierul
  // prost numit, sărirea tăcută a fișierului lăsa lista goală, iar `discover`
  // arunca „nicio migrație" — aceeași clasă de eroare, altă cauză, deci o
  // aserțiune care nu deosebea reparat de stricat.
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", "-- @guard table t1\nCREATE TABLE t1 (id INT);\n");
  fixture(dir, "core.sql", "-- @guard table t2\nCREATE TABLE t2 (id INT);\n");
  assert.throws(() => discover(dir),
                (err: unknown) => err instanceof MigrationError &&
                                  /core\.sql: numele nu are forma/.test((err as Error).message));
});

test("două fișiere cu același număr de versiune sunt o eroare", () => {
  const dir = tmp();
  fixture(dir, "0000_bootstrap.sql", BOOTSTRAP_BODY);
  fixture(dir, "0001_core.sql", "-- @guard table t1\nCREATE TABLE t1 (id INT);\n");
  fixture(dir, "0001_altceva.sql", "-- @guard table t2\nCREATE TABLE t2 (id INT);\n");
  assert.throws(() => discover(dir), MigrationError);
});
