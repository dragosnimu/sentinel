/**
 * Garda de schemă: `checkSchemaGuard` (logica pură) și `withSchemaGuard`
 * (cablarea pe pool, din `lib/db.ts`).
 *
 * ## Ce dovedesc testele astea, și ce nu
 *
 * `checkSchemaGuard` rulează împotriva unui `FakeDb` care doar RĂSPUNDE la
 * interogările de gardă și de registru, exact ca dublul din `tests/migrate.test.ts`
 * — vezi capul aceluia pentru ce nu se poate afirma fără MariaDB la capăt
 * (`information_schema` chiar are coloanele cerute, șamd.).
 *
 * `withSchemaGuard` se probează cu un pool fals minimal — nu mysql2 — fiindcă
 * proprietatea de verificat (memoizare, care refuzuri se țin minte și care nu)
 * e a ÎNVELIȘULUI, nu a driverului.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  SchemaGuardError, checkSchemaGuard, schemaGuardMessage,
} from "../lib/schema-guard";
import { withSchemaGuard } from "../lib/db";
import type { Db } from "../lib/migrate";
import type { SchemaGuardResult } from "../lib/schema-guard";
import type { Pool } from "../lib/db";

// ---------------------------------------------------------------------------
// checkSchemaGuard — fixtures
// ---------------------------------------------------------------------------

function tmp(): string {
  return mkdtempSync(path.join(tmpdir(), "agg-schema-guard-"));
}

function fixture(dir: string, file: string, body: string): void {
  writeFileSync(path.join(dir, file), body, { encoding: "utf8" });
}

/** O migrație cu DOUĂ instrucțiuni, ca „lipsește a doua" să se poată deosebi
 *  de „lipsește tot fișierul". */
const TWO_STATEMENTS =
  "-- @guard table t1\nCREATE TABLE t1 (id INT);\n" +
  "-- @guard table t2\nCREATE TABLE t2 (id INT);\n";

type Script = {
  /** `1`/`0` = tabela schema_version există/lipsește; `"blind"` = niciun
   *  rând întors, ca un `information_schema` care nu răspunde. */
  schemaVersionTable?: 1 | 0 | "blind";
  /** Cheie "fișier#index" -> sha256 CONSEMNAT, ca într-un registru real. */
  ledger?: Map<string, string>;
};

class FakeDb implements Db {
  readonly asked: string[] = [];
  constructor(private readonly script: Script) {}

  async all(sql: string, params: unknown[] = []): Promise<Record<string, unknown>[]> {
    this.asked.push(sql);
    if (sql.includes("information_schema.TABLES")) {
      const present = this.script.schemaVersionTable ?? 1;
      if (present === "blind") return [];
      return [{ n: String(present) }];
    }
    if (sql.includes("FROM schema_version")) {
      const file = String(params[0]);
      const rows: Record<string, unknown>[] = [];
      for (const [key, sha] of this.script.ledger ?? []) {
        const [f, idx] = key.split("#");
        if (f === file) rows.push({ stmt_index: idx, stmt_sha256: sha });
      }
      return rows;
    }
    throw new Error(`FakeDb: interogare neprevăzută în checkSchemaGuard: ${sql}`);
  }

  async run(): Promise<void> {
    throw new Error("checkSchemaGuard n-are voie să scrie nimic");
  }
}

/** Suma de control reală a instrucțiunii `n` din `TWO_STATEMENTS`, citită prin
 *  `discover()` — nu recalculată aici, ca sha256-ul din test să nu poată
 *  diverge de cel pe care runner-ul chiar îl scrie. */
async function realSha(dir: string, file: string, index: number): Promise<string> {
  const { discover } = await import("../lib/migrate");
  const [migration] = discover(dir).filter((m) => m.file === file);
  const stmt = migration.statements.find((s) => s.index === index);
  if (!stmt) throw new Error(`nicio instrucțiune #${index} în ${file}`);
  return stmt.sha256;
}

// ---------------------------------------------------------------------------
// checkSchemaGuard
// ---------------------------------------------------------------------------

test("schema la zi: garda trece și numără instrucțiunile confirmate", async () => {
  // Falsă dacă garda ar refuza o schemă corectă — ar transforma orice deploy
  // normal într-o pană totală.
  const dir = tmp();
  fixture(dir, "0001_core.sql", TWO_STATEMENTS);
  const sha1 = await realSha(dir, "0001_core.sql", 1);
  const sha2 = await realSha(dir, "0001_core.sql", 2);

  const db = new FakeDb({
    schemaVersionTable: 1,
    ledger: new Map([["0001_core.sql#1", sha1], ["0001_core.sql#2", sha2]]),
  });
  const result = await checkSchemaGuard(db, dir);
  assert.deepEqual(result, { ok: true, appliedStatements: 2 });
});

test("bază complet goală: schema_version lipsește, nu e «schemă veche»", async () => {
  // Eșecul de deosebit: un mesaj de „rulează migrate" pe o gazdă la prima
  // instalare vs. unul de „ai uitat o migrație" pe o gazdă în producție sunt
  // răspunsuri diferite pentru operator. Amestecate, cineva caută o migrație
  // lipsă pe o instalare care pur și simplu n-a pornit încă.
  const dir = tmp();
  fixture(dir, "0001_core.sql", TWO_STATEMENTS);

  const db = new FakeDb({ schemaVersionTable: 0 });
  const result = await checkSchemaGuard(db, dir);
  assert.deepEqual(result, { ok: false, kind: "not-installed" });
});

test("o migrație neaplicată: outdated, cu fișierul și indexul exact", async () => {
  // ESTE eșecul din §Partea 1: cod care cere o coloană pe care schema n-o are
  // încă. Falsă dacă garda ar trece cu instrucțiuni lipsă din registru, sau
  // dacă n-ar spune CARE migrație lipsește.
  const dir = tmp();
  fixture(dir, "0001_core.sql", TWO_STATEMENTS);
  const sha1 = await realSha(dir, "0001_core.sql", 1);

  const db = new FakeDb({
    schemaVersionTable: 1,
    ledger: new Map([["0001_core.sql#1", sha1]]), // #2 lipsește
  });
  const result = await checkSchemaGuard(db, dir);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.kind, "outdated");
  if (result.kind !== "outdated") throw new Error("unreachable");
  assert.deepEqual(result.missing, [{ migration: "0001_core.sql", index: 2 }]);
  assert.deepEqual(result.changed, []);
});

test("information_schema orb: unknown, nu «bine» și nu «lipsește»", async () => {
  // A treia stare, distinctă de primele două: „nu se poate ști" nu are voie
  // să treacă drept „e în regulă" — regula din CLAUDE.md, aplicată aici.
  const dir = tmp();
  fixture(dir, "0001_core.sql", TWO_STATEMENTS);

  const db = new FakeDb({ schemaVersionTable: "blind" });
  const result = await checkSchemaGuard(db, dir);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.kind, "unknown");
});

test("instrucțiune consemnată cu altă sumă de control: istorie rescrisă, " +
     "raportată separat de cea neaplicată", async () => {
  const dir = tmp();
  fixture(dir, "0001_core.sql", TWO_STATEMENTS);
  const sha2 = await realSha(dir, "0001_core.sql", 2);

  const db = new FakeDb({
    schemaVersionTable: 1,
    ledger: new Map([
      ["0001_core.sql#1", "0".repeat(64)], // sumă falsă: fișierul a fost editat
      ["0001_core.sql#2", sha2],
    ]),
  });
  const result = await checkSchemaGuard(db, dir);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.kind, "outdated");
  if (result.kind !== "outdated") throw new Error("unreachable");
  assert.deepEqual(result.missing, []);
  assert.deepEqual(result.changed, [{ migration: "0001_core.sql", index: 1 }]);
});

test("mesajul deosebește «neinstalat» de «învechit» de «necunoscut»", () => {
  // Falsă dacă cele trei mesaje s-ar suprapune — un operator care citește
  // jurnalul trebuie să știe dacă rulează `npm run migrate` pentru prima oară
  // sau ca să prindă din urmă codul.
  const notInstalled = schemaGuardMessage({ ok: false, kind: "not-installed" });
  const unknown = schemaGuardMessage({ ok: false, kind: "unknown", detail: "n-a răspuns" });
  const outdated = schemaGuardMessage({
    ok: false, kind: "outdated",
    missing: [{ migration: "0002_x.sql", index: 3 }], changed: [],
  });

  assert.match(notInstalled, /nu e instalată/);
  assert.match(unknown, /nu se poate verifica/);
  assert.match(outdated, /în urma codului/);
  assert.match(outdated, /0002_x\.sql/);
  assert.doesNotMatch(unknown, /\bbine\b/i);
  // Cele trei mesaje chiar sunt distincte — nu doar etichetele din `kind`.
  assert.notEqual(notInstalled, unknown);
  assert.notEqual(unknown, outdated);
  assert.notEqual(notInstalled, outdated);
});

test("SchemaGuardError poartă rezultatul întreg, netrunchiat", () => {
  const result: SchemaGuardResult = {
    ok: false, kind: "outdated",
    missing: [{ migration: "0003_y.sql", index: 1 }], changed: [],
  };
  const err = new SchemaGuardError(result);
  assert.equal(err.name, "SchemaGuardError");
  assert.equal(err.result, result);
  assert.match(err.message, /0003_y\.sql/);
});

// ---------------------------------------------------------------------------
// withSchemaGuard — memoizarea și ce anume se ține minte
// ---------------------------------------------------------------------------

/** Un pool minimal, doar cât cere interfața `Pool` din `lib/db.ts`. */
function fakeRawPool(): Pool & { queries: Array<[string, unknown[] | undefined]> } {
  const queries: Array<[string, unknown[] | undefined]> = [];
  return {
    queries,
    async query(sql: string, params?: unknown[]) {
      queries.push([sql, params]);
      return [[{ ok: 1 }], []];
    },
    async end() { /* nimic */ },
    on() { return this; },
  };
}

test("prima interogare așteaptă garda; a doua nu o mai cere din nou", async () => {
  // Costul pe care memoizarea îl cumpără: fără ea, fiecare cerere a panoului
  // ar re-parcurge toate migrațiile cunoscute la fiecare interogare.
  const raw = fakeRawPool();
  let checks = 0;
  const check = async (): Promise<SchemaGuardResult> => {
    checks++;
    return { ok: true, appliedStatements: 3 };
  };
  const pool = withSchemaGuard(raw, check);

  await pool.query("SELECT 1");
  await pool.query("SELECT 2");
  assert.equal(checks, 1, "garda a fost cerută de mai multe ori pentru același pool");
  assert.deepEqual(raw.queries.map((q) => q[0]), ["SELECT 1", "SELECT 2"],
                   "interogările reale nu au ajuns la pool-ul brut");
});

test("un refuz REAL (outdated) rămâne refuzat, fără să mai întrebe schema", async () => {
  const raw = fakeRawPool();
  let checks = 0;
  const check = async (): Promise<SchemaGuardResult> => {
    checks++;
    return { ok: false, kind: "outdated",
             missing: [{ migration: "0001_x.sql", index: 1 }], changed: [] };
  };
  const pool = withSchemaGuard(raw, check);

  await assert.rejects(pool.query("SELECT 1"), SchemaGuardError);
  await assert.rejects(pool.query("SELECT 2"), SchemaGuardError);
  assert.equal(checks, 1, "un refuz stabil s-a re-verificat în loc să rămână ținut minte");
  assert.deepEqual(raw.queries, [], "interogări au ajuns la pool-ul brut cât garda refuza");
});

test("«unknown» NU se ține minte: interogarea următoare reîncearcă", async () => {
  // Falsă dacă un blip trecător de rețea la pornire ar bloca definitiv
  // procesul, chiar după ce baza redevine sănătoasă — vezi capul lui
  // `withSchemaGuard` în `lib/db.ts`.
  const raw = fakeRawPool();
  let checks = 0;
  const check = async (): Promise<SchemaGuardResult> => {
    checks++;
    if (checks === 1) return { ok: false, kind: "unknown", detail: "baza nu răspunde acum" };
    return { ok: true, appliedStatements: 5 };
  };
  const pool = withSchemaGuard(raw, check);

  await assert.rejects(pool.query("SELECT 1"), SchemaGuardError);
  await pool.query("SELECT 2");
  assert.equal(checks, 2, "starea «unknown» a fost ținută minte în loc să reîncerce");
  assert.deepEqual(raw.queries.map((q) => q[0]), ["SELECT 2"]);
});

test("o eroare care nu vine de la gardă (bază picată) nu se ține minte", async () => {
  const raw = fakeRawPool();
  let checks = 0;
  const check = async (): Promise<SchemaGuardResult> => {
    checks++;
    if (checks === 1) throw new Error("ECONNREFUSED");
    return { ok: true, appliedStatements: 1 };
  };
  const pool = withSchemaGuard(raw, check);

  await assert.rejects(pool.query("SELECT 1"), /ECONNREFUSED/);
  await pool.query("SELECT 2");
  assert.equal(checks, 2, "o eroare de conectare a fost tratată ca un verdict permanent despre schemă");
});

test("query() reușit deleagă la pool-ul brut, cu SQL și parametrii primiți, " +
     "și întoarce exact ce a răspuns driverul", async () => {
  const raw = fakeRawPool();
  const pool = withSchemaGuard(raw, async () => ({ ok: true, appliedStatements: 0 }));
  const [rows] = await pool.query("SELECT * FROM t WHERE id = ?", [42]);
  assert.deepEqual(raw.queries, [["SELECT * FROM t WHERE id = ?", [42]]]);
  assert.deepEqual(rows, [{ ok: 1 }]);
});

test("on() și end() deleagă direct la pool-ul brut, fără să treacă prin gardă", async () => {
  // Nu sunt interogări de date; gata cu așteptarea, altfel `pool.on(\"connection\", …)`
  // — care se cheamă la CREAREA pool-ului, înainte ca vreo cerere să existe —
  // ar bloca dacă vreodată garda ar fi cerută și acolo.
  const raw = fakeRawPool();
  let endCalled = false;
  raw.end = async () => { endCalled = true; };
  let onCalled = 0;
  raw.on = () => { onCalled++; return raw; };
  // Verificarea nu se cheamă NICIODATĂ aici — dacă `on`/`end` ar aștepta-o,
  // testul ar rămâne agățat, iar `run-tests.mjs` l-ar transforma în test PICAT
  // pe termen, nu într-o suită care atârnă tăcut.
  const pool = withSchemaGuard(raw, () => new Promise(() => { /* nu se rezolvă niciodată */ }));

  pool.on("connection", () => {});
  await pool.end();
  assert.equal(onCalled, 1);
  assert.equal(endCalled, true);
});
