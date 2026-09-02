/**
 * Stratul de conexiune: opțiunile pool-ului și adaptorul spre runner.
 *
 * ## Ce e afirmație pe CONFIGURAȚIE și ce e afirmație pe EFECT
 *
 * Testele de mai jos care privesc opțiunile pool-ului sunt afirmații pe ce
 * CEREM driverului, nu pe ce face el. Fără MariaDB nu se poate mai mult, și e
 * scris aici ca să nu fie citit ca mai mult. Ce apără totuși e real: fiecare
 * opțiune de mai jos a fost aleasă împotriva unui mod de eșec concret, iar o
 * ștergere accidentală la un refactor n-ar produce nicio eroare — doar
 * purtarea implicită, tăcut.
 *
 * Adaptorul (`queryableDb`) se testează pe efect: i se dă un dublu și se
 * verifică ce face cu ce primește.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildPoolOptions, closePool, getPool, queryableDb } from "../lib/db";
import { readDbConfig } from "../lib/env";
import { SchemaGuardError } from "../lib/schema-guard";
import type { Pool, Queryable } from "../lib/db";
import type { SchemaGuardResult } from "../lib/schema-guard";

const ENV = {
  AGGREGATOR_DB_USER: "u",
  AGGREGATOR_DB_PASSWORD: "p",
  AGGREGATOR_DB_NAME: "d",
};

test("pool-ul e mic, mărginit, și NU calculat din max_connections", () => {
  // `max_connections = 2000` e limita întregului server MariaDB de pe
  // găzduirea partajată, nu bugetul nostru; `max_user_connections` nu a fost
  // măsurată. Un pool „generos, avem 2000" produce erori de conectare pe care
  // nimeni nu le mai leagă de o cifră scrisă cu luni în urmă.
  const options = buildPoolOptions(readDbConfig(ENV));
  assert.equal(options.connectionLimit, 8);
  assert.ok((options.connectionLimit as number) <= 64);
});

test("coada e mărginită: o bază împotmolită dă erori, nu OOM", () => {
  // `queueLimit: 0` e implicitul lui mysql2 și înseamnă nemărginit. Cu el, o
  // bază care nu răspunde face coada să crească până când procesul moare fără
  // să spună de ce.
  const options = buildPoolOptions(readDbConfig(ENV));
  assert.notEqual(options.queueLimit, 0);
  assert.equal(typeof options.queueLimit, "number");
});

test("datele nu se convertesc în Date, iar BIGINT vine ca șir", () => {
  // `dateStrings` lipsă: mysql2 convertește DATETIME folosind fusul PROCESULUI,
  // iar coloanele noastre țin UTC — fiecare timp citit ar fi mutat tăcut cu
  // câteva ore pe o gazdă din alt fus.
  //
  // `bigNumberStrings` lipsă (dar `supportBigNumbers` pus): tipul lui
  // `source_id` ar depinde de MĂRIME — număr sub 2^53, șir peste. Un bug care
  // apare o dată, peste ani.
  const options = buildPoolOptions(readDbConfig(ENV));
  assert.equal(options.dateStrings, true);
  assert.equal(options.supportBigNumbers, true);
  assert.equal(options.bigNumberStrings, true);
});

test("`multipleStatements` rămâne oprit", () => {
  // Cu el pornit, un `;` strecurat într-un parametru devine SQL arbitrar.
  const options = buildPoolOptions(readDbConfig(ENV));
  assert.equal(options.multipleStatements, false);
});

test("pool-ul se creează o singură dată, oricâte importuri ar fi", async () => {
  // În dezvoltare, Next.js reîncarcă modulele la fiecare salvare. Cu o
  // variabilă de modul, fiecare reîncărcare ar lăsa în urmă un pool de
  // conexiuni deschise, până când serverul refuză conexiuni noi.
  await closePool();
  let made = 0;
  const fake = (): Pool => {
    made++;
    return {
      async query() { return [[], []]; },
      async end() { /* nimic */ },
      on() { return this; },
    };
  };
  const first = getPool(fake, ENV);
  const second = getPool(fake, ENV);
  assert.equal(made, 1);
  assert.equal(first, second);
  await closePool();
  // După închidere, un pool nou — altfel `closePool` ar lăsa în urmă un obiect
  // închis pe care apelantul următor l-ar primi ca funcțional.
  getPool(fake, ENV);
  assert.equal(made, 2);
  await closePool();
});

test("`all` refuză un rezultat care nu e set de rânduri", async () => {
  // Un DDL sau un UPDATE întorc un antet de rezultat, nu un tablou. Întors ca
  // `[]`, un apelant ar citi „n-am găsit nimic" acolo unde adevărul e „am
  // întrebat altceva decât credeam" — și exact așa ar raporta o gardă
  // „obiectul lipsește" pentru totdeauna.
  const header: Queryable = { async query() { return [{ affectedRows: 1 }, []]; } };
  await assert.rejects(queryableDb(header).all("SELECT 1"), /set de rânduri/);
});

test("`all` întoarce rândurile, `run` nu se uită la ce a întors", async () => {
  const calls: Array<[string, unknown[] | undefined]> = [];
  const q: Queryable = {
    async query(sql, params) { calls.push([sql, params]); return [[{ n: "1" }], []]; },
  };
  const db = queryableDb(q);
  assert.deepEqual(await db.all("SELECT 1", ["x"]), [{ n: "1" }]);
  await db.run("CREATE TABLE t (id INT)");
  assert.deepEqual(calls.map((c) => c[0]), ["SELECT 1", "CREATE TABLE t (id INT)"]);
  assert.deepEqual(calls[0][1], ["x"]);
});

// ---------------------------------------------------------------------------
// Garda de schemă: cine o primește prin `getPool`, și cine n-o primește
// ---------------------------------------------------------------------------

test("`getPool` FĂRĂ `factory` (driverul real) leagă garda de schemă", async () => {
  // Proba pe care restul suitei n-o poate da: `withSchemaGuard` e testat izolat
  // în `tests/schema-guard.test.ts`, dar nimic de acolo dovedește că `getPool`
  // chiar îl pune pe drumul driverului REAL — cel pe care `factory` NU e dat,
  // adică exact drumul pe care merg `lib/auth/context.ts`, ruta de sincronizare
  // și cea de retenție.
  //
  // Fără MariaDB la capăt: pool-ul lui mysql2 e LAZY — `createPool()` nu
  // deschide nicio conexiune —, deci se poate crea pool-ul REAL și totuși nu se
  // atinge rețeaua, cât timp `guardCheck` injectat respinge ÎNAINTE ca vreo
  // interogare să ajungă la `rawPool.query`. Dacă ternarul din `getPool` s-ar
  // inversa sau s-ar șterge, `pool.query` ar fi cel al lui mysql2 direct —
  // fie ar arunca imediat pe opțiuni greșite, fie ar încerca o conexiune reală
  // la `127.0.0.1:3306`, nu s-ar opri cu `SchemaGuardError`.
  await closePool();
  try {
    let checked = 0;
    const pool = getPool(undefined, ENV, async (): Promise<SchemaGuardResult> => {
      checked++;
      return { ok: false, kind: "unknown", detail: "probă — fără MariaDB aici" };
    });
    await assert.rejects(pool.query("SELECT 1"), SchemaGuardError);
    assert.equal(checked, 1, "`getPool` fără factory n-a chemat garda deloc");
  } finally {
    await closePool();
  }
});

test("`getPool` CU `factory` explicit nu trece prin gardă", async () => {
  // Cealaltă jumătate: dublurile de test (toate cele din `tests/*-harness.ts`)
  // dau un `factory`, iar ele n-au nicio schemă de apărat. Dacă garda s-ar
  // aplica și acolo, fiecare test care folosește un asemenea dublu ar trebui
  // să știe să răspundă la interogările ei — ceea ce niciunul nu face azi.
  await closePool();
  try {
    const pool = getPool(() => ({
      async query() { return [[{ n: "1" }], []]; },
      async end() { /* nimic */ },
      on() { return this; },
    }), ENV);
    const [rows] = await pool.query("SELECT 1");
    assert.deepEqual(rows, [{ n: "1" }]);
  } finally {
    await closePool();
  }
});
