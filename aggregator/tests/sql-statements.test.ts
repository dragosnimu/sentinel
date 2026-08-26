/**
 * Spargerea unui fișier SQL în instrucțiuni.
 *
 * Ce se strică pentru operator dacă modulul ăsta greșește: migrația
 * agregatorului fie moare cu o eroare de sintaxă pe un fișier corect (și atunci
 * baza rămâne pe jumătate creată, iar sincronizarea nu pornește), fie — mai rău
 * — rulează o instrucțiune tăiată în două, care înseamnă altceva decât ce
 * scrie în fișier.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { SqlParseError, splitStatements } from "../lib/sql-statements";

const G = "-- @guard none proba\n";

test("un `;` dintr-un literal NU taie instrucțiunea", () => {
  // Eșecul: corpul triggerului de append-only conține un mesaj de eroare între
  // ghilimele. Tăiat pe primul `;` din el, jumătate ajunge la server ca SQL
  // invalid, iar tabela `audit_entries` rămâne fără protecția care o face
  // append-only — adică fără chiar proprietatea pentru care există agregatorul.
  const stmts = splitStatements(
    `${G}SELECT 'a;b' AS x;\n${G}SELECT 2;\n`, "t.sql");
  assert.equal(stmts.length, 2);
  assert.equal(stmts[0].sql, "SELECT 'a;b' AS x");
  assert.equal(stmts[1].sql, "SELECT 2");
});

test("ghilimeaua dublată nu închide literalul", () => {
  const stmts = splitStatements(`${G}SELECT 'it''s; fine' AS x;\n`, "t.sql");
  assert.equal(stmts.length, 1);
  assert.equal(stmts[0].sql, "SELECT 'it''s; fine' AS x");
});

test("backslash-ul scapă ghilimeaua, ca în MariaDB", () => {
  const stmts = splitStatements(`${G}SELECT 'a\\'; b' AS x;\n`, "t.sql");
  assert.equal(stmts.length, 1);
  assert.ok(stmts[0].sql.includes("; b"), stmts[0].sql);
});

test("un `;` dintr-un comentariu nu produce o instrucțiune", () => {
  const stmts = splitStatements(
    `${G}-- vezi mai jos; și încă ceva\nSELECT 1;\n`, "t.sql");
  assert.equal(stmts.length, 1);
  assert.equal(stmts[0].sql, "SELECT 1");
});

test("`#` e comentariu până la sfârșitul liniei", () => {
  // A doua formă de comentariu din MariaDB. Dacă ar înceta să fie tratată ca
  // atare, un `;` dintr-un comentariu `#` ar tăia instrucțiunea, iar textul
  // comentariului ar pleca spre server ca SQL.
  const stmts = splitStatements(
    `${G}SELECT 1 # nota; cu punct și virgulă\n;\n`, "t.sql");
  assert.equal(stmts.length, 1);
  assert.equal(stmts[0].sql, "SELECT 1");
});

test("două `;` la rând sunt o eroare, nu o instrucțiune goală sărită tăcut", () => {
  // Promisiunea e scrisă în `finish()`: „nu se sare tăcut". Un `;` în plus e
  // aproape sigur o greșeală de editare, iar un rând de registru care nu descrie
  // nimic e mai rău decât o eroare — la reluare nimeni nu mai poate spune ce
  // anume s-a aplicat sub indexul ăla.
  assert.throws(() => splitStatements(`${G}SELECT 1;;\n`, "t.sql"),
                (err: unknown) => err instanceof SqlParseError &&
                                  /goal/.test((err as Error).message));
});

test("backslash-ul NU scapă în interiorul unui identificator între backtick-uri", () => {
  // În MariaDB, `\` nu are înțeles special între backtick-uri: acolo doar
  // dublarea backtick-ului scapă. Tratat ca escape, un identificator care se
  // termină în `\` ar înghiți backtick-ul de închidere, iar restul fișierului
  // ar fi citit ca fiind în interiorul numelui — inclusiv `;`-urile.
  const stmts = splitStatements("-- @guard none proba\nSELECT `a\\` AS x;\n"
                                + "-- @guard none proba\nSELECT 2;\n", "t.sql");
  assert.equal(stmts.length, 2, `s-a înghițit backtick-ul: ${JSON.stringify(stmts.map(s => s.sql))}`);
  assert.equal(stmts[0].sql, "SELECT `a\\` AS x");
  assert.equal(stmts[1].sql, "SELECT 2");
});

test("`--` fără spațiu după el NU e comentariu", () => {
  // Regula MariaDB. Dacă parserul ar trata `1--2` drept comentariu, ar șterge
  // restul liniei dintr-o expresie și ar trimite serverului altceva.
  const stmts = splitStatements(`${G}SELECT 1--2;\n`, "t.sql");
  assert.equal(stmts[0].sql, "SELECT 1--2");
});

test("comentariul devine un spațiu, nu nimic", () => {
  // `SELECT/*x*/1` fără spațiu ar deveni `SELECT1`.
  const stmts = splitStatements(`${G}SELECT/*x*/1;\n`, "t.sql");
  assert.equal(stmts[0].sql, "SELECT 1");
});

test("o instrucțiune fără gardă e o EROARE, nu una fără pre-verificare", () => {
  // Eșecul: la reluarea unei migrații căzute, instrucțiunea fără gardă se
  // re-rulează, moare pe „obiectul există deja", iar migrația rămâne blocată
  // definitiv cu un mesaj care arată ca o problemă de bază de date.
  assert.throws(() => splitStatements("SELECT 1;\n", "t.sql"),
                (err: unknown) => err instanceof SqlParseError &&
                                  /@guard/.test((err as Error).message));
});

test("două gărzi pentru o instrucțiune sunt tot o eroare", () => {
  assert.throws(() => splitStatements(`${G}${G}SELECT 1;\n`, "t.sql"), SqlParseError);
});

test("`DELIMITER` se refuză, nu se ignoră", () => {
  // Eșecul: driverul nu cunoaște directiva. Ignorată, corpul triggerului se
  // taie la primul `;` dinăuntru; „interpretată" de noi, runner-ul și `mysql`
  // ar aplica lucruri diferite din același fișier.
  assert.throws(() => splitStatements("DELIMITER $$\n", "t.sql"),
                (err: unknown) => err instanceof SqlParseError &&
                                  /DELIMITER/.test((err as Error).message));
});

test("comentariul executabil `/*!` se refuză", () => {
  // Tratat ca un comentariu obișnuit, ar ȘTERGE cod pe care serverul l-ar fi
  // executat — o diferență între fișier și bază pe care nimic n-o raportează.
  assert.throws(() => splitStatements(`${G}SELECT /*!40101 1 */ 2;\n`, "t.sql"),
                SqlParseError);
});

test("text după ultimul `;` e o eroare, fiindcă așa arată un fișier trunchiat", () => {
  assert.throws(() => splitStatements(`${G}SELECT 1;\n${G}SELECT 2`, "t.sql"),
                (err: unknown) => err instanceof SqlParseError &&
                                  /neterminat/.test((err as Error).message));
});

test("un fișier fără nicio instrucțiune e o eroare", () => {
  // O migrație goală care trece verde e o migrație care nu s-a aplicat și
  // despre care registrul spune că s-a aplicat.
  assert.throws(() => splitStatements("-- doar comentarii\n", "t.sql"), SqlParseError);
});

test("gărzile se parsează în forme tipizate, iar cele stricate se refuză", () => {
  const ok = splitStatements(
    "-- @guard table instances\nSELECT 1;\n" +
    "-- @guard index audit_entries ix_a\nSELECT 2;\n" +
    "-- @guard column instances label\nSELECT 3;\n" +
    "-- @guard trigger t_no_update\nSELECT 4;\n" +
    "-- @guard none nu creează obiecte\nSELECT 5;\n", "t.sql");
  assert.deepEqual(ok.map((s) => s.guard.kind),
                   ["table", "index", "column", "trigger", "none"]);
  assert.deepEqual(ok[1].guard, { kind: "index", table: "audit_entries", name: "ix_a" });

  for (const bad of ["table", "table a b", "index audit_entries", "trigger",
                     "none", "tabel instances", "table 9nume"]) {
    assert.throws(() => splitStatements(`-- @guard ${bad}\nSELECT 1;\n`, "t.sql"),
                  SqlParseError, `garda "${bad}" ar fi trebuit refuzată`);
  }
});

test("suma de control ignoră comentariile și indentarea, dar nu identificatorii", () => {
  // Eșecul pe care îl previne, în ambele direcții: dacă suma ar prinde
  // comentariile, rescrierea unui comentariu ar bloca migrațiile cu „istorie
  // rescrisă"; dacă ar ignora identificatorii, o coloană redenumită într-o
  // migrație deja aplicată ar trece neobservată, iar două instalări ar
  // diverge tăcut.
  const a = splitStatements(`${G}SELECT   1   AS  x;\n`, "t.sql")[0];
  const b = splitStatements(
    "-- @guard none alt motiv\n/* alt comentariu */\nSELECT 1 AS x;\n", "t.sql")[0];
  assert.equal(a.sha256, b.sha256);

  const c = splitStatements(`${G}SELECT 1 AS y;\n`, "t.sql")[0];
  assert.notEqual(a.sha256, c.sha256);
});

test("spațiile DINĂUNTRUL literalilor rămân neatinse", () => {
  // Normalizarea lor ar schimba datele: mesajul unui trigger, valoarea
  // implicită a unei coloane.
  const s = splitStatements(`${G}SELECT 'a    b' AS x;\n`, "t.sql")[0];
  assert.ok(s.sql.includes("'a    b'"), s.sql);
});

test("indexul și linia identifică instrucțiunea", () => {
  // Fără ele, mesajul unei migrații căzute spune „a eșuat" fără să spună unde,
  // exact în momentul în care cineva caută.
  const stmts = splitStatements(`${G}SELECT 1;\n\n${G}SELECT 2;\n`, "t.sql");
  assert.deepEqual(stmts.map((s) => s.index), [1, 2]);
  // Linia gărzii, nu a cuvântului `SELECT`: garda e primul lucru din
  // intervalul instrucțiunii, și e de unde începe cineva să citească.
  assert.equal(stmts[0].line, 1);
  assert.equal(stmts[1].line, 4);
});
