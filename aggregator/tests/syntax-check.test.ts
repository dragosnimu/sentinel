/**
 * Verificarea de sintaxă: trei verdicte, iar „n-am putut verifica" nu e „bine".
 *
 * Ce se strică pentru operator dacă modulul ăsta greșește: comanda de
 * verificare devine chiar tiparul pe care depozitul ăsta îl păzește — un
 * instrument care raportează „nimic în neregulă" fiindcă nu s-a uitat. Aici
 * asta ar însemna un DDL nevalidat, aplicat pe baza de producție a
 * agregatorului, care moare la jumătate.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ER_UNSUPPORTED_PS, allParsed, classifyPrepareError, syntaxCheck, syntaxExitCode,
} from "../lib/syntax-check";
import { splitStatements } from "../lib/sql-statements";
import type { SyntaxVerdict } from "../lib/syntax-check";
import type { Queryable } from "../lib/db";

test("doar ER_UNSUPPORTED_PS devine „neverificat”", () => {
  // `ER_UNSUPPORTED_PS` e serverul care spune „nu pot pregăti asta" — o limită a
  // LUI, nu un refuz al instrucțiunii noastre. Ce anume intră în categoria asta
  // ține de versiune: pe MariaDB 11.8.8, măsurat pe 15 august 2026, nici măcar
  // `CREATE TRIGGER` nu intră. Clasificarea rămâne corectă și rămâne probată,
  // fiindcă altă versiune o poate readuce.
  assert.equal(classifyPrepareError({ errno: ER_UNSUPPORTED_PS }), "unchecked");
  assert.equal(classifyPrepareError({ code: "ER_UNSUPPORTED_PS" }), "unchecked");
});

test("orice altă eroare cu număr e un REFUZ", () => {
  // O greșeală de sintaxă în DDL trebuie să iasă roșie. Clasificată drept
  // „neverificat", ar arăta la fel ca un trigger — adică s-ar pierde.
  assert.equal(classifyPrepareError({ errno: 1064, message: "syntax error" }), "rejected");
  assert.equal(classifyPrepareError({ errno: 1901 }), "rejected");
});

test("o eroare fără număr e „nu știu”, nu trecere", () => {
  // Conexiune căzută la mijloc, protocol rupt. Nu e nici bună, nici rea.
  assert.equal(classifyPrepareError(new Error("socket hang up")), "unknown");
  assert.equal(classifyPrepareError(undefined), "unknown");
});

test("`allParsed` e fals dacă vreo instrucțiune a rămas neverificată", () => {
  assert.equal(allParsed([{ migration: "a", index: 1, status: "parsed", detail: "" }]), true);
  assert.equal(allParsed([{ migration: "a", index: 1, status: "parsed", detail: "" },
                          { migration: "a", index: 2, status: "unchecked", detail: "" }]),
               false);
  // O listă goală nu e „totul e bine": e „n-am probat nimic".
  assert.equal(allParsed([]), false);
});

test("codul de ieșire: refuzurile pică, `NEVERIFICAT` nu", async () => {
  // `--syntax-check` e PRIMA comandă pe care o rulează operatorul împotriva
  // bazei reale. Cele două greșeli simetrice, amândouă tăcute:
  //
  //   * un refuz care iese cu 0 — DDL respins de server, comandă verde, iar
  //     cine automatizează peste ea trece mai departe la aplicare;
  //   * un `NEVERIFICAT` care iese cu 1 — comanda ar fi roșie pe orice server
  //     care nu poate pregăti vreo instrucțiune, indiferent dacă schema noastră
  //     e bună, deci semnalul își pierde înțelesul și ajunge ignorat. (Pe
  //     MariaDB 11.8.8 nu iese niciun `NEVERIFICAT`; pe altă versiune poate.)
  const v = (status: SyntaxVerdict["status"], index = 1): SyntaxVerdict =>
    ({ migration: "0001_core.sql", index, status, detail: "" });

  assert.equal(syntaxExitCode([v("parsed")]), 0);
  assert.equal(syntaxExitCode([v("parsed"), v("unchecked", 2)]), 0,
               "un `unchecked` a picat rularea");
  assert.equal(syntaxExitCode([v("parsed"), v("rejected", 2)]), 1,
               "un refuz a ieșit cu 0");
  assert.equal(syntaxExitCode([v("parsed"), v("unknown", 2)]), 1,
               "un „nu știu” a ieșit cu 0");
  // Și cazul în care nu s-a probat nimic: aceeași regulă ca `allParsed`.
  assert.equal(syntaxExitCode([]), 1, "o listă goală a raportat succes");
});

test("verificarea nu creează nimic: doar SET, PREPARE, DEALLOCATE", async () => {
  // Comanda asta e gândită să poată fi rulată pe baza de producție. Dacă ar
  // executa DDL-ul în loc să-l pregătească, ar schimba chiar lucrul pe care
  // pretinde doar că îl inspectează.
  const seen: string[] = [];
  const q: Queryable = {
    async query(sql: string) { seen.push(sql); return [[], []]; },
  };
  const stmts = splitStatements(
    "-- @guard table t\nCREATE TABLE t (id INT);\n", "0001_core.sql");
  const verdicts = await syntaxCheck(q, "0001_core.sql", stmts);

  assert.deepEqual(verdicts.map((v) => v.status), ["parsed"]);
  assert.equal(seen.length, 3);
  assert.ok(seen[0].startsWith("SET @"), seen[0]);
  assert.ok(seen[1].startsWith("PREPARE "), seen[1]);
  assert.ok(seen[2].startsWith("DEALLOCATE PREPARE "), seen[2]);
  assert.ok(!seen.some((s) => s.startsWith("CREATE")), seen.join(" | "));
});

test("instrucțiunea pleacă drept PARAMETRU, nu lipită în text", async () => {
  // Lipirea ar cere un al doilea escapator, scris de noi, peste unul care
  // există deja în driver — iar cel scris de noi ar fi cel care greșește.
  const params: unknown[][] = [];
  const q: Queryable = {
    async query(_sql: string, p?: unknown[]) { if (p) params.push(p); return [[], []]; },
  };
  const stmts = splitStatements(
    "-- @guard table t\nCREATE TABLE t (id INT);\n", "0001_core.sql");
  await syntaxCheck(q, "0001_core.sql", stmts);
  assert.deepEqual(params, [["CREATE TABLE t (id INT)"]]);
});

test("un `DEALLOCATE` care eșuează NU se pierde", async () => {
  // Eșecul pe care îl previne: pregătirea rămâne în sesiune, iar următoarea
  // `PREPARE` cu același nume moare cu „name already exists" — ceea ce s-ar
  // citi ca un refuz al INSTRUCȚIUNII URMĂTOARE. Cauza într-un loc, efectul în
  // altul, iar raportul ar acuza un DDL corect.
  const q: Queryable = {
    async query(sql: string) {
      if (sql.startsWith("DEALLOCATE")) {
        throw Object.assign(new Error("Unknown prepared statement handler"),
                            { errno: 1243 });
      }
      return [[], []];
    },
  };
  const stmts = splitStatements(
    "-- @guard table t\nCREATE TABLE t (id INT);\n", "0001_core.sql");
  const [verdict] = await syntaxCheck(q, "0001_core.sql", stmts);
  // Instrucțiunea CHIAR a fost analizată — verdictul ei rămâne `parsed` —, dar
  // faptul că sesiunea a rămas murdară trebuie să se vadă.
  assert.equal(verdict.status, "parsed");
  assert.match(verdict.detail, /nu s-a putut elibera/);
  assert.match(verdict.detail, /Unknown prepared statement/);
});

test("un refuz al serverului ajunge în verdict cu mesajul lui", async () => {
  const q: Queryable = {
    async query(sql: string) {
      if (sql.startsWith("PREPARE")) {
        throw Object.assign(new Error("You have an error in your SQL syntax"),
                            { errno: 1064 });
      }
      return [[], []];
    },
  };
  const stmts = splitStatements(
    "-- @guard table t\nCREATE TABLE t (id INT);\n", "0001_core.sql");
  const [verdict] = await syntaxCheck(q, "0001_core.sql", stmts);
  assert.equal(verdict.status, "rejected");
  assert.match(verdict.detail, /SQL syntax/);
});
