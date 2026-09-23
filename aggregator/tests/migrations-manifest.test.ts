/**
 * `lib/migrations-manifest.ts` (comis, generat) contra `migrations/` (pe disc,
 * adevărul).
 *
 * ## Eșecul pe care îl previne
 *
 * `lib/schema-guard.ts` nu mai citește `migrations/` la servire — vezi capul
 * lui pentru incidentul din 23 septembrie 2026. Verifică în schimb
 * `MIGRATIONS_MANIFEST`, comis în depozit. Dacă manifestul se desincronizează
 * de directorul real — o migrație nouă adăugată fără
 * `npm run generate-migrations-manifest`, sau o instrucțiune editată DUPĂ ce
 * manifestul a fost generat — garda ar continua să compare bazele de date cu o
 * listă VECHI: fie ar trece tăcut o schemă neaplicată drept „la zi" (migrația
 * nouă nu apare în manifest, deci nimic n-o cere), fie ar refuza o schemă
 * corectă crezând o instrucțiune „schimbată" (sha256 din manifest nu mai
 * corespunde fișierului). Amândouă sunt exact eșecul din capul lui
 * `lib/schema-guard.ts`, mutat dintr-un director șters pe găzduire într-un
 * fișier comis uitat pe mașina cuiva.
 *
 * Testul ăsta rulează `discover()` REAL, pe `migrations/` din depozit — poate,
 * fiindcă `npm test` rulează din sursă, nu din bundle-ul publicat unde
 * incidentul a lovit. E chiar de-asta manifestul trebuie verificat AICI, la
 * fiecare `npm test`, nu doar la generare: dacă cineva adaugă o migrație și
 * uită scriptul, suita asta pică înainte de livrare, nu garda la trei gazde
 * distanță.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { MIGRATIONS_DIR, discover } from "../lib/migrate";
import { MIGRATIONS_MANIFEST } from "../lib/migrations-manifest";

test("manifestul comis are exact fișierele din migrations/", () => {
  // Falsă dacă o migrație nouă a fost adăugată în migrations/ fără
  // `npm run generate-migrations-manifest` — manifestul ar rămâne cu un
  // fișier în minus, iar garda de schemă n-ar cere niciodată instrucțiunile
  // lui.
  const real = discover(MIGRATIONS_DIR).map((m) => m.file).sort();
  const recorded = MIGRATIONS_MANIFEST.map((m) => m.file).sort();
  assert.deepEqual(
    recorded, real,
    "lib/migrations-manifest.ts nu conține exact fișierele din migrations/ — " +
    "rulează `npm run generate-migrations-manifest` din aggregator/");
});

test("fiecare migrație din manifest are aceleași instrucțiuni (index, sha256) " +
     "ca fișierul de pe disc", () => {
  // Falsă dacă o instrucțiune a fost editată DUPĂ ce manifestul a fost
  // generat — sha256-ul din manifest ar rămâne cel VECHI, iar garda de schemă
  // ar refuza o bază la care instrucțiunea chiar s-a aplicat (crezând-o
  // „schimbată" față de un text pe care nimeni nu l-a mai rulat), sau ar trece
  // tăcut una nouă drept deja cunoscută dacă indexul se potrivește din
  // întâmplare.
  const real = discover(MIGRATIONS_DIR);
  for (const migration of real) {
    const recorded = MIGRATIONS_MANIFEST.find((m) => m.file === migration.file);
    assert.ok(recorded, `${migration.file} lipsește din lib/migrations-manifest.ts`);
    const realStatements = migration.statements.map((s) => ({ index: s.index, sha256: s.sha256 }));
    const recordedStatements = recorded!.statements
      .map((s) => ({ index: s.index, sha256: s.sha256 }))
      .sort((a, b) => a.index - b.index);
    assert.deepEqual(
      recordedStatements, realStatements,
      `${migration.file}: instrucțiunile din manifest nu mai corespund fișierului — ` +
      "editat după generare? rulează `npm run generate-migrations-manifest`");
  }
});
