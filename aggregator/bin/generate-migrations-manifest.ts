#!/usr/bin/env node
/**
 * Regenerează `lib/migrations-manifest.ts` din `migrations/`.
 *
 * ## De ce hangi există
 *
 * `lib/schema-guard.ts` rula, până la incidentul din 23 septembrie 2026,
 * `discover(MIGRATIONS_DIR)` LA FIECARE cerere care atinge baza —
 * `MIGRATIONS_DIR` fiind o cale calculată din `import.meta.url`, pe care
 * compilarea o îngheață la calea ABSOLUTĂ de pe mașina de build. Pe găzduire,
 * build-ul rulează în `<domeniu>/hbuilds/source/`, iar directorul ăla NU
 * supraviețuiește publicării — măsurat, cu două fișiere fără de care build-ul
 * n-ar fi putut rula, dispărute după un build reușit. Calea înghețată arăta
 * deci spre un director șters, garda pica pe `ENOENT` la primul contact cu
 * baza, `POST /login` răspundea 503, iar toate fluxurile de expediere de pe
 * ambele gazde Sentinel au rămas blocate 20+ ore.
 *
 * Fixul nu e o cale mai bună — orice cale calculată la compilare pe mașina de
 * build e supusă aceluiași eșec. Fixul e să nu mai existe nicio citire de pe
 * disc pe drumul de servire: `lib/schema-guard.ts` compară doar trei lucruri
 * cu `schema_version` — numele fișierului, indexul instrucțiunii, sha256 —, iar
 * cele trei pot fi DATĂ, compilată direct în bundle-ul JS prin `import`, nu
 * citite la runtime. Un `import` static ajunge în bundle-ul pe care Next îl
 * produce pe mașina de build, deci nu depinde de ce supraviețuiește pe disc
 * DUPĂ build.
 *
 * ## De ce scriptul, nu un pas manual
 *
 * Un pas manual e exact cum a intrat defectul ăsta: cineva a scris o cale la
 * un moment dat, corectă atunci, și n-a mai fost re-verificată cu efectul
 * DUPĂ o publicare. Manifestul generat manual ar avea aceeași soartă — corect
 * azi, tăcut greșit după prima migrație adăugată fără regenerare. De-aia
 * `tests/migrations-manifest.test.ts` compară manifestul comis cu
 * `discover()` REAL la fiecare rulare de `npm test`: dacă cineva uită
 * `npm run generate-migrations-manifest`, suita pică înainte de livrare, nu
 * garda la trei gazde distanță.
 *
 * ## Ce NU face
 *
 * Nu rulează pe găzduire și nu intră în arhiva publicată — la fel ca
 * `bin/migrate.ts`, e un instrument de pe mașina operatorului. Ce se publică e
 * DOAR fișierul generat, `lib/migrations-manifest.ts`, care intră în `lib/` ca
 * orice alt fișier de cod.
 *
 * ## A doua ieșire: `lib/migrations-manifest.sources.json`
 *
 * `tests/security/test_repo_is_sanitised.py` scanează tot depozitul pe VALOARE
 * după forme de secret, iar cele 78+ sha256 din `migrations-manifest.ts` au
 * exact forma unuia. Garda aia rula, până acum, `node --import tsx` peste
 * `discover()` ca să deriveze care hexa sunt sha256-uri REALE — corect, dar cu
 * o consecință măsurată pe o clonă proaspătă: fără `npm ci` (nimeni nu-l
 * rulează pentru suita Python), `aggregator/node_modules` lipsește, garda nu
 * poate deriva nimic și fiecare hexa rămâne „neverificat", nu „curat". Pe orice
 * checkout fără `node_modules` — inclusiv CI-ul care rulează doar suita Python
 * — garda era roșie mereu, adică exact genul de gardă pe care cineva o scoate.
 *
 * Fixul nu e o a doua parsare SQL în Python — ar fi al doilea punct orb descris
 * mai sus. E să scrie AICI, în JSON comis, tot ce Python are nevoie ca să
 * verifice fiecare sha256 fără să mai parseze nimic:
 *
 *   - `sql`: textul normalizat exact peste care s-a calculat `sha256`-ul din
 *     manifest (`Statement.sql`, aceeași valoare, nu una recalculată). Python
 *     doar cere `hashlib.sha256(sql).hexdigest()` — un hash, nu o parsare — și
 *     compară cu ce scrie în `migrations-manifest.ts`;
 *   - `sourceStart`/`sourceEnd`: offset-uri în OCTEȚI (nu în caractere — fișierele
 *     au diacritice, deci un index de caracter JS NU e un offset de octet UTF-8)
 *     în fișierul `.sql` de pe disc, care delimitează exact felia consumată de
 *     `splitStatements` pentru instrucțiunea asta. Feliile succesive dintr-un
 *     fișier se ATING exact — sfârșitul uneia e începutul următoarei, prima
 *     începe la 0, ultima se termină la lungimea fișierului — deci Python poate
 *     verifica offset-urile fără să știe nimic despre SQL: dacă un offset a fost
 *     falsificat, feliile nu se mai ating (o gaură sau o suprapunere), iar garda
 *     pică înainte să se uite la conținut.
 *
 * Asta dovedește că `sql` e derivat din OCTEȚII reali ai fișierului `.sql` de
 * pe disc (nu inventat): non-spațiile lui `sql`, în ordine, trebuie să apară,
 * tot în ordine, în felia [sourceStart, sourceEnd) — proprietate adevărată
 * mereu pentru orice normalizare corectă (ea doar șterge comentarii și
 * comprimă spații, nu adaugă, nu reordonează), deci Python o poate cere fără
 * să știe UNDE sunt comentariile, doar CĂ non-spațiile stau în ordinea aia.
 */

import { writeFileSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { MIGRATIONS_DIR, discover } from "../lib/migrate";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT_FILE = path.join(HERE, "..", "lib", "migrations-manifest.ts");
const SOURCES_FILE = path.join(HERE, "..", "lib", "migrations-manifest.sources.json");

function render(migrations: ReturnType<typeof discover>): string {
  const lines: string[] = [];
  lines.push("/**");
  lines.push(" * GENERAT — nu edita manual.");
  lines.push(" *");
  lines.push(" * Regenerează cu `npm run generate-migrations-manifest`, din `aggregator/`,");
  lines.push(" * după orice migrație nouă sau editată în `migrations/`. Vezi capul lui");
  lines.push(" * `bin/generate-migrations-manifest.ts` pentru de ce fișierul ăsta există, și");
  lines.push(" * `tests/migrations-manifest.test.ts` pentru proba care pică dacă fișierul ăsta");
  lines.push(" * se desincronizează de `migrations/`.");
  lines.push(" */");
  lines.push("");
  lines.push("export type ManifestStatement = { readonly index: number; readonly sha256: string };");
  lines.push("export type ManifestMigration = {");
  lines.push("  readonly file: string;");
  lines.push("  readonly statements: readonly ManifestStatement[];");
  lines.push("};");
  lines.push("");
  lines.push("export const MIGRATIONS_MANIFEST: readonly ManifestMigration[] = [");
  for (const migration of migrations) {
    lines.push(`  { file: ${JSON.stringify(migration.file)}, statements: [`);
    for (const stmt of migration.statements) {
      lines.push(`    { index: ${stmt.index}, sha256: ${JSON.stringify(stmt.sha256)} },`);
    }
    lines.push("  ] },");
  }
  lines.push("];");
  lines.push("");
  return lines.join("\n");
}

/**
 * `lib/migrations-manifest.sources.json` — vezi capul fișierului, secțiunea
 * „A doua ieșire", pentru ce anume dovedește și de ce.
 *
 * `stmt.sourceEnd` din `Statement` e un index de CARACTER JS (UTF-16), nu un
 * offset de octet — fișierele de migrație au diacritice. `Buffer.byteLength`
 * peste prefixul textului până la indexul ăla dă offset-ul real în octeți, cel
 * pe care Python îl va folosi ca să taie din fișierul citit ca octeți de pe
 * disc. `sourceStart` al fiecărei instrucțiuni e `sourceEnd`-ul precedentei din
 * ACELAȘI fișier (0 pentru prima) — feliile succesive se ating exact, dinadins:
 * proprietatea aia e ce prinde un offset falsificat, fără ca Python să știe
 * nimic despre SQL.
 */
function renderSources(migrations: ReturnType<typeof discover>): string {
  const out = {
    _comment:
      "GENERAT — nu edita manual. Regenerează cu `npm run generate-migrations-manifest`, " +
      "din `aggregator/`. Citit doar de tests/security/test_repo_is_sanitised.py, ca să " +
      "verifice sha256-urile din migrations-manifest.ts fără `node`. Vezi capul lui " +
      "bin/generate-migrations-manifest.ts.",
    migrations: migrations.map((migration) => {
      const fileText = readFileSync(path.join(MIGRATIONS_DIR, migration.file), "utf8");
      let sourceStart = 0;
      const statements = migration.statements.map((stmt) => {
        const sourceEnd = Buffer.byteLength(fileText.slice(0, stmt.sourceEnd), "utf8");
        const entry = { index: stmt.index, sql: stmt.sql, sourceStart, sourceEnd };
        sourceStart = sourceEnd;
        return entry;
      });
      return { file: migration.file, statements };
    }),
  };
  return JSON.stringify(out, null, 2) + "\n";
}

function main(): void {
  // `discover()` real, aceeași funcție pe care `bin/migrate.ts` o cheamă ca
  // să APLICE migrațiile — dacă parsarea SQL e stricată, scriptul ăsta pică la
  // fel de zgomotos ca migrarea reală, nu tăcut cu un manifest gol.
  const migrations = discover(MIGRATIONS_DIR);
  writeFileSync(OUT_FILE, render(migrations), "utf8");
  writeFileSync(SOURCES_FILE, renderSources(migrations), "utf8");
  const totalStatements = migrations.reduce((n, m) => n + m.statements.length, 0);
  console.log(
    `[generate-migrations-manifest] scris ${OUT_FILE} și ${SOURCES_FILE}: ` +
    `${migrations.length} migrații, ${totalStatements} instrucțiuni.`);
}

main();
