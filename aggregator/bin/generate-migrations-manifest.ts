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
 */

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { MIGRATIONS_DIR, discover } from "../lib/migrate";

const OUT_FILE = path.join(
  path.dirname(fileURLToPath(import.meta.url)), "..", "lib", "migrations-manifest.ts");

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

function main(): void {
  // `discover()` real, aceeași funcție pe care `bin/migrate.ts` o cheamă ca
  // să APLICE migrațiile — dacă parsarea SQL e stricată, scriptul ăsta pică la
  // fel de zgomotos ca migrarea reală, nu tăcut cu un manifest gol.
  const migrations = discover(MIGRATIONS_DIR);
  writeFileSync(OUT_FILE, render(migrations), "utf8");
  const totalStatements = migrations.reduce((n, m) => n + m.statements.length, 0);
  console.log(
    `[generate-migrations-manifest] scris ${OUT_FILE}: ` +
    `${migrations.length} migrații, ${totalStatements} instrucțiuni.`);
}

main();
