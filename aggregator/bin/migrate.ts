#!/usr/bin/env node
/**
 * Linia de comandă a migrațiilor agregatorului.
 *
 *     npm run migrate                 aplică ce lipsește
 *     npm run migrate -- --dry-run    spune ce ar face; NU scrie nimic
 *     npm run migrate -- --syntax-check
 *                                     dă fiecare instrucțiune serverului spre
 *                                     ANALIZĂ (PREPARE/DEALLOCATE) și raportează
 *                                     verdictul. Nu creează și nu șterge nimic.
 *
 * `--dry-run` și `--syntax-check` sunt cele două comenzi care se pot rula pe o
 * bază de producție fără să o schimbe. Prima citește `information_schema` și
 * registrul; a doua cere serverului să parseze DDL-ul. Împreună răspund la
 * întrebarea pe care nimeni nu o poate răspunde de pe o mașină fără MariaDB:
 * „sintaxa asta e acceptată acolo unde chiar rulează?"
 *
 * O conexiune singură, nu pool: `GET_LOCK` și `PREPARE` sunt legate de sesiune.
 */

import {
  createDirectConnection, queryableDb,
} from "../lib/db";
import { discover, migrate } from "../lib/migrate";
import { allParsed, syntaxCheck, syntaxExitCode } from "../lib/syntax-check";
import type { SyntaxVerdict } from "../lib/syntax-check";

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const dryRun = argv.includes("--dry-run");
  const syntaxOnly = argv.includes("--syntax-check");
  const unknownFlags = argv.filter((a) => a !== "--dry-run" && a !== "--syntax-check");
  if (unknownFlags.length) {
    // Un flag scris greșit nu se ignoră: cineva care a scris `--dryrun` crede
    // că n-a schimbat nimic.
    console.error(`argumente necunoscute: ${unknownFlags.join(" ")}`);
    return 2;
  }
  if (dryRun && syntaxOnly) {
    console.error("--dry-run și --syntax-check fac lucruri diferite; alege una");
    return 2;
  }

  const connection = await createDirectConnection();
  try {
    const db = queryableDb(connection);

    if (syntaxOnly) {
      const all: SyntaxVerdict[] = [];
      for (const migration of discover()) {
        const verdicts = await syntaxCheck(connection, migration.file, migration.statements);
        all.push(...verdicts);
        for (const v of verdicts) {
          if (v.status === "parsed") {
            console.log(`  ok        ${v.migration} #${v.index}`);
          } else if (v.status === "unchecked") {
            console.log(`  NEVERIF.  ${v.migration} #${v.index} — serverul nu poate ` +
                        `pregăti instrucțiunea asta (${v.detail})`);
          } else {
            console.error(`  ${v.status.toUpperCase()} ${v.migration} #${v.index} — ${v.detail}`);
          }
        }
        // `allParsed` e sensul strict: nu se folosește ca verdict aici, fiindcă
        // `unchecked` e un răspuns al serverului și depinde de versiunea lui,
        // dar se tipărește ca să se vadă când un fișier chiar a fost verificat
        // integral. Pe MariaDB 11.8.8 asta se întâmplă pentru tot `0001_core.sql`
        // (măsurat, 15 august 2026).
        if (allParsed(verdicts)) console.log(`  ${migration.file}: toate analizate`);
      }
      const bad = all.filter((v) => v.status === "rejected" || v.status === "unknown").length;
      const unchecked = all.filter((v) => v.status === "unchecked").length;
      console.log(`verificare de sintaxă: ${bad} respinse, ${unchecked} NEVERIFICATE`);
      if (unchecked) {
        console.log("  „NEVERIFICATE” nu înseamnă „bune”: serverul nu le-a putut " +
                    "analiza, deci despre ele nu s-a aflat nimic.");
      }
      // Decizia stă în `syntaxExitCode`, unde se poate afirma fără bază de date.
      // Liniile de mai sus rămân sursa pentru om; codul de ieșire e pentru
      // orice ar automatiza cineva peste comanda asta.
      return syntaxExitCode(all);
    }

    const report = await migrate(db, { dryRun });
    const counts = new Map<string, number>();
    for (const s of report.statements) counts.set(s.outcome, (counts.get(s.outcome) ?? 0) + 1);
    const summary = [...counts.entries()].map(([k, v]) => `${k}=${v}`).sort().join(" ");
    console.log(dryRun ? `dry-run: ${summary}` : `migrații: ${summary}`);
    return 0;
  } finally {
    await connection.end();
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(String(err instanceof Error ? err.message : err));
    process.exit(1);
  },
);
