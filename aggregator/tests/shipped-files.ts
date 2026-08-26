/**
 * Ce înseamnă „codul livrat" pentru gărzile care citesc depozitul.
 *
 * Un singur loc, fiindcă lista asta a avut deja un punct orb care contează, și
 * două copii ale ei ar însemna două puncte oarbe care se pot desincroniza: până
 * pe 17 august 2026, `tests/auth-attempts-writers.test.ts` umbla prin `app/`,
 * `lib/`, `bin/` și `migrations/` — **și nu prin RĂDĂCINA proiectului**.
 *
 * De ce contează exact rădăcina: în Next.js, `middleware.ts` TREBUIE să stea
 * acolo, nu în `app/`, și e locul clasic în care ajunge apărarea unui panou. Un
 * `middleware.ts` cu un `INSERT INTO login_attempts` în el ar fi trecut toate
 * cele nouă reguli ale gărzii, verde — iar tabela aia e starea celor trei
 * limitatoare, deci un rând scris pe lângă `checkThrottles` prelungește la
 * nesfârșit plafonul care tocmai a refuzat pe toată lumea.
 *
 * ## Rădăcina se citește NERECURSIV, dinadins
 *
 * `node_modules/` și `.next/` sunt tot în rădăcină. O parcurgere recursivă de
 * acolo ar fi însemnat zeci de mii de fișiere la fiecare rulare a fiecărei
 * gărzi — adică o suită lentă, adică o gardă pe care o scoate cineva. Ce trebuie
 * prins e un fișier de nivel întâi (`middleware.ts`, `instrumentation.ts`,
 * `next.config.mjs`), iar alea sunt toate la nivelul întâi prin definiția
 * framework-ului.
 *
 * ## Punctul orb care a RĂMAS: un director frate nou
 *
 * `SHIPPED_DIRS` e o listă scrisă cu mâna, nu ceva derivat. Un director nou lângă
 * cele patru — `jobs/`, `workers/`, `scripts/` — e INVIZIBIL pentru fiecare gardă
 * construită aici, și nimic nu o spune: gărzile trec verzi, fiindcă fișierul pe
 * care ar fi trebuit să-l vadă nu e în listă. Măsurat pe 17 august 2026, și
 * RE-măsurat după ce recensămintele au fost rescrise să numere numele în loc de
 * ortografii: un `aggregator/jobs/rollup.ts` care importă driverul ȘI golește
 * `sql_mode`, amândouă cât se poate de banal scrise, lasă suita la
 * `pass 519 / fail 0`.
 *
 * Nu e reparat aici fiindcă reparația nu e o linie: „livrat" ar trebui să
 * însemne ce ajunge la runtime, iar asta se poate deriva în feluri care nu sunt
 * echivalente — tot ce nu e ignorat de `.gitignore`, tot ce importă rădăcina
 * Next.js, sau lista curentă plus o regulă care refuză un director frate
 * nedeclarat. Fiecare are alt preț (viteză, false pozitive, ce se strică la
 * `next build`), iar alegerea schimbă purtarea fiecărei gărzi din suită, nu doar
 * a uneia. Până se alege, limita e scrisă și în capul lui
 * `tests/db-strict-mode.test.ts`, care se sprijină pe ea.
 */

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

/** Directoarele livrate, parcurse RECURSIV. `tests/` nu e aici: dublul are voie
 *  să scrie ce codul livrat n-are voie. */
export const SHIPPED_DIRS = ["app", "lib", "bin", "migrations"];

/**
 * Extensiile în care se poate ascunde cod sau SQL.
 *
 * `.mts` și `.cts` sunt aici fiindcă lipseau, iar lipsa lor era o gaură măsurată,
 * nu una teoretică: pe 17 august 2026, `lib/reports-db.mts` — care importa
 * driverul și golea `sql_mode`, amândouă scrise cât se poate de banal — lăsa
 * suita întreagă verde. Sunt omoloagele TypeScript ale lui `.mjs`/`.cjs`, deja
 * pe listă, le compilează același `tsc` și le încarcă același Node; nimic din ce
 * citește gărzile astea nu le deosebește de `.ts`.
 */
export const SHIPPED_EXTENSIONS = /\.(tsx?|jsx?|mts|cts|mjs|cjs|sql)$/;

/**
 * Fișierele livrate: cele patru directoare, plus fișierele din rădăcină.
 *
 * Căile sunt relative la rădăcina agregatorului, cu `/`, ca să poată fi scrise
 * ca atare în registrele gărzilor.
 */
export function shippedFiles(): string[] {
  const out: string[] = [];

  const walk = (relative: string): void => {
    for (const entry of readdirSync(path.join(ROOT, relative), { withFileTypes: true })) {
      const next = `${relative}/${entry.name}`;
      if (entry.isDirectory()) walk(next);
      else if (SHIPPED_EXTENSIONS.test(entry.name)) out.push(next);
    }
  };
  for (const dir of SHIPPED_DIRS) walk(dir);

  for (const entry of readdirSync(ROOT, { withFileTypes: true })) {
    if (entry.isDirectory()) continue;
    if (SHIPPED_EXTENSIONS.test(entry.name)) out.push(entry.name);
  }
  return out.sort();
}

/** Fișierele livrate al căror TEXT se potrivește. Sortate, pentru comparații. */
export function shippedMatching(pattern: RegExp | string): string[] {
  const matches = typeof pattern === "string"
    ? (text: string) => text.includes(pattern)
    : (text: string) => pattern.test(text);
  return shippedFiles()
    .filter((file) => matches(readShipped(file)))
    .sort();
}

export function readShipped(file: string): string {
  return readFileSync(path.join(ROOT, file), "utf8");
}
