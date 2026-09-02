/**
 * Garda de schemă: agregatorul refuză să servească peste o schemă mai veche
 * decât codul, în loc să cadă tăcut pe o coloană inexistentă.
 *
 * ## Eșecul pe care îl previne
 *
 * Măsurat: agregatorul a picat o vineri fiindcă rula cod care cerea o coloană
 * inexistentă, ȘI N-A SPUS NIMIC LA PORNIRE. Simptomul a apărut la prima cerere
 * care atingea coloana aia, ca o eroare de bază de date opacă, minute sau zile după
 * deploy — nu ca un refuz clar, la primul contact cu baza.
 *
 * `lib/migrate.ts` dovedește riguros ce se aplică LA MIGRARE. Fișierul ăsta e
 * cealaltă jumătate: ce se verifică LA SERVIRE, înainte de orice interogare
 * care ar putea presupune o coloană, un index sau un trigger care încă nu
 * există. Registrul (`schema_version`) e sursa de adevăr pentru amândouă —
 * garda nu re-probează `information_schema` obiect cu obiect (asta ar
 * însemna o interogare per instrucțiune, la FIECARE pornire de proces); se
 * încrede în ce a consemnat `migrate.ts`, care la rândul lui nu consemnează
 * nimic fără să fi confirmat efectul. Vezi capul lui `lib/migrate.ts`.
 *
 * ## Trei stări, nu două
 *
 * O bază complet goală (nicio migrație rulată vreodată) și o bază în urmă cu
 * câteva migrații sunt lucruri diferite pentru operator — prima e „încă nu s-a
 * instalat", a doua e „codul a luat-o înainte, cineva a uitat `npm run
 * migrate`". Amestecate, mesajul de eroare ar trimite pe cineva să caute o
 * migrație lipsă pe o instalare care pur și simplu n-a pornit încă. Și există
 * o a treia stare, la fel de reală: „nu se poate ști" — baza nu răspunde,
 * `information_schema` nu se poate citi. Aia NU e „bine" și nu e nici
 * „bază veche" — e necunoscut, iar CLAUDE.md e explicit că „necunoscut" și
 * „bine" nu au voie să arate la fel.
 *
 * ## Cine cheamă garda, și de ce nu poate fi ocolită din greșeală
 *
 * `withSchemaGuard` din `lib/db.ts` învelește pool-ul REAL (nu dublurile de
 * test, care n-au nicio schemă de apărat) astfel încât ORICE interogare
 * trimisă prin `getPool()` fără `factory` explicit așteaptă întâi garda, o
 * singură dată cât trăiește pool-ul. Fișierul ăsta conține doar logica pură de
 * verificare — testabilă fără vreun driver de bază de date, cu un dublu `Db` ca în
 * `tests/migrate.test.ts`.
 */

import { MIGRATIONS_DIR, discover, guardPresent } from "./migrate";
import type { Db } from "./migrate";

/** O instrucțiune dintr-o migrație cunoscută codului, identificată ca în
 *  registru: fișierul plus indexul instrucțiunii înăuntrul lui. */
export type StatementRef = { migration: string; index: number };

export type SchemaGuardResult =
  | { ok: true; appliedStatements: number }
  /** Bază complet goală: `schema_version` nu există. Nu e „schemă veche" —
   *  e „neinstalat". Vezi capul fișierului. */
  | { ok: false; kind: "not-installed" }
  /** Nu se poate ști. Nu se confundă cu „bine". */
  | { ok: false; kind: "unknown"; detail: string }
  /** `discover(dir)` a picat pe ENOENT/ENOTDIR: directorul de migrații nu
   *  există pe mașina care servește, sau nu e director. NU e o stare a
   *  schemei — schema n-a fost măcar întrebată — e o eroare de împachetare a
   *  livrării: `migrations/` n-a ajuns în arhiva urcată pe găzduire. Spre
   *  deosebire de `unknown`, cauza nu se rezolvă singură cât trăiește
   *  procesul (nu e un blip trecător de rețea), deci `withSchemaGuard` din
   *  `lib/db.ts` o ține minte la fel ca `not-installed` și `outdated`. */
  | { ok: false; kind: "migrations-unreadable"; dir: string }
  /** `schema_version` există, dar codul cunoaște instrucțiuni pe care
   *  registrul nu le are consemnate (`missing`) — sau le are consemnate cu
   *  altă sumă de control decât fișierul de azi, adică migrația a fost
   *  editată după ce a rulat (`changed`). Amândouă listele se raportează
   *  o dată, nu doar prima, ca operatorul să vadă tot deodată — la fel ca
   *  `auditLedger` din `lib/migrate.ts`. */
  | { ok: false; kind: "outdated"; missing: StatementRef[]; changed: StatementRef[] };

/**
 * Verifică schema curentă contra migrațiilor cunoscute codului.
 *
 * NU rulează nimic și nu scrie nimic — o singură gardă de tabelă plus câte o
 * interogare pe registru per migrație cunoscută, aceeași formă ca `ledgerFor`
 * din `lib/migrate.ts`. Cade pe `discover()` dacă directorul de migrații e
 * stricat pe FOND — un fișier cu numele greșit, o versiune dublată — e o
 * eroare de cod, nu o stare de schemă, deci nu se transformă într-un
 * `SchemaGuardResult`. Singura excepție e când directorul însuși lipsește
 * (ENOENT) sau nu e director (ENOTDIR): aia nu e un defect în migrații, e
 * livrarea care nu l-a trimis — vezi `kind: "migrations-unreadable"`.
 */
export async function checkSchemaGuard(
  db: Db, dir: string = MIGRATIONS_DIR,
): Promise<SchemaGuardResult> {
  let migrations: ReturnType<typeof discover>;
  try {
    migrations = discover(dir);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    if (code === "ENOENT" || code === "ENOTDIR") {
      return { ok: false, kind: "migrations-unreadable", dir };
    }
    throw err;
  }

  const tablePresent = await guardPresent(db, { kind: "table", table: "schema_version" });
  if (tablePresent === false) return { ok: false, kind: "not-installed" };
  if (tablePresent !== true) {
    return { ok: false, kind: "unknown",
             detail: "tabela schema_version nu se poate citi din information_schema" };
  }

  const missing: StatementRef[] = [];
  const changed: StatementRef[] = [];
  let appliedStatements = 0;

  for (const migration of migrations) {
    const rows = await db.all(
      "SELECT stmt_index, stmt_sha256 FROM schema_version WHERE migration = ?",
      [migration.file]);
    const recorded = new Map<number, string>();
    for (const row of rows) {
      recorded.set(Number(row.stmt_index), String(row.stmt_sha256));
    }
    for (const stmt of migration.statements) {
      const sha = recorded.get(stmt.index);
      if (sha === undefined) {
        missing.push({ migration: migration.file, index: stmt.index });
        continue;
      }
      appliedStatements++;
      if (sha !== stmt.sha256) changed.push({ migration: migration.file, index: stmt.index });
    }
  }

  if (missing.length || changed.length) return { ok: false, kind: "outdated", missing, changed };
  return { ok: true, appliedStatements };
}

/** Grupează referințele pe fișier, ca mesajul să nu fie o listă plată de zeci
 *  de perechi migrație/index — operatorul citește pe fișier. */
function describeRefs(refs: StatementRef[]): string {
  const byFile = new Map<string, number[]>();
  for (const ref of refs) {
    const list = byFile.get(ref.migration);
    if (list) list.push(ref.index); else byFile.set(ref.migration, [ref.index]);
  }
  return [...byFile.entries()]
    .map(([file, idx]) => `${file} (#${idx.sort((a, b) => a - b).join(", #")})`)
    .join(", ");
}

/** Mesajul pentru operator — în jurnal (`console.error`, prin `guarded()` din
 *  `lib/auth/context.ts`) sau în corpul unui răspuns 500/503, după rută. */
export function schemaGuardMessage(
  result: Extract<SchemaGuardResult, { ok: false }>,
): string {
  switch (result.kind) {
    case "not-installed":
      return "schema agregatorului nu e instalată — tabela schema_version " +
             "lipsește. Rulează `npm run migrate` înainte de a servi cereri.";
    case "unknown":
      return `schema agregatorului nu se poate verifica: ${result.detail}. ` +
             "Nu se servesc cereri către bază pe o presupunere.";
    case "migrations-unreadable":
      return `directorul de migrații nu poate fi citit (${result.dir}). ` +
             "Asta nu e baza de date căzută — arhiva de livrare probabil nu " +
             "conține migrations/. Vezi lista din aggregator/README.md.";
    case "outdated": {
      const parts: string[] = [];
      if (result.missing.length) {
        parts.push(`neaplicate: ${describeRefs(result.missing)}`);
      }
      if (result.changed.length) {
        parts.push("consemnate cu altă sumă de control decât fișierul curent " +
                   `(istorie rescrisă): ${describeRefs(result.changed)}`);
      }
      return `schema agregatorului e în urma codului — ${parts.join("; ")}. ` +
             "Rulează `npm run migrate` înainte de a servi cereri pe schema asta.";
    }
  }
}

/** Aruncată de `withSchemaGuard` (`lib/db.ts`) când garda refuză. `result`
 *  rămâne pe obiect, netrunchiat — un apelant care vrea să deosebească
 *  „neinstalat" de „învechit" programatic n-are nevoie să repareze mesajul. */
export class SchemaGuardError extends Error {
  readonly result: Extract<SchemaGuardResult, { ok: false }>;
  constructor(result: Extract<SchemaGuardResult, { ok: false }>) {
    super(schemaGuardMessage(result));
    this.name = "SchemaGuardError";
    this.result = result;
  }
}
