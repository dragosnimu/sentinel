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
 * ## Al doilea eșec pe care îl previne: o cale înghețată la compilare
 *
 * Măsurat pe 23 septembrie 2026: o versiune anterioară citea, la fiecare
 * cerere, `discover(MIGRATIONS_DIR)` de pe disc — `MIGRATIONS_DIR` fiind
 * calculată din `import.meta.url`, pe care compilarea o îngheață la calea
 * ABSOLUTĂ de pe mașina de build. Pe găzduire build-ul rulează în
 * `<domeniu>/hbuilds/source/`, care NU supraviețuiește publicării. Calea
 * înghețată arăta deci spre un director șters, garda pica pe `ENOENT` la
 * primul contact cu baza, `POST /login` răspundea 503, iar toate fluxurile de
 * expediere de pe ambele gazde Sentinel au rămas blocate 20+ ore.
 *
 * Fișierul ăsta nu mai citește NIMIC de pe disc. Ce compară garda cu
 * `schema_version` — numele fișierului, indexul instrucțiunii, sha256 — e
 * `MIGRATIONS_MANIFEST` din `lib/migrations-manifest.ts`: DATĂ, importată
 * static, deci compilată direct în bundle-ul JS de Next, nu citită la runtime.
 * Manifestul e GENERAT din `migrations/`, comis în depozit — vezi
 * `bin/generate-migrations-manifest.ts` — și verificat împotriva directorului
 * real la fiecare `npm test`, în `tests/migrations-manifest.test.ts`, ca
 * desincronizarea (migrație nouă negenerată, instrucțiune editată după
 * generare) să pice suita, nu garda de la trei gazde distanță.
 *
 * `bin/migrate.ts` rămâne pe drumul vechi, dinadins: el chiar APLICĂ SQL-ul,
 * deci are nevoie de fișierele reale, nu doar de sumele lor de control. Rulează
 * de pe mașina operatorului, unde `MIGRATIONS_DIR` e o cale reală, nu una
 * înghețată la compilarea unui bundle care va călători în altă parte.
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
 * O a patra stare, distinctă și de-astea trei: manifestul compilat în bundle
 * poate fi el însuși gol sau stricat — un merge prost rezolvat, un generator
 * vechi rulat peste un `lib/` incomplet. Nu e „schemă veche" (schema n-a fost
 * măcar întrebată) și nu e „necunoscut" (nu e o problemă trecătoare de rețea —
 * nu se rezolvă singură cât procesul trăiește). Vezi `kind: "manifest-invalid"`.
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

import { guardPresent } from "./migrate";
import type { Db } from "./migrate";
import { MIGRATIONS_MANIFEST } from "./migrations-manifest";
import type { ManifestMigration } from "./migrations-manifest";

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
  /** `MIGRATIONS_MANIFEST` (`lib/migrations-manifest.ts`) e gol sau nu are
   *  forma așteptată — vezi `invalidManifestReason` mai jos pentru ce anume se
   *  verifică. NU e o stare a schemei — schema n-a fost măcar întrebată — e un
   *  defect în bundle-ul livrat: manifestul comis nu s-a regenerat, sau
   *  s-a rupt la un merge. Spre deosebire de `unknown`, cauza nu se rezolvă
   *  singură cât trăiește procesul (nu e un blip trecător de rețea), deci
   *  `withSchemaGuard` din `lib/db.ts` o ține minte la fel ca `not-installed`
   *  și `outdated`. */
  | { ok: false; kind: "manifest-invalid"; detail: string }
  /** `schema_version` există, dar codul cunoaște instrucțiuni pe care
   *  registrul nu le are consemnate (`missing`) — sau le are consemnate cu
   *  altă sumă de control decât fișierul de azi, adică migrația a fost
   *  editată după ce a rulat (`changed`). Amândouă listele se raportează
   *  o dată, nu doar prima, ca operatorul să vadă tot deodată — la fel ca
   *  `auditLedger` din `lib/migrate.ts`. */
  | { ok: false; kind: "outdated"; missing: StatementRef[]; changed: StatementRef[] };

/** Nume de fișier de migrație valid — aceeași formă ca `NAME_RE` din
 *  `lib/migrate.ts`, repetată aici dinadins: cele două module nu au voie să
 *  depindă unul de constanta privată a celuilalt, iar forma e stabilă (fixată
 *  în `splitStatements`/`discover` de multă vreme). */
const MANIFEST_FILE_RE = /^\d{4}_[a-z0-9_]+\.sql$/;
const MANIFEST_SHA256_RE = /^[0-9a-f]{64}$/;

/**
 * Manifestul e cod generat (`bin/generate-migrations-manifest.ts`), dar tot
 * poate ajunge stricat pe drumul până la bundle: un merge prost rezolvat, un
 * `lib/migrations-manifest.ts` gol scris de o rulare întreruptă. Un manifest
 * gol sau cu forma greșită NU are voie să treacă drept „nimic de verificat" —
 * cu zero migrații cunoscute, bucla de mai jos n-ar găsi nimic de comparat și
 * ar întoarce `ok: true` pe ORICE bază, oricât de veche.
 *
 * Întoarce un mesaj când manifestul e stricat, `null` când e valid — aceeași
 * formă ca `missingSqlModes` din `lib/db.ts`, pentru același motiv: apelantul
 * nu trebuie să deosebească „nimic de raportat" de „un tablou gol de motive".
 */
function invalidManifestReason(manifest: readonly ManifestMigration[]): string | null {
  if (!Array.isArray(manifest) || manifest.length === 0) {
    return "lib/migrations-manifest.ts e gol";
  }
  for (const migration of manifest) {
    if (!migration || typeof migration.file !== "string" ||
        !MANIFEST_FILE_RE.test(migration.file)) {
      return `un fișier din manifest n-are un nume valid de migrație: ` +
             `${JSON.stringify(migration?.file)}`;
    }
    if (!Array.isArray(migration.statements) || migration.statements.length === 0) {
      return `${migration.file}: nicio instrucțiune consemnată în manifest`;
    }
    for (const stmt of migration.statements) {
      if (!stmt || !Number.isInteger(stmt.index) || stmt.index < 1) {
        return `${migration.file}: index de instrucțiune invalid în manifest ` +
               `(${JSON.stringify(stmt?.index)})`;
      }
      if (typeof stmt.sha256 !== "string" || !MANIFEST_SHA256_RE.test(stmt.sha256)) {
        return `${migration.file} #${stmt.index}: sha256 invalid în manifest`;
      }
    }
  }
  return null;
}

/**
 * Verifică schema curentă contra migrațiilor cunoscute codului.
 *
 * NU rulează nimic și nu scrie nimic — o singură gardă de tabelă plus câte o
 * interogare pe registru per migrație cunoscută, aceeași formă ca `ledgerFor`
 * din `lib/migrate.ts`. Sursa migrațiilor cunoscute e `MIGRATIONS_MANIFEST`,
 * nu discul — vezi capul fișierului pentru de ce. Dacă manifestul însuși e
 * gol sau stricat, asta nu e un defect în migrații și nu e o stare a schemei —
 * e livrarea care n-a regenerat manifestul, sau l-a rupt la un merge — vezi
 * `kind: "manifest-invalid"`.
 */
export async function checkSchemaGuard(
  db: Db, manifest: readonly ManifestMigration[] = MIGRATIONS_MANIFEST,
): Promise<SchemaGuardResult> {
  const invalid = invalidManifestReason(manifest);
  if (invalid) return { ok: false, kind: "manifest-invalid", detail: invalid };

  const tablePresent = await guardPresent(db, { kind: "table", table: "schema_version" });
  if (tablePresent === false) return { ok: false, kind: "not-installed" };
  if (tablePresent !== true) {
    return { ok: false, kind: "unknown",
             detail: "tabela schema_version nu se poate citi din information_schema" };
  }

  const missing: StatementRef[] = [];
  const changed: StatementRef[] = [];
  let appliedStatements = 0;

  for (const migration of manifest) {
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
    case "manifest-invalid":
      return `manifestul de migrații compilat în cod e stricat: ${result.detail}. ` +
             "Asta nu e baza de date căzută și nu e o migrație lipsă — e un " +
             "defect de livrare: rulează `npm run generate-migrations-manifest` " +
             "din aggregator/, comite lib/migrations-manifest.ts și republică.";
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
