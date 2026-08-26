/**
 * Verificarea de sintaxă a migrațiilor, fără să se schimbe nimic în bază.
 *
 * Există dintr-un motiv scris pe față: schema asta a fost scrisă pe o mașină
 * fără MariaDB. Tot ce afirmă cineva despre ea — că `INET6` e acceptat acolo unde
 * e pus, că un `COMMENT` pe coloană se scrie așa, că un trigger cu `SIGNAL` fără
 * `BEGIN ... END` trece — e o CREDINȚĂ până când o parsează serverul. Modulul
 * ăsta face parsarea aia, și doar atât: `PREPARE` analizează instrucțiunea și
 * `DEALLOCATE PREPARE` o aruncă. Nu se creează nimic, nu se șterge nimic.
 *
 * ## Trei verdicte, nu două
 *
 * * `parsed` — serverul a acceptat instrucțiunea la analiză.
 * * `unchecked` — **serverul a spus că nu poate pregăti instrucțiunea asta**
 *   (`ER_UNSUPPORTED_PS`, 1295). NU înseamnă „e bună". Cine citește raportul
 *   trebuie să vadă diferența, altfel modul ăsta devine chiar greșeala pe care o
 *   previne: un instrument care spune „nimic în neregulă" fiindcă nu s-a uitat.
 *
 *   Fișierul ăsta prezicea, până pe 15 august 2026, că `CREATE TRIGGER` produce
 *   verdictul ăsta. **Predicția a fost greșită, măsurat pe gazdă:** pe MariaDB
 *   11.8.8, `--syntax-check` a raportat `0 respinse, 0 NEVERIFICATE` peste toate
 *   cele șase instrucțiuni din `0001_core.sql`, dintre care două sunt
 *   `CREATE TRIGGER`; aplicarea de după a creat ambele triggere. Deci serverul
 *   ăla CHIAR le pregătește, iar verificarea e mai puternică decât o descria
 *   textul de aici — nu mai slabă.
 *
 *   Ramura rămâne, și nu din prudență decorativă: `unchecked` e o proprietate a
 *   VERSIUNII DE SERVER, nu a schemei noastre. Ce nu se poate pregăti pe 11.8.8
 *   se poate pe alta, și invers. Clasificarea a fost mereu corectă; doar
 *   așteptarea despre ce va ieși era falsă.
 * * `rejected` — serverul a refuzat-o, cu mesajul lui.
 *
 * Și un al patrulea, pentru orice altceva: `unknown`. O conexiune căzută la
 * mijloc nu e nici bună, nici rea.
 *
 * ## Ce NU prinde
 *
 * `PREPARE` analizează; nu execută. Rămân neverificate lucrurile pe care
 * serverul le decide la creare: dimensiunea maximă a unui rând, lungimea
 * maximă a unei chei, existența unui obiect cu același nume, drepturile.
 * Scris aici fiindcă o limită nedocumentată e cea care mușcă.
 */

import type { Queryable } from "./db";
import type { Statement } from "./sql-statements";

/** MariaDB: „This command is not supported in the prepared statement protocol yet". */
export const ER_UNSUPPORTED_PS = 1295;

/** Numele instrucțiunii pregătite. Legat de sesiune, deci verificarea are
 *  nevoie de o CONEXIUNE, nu de un pool. */
const PROBE_NAME = "sentinel_syntax_probe";
const PROBE_VAR = "@sentinel_syntax_probe_sql";

export type SyntaxStatus = "parsed" | "unchecked" | "rejected" | "unknown";

export type SyntaxVerdict = {
  migration: string;
  index: number;
  status: SyntaxStatus;
  detail: string;
};

type DriverError = { errno?: unknown; code?: unknown; message?: unknown };

/**
 * Ce înseamnă eroarea întoarsă de `PREPARE`.
 *
 * Funcție pură, cu eroarea ca argument, tocmai ca să poată fi afirmată într-un
 * test fără bază de date. Regula care contează: doar `ER_UNSUPPORTED_PS` devine
 * „n-am putut verifica"; orice altă eroare cu număr e un REFUZ al serverului, iar
 * o eroare fără număr (rețea, protocol) e „nu știu" — și niciuna din cele două
 * din urmă nu are voie să fie citită ca trecere.
 */
export function classifyPrepareError(err: unknown): SyntaxStatus {
  const e = (err ?? {}) as DriverError;
  const errno = typeof e.errno === "number" ? e.errno : undefined;
  if (errno === ER_UNSUPPORTED_PS || e.code === "ER_UNSUPPORTED_PS") return "unchecked";
  if (errno !== undefined) return "rejected";
  return "unknown";
}

function detailOf(err: unknown): string {
  const e = (err ?? {}) as DriverError;
  const message = typeof e.message === "string" ? e.message : String(err);
  return message.slice(0, 300);
}

export async function syntaxCheck(
  q: Queryable, migration: string, statements: Statement[],
): Promise<SyntaxVerdict[]> {
  const out: SyntaxVerdict[] = [];
  for (const stmt of statements) {
    let status: SyntaxStatus = "unknown";
    let detail = "";
    try {
      // Instrucțiunea pleacă drept PARAMETRU într-o variabilă de sesiune, nu
      // lipită în text: driverul o scapă, iar `PREPARE ... FROM @var` o ia de
      // acolo. Lipirea ar cere un al doilea escapator, scris de noi.
      await q.query(`SET ${PROBE_VAR} = ?`, [stmt.sql]);
      await q.query(`PREPARE ${PROBE_NAME} FROM ${PROBE_VAR}`);
      status = "parsed";
      try {
        await q.query(`DEALLOCATE PREPARE ${PROBE_NAME}`);
      } catch (err) {
        // Nu schimbă verdictul instrucțiunii, dar nu se înghite: o pregătire
        // rămasă în sesiune face următoarea să eșueze cu „name already exists",
        // iar aia s-ar citi ca un refuz al instrucțiunii următoare.
        detail = `pregătirea nu s-a putut elibera: ${detailOf(err)}`;
      }
    } catch (err) {
      status = classifyPrepareError(err);
      detail = detailOf(err);
    }
    out.push({ migration, index: stmt.index, status, detail });
  }
  return out;
}

/** `true` doar dacă TOATE instrucțiunile au fost analizate cu succes. Un
 *  `unchecked` nu e o trecere — de-aia funcția asta există, în loc să numere
 *  cineva refuzurile la fața locului. */
export function allParsed(verdicts: SyntaxVerdict[]): boolean {
  return verdicts.length > 0 && verdicts.every((v) => v.status === "parsed");
}

/**
 * Codul de ieșire al lui `--syntax-check`.
 *
 * Funcție, nu două variabile numărate în `bin/migrate.ts`, fiindcă asta e o
 * DECIZIE și `--syntax-check` e prima comandă pe care o rulează operatorul
 * împotriva bazei reale. O decizie care trăiește doar în corpul unui `main()`
 * care cheamă `process.exit` nu se poate afirma fără o bază de date.
 *
 * Regula, și de ce e asimetrică:
 *
 * * `rejected` sau `unknown` → **eșec**. Prima e serverul care refuză DDL-ul
 *   nostru; a doua e „nu știu ce s-a întâmplat", iar „nu știu" nu e trecere.
 * * `unchecked` → **NU e eșec**. E răspunsul serverului „nu pot pregăti asta",
 *   deci depinde de versiunea lui, nu de schema noastră: dacă ar pica rularea,
 *   comanda ar fi roșie mereu pe orice server care nu poate pregăti ceva, și ar
 *   înceta să mai însemne ceva. Tot nu înseamnă „bune", și de-aia se tipărește
 *   pe linia ei și în sumar. Pe MariaDB 11.8.8 (măsurat, 15 august 2026) niciuna
 *   dintre instrucțiunile livrate nu iese așa — nici măcar cele două
 *   `CREATE TRIGGER`, despre care fișierul ăsta prezicea contrariul.
 * * lista goală → **eșec**. N-a fost probat nimic; vezi `allParsed`.
 */
export function syntaxExitCode(verdicts: SyntaxVerdict[]): number {
  if (verdicts.length === 0) return 1;
  return verdicts.some((v) => v.status === "rejected" || v.status === "unknown") ? 1 : 0;
}
