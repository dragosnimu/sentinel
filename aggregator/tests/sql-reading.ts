/**
 * Citirea instrucțiunii, pentru dublurile de test.
 *
 * Regula din care iese fișierul ăsta: **un dublu nu reimplementează SQL-ul, îl
 * citește.** Un dublu care leagă parametrii după o ordine presupusă găsește
 * exact ce se aștepta să găsească — deci o coloană mutată, un `WHERE` pierdut
 * sau un `COALESCE` șters trec verzi. Cele mai multe defecte prinse în
 * `aggregator/` de la E2.3 încoace au fost prinse fiindcă dublul s-a uitat la
 * text: filtrul de instanță din `COUNT`, `GREATEST` pe cursor, `UTC_TIMESTAMP`
 * față de ora sesiunii.
 *
 * Scos într-un fișier comun fiindcă a doua copie a unui cititor de instrucțiuni
 * e a doua șansă ca cele două să difere — iar atunci un test ar trece pe o formă
 * pe care celălalt o refuză, fără ca nimic să spună de ce.
 *
 * Nu e un parser de SQL și nu încearcă să fie. Cunoaște EXACT formele pe care le
 * emite codul din `lib/`; orice altceva aruncă, fiindcă un dublu care ghicește o
 * expresie necunoscută poate inventa chiar purtarea pe care testul o caută.
 */

import assert from "node:assert/strict";

export type Row = Record<string, unknown>;

/**
 * Valoarea unei coloane, scrisă în forma pe care dublul o COMPARĂ.
 *
 * Există fiindcă `String(buffer)` decodează octeții ca UTF-8: octeții invalizi
 * devin caracterul de înlocuire, deci doi digești distincți pot ieși ca același
 * text. Iar `actor_attrs.value_hash` e `BINARY(32)` — octeți oarecare — ȘI e
 * membru al cheii unice. Un dublu care nu-i deosebește ar declara idempotență
 * exact acolo unde MariaDB ar vedea două rânduri, adică ar face verde chiar
 * defectul pe care testele de la #66 îl caută.
 *
 * Hexa e injectivă, spre deosebire de decodare. Prefixul spune că valoarea e
 * binară; el nu e o garanție împotriva unui ȘIR scris la fel — dar diferența
 * dintre un digest și textul „0x…" nu e o întrebare pe care o pune vreo tabelă
 * din schemă.
 */
export function cell(value: unknown): string {
  return Buffer.isBuffer(value) ? `0x${value.toString("hex")}` : String(value);
}

/** Ce întoarce `UTC_TIMESTAMP(6)` în dubluri. Fix, ca să fie recunoscibil. */
export const FAKE_NOW = "2026-08-15 10:00:00.000000";

/**
 * Conținutul unei paranteze, până la PERECHEA ei.
 *
 * Numărare de adâncime, nu „primul `)`": `UTC_TIMESTAMP(6)` are unul înăuntru,
 * iar tăiatul acolo ar face dublul să citească altceva decât scrie
 * instrucțiunea — adică exact greșeala pe care dublul există ca s-o prindă,
 * făcută de el însuși.
 */
export function parenGroup(text: string, open: number): string {
  assert.equal(text[open], "(", `nu începe cu paranteză: ${text.slice(open, open + 20)}`);
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")" && --depth === 0) return text.slice(open + 1, i);
  }
  throw new Error(`paranteză neînchisă în: ${text}`);
}

/** Împarte la virgulele de la adâncime zero. */
export function splitTop(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of text) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "," && depth === 0) { out.push(current.trim()); current = ""; continue; }
    current += ch;
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

export function splitOnce(text: string, sep: string): [string, string] {
  const at = text.indexOf(sep);
  return [text.slice(0, at).trim(), text.slice(at + 1).trim()];
}

/**
 * O expresie din instrucțiune, evaluată. Formele necunoscute ARUNCĂ.
 *
 * `incoming` e rândul pe care instrucțiunea încearcă să-l insereze — de el are
 * nevoie `VALUES(col)`, forma prin care un upsert spune „ia valoarea nouă".
 */
export function evaluate(
  expression: string, existing: Row | undefined, take: () => unknown,
  incoming?: Row,
): unknown {
  // `VALUES(col)` — valoarea din rândul care se insera, nu cea stocată. MariaDB
  // n-are forma cu alias de rând (`AS new`) din MySQL 8.0.19+, deci asta e
  // ortografia pe care o emite `lib/ingest.ts` pentru fluxurile mutabile.
  const fromValues = /^VALUES\((\w+)\)$/.exec(expression);
  if (fromValues) {
    if (!incoming) {
      throw new Error(`dublu: VALUES(${fromValues[1]}) fără rândul care se inserează`);
    }
    return incoming[fromValues[1]];
  }
  return evaluateSimple(expression, existing, take);
}

function evaluateSimple(
  expression: string, existing: Row | undefined, take: () => unknown,
): unknown {
  if (expression === "?") return take();
  if (expression === "UTC_TIMESTAMP(6)") return FAKE_NOW;
  if (expression === "NULL") return null;
  if (/^\d+$/.test(expression)) return Number(expression);
  const quoted = /^'([a-z_]+)'$/.exec(expression);
  if (quoted) return quoted[1];

  // `COALESCE(col, UTC_TIMESTAMP(6))` — se scrie o dată, apoi se păstrează.
  const coalesceNow = /^COALESCE\(([a-z_]+), UTC_TIMESTAMP\(6\)\)$/.exec(expression);
  if (coalesceNow) return existing?.[coalesceNow[1]] ?? FAKE_NOW;

  // `COALESCE(col, ?)` — păstrează ce era, dacă nu e NULL.
  const coalesceParam = /^COALESCE\(([a-z_]+), \?\)$/.exec(expression);
  if (coalesceParam) {
    const incoming = take();
    return existing?.[coalesceParam[1]] ?? incoming;
  }

  // `GREATEST(COALESCE(col, 0), COALESCE(?, 0))` — cursor monoton.
  const greatest =
    /^GREATEST\(COALESCE\(([a-z_]+), 0\), COALESCE\(\?, 0\)\)$/.exec(expression);
  if (greatest) {
    const incoming = Number(take() ?? 0);
    return Math.max(Number(existing?.[greatest[1]] ?? 0), incoming);
  }

  throw new Error(`dublu: expresie neprevăzută: ${expression}`);
}

export type MultiRowInsert = {
  table: string;
  columns: string[];
  /** Câți parametri consumă un rând. Restul valorilor sunt literali din text. */
  rows: Row[];
  /** Atribuirile din `ON DUPLICATE KEY UPDATE`, în ordine. Gol = `INSERT IGNORE`. */
  updates: [string, string][];
  ignore: boolean;
};

/**
 * Un `INSERT` cu MAI MULTE rânduri, citit din text.
 *
 * Ăsta e felul în care ingestia scrie: `rânduri × coloane` parametri într-o
 * singură instrucțiune, cu sau fără ramură de actualizare. Dublul citește
 * coloanele și tuplurile din INSTRUCȚIUNE, nu le presupune — o coloană mutată
 * sau un parametru în plus se văd aici, nu peste o lună în date.
 */
export function readMultiRowInsert(sql: string, params: unknown[]): MultiRowInsert {
  const table = /^INSERT (?:IGNORE )?INTO (\w+) \(/.exec(sql);
  assert.ok(table, `nu recunosc forma instrucțiunii: ${sql.slice(0, 60)}`);
  const columns = splitTop(parenGroup(sql, sql.indexOf("(")));
  const at = sql.indexOf("VALUES");
  const firstTuple = splitTop(parenGroup(sql, sql.indexOf("(", at)));
  assert.equal(columns.length, firstTuple.length,
               `INSERT cu ${columns.length} coloane și ${firstTuple.length} valori`);

  const perRow = firstTuple.filter((v) => v === "?").length;
  assert.ok(perRow > 0, "instrucțiune fără niciun parametru");
  assert.equal(params.length % perRow, 0,
               `${params.length} parametri nu se împart la ${perRow}`);

  const rows: Row[] = [];
  for (let i = 0; i < params.length; i += perRow) {
    const slice = params.slice(i, i + perRow);
    let next = 0;
    const row: Row = {};
    firstTuple.forEach((value, index) => {
      row[columns[index]] = value === "?"
        ? slice[next++]
        : evaluateSimple(value, undefined, () => { throw new Error("parametru neașteptat"); });
    });
    rows.push(row);
  }

  const updates: [string, string][] = [];
  const clause = sql.indexOf("ON DUPLICATE KEY UPDATE");
  if (clause > 0) {
    for (const assignment of splitTop(sql.slice(clause + "ON DUPLICATE KEY UPDATE".length))) {
      updates.push(splitOnce(assignment, "="));
    }
  }
  return { table: table[1], columns, rows, updates,
           ignore: /^INSERT IGNORE /.test(sql) };
}

/**
 * Aplică un `INSERT ... ON DUPLICATE KEY UPDATE` citit din text.
 *
 * Ordinea consumării parametrilor e cea a MariaDB: lista `VALUES` întâi, apoi
 * clauza de actualizare. Un dublu care le-ar lua invers ar lega valori la
 * coloane greșite fără ca nimic să pară stricat.
 */
export function applyUpsert(
  sql: string, params: unknown[], existing: Row | undefined,
): Row {
  const columns = splitTop(parenGroup(sql, sql.indexOf("(")));
  const values = splitTop(parenGroup(sql, sql.indexOf("(", sql.indexOf("VALUES"))));
  assert.equal(columns.length, values.length,
               `INSERT cu ${columns.length} coloane și ${values.length} valori`);

  let next = 0;
  const take = () => params[next++];

  const at = sql.indexOf("ON DUPLICATE KEY UPDATE");

  if (!existing) {
    const row: Row = {};
    values.forEach((value, i) => { row[columns[i]] = evaluate(value, undefined, take); });
    // Parametrii ramurii de actualizare se leagă chiar dacă inserarea nu se
    // ciocnește de nimic: sunt în instrucțiune, deci driverul îi consumă. Un
    // dublu care i-ar ignora ar accepta o instrucțiune cu numărul greșit de
    // parametri, iar aia pică abia pe server.
    if (at > 0) {
      for (const assignment of splitTop(sql.slice(at + "ON DUPLICATE KEY UPDATE".length))) {
        evaluate(splitOnce(assignment, "=")[1], undefined, take);
      }
    }
    assert.equal(next, params.length, `parametri nefolosiți: ${sql}`);
    return row;
  }

  values.forEach((value) => { if (value === "?") take(); });
  assert.ok(at > 0, `rând existent, dar instrucțiunea n-are ramură de actualizare: ${sql}`);
  const patch: Row = {};
  for (const assignment of splitTop(sql.slice(at + "ON DUPLICATE KEY UPDATE".length))) {
    const [column, expression] = splitOnce(assignment, "=");
    patch[column] = evaluate(expression, existing, take);
  }
  assert.equal(next, params.length, `parametri nefolosiți: ${sql}`);
  return { ...existing, ...patch };
}

/** Împarte la un separator de la adâncimea zero (`" AND "`, de pildă). */
function splitTopOn(text: string, separator: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (depth === 0 && text.startsWith(separator, i)) {
      out.push(current.trim());
      current = "";
      i += separator.length - 1;
      continue;
    }
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    current += ch;
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

export type DeleteFilter = { columns: string[]; tuples: unknown[][]; negated: boolean };
export type ParsedDelete = {
  table: string;
  /** `null` dacă instrucțiunea NU filtrează pe instanță — vezi `readDelete`. */
  instance: unknown | null;
  filters: DeleteFilter[];
};

/**
 * Un `DELETE` de curățare a sub-rândurilor, citit din text.
 *
 * Ca peste tot aici: coloanele, tuplurile și NEGAREA vin din instrucțiune, nu
 * dintr-o formă presupusă. Negarea e chiar bucata care nu se poate presupune —
 * un dublu care ar trata `NOT IN` ca `IN` ar șterge exact sub-rândurile trimise
 * și ar păstra gunoiul, adică ar face verde reparația inversată.
 *
 * Filtrul de INSTANȚĂ e opțional în tipar, la fel ca în numărătoare și din
 * același motiv: un dublu care l-ar presupune n-ar putea arăta niciodată ce face
 * un `DELETE` fără el — și anume să șteargă sub-rândurile ALTUI server, care nu
 * se mai întorc, fiindcă cursorul lui a trecut demult peste ele.
 */
export function readDelete(sql: string, params: unknown[]): ParsedDelete {
  const head = /^DELETE FROM (\w+) WHERE (instance_id = \? AND )?/.exec(sql);
  assert.ok(head, `nu recunosc forma instrucțiunii: ${sql.slice(0, 80)}`);
  let next = 0;
  const take = () => params[next++];
  const instance = (head as RegExpExecArray)[2] === undefined ? null : take();

  const filters: DeleteFilter[] = [];
  for (const clause of splitTopOn(sql.slice((head as RegExpExecArray)[0].length), " AND ")) {
    const parsed =
      /^(?:\(([\w, ]+)\)|(\w+)) (NOT )?IN \(([\s\S]*)\)$/.exec(clause);
    assert.ok(parsed, `predicat necunoscut într-un DELETE: ${clause}`);
    const [, multi, single, negated, list] = parsed as RegExpExecArray;
    const columns = multi !== undefined
      ? multi.split(",").map((c) => c.trim())
      : [single];
    const tuples: unknown[][] = [];
    for (const entry of splitTop(list)) {
      if (columns.length === 1) {
        assert.equal(entry, "?", `valoare literală într-un DELETE: ${entry}`);
        tuples.push([take()]);
        continue;
      }
      const inner = splitTop(parenGroup(entry, 0));
      assert.equal(inner.length, columns.length,
                   `tuplu cu ${inner.length} valori pentru ${columns.length} coloane`);
      tuples.push(inner.map((value) => {
        assert.equal(value, "?", `valoare literală într-un DELETE: ${value}`);
        return take();
      }));
    }
    filters.push({ columns, tuples, negated: negated !== undefined });
  }
  assert.equal(next, params.length, `parametri nefolosiți: ${sql}`);
  return { table: (head as RegExpExecArray)[1], instance, filters };
}

/**
 * Numele coloanelor declarate de un `CREATE TABLE`, citite din textul livrat.
 *
 * Din ea iese garda care ar fi prins #62 din prima zi: dublul refuză un `INSERT`
 * care numește o coloană pe care tabela nu o are. `received_at` emis într-o
 * tabelă de legătură nu se vede nici în rândul stocat, nici în numărătoare — pe
 * MariaDB e „Unknown column in 'field list'", iar aici era, până acum, tăcere.
 *
 * Se taie la virgulele de la nivelul de sus, DUPĂ ce se scot literalii de șir: un
 * `COMMENT 'a, b'` sau un `ENUM('x','y')` ar rupe altfel declarația în două.
 * Liniile care încep cu un cuvânt-cheie de constrângere nu sunt coloane.
 */
const NOT_A_COLUMN = /^(PRIMARY|UNIQUE|KEY|INDEX|CONSTRAINT|FOREIGN|FULLTEXT|SPATIAL|CHECK)\b/i;

export function tableColumns(createSql: string): string[] {
  const text = createSql.replace(/'[^']*'/g, "''");
  const body = parenGroup(text, text.indexOf("("));
  const out: string[] = [];
  for (const part of splitTop(body)) {
    if (NOT_A_COLUMN.test(part)) continue;
    const words = part.split(/\s+/);
    if (words.length < 2 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(words[0])) continue;
    if (!/^[A-Za-z]/.test(words[1])) continue;
    out.push(words[0]);
  }
  return out;
}

/**
 * TIPUL declarat al unei coloane, din textul unui `CREATE TABLE`.
 * `undefined` dacă tabela n-o are.
 *
 * `tableColumns` de mai sus citește doar NUMELE, iar pata oarbă aia e scrisă în
 * `lib/streams.ts`: nimic din suită nu putea spune că `value_hash` chiar e
 * `BINARY(32)`, deci `byteLength: 32` din declarația unui `HashedColumn` era o
 * intenție, nu un fapt. Numărul ăla decide dacă un digest intră întreg sau
 * completat cu zerouri — și `BINARY(n)` nu refuză, ci potrivește tăcut —, deci
 * trebuie citit din fișierul livrat.
 *
 * Se întoarce al doilea cuvânt al declarației, cu literalii scoși ca în
 * `tableColumns`: `BINARY(32)`, `TEXT`, `DATETIME(6)`. Nu e un parser de tipuri
 * și nu normalizează nimic — cine compară scrie forma exact cum e în migrație.
 *
 * ## NU e `columnTypeAnyCase` din `tests/schema.test.ts`, și nu se unifică
 *
 * Cealaltă răspunde la altă întrebare — „**apare** coloana asta, oricum ar fi
 * scrisă?" —, deci potrivește numele INSENSIBIL la majuscule, fiindcă de asta
 * atârnă garda care ține harta de infrastructură (`webroot`, `repo_path`) în
 * afara replicii: pentru MariaDB `WebRoot` e aceeași coloană, iar o potrivire
 * sensibilă ar fi ocolită de o singură majusculă.
 *
 * Asta răspunde la „ce **tip** are, exact?", pentru comparat cu `BINARY(32)`.
 * Cele două au stat o vreme cu același nume, cu apelanți disjuncți; o „unificare"
 * spre varianta de aici ar redeschide tăcut scurgerea. Dacă vreodată se unifică,
 * se unifică spre insensibilitate — și aserțiunea care o probează e în testul
 * „coloanele care NU pleacă din `assets` nu există în schema replicii".
 */
export function columnType(createSql: string, column: string): string | undefined {
  const text = createSql.replace(/'[^']*'/g, "''");
  const body = parenGroup(text, text.indexOf("("));
  for (const part of splitTop(body)) {
    if (NOT_A_COLUMN.test(part)) continue;
    const words = part.split(/\s+/);
    if (words.length < 2 || words[0] !== column) continue;
    if (!/^[A-Za-z]/.test(words[1])) continue;
    return words[1].toUpperCase();
  }
  return undefined;
}

/**
 * Coloanele cheii unice, citite din textul unui `CREATE TABLE`.
 *
 * E singurul loc din suită care spune ce înseamnă „același rând" pentru o
 * tabelă, iar răspunsul vine din fișierul livrat, nu dintr-o listă ținută în
 * paralel. Îl folosesc două lucruri care trebuie să nu se contrazică: garda din
 * `tests/schema.test.ts`, care compară cheia cu identitatea declarată a
 * fluxului, și dublul din `tests/sync-harness.ts`, care ține rândurile pe cheia
 * asta — deci un flux care s-ar înregistra cu altă identitate decât cea din
 * schemă nu doar că pică garda, ci și scrie peste rânduri în dublu.
 */
export function uniqueKeyColumns(createSql: string): string[] {
  const inline = /UNIQUE KEY \w+ \(([^)]*)\)/.exec(createSql.replace(/'[^']*'/g, "''"));
  if (!inline) return [];
  return inline[1].replace(/\s+/g, "").split(",");
}
