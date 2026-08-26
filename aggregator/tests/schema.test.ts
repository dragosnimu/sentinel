/**
 * Schema livrată: ce se poate afirma despre ea de pe o mașină fără MariaDB.
 *
 * ## Ce sunt testele astea, exact
 *
 * Fișierele SQL de aici **nu au fost executate de niciun server** în momentul
 * scrierii lor. Testele de mai jos sunt de două feluri, și diferența e scrisă
 * ca să nu fie citită greșit:
 *
 *   * **parsare reală** — `discover()` și `splitStatements()` chiar rulează
 *     peste fișierele livrate. Ce dovedesc: că fiecare instrucțiune are exact o
 *     gardă, că gărzile sunt bine formate, că nu există `DELIMITER`, că nimic nu
 *     e trunchiat. Astea sunt fapte.
 *   * **aserțiuni pe TEXT** — „nu apare `FOREIGN KEY`", „`at` e DATETIME".
 *     Apără DECIZII de proiectare împotriva ștergerii lor la un refactor. NU
 *     dovedesc că MariaDB acceptă fișierul; pentru asta există
 *     `npm run migrate -- --syntax-check`, care cere serverului să-l analizeze.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

import { BOOTSTRAP_FILE, MIGRATIONS_DIR, discover } from "../lib/migrate";
import { allStreams, linkTables } from "../lib/streams";
import { splitStatements } from "../lib/sql-statements";
import { tableColumns } from "./sql-reading";
import type { Statement } from "../lib/sql-statements";

const shipped = () => discover();
const core = () => shipped()[0];
const coreText = () =>
  readFileSync(path.join(MIGRATIONS_DIR, "0001_core.sql"), "utf8");

test("fișierele livrate se parsează, iar fiecare instrucțiune are o gardă", () => {
  // Parsare reală. Un fișier care nu se poate încărca ar fi descoperit abia pe
  // gazdă, în mijlocul unei instalări.
  //
  // Testul ăsta NU numără migrațiile. A numărat, o fază întreagă: `assert.equal(
  // migrations.length, 1, "așteptam o singură migrație în faza asta")`. E o
  // aserțiune care fixează un număr despre care se știe că va crește, deci
  // singurul lucru pe care îl măsoară e „faza nu s-a mișcat" — iar când se
  // mișcă, pică fără să se fi stricat nimic, și cineva o „repară" punând 2.
  // Ce trebuie apărat e PROPRIETATEA din titlu, și ea trebuie să țină pentru
  // fiecare fișier livrat, inclusiv pentru cele care nu existau când s-a scris.
  const migrations = shipped();
  for (const migration of migrations) {
    assert.ok(migration.statements.length > 0,
              `${migration.file}: fișier fără nicio instrucțiune — o migrație ` +
              "care nu face nimic, consemnată ca aplicată");
    for (const stmt of migration.statements) {
      // Garda e obligatorie prin parser (o instrucțiune fără ea e eroare de
      // încărcare), dar se afirmă și aici: proprietatea din titlu nu are voie să
      // depindă doar de faptul că altcineva aruncă.
      assert.ok(stmt.guard && typeof stmt.guard.kind === "string",
                `${migration.file} #${stmt.index}: gardă lipsă sau malformată`);
      if (stmt.guard.kind === "none") {
        // `guard none` se consemnează cu `verified = 0`, deci motivul e singurul
        // lucru care rămâne despre ce n-a fost dovedit.
        assert.ok(stmt.guard.reason,
                  `${migration.file} #${stmt.index}: "guard none" fără motiv`);
      }
    }
  }

  const bootstrap = splitStatements(
    readFileSync(path.join(MIGRATIONS_DIR, BOOTSTRAP_FILE), "utf8"), BOOTSTRAP_FILE);
  assert.equal(bootstrap.length, 1);
  assert.deepEqual(bootstrap[0].guard, { kind: "table", table: "schema_version" });
});

/** Obiectul pe care îl creează o instrucțiune, dedus din textul ei. */
function objectOf(stmt: Statement): string {
  const table = /^CREATE TABLE (?:IF NOT EXISTS )?([A-Za-z_][A-Za-z0-9_]*)\b/.exec(stmt.sql);
  if (table) return `table:${table[1]}`;
  const index = /^CREATE (?:UNIQUE )?INDEX ([A-Za-z_][A-Za-z0-9_]*) ON ([A-Za-z_][A-Za-z0-9_]*)\b/
    .exec(stmt.sql);
  if (index) return `index:${index[2]}.${index[1]}`;
  const trigger = /^CREATE TRIGGER ([A-Za-z_][A-Za-z0-9_]*)\b/.exec(stmt.sql);
  if (trigger) return `trigger:${trigger[1]}`;
  // `ALTER TABLE … ADD COLUMN` e prima formă care nu CREEAZĂ un obiect nou, ci
  // adaugă unul într-unul existent. Garda potrivită e `column <tabelă> <nume>`,
  // pe care runner-ul o știe deja (caută în `information_schema.COLUMNS`), și e
  // singura care face reluarea sigură: fără ea, o migrație reluată după o cădere
  // ar muri pe „Duplicate column name".
  const added = /^ALTER TABLE ([A-Za-z_][A-Za-z0-9_]*) ADD COLUMN ([A-Za-z_][A-Za-z0-9_]*)\b/
    .exec(stmt.sql);
  if (added) return `column:${added[1]}.${added[2]}`;
  // „Nu recunosc" nu e „e în regulă": o instrucțiune de altă formă trebuie să
  // pice testul ăsta până când cineva decide ce gardă i se potrivește.
  return `NECUNOSCUT: ${stmt.sql.slice(0, 60)}`;
}

/** Ce obiect declară garda. */
function guardObject(stmt: Statement): string {
  const g = stmt.guard;
  switch (g.kind) {
    case "table": return `table:${g.table}`;
    case "index": return `index:${g.table}.${g.name}`;
    case "column": return `column:${g.table}.${g.name}`;
    case "trigger": return `trigger:${g.name}`;
    case "none": return "none";
  }
}

/**
 * Instrucțiunile care NU creează niciun obiect, ci schimbă un ATRIBUT al unuia
 * care există deja. Recensământ ÎNCHIS: `fișier#index` → ce schimbă.
 *
 * De ce nu o formă recunoscută în `objectOf`: un tipar care ar accepta orice
 * `ALTER TABLE … MODIFY COLUMN` ar scuti de gardă și o schimbare de TIP, tăcut.
 * Aici, orice instrucțiune de altă formă decât cele create rămâne roșie până
 * când cineva o scrie mai jos — iar scrierea ei aici e declarația.
 *
 * Și de ce n-au altă gardă decât `none`: `guardPresent` întreabă
 * `information_schema` dacă un OBIECT există. O colație și un comentariu sunt
 * atribute ale unui obiect care există deja, deci o gardă `table`/`column` ar
 * fi MAI RĂU decât niciuna — obiectul e acolo, instrucțiunea s-ar sări pentru
 * totdeauna cu `note = 'reconciled'`, și nimic n-ar rula vreodată. `none` se
 * consemnează cu `verified = 0`: „a rulat, n-am putut dovedi efectul".
 */
const ATTRIBUTE_ONLY: Record<string, string> = {
  "0009_auth_bounds.sql#2": "colația și comentariul lui login_attempts.username",
  "0009_auth_bounds.sql#3": "COMMENT-ul tabelei login_attempts: pragul de 15 minute",
  "0009_auth_bounds.sql#4": "COMMENT-ul lui users.failed_attempts, coloană inertă",
  "0009_auth_bounds.sql#5": "COMMENT-ul lui users.locked_until, coloană inertă",
};

test("garda fiecărei instrucțiuni numește obiectul pe care îl creează", () => {
  // Eșecul pe care îl previne: o gardă care numește alt obiect. Dacă numește
  // unul care există, instrucțiunea se sare pentru totdeauna și obiectul ei nu
  // se creează niciodată — cu registrul spunând că e aplicată. Dacă numește
  // unul care nu apare niciodată, migrația se oprește la fiecare rulare.
  //
  // Peste TOATE migrațiile livrate, nu doar peste prima: o verificare legată de
  // `shipped()[0]` ar fi lăsat fiecare fișier nou fără nicio pază, tăcut.
  let checked = 0;
  const declared: string[] = [];
  for (const migration of shipped()) {
    for (const stmt of migration.statements) {
      const key = `${migration.file}#${stmt.index}`;
      if (key in ATTRIBUTE_ONLY) {
        declared.push(key);
        assert.equal(guardObject(stmt), "none",
                     `${key}: declarată ca schimbare de atribut, dar poartă o gardă ` +
                     "care pretinde că un obiect se creează — obiectul există deja, " +
                     "deci instrucțiunea s-ar sări pentru totdeauna");
        assert.match(stmt.sql, /^ALTER TABLE \w+ (MODIFY COLUMN \w+ |COMMENT = ')/,
                     `${key}: declarată ca schimbare de atribut, dar nu are forma ` +
                     "unei schimbări de atribut");
        checked++;
        continue;
      }
      assert.equal(guardObject(stmt), objectOf(stmt),
                   `${migration.file} #${stmt.index} (linia ${stmt.line}): garda și ` +
                   "instrucțiunea vorbesc despre obiecte diferite");
      checked++;
    }
  }
  // O intrare moartă pică la fel ca una lipsă: o scutire pentru o instrucțiune
  // care nu mai există e o scutire care într-o zi acoperă altceva.
  assert.deepEqual(declared.sort(), Object.keys(ATTRIBUTE_ONLY).sort(),
                   "instrucțiunile fără obiect nu sunt exact cele declarate în " +
                   "ATTRIBUTE_ONLY");
  // Bucla goală ar trece verde — chiar tiparul din CLAUDE.md.
  assert.ok(checked >= 6, `doar ${checked} instrucțiuni verificate`);
});

/** Tipul dintr-o declarație de coloană: tot ce e înaintea primului atribut. */
function typeOf(declaration: string): string {
  const words = declaration.trim().split(/\s+/);
  const out: string[] = [];
  for (const word of words) {
    if (/^(NOT|NULL|DEFAULT|COMMENT|CHARACTER|COLLATE|AUTO_INCREMENT)$/i.test(word)) break;
    out.push(word);
  }
  assert.ok(out.length, `nu pot citi tipul din: ${declaration}`);
  return out.join(" ");
}

test("un `MODIFY COLUMN` repetă definiția întreagă, nu doar bucata schimbată", () => {
  // Eșecul pe care îl previne, și e tăcut de la un capăt la altul: MariaDB
  // rescrie DEFINIȚIA coloanei, nu o peticește. O migrație scrisă ca să adauge
  // un `COMMENT` și care uită `NOT NULL DEFAULT 0` face coloana nulabilă fără
  // nicio eroare, iar `users.failed_attempts` e citită de orice unealtă de
  // administrare care se uită în tabelă.
  //
  // Se compară cu declarația din `CREATE TABLE`, nu cu o listă scrisă aici: o
  // listă ar fi a doua sursă de adevăr, și s-ar învechi tăcut.
  let checked = 0;
  for (const migration of shipped()) {
    for (const stmt of migration.statements) {
      const parsed = /^ALTER TABLE (\w+) MODIFY COLUMN (\w+) (.+?);?$/.exec(stmt.sql);
      if (!parsed) continue;
      const [, table, column, definition] = parsed;
      const where = `${migration.file} #${stmt.index}: ${table}.${column}`;
      const declared = columnDeclaration(tableSql(table), column);
      assert.ok(declared, `${where}: nu găsesc coloana în CREATE TABLE-ul ei`);
      const original = (declared as string).slice(column.length).trim();

      assert.ok(definition.startsWith(typeOf(original)),
                `${where}: tipul rescris (${definition.slice(0, 40)}…) nu începe cu ` +
                `cel din CREATE TABLE (${typeOf(original)})`);
      if (/\bNOT NULL\b/.test(original)) {
        assert.match(definition, /\bNOT NULL\b/,
                     `${where}: era NOT NULL și rescrierea nu o mai spune — coloana ` +
                     "devine nulabilă, fără nicio eroare");
      }
      const implicit = /\bDEFAULT (\S+)/.exec(original);
      if (implicit) {
        assert.ok(definition.includes(`DEFAULT ${implicit[1]}`),
                  `${where}: implicitul ${implicit[1]} s-a pierdut la rescriere`);
      }
      checked++;
    }
  }
  // Bucla goală ar trece verde — chiar tiparul din CLAUDE.md.
  assert.ok(checked >= 3, `doar ${checked} instrucțiuni MODIFY COLUMN verificate`);
});

test("cele patru tabele ale fazei există, sub numele din plan", () => {
  const objects = core().statements.map(objectOf);
  for (const name of ["instances", "audit_entries", "sync_cursors"]) {
    assert.ok(objects.includes(`table:${name}`), `lipsește tabela ${name}: ${objects}`);
  }
  // A patra, `schema_version`, e în bootstrap — singura care nu se poate
  // consemna în registrul pe care îl creează.
});

test("NICIO cheie străină", () => {
  // Cursoarele avansează independent pe flux, deci o detecție poate ajunge
  // legitim înaintea incidentului ei. Cu o cheie străină, ordinea aia —
  // normală, nu excepțională — respinge rândul, iar rândul respins nu se mai
  // întoarce: expeditorul primește ecoul doar pentru ce a intrat. Se stochează
  // referințe atârnate și se reconciliază.
  //
  // Peste TOATE migrațiile livrate: legată de `shipped()[0]`, verificarea ar fi
  // lăsat fiecare fișier nou fără nicio pază — iar `0003_entities.sql` e chiar
  // locul unde tentația e mare, fiindcă acolo entitățile chiar se referă una
  // la alta.
  const offenders: string[] = [];
  let scanned = 0;
  for (const migration of shipped()) {
    for (const stmt of migration.statements) {
      scanned++;
      if (/FOREIGN KEY|REFERENCES [A-Za-z_]/i.test(stmt.sql)) {
        offenders.push(`${migration.file} #${stmt.index} linia ${stmt.line}`);
      }
    }
  }
  assert.deepEqual(offenders, [], `chei străine în schema replicii: ${offenders}`);
  assert.ok(scanned >= 20, `doar ${scanned} instrucțiuni scanate`);
});

test("identitatea replicată e (instance_id, source_id), și e singura unicitate", () => {
  // Pe ea stă idempotența ingestiei: același rând retrimis nimerește aceeași
  // cheie, deci o reluare e o operație nulă. Iar „singura" contează la fel de
  // mult: agregatorul e o replică, nu o a doua sursă de adevăr, și nu are voie
  // să recreeze invarianții serverului. Amprenta F deschisă, rezolvată și
  // redeschisă e istorie legitimă; o unicitate în plus ar respinge al doilea
  // rând, iar simptomul ar fi „lipsește un incident din panou".
  const audit = core().statements.find((s) => objectOf(s) === "table:audit_entries");
  assert.ok(audit, "nu găsesc tabela audit_entries");
  const uniques = [...(audit as Statement).sql.matchAll(/UNIQUE KEY (\w+) \(([^)]*)\)/g)];
  assert.equal(uniques.length, 1, `audit_entries are ${uniques.length} chei unice`);
  assert.equal(uniques[0][2].replace(/\s+/g, ""), "instance_id,source_id");
});

test("timpii sunt DATETIME, nu TIMESTAMP", () => {
  // `TIMESTAMP` se termină în 2038 și se convertește după fusul sesiunii — două
  // feluri diferite de a strica tăcut un istoric de securitate.
  for (const migration of shipped()) {
    for (const stmt of migration.statements) {
      const withoutDefaults = stmt.sql
        .replace(/CURRENT_TIMESTAMP\(6\)/g, "")
        .replace(/UTC_TIMESTAMP\(6\)/g, "");
      assert.ok(!withoutDefaults.includes("TIMESTAMP"),
                `${migration.file} #${stmt.index}: folosește TIMESTAMP`);
    }
  }
});

test("coloanele libere ale sursei nu primesc o margine inventată aici", () => {
  // `actor`, `operation`, `target`, `detail`, `result` sunt `text` nemărginit
  // în Postgres. Un `VARCHAR(n)` aici ar tăia (sau ar respinge) exact
  // conținutul care intră în `entry_hash` — iar un rând tăiat arată identic cu
  // unul falsificat când se verifică lanțul.
  const audit = core().statements.find((s) => objectOf(s) === "table:audit_entries");
  const sql = (audit as Statement).sql;
  for (const column of ["actor", "source", "operation", "target", "result"]) {
    assert.match(sql, new RegExp(`\\b${column} TEXT\\b`), `${column} nu mai e TEXT`);
  }
  assert.match(sql, /\bdetail MEDIUMTEXT\b/);
});

test("identificatorii se compară pe octeți, nu printr-o colație", () => {
  // Sub o colație insensibilă la majuscule, `Prod` și `prod` sunt același rând.
  // Regula de identificator a expeditorului acceptă litere mari, deci două
  // instanțe distincte s-ar putea ciocni într-o cheie unică — iar efectul ar fi
  // istoria a două servere amestecată sub o singură identitate.
  const text = coreText();
  const declarations = [...text.matchAll(/\binstance_id\s+VARCHAR\(64\)([^,\n]*)/g)];
  assert.ok(declarations.length >= 3, `doar ${declarations.length} coloane instance_id`);
  for (const d of declarations) {
    assert.match(d[1], /CHARACTER SET ascii COLLATE ascii_bin/, d[0]);
  }
});

/**
 * Instrucțiunea DECLARĂ coloana asta?
 *
 * Fără expresii regulate, dinadins: `stmt.sql` vine normalizat pe o singură
 * linie (suma de control ignoră indentarea), iar o potrivire pe cuvânt ar
 * răspunde „da" și pentru un COMENTARIU care explică de ce lipsește o coloană —
 * iar fișierul chiar conține unul despre `webroot`. Deci se taie la virgulele de
 * la nivelul de sus și se cere ca o bucată să ÎNCEAPĂ cu numele, urmat de un tip.
 */
function declaresColumn(sql: string, column: string): boolean {
  return columnTypeAnyCase(sql, column) !== null;
}

/**
 * Tipul cu care e declarată o coloană, sau `null` dacă tabela nu o declară.
 *
 * Comparație INSENSIBILĂ LA MAJUSCULE: pentru MySQL, `WebRoot` și `webroot` sunt
 * același identificator. O gardă care se uită doar la varianta cu litere mici e
 * ocolită de o singură majusculă — măsurat, `WebRoot TEXT NULL` trecea.
 *
 * ## De ce NU e `columnType` din `tests/sql-reading.ts` (#66)
 *
 * Fiindcă răspund la două întrebări diferite, și numele identic era o capcană:
 * cele două au stat o vreme cu ACELAȘI nume și purtări diferite, apelate din
 * fișiere disjuncte, adică exact „a doua copie a unui cititor de instrucțiuni"
 * împotriva căreia e scris `tests/sql-reading.ts`.
 *
 *   * asta întreabă „**apare** coloana asta, oricum ar fi scrisă?" — deci
 *     potrivirea e insensibilă la majuscule, fiindcă întrebarea e despre ce
 *     acceptă MariaDB, iar o singură majusculă ar ocoli garda de mai jos;
 *   * cealaltă întreabă „ce **tip** are coloana asta, exact?" — deci potrivirea
 *     e pe numele scris, scoate literalii înainte de tăiere și întoarce tipul cu
 *     majuscule, ca `BINARY(32)` să se poată compara cu o declarație.
 *
 * Cine le unifică „în direcția evidentă" — cea care întoarce tipul — pierde
 * insensibilitatea, iar ce se redeschide tăcut e scurgerea hărții de
 * infrastructură: `WebRoot TEXT NULL` trece iar. De-aia insensibilitatea nu se
 * lasă pe seama docstring-ului ăstuia: e o aserțiune, în testul care depinde de
 * ea.
 *
 * ## CE NU VEDE, azi — și e o gaură, nu o margine (#88)
 *
 * Întrebarea de mai sus e „apare coloana asta, oricum ar fi SCRISĂ?", și la ea
 * răspunde doar pentru coloanele dintr-un `CREATE TABLE`, scrise fără ghilimele
 * inverse. Cititorul taie de la PRIMA paranteză (`sql.slice(sql.indexOf("(") +
 * 1)`) și se uită la primul cuvânt al fiecărei bucăți, deci pe orice altă formă
 * răspunde „nu" — și răspunde „nu" TĂCUT, ceea ce nu e același lucru cu „nu
 * știu să citesc asta". Măsurat, cu funcția asta scoasă într-un fișier separat:
 *
 *   true  | webroot    | CREATE TABLE t (id BIGINT NOT NULL, WebRoot TEXT NULL)
 *   false | webroot    | ALTER TABLE asset_entries ADD COLUMN webroot TEXT NULL
 *   false | repo_path  | ALTER TABLE asset_entries ADD COLUMN repo_path TEXT NULL
 *   false | webroot    | ALTER TABLE asset_entries MODIFY COLUMN webroot TEXT NULL
 *   false | webroot    | ALTER TABLE t ADD webroot TEXT NULL
 *   false | webroot    | CREATE TABLE t (id BIGINT NOT NULL, `webroot` TEXT NULL)
 *   false | updated_at | ALTER TABLE incident_entries ADD COLUMN updated_at DATETIME(6) NULL COMMENT '…'
 *
 * Ultimele două rânduri arată că nu e o singură cauză: la `ALTER … TEXT` nu
 * există paranteză deloc și `indexOf` dă `-1`, deci se citește toată
 * instrucțiunea și primul cuvânt e `ALTER`; la `ALTER … DATETIME(6)` paranteza
 * există, dar e a TIPULUI, deci se citește de după ea. Amândouă ies „nu".
 *
 * Ce înseamnă asta pentru garda de mai jos, pe șleau: o migrație care adaugă
 * `webroot` prin `ALTER TABLE asset_entries ADD COLUMN webroot TEXT NULL` NU e
 * văzută, iar testul „coloanele care NU pleacă din `assets` nu există în schema
 * replicii" rămâne verde. Și `ALTER TABLE … ADD COLUMN` nu e o formă exotică
 * inventată aici: e forma STABILITĂ a depozitului — `incident_entries` și-a
 * primit așa `updated_at` (`0006`) și `auto_action`/`auto_action_at` (`0007`),
 * iar `columnsOf` din fișierul ăsta o citește tocmai fiindcă altfel ar răspunde
 * despre altă schemă decât cea livrată.
 *
 * Riscul celălalt — că despicătorul pe virgule nu scoate literalii de șir, deci
 * un `COMMENT '…, webroot TEXT …'` ar da un fals POZITIV — e real, dar e cel
 * ZGOMOTOS: se vede ca test roșu. Ăsta e cel tăcut, și de-aia e scris aici.
 *
 * De ce nu e reparat în aceeași schimbare: reparația nu e „încă o formă de
 * ALTER" — enumerarea formelor de SQL nu se termină mai bine decât enumerarea
 * normalizărilor. Forma corectă e cea pe care `columnsOf` o are deja, la câteva
 * zeci de linii mai jos: se recunosc formele CUNOSCUTE și se PICĂ zgomotos pe
 * oricare alta, ca „nu știu să citesc asta" să nu mai poată ieși ca „n-are
 * nimic". Aia e o schimbare de proiectare a unei gărzi de securitate, și e #88.
 */
function columnTypeAnyCase(sql: string, column: string): string | null {
  const body = sql.slice(sql.indexOf("(") + 1);
  for (const part of body.split(",")) {
    const words = part.trim().split(/\s+/);
    if (words.length < 2) continue;
    if (words[0].toLowerCase() !== column.toLowerCase()) continue;
    if (!/^[A-Za-z]/.test(words[1])) continue;
    return words[1];
  }
  return null;
}

/**
 * Tabelele proprii ale AGREGATORULUI. Tot ce nu e aici e o replică.
 *
 * Lista e scurtă și scrisă pe față fiindcă distincția decide ce invarianți au
 * voie să existe: pe datele proprii, agregatorul poate impune ce vrea; pe o
 * replică, unicitatea în plus respinge istorie legitimă. Adăugarea unei tabele
 * aici e o declarație, nu o formalitate.
 */
const AGGREGATOR_OWNED = new Set([
  "schema_version", "instances", "sync_cursors", "audit_chain_state",
  // Autentificarea panoului (`0008_auth.sql`). Numele coincid cu patru tabele
  // de pe serverul monitorizat, iar ALEA nu pleacă niciodată de acolo — conțin
  // adresele IP ale operatorului și datele lui personale. Astea sunt ale
  // agregatorului: alți utilizatori, alte sesiuni, alt jurnal de încercări,
  // populate local. Că niciun flux nu scrie în ele nu se lasă pe seama
  // coincidenței de nume: e o aserțiune, în `tests/auth-schema.test.ts`.
  "users", "sessions", "login_attempts", "user_instances",
]);

/**
 * Textul instrucțiunii fără literalii de șir.
 *
 * `COMMENT 'ceva'` și `DEFAULT 'ceva'` sunt DATE, nu structură. Fără curățarea
 * asta, numărarea cuvântului `UNIQUE` de mai jos ar fi păcălită de un comentariu
 * care îl conține — iar comentariile de aici chiar vorbesc despre unicitate,
 * fiindcă acolo se explică de ce NU se recreează indexurile serverului.
 */
function withoutStrings(sql: string): string {
  return sql.replace(/'[^']*'/g, "''");
}

/** Tabela pe care o atinge o instrucțiune, sau `null` dacă nu se poate spune. */
function touchedTable(sql: string): string | null {
  // `IF NOT EXISTS` e opțional în tipar: bootstrap-ul îl folosește, iar o tabelă
  // pe care n-o poți atribui e o tabelă care iese din verificare.
  for (const pattern of [/^CREATE TABLE (?:IF NOT EXISTS )?(\w+)/,
                         /^CREATE (?:UNIQUE )?INDEX \w+ ON (\w+)/,
                         /^ALTER TABLE (\w+)/, /^CREATE TRIGGER \w+ [\s\S]*? ON (\w+)/]) {
    const found = pattern.exec(sql);
    if (found) return found[1];
  }
  return null;
}

type Touch = { where: string; sql: string; creates: boolean };

/**
 * Toate instrucțiunile care ating fiecare tabelă, plus tabelele CREATE.
 *
 * O instrucțiune care conține `UNIQUE` și nu se poate atribui unei tabele e ea
 * însăși un eșec: nu se poate spune despre ce vorbește, deci nu se poate spune
 * nici că e în regulă.
 */
function touchesByTable(): { created: Set<string>; touches: Map<string, Touch[]> } {
  const created = new Set<string>();
  const touches = new Map<string, Touch[]>();
  const orphans: string[] = [];

  for (const migration of shipped()) {
    for (const stmt of migration.statements) {
      const where = `${migration.file} #${stmt.index}`;
      const table = touchedTable(stmt.sql);
      if (table === null) {
        if (/\bUNIQUE\b/i.test(withoutStrings(stmt.sql))) orphans.push(where);
        continue;
      }
      const creates = /^CREATE TABLE/.test(stmt.sql);
      if (creates) created.add(table);
      touches.set(table, [...(touches.get(table) ?? []),
                          { where, sql: stmt.sql, creates }]);
    }
  }
  assert.deepEqual(orphans, [],
                   `instrucțiuni cu UNIQUE pe care nu le pot atribui unei tabele: ${orphans}`);
  return { created, touches };
}

/**
 * Coloanele unei tabele, citite din TOATE instrucțiunile care o ating.
 *
 * `CREATE TABLE` nu e singura cale prin care o tabelă capătă o coloană, și nici
 * măcar cea obișnuită după prima fază: `incident_entries` și-a primit
 * `updated_at`, `auto_action` și `auto_action_at` prin `ALTER TABLE … ADD
 * COLUMN` (`0006`, `0007`), fiindcă `0001`–`0005` sunt aplicate pe baza reală și
 * nu se mai editează.
 *
 * Citit doar din `CREATE TABLE`, recensământul de mai jos NUMĂRA GREȘIT: o
 * tabelă replicată obișnuită care își primește `received_at`/`batch_seq` printr-un
 * `ALTER` ar fi ieșit „fără contabilitatea sosirii", deci ar fi cerut un părinte
 * în `LINK_PARENTS` — iar mesajul („o tabelă nouă fără părinte declarat n-ar avea
 * cine s-o scrie") l-ar fi trimis pe următorul s-o declare tabelă de legătură.
 * Ar fi ajuns atunci scrisă ca sub-rând: fără contabilitatea sosirii pe care o
 * ARE, și cu mulțimea ei ștearsă la fiecare lot al altui flux. O gardă care se
 * înșală în direcția „sigură" tot se înșală — aceeași lecție ca la
 * `TABLE_COLUMNS` din `tests/sync-harness.ts`.
 *
 * Formele de `ALTER` pe care nu le cunoaște se REFUZĂ, nu se sar: o coloană
 * ștearsă sau redenumită printr-o formă necitită ar face numărătoarea să
 * răspundă despre o schemă care nu mai există. „Nu știu să citesc asta" și „n-are
 * nimic" sunt lucruri diferite.
 */
function columnsOf(table: string, touches: Touch[]): string[] {
  const create = touches.find((t) => t.creates);
  assert.ok(create, `${table}: nu găsesc instrucțiunea care o creează`);
  const columns = tableColumns((create as Touch).sql);
  for (const touch of touches) {
    if (touch.creates || !/^ALTER TABLE\b/.test(touch.sql)) continue;
    const added = /^ALTER TABLE \w+ ADD COLUMN (\w+)\b/.exec(touch.sql);
    assert.ok(added,
              `${touch.where}: formă de ALTER pe care recensământul de coloane nu ` +
              `o citește (${touch.sql.slice(0, 60)}…). Învață-l s-o citească — ` +
              "o formă sărită înseamnă un răspuns despre altă schemă decât cea livrată");
    columns.push((added as RegExpExecArray)[1]);
  }
  return columns;
}

/** Textul unei tabele din orice migrație livrată. */
function tableSql(name: string): string {
  for (const migration of shipped()) {
    const stmt = migration.statements.find((s) => objectOf(s) === `table:${name}`);
    if (stmt) return stmt.sql;
  }
  throw new Error(`nu găsesc tabela ${name} în nicio migrație livrată`);
}

test("coloanele care NU pleacă din `assets` nu există în schema replicii", () => {
  // Împreună, alea sunt o hartă gratuită a infrastructurii: unde stă fiecare
  // vhost, din ce depozit se desfășoară, ce baze de date există și pe ce
  // porturi. Un agregator compromis ar da recunoașterea — partea scumpă a unui
  // atac — despre un server pe care atacatorul nu l-a atins încă.
  //
  // Verificarea e pe TOATĂ schema, nu doar pe tabela de active: o coloană
  // `webroot` strecurată în altă tabelă ar scurge exact același lucru.
  const forbidden = ["vhost_file", "webroot", "repo_path", "repo_remote",
                     "repo_branch", "container_image", "databases"];

  // Cum se scrie numele în SQL nu contează, și asta se PROBEAZĂ, nu se
  // presupune: lista de mai sus e cu litere mici, migrațiile de azi la fel, deci
  // o potrivire sensibilă la majuscule ar rămâne verde până în ziua în care
  // cineva scrie altfel — iar pentru MariaDB `WebRoot` și `webroot` sunt aceeași
  // coloană. Măsurat, exact așa trecea. Aserțiunea stă aici, nu lângă
  // `columnTypeAnyCase`, fiindcă asta e garda care cade dacă insensibilitatea se
  // pierde la o „unificare" cu `columnType` din `tests/sql-reading.ts`.
  assert.ok(declaresColumn("CREATE TABLE t (id BIGINT NOT NULL, WebRoot TEXT NULL)",
                           "webroot"),
            "o singură majusculă ocolește garda: WebRoot ar intra în replică");

  // ATENȚIE, ȘI E O GAURĂ, NU O MARGINE (#88): recensământul de mai jos vede
  // DOAR coloanele dintr-un `CREATE TABLE`, scrise fără ghilimele inverse. O
  // migrație care ar adăuga `webroot` prin `ALTER TABLE asset_entries ADD
  // COLUMN webroot TEXT NULL` — forma stabilită a depozitului, vezi `0006` și
  // `0007` — trece pe lângă el, iar testul ăsta rămâne VERDE. Măsurat, cu
  // cazurile scrise cap la cap în docstring-ul lui `columnTypeAnyCase`. Deci
  // „niciun infractor" de mai jos înseamnă „niciunul în forma pe care o citesc",
  // nu „niciunul".

  const offenders: string[] = [];
  for (const migration of shipped()) {
    for (const stmt of migration.statements) {
      for (const column of forbidden) {
        if (declaresColumn(stmt.sql, column)) {
          offenders.push(`${migration.file} #${stmt.index}: ${column}`);
        }
      }
    }
  }
  assert.deepEqual(offenders, [],
                   `coloane din harta de infrastructură ajunse în replică: ${offenders}`);

  // Și jumătatea care ține testul onest: subsetul care CHIAR trebuie să plece
  // există. Altfel, o tabelă goală ar trece la fel de bine.
  const assets = tableSql("asset_entries");
  for (const column of ["name", "kind", "criticality", "is_internet_exposed",
                        "protected", "first_seen", "last_seen"]) {
    assert.ok(declaresColumn(assets, column),
                 `lipsește coloana ${column} din subsetul care pleacă`);
  }
  assert.match(tableSql("asset_tags"), /\btag\b/, "lipsește desfășurarea lui tags");
});

test("fiecare tabelă fără contabilitatea sosirii își declară părintele", () => {
  // RECENSĂMÂNT, nu recunoaștere. Întrebarea e „câte tabele replicate n-au
  // `received_at`/`batch_seq`, și sunt toate declarate drept tabele de
  // legătură?", iar răspunsul se compară ca MULȚIME, în amândouă direcțiile.
  //
  // Ce se strică fără garda asta, și s-a stricat (#62): `writeSql` emitea
  // coloanele de contabilitate necondiționat, iar cele cinci tabele de legătură
  // nu le au. Un flux înregistrat peste oricare dintre ele ar fi murit la primul
  // lot cu „Unknown column 'received_at' in 'field list'" — un mesaj care arată
  // spre o coloană, nu spre decizia de proiectare care lipsea.
  //
  // De ce nu o listă de excepții pe nume în `writeSql`: o listă e un
  // recunoscător, iar un recunoscător rămâne mereu cu o ortografie în urmă. A
  // șasea tabelă de legătură ar primi tăcut coloane care nu există. Numărătoarea
  // de aici pică în ziua în care apare, nu în ziua în care se expediază.
  const { created, touches } = touchesByTable();
  const replicated = [...created].filter((t) => !AGGREGATOR_OWNED.has(t)).sort();
  const accounted: string[] = [];
  const unaccounted: string[] = [];
  for (const table of replicated) {
    // Coloanele TABELEI, nu doar cele din `CREATE TABLE`: vezi `columnsOf`.
    const columns = columnsOf(table, touches.get(table) ?? []);
    const both = columns.includes("received_at") && columns.includes("batch_seq");
    // Una fără cealaltă n-are înțeles: contabilitatea sosirii e o pereche.
    assert.equal(columns.includes("received_at"), columns.includes("batch_seq"),
                 `${table}: are doar una dintre received_at/batch_seq`);
    (both ? accounted : unaccounted).push(table);
  }

  assert.deepEqual(unaccounted.sort(), linkTables().map(([child]) => child).sort(),
                   "tabelele replicate FĂRĂ contabilitatea sosirii nu sunt exact cele " +
                   "declarate ca tabele de legătură în `lib/streams.ts`. O tabelă nouă " +
                   "fără părinte declarat n-ar avea cine s-o scrie; una declarată și " +
                   "inexistentă e o intrare moartă");

  for (const [child, parent] of linkTables()) {
    assert.ok(accounted.includes(parent),
              `${child}: părintele declarat (${parent}) nu e o tabelă replicată cu ` +
              "contabilitate proprie a sosirii");
  }

  // Bucla goală ar trece verde, iar aici ar trece verde de două ori: două mulțimi
  // vide sunt egale. Cifrele sunt cele măsurate azi, ca praguri, nu ca egalități.
  assert.ok(unaccounted.length >= 5,
            `doar ${unaccounted.length} tabele de legătură găsite în schemă`);
  assert.ok(accounted.length >= 10,
            `doar ${accounted.length} tabele replicate cu contabilitate proprie`);
});

test("recensământul de coloane citește și ce a venit prin ALTER TABLE", () => {
  // Regula de CITIRE, declanșată izolat — ca `assertChildDeclarable` din
  // `tests/subrows.test.ts`, și din același motiv: o regulă a cărei declanșare
  // n-a fost văzută singură e o regulă despre care nu se știe pe ce pică.
  //
  // Instrucțiunile de aici sunt sintetice fiindcă forma greșită NU există în
  // migrațiile livrate — și tocmai asta o face periculoasă: recensământul citea
  // doar `CREATE TABLE`, iar prima tabelă replicată obișnuită care își primește
  // contabilitatea sosirii printr-un `ALTER` ar fi fost declarată tabelă de
  // legătură, cu mesajul gărzii drept îndrumare.
  const create: Touch = {
    where: "sintetic #1", creates: true,
    sql: "CREATE TABLE probe_entries (id BIGINT UNSIGNED NOT NULL, " +
         "instance_id VARCHAR(64) NOT NULL, PRIMARY KEY (id))",
  };
  const add = (column: string): Touch => ({
    where: `sintetic ${column}`, creates: false,
    sql: `ALTER TABLE probe_entries ADD COLUMN ${column} DATETIME(6) NULL`,
  });

  assert.deepEqual(columnsOf("probe_entries", [create]), ["id", "instance_id"]);
  assert.deepEqual(
    columnsOf("probe_entries", [create, add("received_at"), add("batch_seq")]),
    ["id", "instance_id", "received_at", "batch_seq"],
    "o coloană adăugată prin ALTER TABLE nu e văzută, deci tabela ar fi numărată " +
    "drept una fără contabilitatea sosirii");

  // Iar o formă de `ALTER` pe care nu știe s-o citească e un EȘEC, nu o
  // instrucțiune sărită: „nu știu" și „n-are nimic" sunt stări diferite.
  assert.throws(
    () => columnsOf("probe_entries", [create, {
      where: "sintetic drop", creates: false,
      sql: "ALTER TABLE probe_entries DROP COLUMN received_at",
    }]), /formă de ALTER/, "o formă necitită a fost sărită în tăcere");

  // Și forma CHIAR e folosită de schema livrată, altfel regula de deasupra ar
  // apăra un drum pe care nu merge nimeni.
  const added = shipped().flatMap((m) => m.statements)
    .filter((s) => /^ALTER TABLE \w+ ADD COLUMN/.test(s.sql));
  assert.ok(added.length >= 3,
            `doar ${added.length} coloane adăugate prin ALTER în migrațiile livrate`);
});

test("granița de date acoperă și tabelele copil, și coloanele cerute de fluxuri", () => {
  // Lista de coloane care NU pleacă din `assets` e pinuită de testul de mai sus,
  // pe SCHEMĂ. Aici se închid celelalte două drumuri prin care ar putea pleca:
  //
  //   * o tabelă de legătură strecurată cu o coloană interzisă — verificarea pe
  //     schemă le acoperă, dar nimic nu spunea că le-a VĂZUT. O regulă care a
  //     încetat să atingă tabelele copil ar trece verde la fel de bine;
  //   * un flux care CERE coloana de la server. Numele din `Column.source` e chiar
  //     ce se cere de pe gazda monitorizată; declarat `webroot`, harta
  //     infrastructurii ar pleca de acolo indiferent ce scrie în schemă.
  const forbidden = ["vhost_file", "webroot", "repo_path", "repo_remote",
                     "repo_branch", "container_image", "databases"];

  const linkNames = linkTables().map(([child]) => child);
  const { created } = touchesByTable();
  for (const table of linkNames) {
    assert.ok(created.has(table),
              `${table} e declarată tabelă de legătură, dar nicio migrație livrată ` +
              "nu o creează — deci verificarea de graniță nu se uită niciodată la ea");
    for (const column of forbidden) {
      assert.ok(!tableColumns(tableSql(table)).includes(column),
                `${table}.${column}: harta de infrastructură într-o tabelă de legătură`);
    }
  }

  const asked: string[] = [];
  const offenders: string[] = [];
  for (const stream of allStreams()) {
    const columns = [...stream.columns.map((c) => [stream.name, c] as const),
                     ...(stream.children ?? []).flatMap(
                       (child) => child.columns.map(
                         (c) => [`${stream.name}.${child.source}`, c] as const))];
    for (const [where, column] of columns) {
      asked.push(`${where}.${column.source}`);
      if (forbidden.includes(column.source) || forbidden.includes(column.target)) {
        offenders.push(`${where}: ${column.source} → ${column.target}`);
      }
    }
  }
  assert.deepEqual(offenders, [],
                   `fluxuri care cer de pe gazdă o coloană care nu pleacă: ${offenders}`);
  // Bucla goală ar trece verde — chiar tiparul din CLAUDE.md.
  assert.ok(asked.length >= 30, `doar ${asked.length} coloane cerute de fluxuri`);
  assert.ok(linkNames.length >= 5, `doar ${linkNames.length} tabele de legătură`);
});

test("indexurile unice parțiale ale serverului NU se recreează", () => {
  // `incidents_fingerprint_open_idx` și `blocklist_active_ip_idx` poartă
  // invarianți REALI pe server. Aici sunt greșite: amprenta F deschisă,
  // rezolvată și redeschisă peste două săptămâni are două rânduri `open` la
  // momente diferite, iar o adresă blocată, deblocată și blocată din nou are
  // două rânduri `active`. Unicitatea ar refuza al doilea rând, iar simptomul ar
  // fi „lipsește un incident din panou" — descoperit târziu și pus, greșit, pe
  // seama expedierii.
  //
  // MariaDB n-are indexuri parțiale, deci forma pe care ar lua-o recrearea e ori
  // o cheie unică pe coloană, ori o coloană întreținută de trigger. Se caută
  // amândouă.
  // ## De ce se NUMĂRĂ cuvântul, în loc să se recunoască construcțiile
  //
  // Versiunea dinainte enumera ortografiile prin care se poate declara o
  // unicitate — `UNIQUE KEY … (…)` în tabelă, `CREATE UNIQUE INDEX`,
  // `ALTER TABLE … ADD UNIQUE`. E o cursă pierdută: SQL are mai multe ortografii
  // decât încap într-o expresie regulată (`UNIQUE INDEX n (…)`, `UNIQUE (…)`
  // fără nume, `CONSTRAINT n UNIQUE (…)`), iar fiecare rundă adăuga exact
  // formele pe care tocmai le probase cineva.
  //
  // Mai rău: un recunoscător de construcții nu poate vedea ABSENȚA. O tabelă
  // căreia i se șterge cheia unică pur și simplu nu apărea în listă, deci nimic
  // n-o verifica. Ce se strică atunci e primul invariant din capul lui
  // `0001_core.sql`: fără `UNIQUE (instance_id, source_id)` moare idempotența —
  // `INSERT IGNORE` inserează duplicate la fiecare retrimitere, numărătoarea
  // iese mai mare decât lotul, verdictul devine `incomplete`, și ruta răspunde
  // 500 la nesfârșit cu un mesaj care arată spre DATE („am trimis N rânduri, în
  // tabelă sunt M"), nu spre constrângerea care lipsește.
  //
  // Deci regula se inversează: se numără aparițiile cuvântului `UNIQUE` peste
  // toate instrucțiunile care ating tabela, se cere EXACT UNA, și se cere ca ea
  // să fie forma inline `UNIQUE KEY <nume> (<coloane>)` care începe cu
  // `instance_id`. Numărarea unui cuvânt nu depinde de ortografie, iar „exact
  // una" prinde absența și excesul prin aceeași aserțiune.
  //
  // Coloanele NU se compară cu un literal: cheia sursei nu e mereu `source_id`.
  // `actor_entries` e identificată de `(instance_id, actor_key)`, iar tabelele de
  // legătură adaugă elementul (`tag`, `ip`, `kind, value_hash`). Ce e comun — și
  // ce ține idempotența — e că unicitatea începe cu `instance_id`.
  const { created, touches } = touchesByTable();
  const replicated = [...created].filter((t) => !AGGREGATOR_OWNED.has(t)).sort();
  assert.ok(replicated.length >= 11,
            `doar ${replicated.length} tabele replicate găsite: ${replicated}`);

  for (const table of replicated) {
    const statements = touches.get(table) ?? [];
    const occurrences: string[] = [];
    for (const touch of statements) {
      for (const _ of withoutStrings(touch.sql).matchAll(/\bUNIQUE\b/gi)) {
        occurrences.push(touch.where);
      }
    }
    assert.equal(occurrences.length, 1,
                 `${table}: ${occurrences.length} apariții ale cuvântului UNIQUE ` +
                 `(${occurrences.join(", ") || "niciuna"}). Exact una, în ` +
                 "`CREATE TABLE`, e identitatea replicată: zero omoară idempotența, " +
                 "două recreează un invariant al serverului.");

    const create = statements.find((s) => s.creates);
    assert.ok(create, `${table}: nu găsesc instrucțiunea care o creează`);
    assert.equal(occurrences[0], (create as Touch).where,
                 `${table}: unicitatea e declarată în afara lui CREATE TABLE ` +
                 `(${occurrences[0]}) — forma prin care s-ar recrea un index unic ` +
                 "parțial al serverului");

    const inline = /UNIQUE KEY \w+ \(([^)]*)\)/.exec(withoutStrings((create as Touch).sql));
    assert.ok(inline,
              `${table}: singura apariție a lui UNIQUE nu e forma ` +
              "`UNIQUE KEY <nume> (<coloane>)`");
    assert.ok((inline as RegExpExecArray)[1].replace(/\s+/g, "").startsWith("instance_id,")
              || (inline as RegExpExecArray)[1].replace(/\s+/g, "") === "instance_id",
              `${table}: unicitatea (${(inline as RegExpExecArray)[1]}) nu începe cu ` +
              "instance_id, deci nu e identitatea replicată");

    // Și cele două coloane numite în plan: exact cele pe care serverul le ține
    // unice parțial, deci cele mai probabile de recreat.
    const columns = (inline as RegExpExecArray)[1].replace(/\s+/g, "").split(",");
    for (const [named, column] of [["incident_entries", "fingerprint"],
                                   ["blocklist_entries", "ip"]] as const) {
      if (table !== named) continue;
      assert.ok(!columns.includes(column),
                `${table}: ${column} a intrat în cheia unică`);
    }
  }

  // Și niciun trigger care ar emula unicitatea parțială pe o tabelă REPLICATĂ.
  //
  // Regula nu e „niciun trigger pe o tabelă replicată": `audit_entries` are
  // două, iar ele sunt chiar invariantul de append-only. Ce nu are voie să
  // existe pe o replică e un trigger care ÎNTREȚINE o coloană — forma prin care
  // s-ar recrea un index unic parțial al serverului (`SET NEW.x = …` plus o
  // cheie unică pe `x`), fiindcă acolo unicitatea ar respinge istorie legitimă.
  // Pe datele proprii ale agregatorului forma aia e chiar cea cerută de plan, și
  // e folosită de `sessions`.
  //
  // Scrisă ca REGULĂ, nu ca listă de nume: varianta dinainte cerea ca textul
  // fiecărui trigger să conțină `audit_entries`, deci primul trigger legitim pe
  // o tabelă proprie o pica — cu un mesaj care spunea că e pe o tabelă replicată,
  // adică îndrumare greșită.
  let triggers = 0;
  for (const migration of shipped()) {
    for (const stmt of migration.statements) {
      if (!/^CREATE TRIGGER/.test(stmt.sql)) continue;
      triggers++;
      const table = touchedTable(stmt.sql);
      assert.ok(table,
                `${migration.file} #${stmt.index}: nu pot spune pe ce tabelă e ` +
                "triggerul, deci nu pot spune nici că e în regulă");
      // Tabelele proprii au regula LOR, în testul de mai jos. „Scutit de regula
      // replicilor" nu e „scutit de orice regulă" — măsurat, un
      // `CREATE TRIGGER instances_stamp BEFORE UPDATE ON instances FOR EACH ROW
      // SET NEW.ship_secret_enc = …` trecea pe aici fără să pice nimic.
      if (AGGREGATOR_OWNED.has(table as string)) continue;
      assert.ok(/\bSIGNAL SQLSTATE\b/.test(stmt.sql),
                `${migration.file} #${stmt.index}: trigger pe tabela replicată ` +
                `${table} care face altceva decât să REFUZE o scriere. Un trigger ` +
                "care întreține o coloană e forma prin care s-ar recrea un index " +
                "unic parțial al serverului, iar pe o replică aia respinge istorie " +
                "legitimă.");
      assert.ok(!/\bSET NEW\./.test(stmt.sql),
                `${migration.file} #${stmt.index}: trigger care scrie o coloană a ` +
                `tabelei replicate ${table}`);
    }
  }
  // Bucla goală ar trece verde — chiar tiparul din CLAUDE.md.
  assert.ok(triggers >= 4, `doar ${triggers} triggere găsite în schema livrată`);
});

/**
 * Triggerele îngăduite pe tabelele PROPRII ale agregatorului, cu ce scriu.
 *
 * Regula replicilor („doar refuz, niciun `SET NEW.`") nu se poate întinde peste
 * ele: pe datele lui proprii agregatorul are voie să întrețină o coloană, iar
 * `sessions.active_token_hash` e chiar forma cerută de plan, fiindcă MariaDB
 * refuză `IF`/`CASE` într-o coloană generată (ERROR 1901, măsurat pe gazdă).
 *
 * Dar „scutit de regula replicilor" devenise „scutit de orice regulă": măsurat,
 * un trigger `BEFORE UPDATE ON instances` care scrie `ship_secret_enc` trecea
 * toată suita. Coloana aia e cheia de expediere a unei instanțe, sigilată; un
 * trigger care o rescrie ar face ca fiecare lot al gazdei ăleia să fie refuzat
 * cu 401, iar `ship_once` nu citește niciodată corpul refuzului — deci simptomul
 * ar fi „nu mai vine nimic de pe serverul X", fără nimic care să arate spre
 * cauză, și cu secretul original pierdut.
 *
 * Deci inventarul, cu tabela, evenimentul și COLOANELE scrise de fiecare. Nu e o
 * verificare structurală și nu se pretinde una — nimic din text nu poate spune
 * că un trigger e „cuminte". Ce face e să facă adăugarea imposibil de făcut
 * TĂCUT: un trigger nou pe o tabelă proprie pică până când cineva scrie aici ce
 * scrie el, iar aia e declarația.
 */
const OWNED_TRIGGERS: Record<string, { table: string; event: string; writes: string[] }> = {
  sessions_active_token_bi: {
    table: "sessions", event: "BEFORE INSERT", writes: ["active_token_hash"],
  },
  sessions_active_token_bu: {
    table: "sessions", event: "BEFORE UPDATE", writes: ["active_token_hash"],
  },
};

/**
 * Coloanele pe care le SCRIE un trigger: partea stângă a fiecărei atribuiri din
 * corpul lui.
 *
 * `SIGNAL SQLSTATE … SET MESSAGE_TEXT = …` e tot un `SET`, dar nu scrie nicio
 * coloană — de-aia refuzurile se recunosc întâi. Tăierea la virgule e la nivelul
 * de sus: expresia livrată e `IF(NEW.revoked_at IS NULL, NEW.token_hash, NULL)`,
 * iar o tăiere naivă ar rupe-o în trei și ar raporta coloane scrise care nu se
 * scriu — adică o gardă roșie din alt motiv decât cel real.
 *
 * O formă de corp pe care nu știe s-o citească e o EROARE, nu o listă goală:
 * „nu știu ce scrie" și „nu scrie nimic" duc la decizii opuse.
 */
function triggerWrites(sql: string): string[] {
  const body = /^CREATE TRIGGER \w+ [A-Z]+ [A-Z]+ ON \w+ FOR EACH ROW (.+)$/
    .exec(withoutStrings(sql));
  assert.ok(body, `nu pot citi corpul triggerului: „${sql.slice(0, 80)}…”`);
  const text = (body as RegExpExecArray)[1].trim();
  if (/^SIGNAL\b/.test(text)) return [];
  const set = /^SET (.+)$/.exec(text);
  assert.ok(set, `corp de trigger pe care regula nu-l citește: „${text.slice(0, 60)}…”`);
  return splitTopLevel((set as RegExpExecArray)[1], ",").map((part) => {
    const column = /^NEW\.(\w+)$/.exec(part.split("=")[0].trim());
    assert.ok(column, `atribuire pe care regula nu o citește: „${part.trim()}”`);
    return (column as RegExpExecArray)[1];
  });
}

/** Taie la separator, dar numai în afara parantezelor. */
function splitTopLevel(text: string, separator: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of text) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (depth === 0 && ch === separator) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts;
}

test("un trigger pe o tabelă PROPRIE e declarat, cu tabela, evenimentul și ce scrie", () => {
  // Ce se strică fără regula asta: vezi `OWNED_TRIGGERS`. Pe scurt — cele opt
  // tabele proprii n-aveau NICIO verificare pe triggere, iar una dintre ele ține
  // cheile de expediere sigilate ale tuturor instanțelor.
  const seen: string[] = [];
  for (const migration of shipped()) {
    for (const stmt of migration.statements) {
      if (!/^CREATE TRIGGER/.test(stmt.sql)) continue;
      // Un trigger pe care nu-l pot atribui unei tabele nu se SARE: sărit, ar
      // ieși din amândouă regulile (și din asta, și din cea a replicilor) printr-o
      // formă pe care nimeni n-o citește. „Nu știu pe ce e" nu e „e în regulă".
      const table = touchedTable(stmt.sql);
      assert.ok(table,
                `${migration.file} #${stmt.index}: nu pot spune pe ce tabelă e ` +
                "triggerul, deci nu pot spune nici că e în regulă");
      if (!AGGREGATOR_OWNED.has(table as string)) continue;
      const name = /^CREATE TRIGGER (\w+)/.exec(stmt.sql) as RegExpExecArray;
      const declared = OWNED_TRIGGERS[name[1]];
      assert.ok(declared,
                `${migration.file} #${stmt.index}: trigger nedeclarat (${name[1]}) pe ` +
                `tabela proprie ${table}. Scrie în OWNED_TRIGGERS ce scrie el — pe ` +
                "datele proprii un trigger are voie să întrețină o coloană, dar nu " +
                "tăcut: `instances.ship_secret_enc` și `users.password_hash` sunt " +
                "tot coloane ale unei tabele proprii");
      assert.equal(table, declared.table,
                   `${name[1]}: declarat pe ${declared.table}, livrat pe ${table as string}`);
      assert.match(stmt.sql,
                   new RegExp(`^CREATE TRIGGER ${name[1]} ${declared.event} ON ${table}\\b`),
                   `${name[1]}: evenimentul livrat nu e ${declared.event}`);
      assert.deepEqual(triggerWrites(stmt.sql), declared.writes,
                       `${name[1]}: scrie alte coloane decât cele declarate`);
      seen.push(name[1]);
    }
  }

  // Și niciuna dintre declarații nu e moartă: o intrare pentru un trigger care
  // nu mai există e o intrare care într-o zi acoperă altceva cu același nume.
  // Bucla goală ar trece verde — aserțiunea asta e cea care o prinde.
  assert.deepEqual(seen.sort(), Object.keys(OWNED_TRIGGERS).sort(),
                   "triggerele livrate pe tabelele proprii nu sunt exact cele " +
                   "declarate în OWNED_TRIGGERS");
});

test("regula triggerelor proprii chiar refuză formele pe care le numește", () => {
  // Regula de CITIRE, declanșată izolat — ca `assertChildDeclarable` din
  // `tests/subrows.test.ts`, și din același motiv: o regulă a cărei declanșare
  // n-a fost văzută singură e o regulă despre care nu se știe pe ce pică.
  // Instrucțiunile sunt sintetice fiindcă formele astea NU există în schema
  // livrată, și tocmai de-aia nimeni nu le-a văzut refuzate.
  assert.deepEqual(
    triggerWrites("CREATE TRIGGER t BEFORE UPDATE ON sessions FOR EACH ROW " +
                  "SET NEW.active_token_hash = IF(NEW.revoked_at IS NULL, " +
                  "NEW.token_hash, NULL)"),
    ["active_token_hash"],
    "virgulele dinăuntrul lui IF(...) au fost citite ca atribuiri separate");

  assert.deepEqual(
    triggerWrites("CREATE TRIGGER t BEFORE DELETE ON audit_entries FOR EACH ROW " +
                  "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'nu'"),
    [], "MESSAGE_TEXT a fost citit ca o coloană scrisă");

  assert.deepEqual(
    triggerWrites("CREATE TRIGGER t BEFORE UPDATE ON instances FOR EACH ROW " +
                  "SET NEW.ship_secret_enc = NEW.ship_secret_enc, NEW.rotated_at = NOW()"),
    ["ship_secret_enc", "rotated_at"],
    "un trigger cu două atribuiri a fost citit ca scriind una singură");

  // Iar un corp pe care nu știe să-l citească e un EȘEC, nu o listă goală.
  assert.throws(
    () => triggerWrites("CREATE TRIGGER t BEFORE UPDATE ON instances FOR EACH ROW " +
                        "BEGIN UPDATE instances SET ship_secret_enc = NULL; END"),
    /corp de trigger pe care regula nu-l citește/,
    "un corp necunoscut a fost citit ca „nu scrie nimic”");
});

/**
 * Coloanele cheii unice a unei tabele, în ordinea din migrație.
 *
 * Aceeași citire ca în garda de unicitate de mai sus, și dinadins tot pe text:
 * fișierul livrat E sursa, iar ce se compară cu el trebuie citit din el.
 */
function uniqueKeyOf(table: string): string[] {
  const inline = /UNIQUE KEY \w+ \(([^)]*)\)/.exec(withoutStrings(tableSql(table)));
  assert.ok(inline, `${table}: nu găsesc o cheie unică inline`);
  return (inline as RegExpExecArray)[1].replace(/\s+/g, "").split(",");
}

/**
 * Declarația completă a unei coloane, din `CREATE TABLE`.
 *
 * Literalii de șir se scot ÎNAINTE de tăierea la virgule: un `COMMENT 'a, b'`
 * conține o virgulă, iar fără curățare declarația s-ar rupe în două, cu
 * jumătatea care poartă colația aruncată. Garda de mai jos ar fi atunci roșie
 * din alt motiv decât cel real — adică ar minți în direcția „sigură", ceea ce
 * tot minciună e.
 */
function columnDeclaration(sql: string, column: string): string | null {
  const body = withoutStrings(sql).slice(sql.indexOf("(") + 1);
  for (const part of body.split(",")) {
    const words = part.trim().split(/\s+/);
    if (words.length < 2) continue;
    if (words[0].toLowerCase() !== column.toLowerCase()) continue;
    if (!/^[A-Za-z]/.test(words[1])) continue;
    return part.trim();
  }
  return null;
}

/**
 * Tipurile pentru care colația chiar decide dacă două valori sunt același rând.
 *
 * `ENUM` și `SET` NU sunt aici, și e o decizie, nu o scăpare: mulțimea lor de
 * valori e ÎNCHISĂ și declarată, iar MariaDB refuză o mulțime cu două etichete
 * care diferă doar prin majuscule (sub o colație insensibilă ele sunt duplicat).
 * Deci o coloană `ENUM` de identitate nu poate contopi două valori legitime
 * distincte — cel mai rău lucru pe care îl face o colație insensibilă acolo e să
 * accepte o etichetă scrisă greșit ca majuscule și s-o canonizeze.
 *
 * Pentru text liber garanția aia nu există: nimeni nu declară dinainte mulțimea
 * etichetelor sau a cheilor de verificare, deci `Prod` și `prod` chiar sunt două
 * valori distincte care s-ar contopi. Măsurat: `actor_attrs.kind` e singurul
 * `ENUM` de identitate din schemă, iar `asset_tags.tag` e text liber și e chiar
 * defectul din lista de scutiri.
 */
const CHARACTER_TYPES = ["VARCHAR", "CHAR", "TEXT", "TINYTEXT", "MEDIUMTEXT",
                         "LONGTEXT"];

/**
 * Coloanele de identitate scutite de regula colației. GOALĂ, și trebuie să rămână.
 *
 * A existat o intrare: `asset_tags.tag` din `0003_entities.sql` era
 * `VARCHAR(190)` fără colație declarată, deci moștenea `utf8mb4_unicode_ci` de la
 * tabelă — pe același activ, etichetele `Prod` și `prod` se ciocneau în cheia
 * unică, iar a doua s-ar fi pierdut tăcut la ingestie.
 *
 * S-a REPARAT în fișier, nu s-a scutit, fiindcă premisa scutirii era greșită:
 * `0003` nu fusese aplicat niciodată pe baza reală, deci nu exista nicio sumă de
 * control de stricat și niciun rând deja contopit despre care să se decidă ceva.
 * O scutire ar fi lăsat în urmă exact ce nu trebuie: un defect documentat, care
 * arată ca o decizie.
 *
 * Mecanismul rămâne, deși lista e goală — el e paza, nu lista. O intrare nouă
 * pică testul de mai jos, deci nu se poate adăuga fără s-o vadă cineva.
 */
const COLLATION_EXEMPT: string[] = [];

test("o coloană de identitate nu se compară printr-o colație insensibilă", () => {
  // Regula, ca regulă și nu ca listă: ORICE coloană de caractere care intră în
  // cheia unică a unei tabele replicate e `_bin`. Scrisă așa, acoperă și
  // coloanele care nu există încă — la fel ca regula `ip`/`_ip` → `INET6`, care
  // nu enumeră adresele cunoscute.
  //
  // Ce se strică fără ea: sub `utf8mb4_unicode_ci`, `'Disk'` și `'disk'` sunt
  // ACELAȘI rând. Două verificări distincte se contopesc într-una, iar sub
  // `INSERT IGNORE` a doua dispare fără eroare, cu filigranul ecouat — adică
  // pierdere de rânduri raportată ca succes. Marginea inventată (`VARCHAR(190)`)
  // și colația sunt aceeași decizie luată o dată: dacă o coloană de identitate
  // trebuie să încapă într-un index, atunci trebuie și să se compare pe octeți.
  //
  // Măsurat înainte de a exista testul ăsta: schimbarea colației lui `check_key`
  // în `_ci` lăsa toată suita verde.
  const { created, touches } = touchesByTable();
  const replicated = [...created].filter((t) => !AGGREGATOR_OWNED.has(t)).sort();
  const offenders: string[] = [];
  let checked = 0;

  for (const table of replicated) {
    const create = (touches.get(table) ?? []).find((s) => s.creates);
    assert.ok(create, `${table}: nu găsesc instrucțiunea care o creează`);
    for (const column of uniqueKeyOf(table)) {
      const declaration = columnDeclaration((create as Touch).sql, column);
      if (declaration === null) {
        // O coloană de cheie pe care tabela n-o declară e o cheie peste ceva ce
        // nu există. Nu e „nimic de verificat", e o eroare.
        offenders.push(`${table}.${column}: în cheia unică, dar nedeclarată`);
        continue;
      }
      const type = declaration.split(/\s+/)[1].toUpperCase();
      if (!CHARACTER_TYPES.some((t) => type.startsWith(t))) continue;
      checked++;
      if (COLLATION_EXEMPT.includes(`${table}.${column}`)) continue;
      if (!/COLLATE (ascii_bin|utf8mb4_bin)\b/.test(declaration)) {
        offenders.push(`${table}.${column}: ${declaration.slice(0, 80)}`);
      }
    }
  }

  assert.deepEqual(offenders, [],
                   "coloane de identitate care se compară printr-o colație " +
                   `insensibilă (sau fără colație declarată): ${offenders}`);
  // Bucla goală ar trece verde. Cifra e cea măsurată: `instance_id` de zece ori,
  // plus `actor_key`, `tag`, `check_key`, `source`, `action`.
  assert.ok(checked >= 15,
            `doar ${checked} coloane de identitate de tip caracter găsite; ` +
            "regula nu mai atinge nimic");
});

test("scutirile de la regula colației nu pot crește tăcut", () => {
  // Fiecare intrare ar fi un rând care se poate pierde tăcut la ingestie, nu o
  // excepție de proiectare. Lista e goală fiindcă singurul caz a fost REPARAT în
  // migrație; orice intrare nouă cere o editare a testului, iar aia e declarația.
  // Copie, nu lista însăși: `assert.deepEqual` are semnătură de aserțiune în
  // `@types/node`, deci comparată direct ar îngusta constanta la `never[]`, iar
  // bucla de mai jos n-ar mai compila — o pază care dispare fiindcă a fost
  // verificată.
  assert.deepEqual([...COLLATION_EXEMPT], [],
                   "lista defectelor de colație scutite nu mai e goală: fiecare " +
                   "intrare e un defect livrat, nu o alegere");

  // Iar o intrare, dacă apare vreodată, trebuie să fie VIE: o scutire pentru o
  // coloană care și-a primit colația (sau care nu mai există) acoperă într-o zi
  // altceva cu același nume. Bucla e goală azi — aserțiunea de deasupra e cea
  // care apără, nu ea.
  for (const entry of COLLATION_EXEMPT) {
    const [table, column] = entry.split(".");
    const declaration = columnDeclaration(tableSql(table), column);
    assert.ok(declaration, `${entry}: scutire pentru o coloană care nu există`);
    assert.ok(!/COLLATE (ascii_bin|utf8mb4_bin)\b/.test(declaration as string),
              `${entry}: și-a primit colația; scoate-o din lista de scutiri`);
  }
});

/**
 * Tipurile în care încape ORICE — deci cele despre care SCHEMA nu poate spune ce
 * e în ele.
 *
 * `TEXT` a lipsit de aici până în august 2026, iar lipsa a lăsat să treacă exact
 * ce caută regula: `incident_entries.summary` și `incident_entries.title` poartă
 * căi de pe gazda monitorizată — detectoarele interpolează în ele `/etc/passwd`,
 * numele contului, uid-ul, shell-ul, home-ul, căile fișierelor scrise sub
 * webroot —, dar sunt `TEXT`, deci treceau pe lângă gardă **prin tip, nu prin
 * decizie**. Măsurat pe gazdă atunci: 9 rezumate din 1476.
 *
 * De ce lista se lărgește în loc să se restrângă: un tip mărginit nu e o dovadă
 * că e mărginit conținutul. `TEXT` e 64 KiB de orice; ce mărginește un `status`
 * e un `CHECK` de pe SERVERUL MONITORIZAT, iar replica nu-l are (`fara CHECK` e
 * scris în schemă, dinadins). Deci întrebarea „ce poate fi în coloana asta" se
 * pune pentru fiecare, iar răspunsul se scrie în README — inclusiv „vocabular
 * fix, nu poartă recunoaștere", care e un răspuns, nu o scutire.
 */
const UNBOUNDED_TYPES = ["JSON", "MEDIUMTEXT", "LONGTEXT", "TEXT"];

test("fiecare coloană nemărginită dintr-o replică e numită în README", () => {
  // Decizia „ce informație de recunoaștere are voie să plece de pe gazdă" s-a
  // luat de două ori pe o listă incompletă: întâi trei coloane, apoi șase, când
  // în schemă erau paisprezece. O listă scrisă de mână despre o schemă care
  // crește e o listă care se destramă tăcut, iar ce se pierde nu e documentația:
  // e locul în care operatorul poate răsturna o decizie în cunoștință de cauză.
  //
  // Deci lista se ține MECANIC. O coloană de caractere nouă într-o tabelă
  // replicată pică testul până când cineva scrie în README ce poartă — iar aia e
  // chiar întrebarea care trebuie pusă înainte, nu după ce datele au ajuns aici.
  // Numerele și timpii nu intră: despre ei se poate spune ce sunt, fiindcă tipul
  // chiar îi mărginește. Despre `TEXT` nu se poate — vezi `UNBOUNDED_TYPES`.
  const readme = readFileSync(path.join(MIGRATIONS_DIR, "..", "README.md"), "utf8");
  const { created, touches } = touchesByTable();
  const missing: string[] = [];
  let found = 0;

  for (const table of [...created].filter((t) => !AGGREGATOR_OWNED.has(t)).sort()) {
    const create = (touches.get(table) ?? []).find((s) => s.creates);
    if (!create) continue;
    const body = withoutStrings(create.sql).slice(create.sql.indexOf("(") + 1);
    for (const part of body.split(",")) {
      const words = part.trim().split(/\s+/);
      if (words.length < 2) continue;
      const type = words[1].toUpperCase();
      if (!UNBOUNDED_TYPES.some((t) => type === t || type.startsWith(`${t}(`))) continue;
      found++;
      if (!readme.includes(`\`${table}.${words[0]}\``)) {
        missing.push(`${table}.${words[0]}`);
      }
    }
  }

  assert.deepEqual(missing, [],
                   "coloane nemărginite dintr-o tabelă replicată care NU sunt " +
                   `numite în README: ${missing}`);
  // Bucla goală ar trece verde. Cifra e cea măsurată după lărgirea la `TEXT`:
  // 89 de coloane în tabelele replicate, față de 14 cât vedea regula când se
  // uita doar la `JSON`/`MEDIUMTEXT`/`LONGTEXT`. Pragul e sub măsurătoare, nu pe
  // ea: o coloană ștearsă legitim nu trebuie să pice testul, dar o regulă care a
  // încetat să atingă schema trebuie.
  assert.ok(found >= 80,
            `doar ${found} coloane nemărginite găsite; regula nu mai atinge nimic`);
});

test("identitatea declarată a fiecărui flux e cheia unică din migrație", () => {
  // Ce se strică dacă cele două nu sunt de acord: `writeSql` exclude din
  // `ON DUPLICATE KEY UPDATE` coloanele pe care le crede identitate, iar MariaDB
  // potrivește rândul după cheia unică REALĂ. Dacă declarația e mai îngustă
  // decât cheia, o coloană de cheie ajunge în `SET`; dacă e mai largă, o coloană
  // de date rămâne înghețată la prima sosire, iar numărătoarea de efect n-o
  // vede — rândul e prezent, filigranul se ecouă, cursorul avansează.
  //
  // De-aia identitatea declarată în `lib/streams.ts` nu e crezută pe cuvânt: e
  // comparată cu cheia din fișierul livrat. Aceeași formă ca testul care ține
  // `MAX_ROWS_PER_BATCH` egal la cele două capete — două surse independente, o
  // aserțiune care le pune față în față. Mutarea deducției din `lib/ingest.ts`
  // într-o declarație ar fi fost, fără testul ăsta, doar o deducție mutată.
  const streams = allStreams();
  assert.ok(streams.length >= 1,
            "niciun flux înregistrat: bucla de mai jos ar trece goală");
  for (const stream of streams) {
    assert.deepEqual([...stream.identity], uniqueKeyOf(stream.table),
                     `fluxul ${stream.name}: identitatea declarată nu e cheia unică a ` +
                     `tabelei ${stream.table}`);
  }
});

test("lista de scutiri de la regula unicității nu poate crește tăcut", () => {
  // `AGGREGATOR_OWNED` decide ce tabele SCAPĂ de regula „exact o unicitate,
  // identitatea replicată". Pe datele lui proprii, agregatorul poate impune ce
  // invarianți vrea; pe o replică, o unicitate în plus respinge istorie
  // legitimă, iar una lipsă omoară idempotența.
  //
  // Docstring-ul listei spunea că adăugarea unei tabele acolo „e o declarație,
  // nu o formalitate" — dar nimic nu o făcea să fie: o tabelă REPLICATĂ
  // strecurată în listă ieșea din verificare fără ca nimic să pice. Aserțiunea
  // de mai jos e pe CONȚINUT, nu pe dimensiune: cine adaugă a cincea intrare
  // trebuie să editeze și testul, iar aia e declarația.
  //
  // Nu e o verificare structurală și nu se pretinde una — nimic din text nu
  // poate spune că o tabelă e „cu adevărat" a agregatorului. Ce face e să facă
  // strecurarea imposibil de făcut TĂCUT.
  assert.deepEqual([...AGGREGATOR_OWNED].sort(),
                   ["audit_chain_state", "instances", "login_attempts", "schema_version",
                    "sessions", "sync_cursors", "user_instances", "users"],
                   "lista tabelelor proprii ale agregatorului s-a schimbat: fiecare " +
                   "intrare scutește o tabelă de regula unicității replicate");

  // Și niciuna dintre ele nu e o intrare moartă: o scutire pentru o tabelă care
  // nu mai există e o scutire care într-o zi acoperă altceva cu același nume.
  //
  // Bootstrap-ul intră în socoteală: `discover()` îl sare dinadins (e singurul
  // fișier care nu se poate consemna în registrul pe care îl creează), dar
  // `schema_version` e o tabelă la fel de reală ca restul.
  const { created } = touchesByTable();
  const bootstrap = splitStatements(
    readFileSync(path.join(MIGRATIONS_DIR, BOOTSTRAP_FILE), "utf8"), BOOTSTRAP_FILE);
  for (const stmt of bootstrap) {
    const table = touchedTable(stmt.sql);
    if (table) created.add(table);
  }

  for (const table of AGGREGATOR_OWNED) {
    assert.ok(created.has(table),
              `${table} e scutită, dar nicio migrație livrată nu o creează`);
  }
});

test("adresele sunt `INET6`, nu text", () => {
  // Regula din plan, marcată acolo „probat pe gazdă": MariaDB are `INET6` nativ
  // și acceptă în aceeași coloană și `203.0.113.10`, și `2001:db8::1`, cu
  // ordonare și comparație corecte. Perechea `VARBINARY(16)` + `VARCHAR(45)` din
  // varianta inițială a planului nu mai e nevoie.
  //
  // Ce se strică fără gardă: o coloană strecurată ca `VARCHAR(45)` compară
  // adrese ca TEXT. `10.0.0.9` și `10.0.0.10` ies invers, iar `BETWEEN`-ul care
  // ține locul lui `<<=` în partea a doua ar da răspunsuri greșite despre ce e
  // blocat — cea mai proastă formă de greșit, fiindcă pare să funcționeze.
  //
  // Regula e pe NUME, nu pe o listă: orice coloană numită `ip` sau terminată în
  // `_ip`. `cidr_text VARCHAR(45)` trece, și e corect că trece — e forma
  // citibilă pentru panou, nu o adresă cu care se compară.
  const offenders: string[] = [];
  let addresses = 0;
  for (const migration of shipped()) {
    for (const stmt of migration.statements) {
      if (!/^CREATE TABLE/.test(stmt.sql)) continue;
      const body = stmt.sql.slice(stmt.sql.indexOf("(") + 1);
      for (const part of body.split(",")) {
        const words = part.trim().split(/\s+/);
        if (words.length < 2) continue;
        const name = words[0].toLowerCase();
        if (name !== "ip" && !name.endsWith("_ip")) continue;
        addresses++;
        if (words[1].toUpperCase() !== "INET6") {
          offenders.push(`${migration.file} #${stmt.index}: ${words[0]} ${words[1]}`);
        }
      }
    }
  }
  assert.deepEqual(offenders, [], `adrese stocate altfel decât INET6: ${offenders}`);
  // Bucla goală ar trece verde — chiar tiparul din CLAUDE.md.
  assert.ok(addresses >= 3, `doar ${addresses} coloane de adresă găsite`);
});

/**
 * Triggerele îngăduite pe `audit_entries`, cu evenimentul fiecăruia.
 *
 * Aceeași formă de inventar ÎNCHIS ca `OWNED_TRIGGERS`, și din același motiv:
 * ce trebuie apărat nu e prezența a două nume, ci faptul că nu există un al
 * TREILEA. Un trigger nou pe arhivă pică până când cineva îl scrie aici, iar
 * scrierea lui aici e declarația.
 *
 * De ce nu o listă de nume căutată în prima migrație: verificarea dinainte
 * filtra `core().statements`, adică `shipped()[0]` = `0001_core.sql`. Măsurat —
 * un fișier nou, `migrations/0009_probe.sql`, cu
 * `CREATE TRIGGER audit_entries_no_insert BEFORE INSERT ON audit_entries … SIGNAL`
 * trecea toată suita, în ambele limbaje. E chiar avertismentul scris la testul
 * gărzilor („o verificare legată de `shipped()[0]` ar fi lăsat fiecare fișier
 * nou fără nicio pază, tăcut"), făcut de regula asta.
 *
 * Ce se strică atunci: `audit_entries` refuză fiecare INSERT cu ERROR 1644, deci
 * fiecare lot al FIECĂREI instanțe e respins, iar `ship_once` nu citește corpul
 * refuzului — simptomul e „nu mai vine nimic de nicăieri", fără cauză vizibilă.
 * Iar cealaltă jumătate a lui „append-only" (UPDATE și DELETE chiar refuzate)
 * pare în continuare în regulă, ceea ce e mai rău decât să lipsească toată:
 * cine crede că arhiva e inviolabilă are dreptate pe jumătate.
 *
 * Ce NU spune inventarul ăsta: că un trigger declarat aici chiar REFUZĂ o
 * scriere în loc s-o rescrie. Aia e regula replicilor de mai sus — `SIGNAL
 * SQLSTATE` obligatoriu, `SET NEW.` interzis —, care ține pentru `audit_entries`
 * fiindcă nu e o tabelă proprie a agregatorului. Cele două se completează.
 */
const AUDIT_ENTRIES_TRIGGERS: Record<string, string> = {
  audit_entries_no_update: "BEFORE UPDATE",
  audit_entries_no_delete: "BEFORE DELETE",
};

test("triggerele pe audit_entries sunt EXACT cele două refuzuri declarate", () => {
  // Evenimentul se cere din TEXT, per trigger. Măsurat pe versiunea care se uita
  // doar la nume: schimbând evenimentul amândurora din `BEFORE UPDATE` /
  // `BEFORE DELETE` în `BEFORE INSERT`, toată suita rămânea verde — iar
  // `audit_entries` devenea tabela în care nu se poate INSERA nimic, cu UPDATE și
  // DELETE libere, deci fără append-only. Numele spunea în continuare
  // `_no_update`. E tiparul din `CLAUDE.md`: o aserțiune pe prezența unui nume în
  // loc de pe decizia luată din el.
  //
  // Peste TOATE migrațiile livrate, ca regula replicilor și ca `OWNED_TRIGGERS`.
  const seen: string[] = [];
  for (const migration of shipped()) {
    for (const stmt of migration.statements) {
      if (!/^CREATE TRIGGER/.test(stmt.sql)) continue;
      // Un trigger pe care nu-l pot atribui unei tabele nu se SARE: sărit, ar
      // ieși din regula asta printr-o formă pe care nimeni n-o citește. „Nu știu
      // pe ce e" nu e „e în regulă".
      const table = touchedTable(stmt.sql);
      assert.ok(table,
                `${migration.file} #${stmt.index}: nu pot spune pe ce tabelă e ` +
                "triggerul, deci nu pot spune nici că e în regulă");
      if (table !== "audit_entries") continue;
      const name = /^CREATE TRIGGER (\w+)/.exec(stmt.sql) as RegExpExecArray;
      const event = AUDIT_ENTRIES_TRIGGERS[name[1]];
      assert.ok(event,
                `${migration.file} #${stmt.index}: trigger nedeclarat (${name[1]}) pe ` +
                "audit_entries. Un trigger în plus pe arhivă e forma prin care " +
                "ingestia TUTUROR instanțelor se oprește — fiecare lot refuzat cu " +
                "ERROR 1644, iar `ship_once` nu citește corpul refuzului, deci " +
                "simptomul e „nu mai vine nimic de nicăieri”. Dacă e legitim, " +
                "scrie-l în AUDIT_ENTRIES_TRIGGERS cu evenimentul lui.");
      assert.match(
        stmt.sql,
        new RegExp(`^CREATE TRIGGER ${name[1]} ${event} ON audit_entries\\b`),
        `${migration.file} #${stmt.index}: ${name[1]} nu e ${event} pe ` +
        `audit_entries: „${stmt.sql.slice(0, 80)}…”`);
      seen.push(name[1]);
    }
  }

  // Și niciuna dintre declarații nu e moartă: o intrare pentru un trigger care nu
  // mai există e o intrare care într-o zi acoperă altceva cu același nume. Tot
  // asta e aserțiunea care prinde bucla goală — `discover()` întors gol ar fi
  // lăsat regula să treacă verde fără să fi citit nimic.
  assert.deepEqual(seen.sort(), Object.keys(AUDIT_ENTRIES_TRIGGERS).sort(),
                   "triggerele livrate pe audit_entries nu sunt exact cele " +
                   "declarate în AUDIT_ENTRIES_TRIGGERS: ori lipsește un refuz " +
                   "(UPDATE sau DELETE devine liber pe arhivă), ori s-a adăugat " +
                   "unul care nu e declarat");
});

test("fișierul se poate da unui client: fără DELIMITER, fără nimic asamblat", () => {
  // Dacă ar avea nevoie de `DELIMITER`, `mysql < 0001_core.sql` și runner-ul ar
  // aplica lucruri diferite — iar verificarea pe gazdă n-ar mai spune nimic
  // despre ce aplică runner-ul.
  const text = coreText();
  assert.ok(!/^\s*DELIMITER\b/im.test(text), "fișierul conține DELIMITER");
  assert.ok(!text.includes("/*!"), "fișierul conține un comentariu executabil");
});
