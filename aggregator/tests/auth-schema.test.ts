/**
 * Schema de autentificare (`migrations/0008_auth.sql`): ce se poate afirma
 * despre ea de pe o mașină fără MariaDB.
 *
 * Aceeași împărțire ca în `tests/schema.test.ts`, și merită repetată fiindcă
 * aici e ușor de citit mai mult decât scrie:
 *
 *   * **parsare reală** — fișierul chiar trece prin `discover()`/`splitStatements()`.
 *     Că fiecare instrucțiune are exact o gardă, că garda numește obiectul creat,
 *     că nu e nimic trunchiat: astea sunt fapte.
 *   * **aserțiuni pe TEXT** — că `active_token_hash` are o cheie unică, că
 *     triggerele o întrețin, că timpii n-au implicit. Apără DECIZII împotriva
 *     ștergerii lor la un refactor. NU dovedesc că MariaDB acceptă fișierul.
 *
 * Ce ar dovedi asta din urmă, și nu se poate face de aici: `npm run migrate --
 * --syntax-check` pe gazdă, care cere SERVERULUI să analizeze fiecare
 * instrucțiune — inclusiv triggerele, măsurat pe MariaDB 11.8.8 — urmat de proba
 * prin efect (al doilea rând activ cu același jeton refuzat cu ERROR 1062).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { discover } from "../lib/migrate";
import { allStreams, linkTables } from "../lib/streams";
import { tableColumns } from "./sql-reading";

const AUTH_TABLES = ["users", "sessions", "login_attempts", "user_instances"];

function authMigration() {
  const found = discover().find((m) => m.file === "0008_auth.sql");
  assert.ok(found, "0008_auth.sql nu e descoperită de runner");
  return found;
}

function statementFor(object: string): string {
  const stmt = authMigration().statements.find((s) => s.sql.includes(object));
  assert.ok(stmt, `nu găsesc instrucțiunea care creează ${object}`);
  return stmt.sql;
}

test("migrația de autentificare se parsează, cu o gardă per instrucțiune", () => {
  // Parsare reală. Un fișier care nu se poate încărca ar fi descoperit abia pe
  // gazdă, în mijlocul unei instalări — iar aici asta ar însemna un panou fără
  // tabele de utilizatori, adică nimeni nu se poate autentifica.
  const migration = authMigration();
  const guards = migration.statements.map((s) => s.guardText.trim());
  assert.deepEqual(guards, [
    "table users",
    "table sessions",
    "trigger sessions_active_token_bi",
    "trigger sessions_active_token_bu",
    "table login_attempts",
    "table user_instances",
  ], "gărzile migrației de autentificare s-au schimbat");
});

test("niciun flux de sincronizare nu scrie în tabelele de autentificare", () => {
  // Eșecul pe care îl previne, și e cel mai ușor de făcut din tot fișierul:
  // `users`, `sessions` și `login_attempts` există și pe serverul monitorizat, și
  // ALEA nu pleacă niciodată de acolo — conțin adresele IP ale operatorului.
  // Dacă un flux de sincronizare ar ajunge vreodată să scrie în tabelele astea,
  // datele personale ale operatorului ar începe să curgă spre o găzduire
  // partajată, iar simptomul ar fi... niciunul. Nimic nu s-ar strica.
  //
  // Verificarea e pe REGISTRUL de fluxuri, nu pe nume: un flux își declară
  // tabela, deci întrebarea „scrie cineva în ele?" are un răspuns mecanic.
  const targets = new Set<string>();
  for (const stream of allStreams()) {
    targets.add(stream.table);
    for (const child of stream.children ?? []) targets.add(child.table);
  }
  for (const [child] of linkTables()) targets.add(child);

  // Bucla goală ar trece verde — chiar tiparul din CLAUDE.md.
  assert.ok(targets.size >= 5, `doar ${targets.size} tabele-țintă găsite în fluxuri`);
  for (const table of AUTH_TABLES) {
    assert.ok(!targets.has(table),
              `fluxul de sincronizare scrie în ${table}: o tabelă de autentificare a ` +
              "ajuns să primească date de pe serverul monitorizat");
  }
});

test("tabelele de autentificare n-au contabilitatea sosirii unei replici", () => {
  // A doua jumătate a aceleiași granițe, dinspre CEALALTĂ direcție: nu doar că
  // niciun flux nu le numește ca țintă, dar tabelele astea nici nu au cum să
  // primească un lot — n-au contabilitatea sosirii (`received_at`, `batch_seq`)
  // pe care `writeSql` o emite pentru orice tabelă replicată.
  //
  // De ce contează amândouă: prima verificare cade dacă cineva redenumește
  // câmpul `table` dintr-un flux; a doua, dacă cineva adaugă un flux nou. Sunt
  // două lacăte pe aceeași ușă, iar ușa asta e datele personale ale operatorului.
  for (const table of AUTH_TABLES) {
    const columns = tableColumns(statementFor(`CREATE TABLE ${table} (`));
    assert.ok(!columns.includes("received_at") && !columns.includes("batch_seq"),
              `${table} are contabilitatea sosirii, deci arată ca o tabelă replicată`);
    assert.ok(!columns.includes("instance_id") || table === "user_instances",
              `${table} poartă instance_id fără să fie o tabelă de drepturi`);
  }
});

test("jetonul de sesiune are o coloană de HASH, și nu una de jeton", () => {
  // Ce se strică fără asta: un dump al bazei — un backup lăsat citibil, panoul
  // găzduirii, personalul furnizorului — ar preda fiecare sesiune vie. Coloana
  // se numește `token_hash` și e exact 64 de caractere, adică SHA-256 hexa; o
  // coloană `token` ar fi credențialul însuși.
  const sessions = statementFor("CREATE TABLE sessions (");
  assert.match(sessions, /token_hash\s+CHAR\(64\) CHARACTER SET ascii COLLATE ascii_bin NOT NULL/);
  const columns = tableColumns(sessions);
  for (const forbidden of ["token", "session_token", "secret"]) {
    assert.ok(!columns.includes(forbidden),
              `sessions.${forbidden}: o coloană care ar ține credențialul în clar`);
  }
});

test("unicitatea sesiunii ACTIVE e impusă de bază, prin coloană plus triggere", () => {
  // Invariantul de pe server e un index unic parțial
  // (`sessions_token_hash_idx ... WHERE revoked_at IS NULL`). MariaDB n-are
  // indexuri parțiale, iar coloana generată — varianta din prima versiune a
  // planului — e REFUZATĂ: `IF` și `CASE` nu sunt acceptate în
  // `GENERATED ALWAYS AS`, nici `STORED`, nici `VIRTUAL` (ERROR 1901, măsurat pe
  // gazdă pe 13 august 2026).
  //
  // Deci: coloană obișnuită, cheie unică pe ea, două triggere care o întrețin.
  // Ce se strică dacă lipsește vreuna dintre cele trei bucăți:
  //   * fără cheia unică — două sesiuni active cu același jeton, iar
  //     `sessionByToken` alege un rând la întâmplare;
  //   * fără `BEFORE INSERT` — coloana rămâne NULL la creare, deci cheia nu
  //     păzește nimic;
  //   * fără `BEFORE UPDATE` — revocarea nu eliberează jetonul, iar coloana
  //     rămâne ocupată de un rând mort.
  const sessions = statementFor("CREATE TABLE sessions (");
  assert.match(sessions, /active_token_hash\s+CHAR\(64\)/);
  assert.match(sessions, /UNIQUE KEY uk_sessions_active_token \(active_token_hash\)/);
  // Coloana e NULL-abilă: pe asta stă totul. Un index unic în MariaDB acceptă
  // oricâte NULL-uri, deci rândurile revocate nu se ciocnesc între ele.
  assert.match(sessions, /active_token_hash\s+CHAR\(64\)[^,]*NULL/);
  assert.ok(!/active_token_hash\s+CHAR\(64\)[^,]*NOT NULL/.test(sessions),
            "active_token_hash e NOT NULL: rândurile revocate s-ar ciocni între ele");

  // Și NU printr-o coloană generată, forma pe care MariaDB o refuză. Se caută
  // în instrucțiunile PARSATE, nu în textul fișierului: comentariul de deasupra
  // triggerelor explică tocmai de ce nu se poate folosi forma aia, iar o
  // verificare pe text ar fi picat din cauza propriei explicații.
  for (const stmt of authMigration().statements) {
    assert.ok(!/GENERATED ALWAYS AS/i.test(stmt.sql),
              `#${stmt.index}: coloană generată — MariaDB refuză IF/CASE acolo (ERROR 1901)`);
  }

  const insert = statementFor("CREATE TRIGGER sessions_active_token_bi");
  const update = statementFor("CREATE TRIGGER sessions_active_token_bu");
  for (const [what, sql] of [["INSERT", insert], ["UPDATE", update]] as const) {
    assert.match(sql, /ON sessions FOR EACH ROW SET NEW\.active_token_hash =/,
                 `triggerul de ${what} nu întreține coloana`);
    assert.match(sql, /IF\(NEW\.revoked_at IS NULL, NEW\.token_hash, NULL\)/,
                 `triggerul de ${what} nu leagă coloana de starea de revocare`);
  }
  assert.ok(insert.includes("BEFORE INSERT"), insert);
  assert.ok(update.includes("BEFORE UPDATE"), update);
});

test("timpii de autentificare n-au implicit, ca să nu fie scriși în alt fus", () => {
  // Restul schemei folosește `DEFAULT CURRENT_TIMESTAMP(6)`, care dă ora FUSULUI
  // SESIUNII. Fusul de pe găzduire nu a fost măsurat, iar aici diferența nu e
  // cosmetică: `expires_at` se compară cu ora serverului la fiecare cerere. O
  // sesiune scrisă în ora locală și comparată cu UTC ori trăiește ore în plus,
  // ori moare la naștere — și niciun simptom nu arată spre un fus orar.
  //
  // Deci coloanele de timp de aici sunt NOT NULL fără implicit, iar cine
  // inserează scrie `UTC_TIMESTAMP(6)`. Verificarea e pe TOATE tabelele
  // fișierului, nu doar pe `sessions`: regula ține pentru coloanele care nu
  // există încă.
  const offenders: string[] = [];
  let checked = 0;
  for (const stmt of authMigration().statements) {
    if (!/^CREATE TABLE/.test(stmt.sql)) continue;
    const table = /^CREATE TABLE (\w+)/.exec(stmt.sql)?.[1] ?? "?";
    for (const part of stmt.sql.slice(stmt.sql.indexOf("(") + 1).split(",")) {
      const words = part.trim().split(/\s+/);
      if (words.length < 2 || !/^DATETIME\(6\)$/i.test(words[1])) continue;
      checked++;
      if (/DEFAULT/i.test(part)) offenders.push(`${table}.${words[0]}`);
    }
  }
  assert.deepEqual(offenders, [],
                   `coloane de timp cu implicit în fusul sesiunii: ${offenders}`);
  assert.ok(checked >= 8, `doar ${checked} coloane DATETIME găsite`);
});

test("vocabularele închise sunt impuse de bază, prin CHECK", () => {
  // `ENUM` s-ar aplica strict doar sub `STRICT_TRANS_TABLES`, iar `sql_mode`-ul
  // găzduirii nu a fost măsurat: sub alt mod, un rol nevalid ar deveni un
  // avertisment și un șir gol — adică un utilizator fără rol, tăcut.
  const users = statementFor("CREATE TABLE users (");
  assert.match(users, /CHECK \(role IN \('owner', 'operator', 'viewer'\)\)/);
  const grants = statementFor("CREATE TABLE user_instances (");
  assert.match(grants, /CHECK \(role IN \('owner', 'operator', 'viewer'\)\)/);
  const attempts = statementFor("CREATE TABLE login_attempts (");
  assert.match(attempts, /CHECK \(\s*stage IS NULL OR stage IN \('password', 'totp'\)\)/);
});

// ---------------------------------------------------------------------------
// `0009_auth_bounds.sql`: ce ține limitarea în picioare, scris în schemă
// ---------------------------------------------------------------------------
function boundsMigration() {
  const found = discover().find((m) => m.file === "0009_auth_bounds.sql");
  assert.ok(found, "0009_auth_bounds.sql nu e descoperită de runner");
  return found;
}

/** Instrucțiunea din `0009` care conține textul dat. */
function boundsStatement(needle: string): string {
  const stmt = boundsMigration().statements.find((s) => s.sql.includes(needle));
  assert.ok(stmt, `nu găsesc în 0009 instrucțiunea care conține „${needle}”`);
  return stmt.sql;
}

test("numărătoarea globală are un index pe `at`, nu o baleiere a tabelei", () => {
  // `countFailuresGlobal` filtrează doar pe `result <> 'ok' AND at >= …`, iar
  // `result <> …` nu e sargabil. Fără un index pe `at` singur, numărătoarea aia
  // e o BALEIERE COMPLETĂ, la fiecare `POST /login` și la fiecare `POST /totp` —
  // adică fix pe drumul pe care se ajunge când panoul e sub rafală, exact când
  // tabela e cea mai mare. Cele două straturi cu prefix au deja indexul lor.
  assert.match(boundsStatement("CREATE INDEX ix_login_attempts_at"),
               /^CREATE INDEX ix_login_attempts_at ON login_attempts \(at\)$/);
});

test("pragul de 15 minute e scris în schemă, nu doar în proza unui docstring", () => {
  // Cine scrie jobul de retenție care va tăia tabela asta citește SQL, nu
  // TypeScript. Dacă șterge rânduri mai noi decât fereastra, șterge chiar starea
  // celor trei limitatoare — iar simptomul nu e o eroare, e un plafon care nu se
  // mai aplică, tăcut.
  const comment = boundsStatement("ALTER TABLE login_attempts COMMENT");
  assert.match(comment, /15 minute/,
               "COMMENT-ul tabelei nu spune cât e fereastra");
  assert.match(comment, /STAREA celor trei limitatoare/,
               "COMMENT-ul nu spune că tabela e stare, nu doar o urmă");
});

test("cele două coloane inerte din `users` o SPUN, în schemă", () => {
  // `failed_attempts` e `NOT NULL DEFAULT 0`: fără comentariu, orice raport sau
  // unealtă de administrare citește din ea „0 eșecuri" despre orice cont, pentru
  // totdeauna. O valoare falsă cu un consumator evident. `locked_until` e NULL
  // peste tot, ceea ce se citește la fel de ușor greșit ca „niciun cont blocat".
  for (const column of ["failed_attempts", "locked_until"]) {
    const stmt = boundsStatement(`MODIFY COLUMN ${column}`);
    assert.match(stmt, /COMMENT 'INERTA/,
                 `users.${column} nu spune în schemă că nu se mai scrie`);
  }
});

test("numele TASTAT se compară pe octeți, ca numele contului", () => {
  // Sub `utf8mb4_unicode_ci`, eșecurile tastate `ADMIN` intrau în fereastra lui
  // `admin`, iar `Admin` și `admin` — două conturi DISTINCTE în `users`, care e
  // `ascii_bin` — își împărțeau fereastra. A număra mai mult înseamnă a REFUZA
  // mai mult, iar eșecul pe care straturile astea există să-l scoată e negarea
  // operatorului legitim.
  //
  // `utf8mb4_bin`, nu `ascii_bin`: coloana ține ce s-a TASTAT, deci o tastare cu
  // diacritice trebuie să încapă (vezi argumentul din `0008_auth.sql`).
  assert.match(boundsStatement("MODIFY COLUMN username"),
               /COLLATE utf8mb4_bin\b/,
               "login_attempts.username se compară printr-o colație insensibilă");
});

test("un utilizator nou nu vede nicio instanță, fiindcă dreptul e un RÂND", () => {
  // „Vede tot din start" e eșecul tăcut: se descoperă când persoana greșită vede
  // serverul greșit. Aici se cere forma care face imposibilă varianta aia —
  // dreptul e o linie în `user_instances`, cu unicitate pe perechea
  // (utilizator, instanță), nu o coloană cu implicit în `users`.
  const grants = statementFor("CREATE TABLE user_instances (");
  assert.match(grants, /UNIQUE KEY uk_user_instances \(user_id, instance_id\)/);
  assert.match(grants,
               /instance_id VARCHAR\(64\) CHARACTER SET ascii COLLATE ascii_bin NOT NULL/);
  const users = statementFor("CREATE TABLE users (");
  for (const column of tableColumns(users)) {
    assert.ok(!column.includes("instance"),
              `users.${column}: apartenența la instanțe nu are voie să fie o coloană ` +
              "în users — de acolo se ajunge la un implicit care înseamnă „toate”");
  }
});
