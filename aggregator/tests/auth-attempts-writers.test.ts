/**
 * O singură cale scrie în `login_attempts`, și trece prin limitator.
 *
 * ## Ce se strică fără regula asta
 *
 * Tabela `login_attempts` NU e doar o urmă: e STAREA celor trei limitatoare.
 * Toate trei numără rânduri din ea (`result <> 'ok'`). Deci orice cale care
 * scrie acolo fără să fi trecut de `checkThrottles` adaugă la numărătoarea care
 * ar fi trebuit s-o oprească, iar un plafon atins nu se mai stinge niciodată:
 * atacatorul îl reumple prin ușa nelimitată, cu o cerere din când în când, și
 * fiecare autentificare legitimă primește 503. Panoul n-are ieșire de urgență —
 * e o aplicație pe găzduire partajată, fără tunel ssh, fără altă ușă.
 *
 * S-a livrat de două ori, deci nu e o grijă teoretică:
 *
 *   * pe server, `security.py:265-278` scrie un rând `locked` la refuzul per
 *     sursă, iar `repo/users.py:247` îl numără;
 *   * aici, ramura cu nume gol și cea non-ASCII din `Authenticator.login`.
 *
 * ## De ce garda NUMĂRĂ căile în loc să le recunoască
 *
 * Fiindcă piesa 3 aduce rute noi care vor vrea să logheze. O gardă care caută
 * tiparele GREȘITE cunoscute e verde pentru al treilea tipar; una care numără
 * căile e roșie pentru orice cale nedeclarată, inclusiv pentru una scrisă într-o
 * formă la care nu s-a gândit nimeni. Aceeași formă ca `OWNED_TRIGGERS` din
 * `tests/schema.test.ts` și ca recensământul de constante din
 * `tests/unit/test_shipper.py`.
 *
 * Regula are trei jumătăți — recensăminte, toate — fiindcă se poate ajunge la
 * tabelă în trei feluri:
 *
 *   1. **prin SQL** — numele tabelei apare într-un SINGUR fișier livrat;
 *   2. **prin `logAttempt`** — care cere un permis emis doar de `checkThrottles`.
 *      Permisul e verificat la EXECUȚIE, nu doar la compilare: un cast e o
 *      afirmație, nu o dovadă;
 *   3. **prin cine ATINGE `logAttempt`** — fiindcă permisul singur nu spune că a
 *      fost emis pentru cererea asta. Un modul livrat care cheamă
 *      `checkThrottles` o dată, ține permisul într-o variabilă de modul și scrie
 *      apoi cu el trece de toate verificările de mai sus: măsurat, 500 de
 *      rânduri cu un singur permis. Recensământul apelantilor e ce îl prinde, și
 *      e nou din 17 august 2026 — până atunci `gate.ts` scria că golul ăsta „e
 *      acoperit de garda care numără căile", iar garda nu pomenea nici
 *      `logAttempt`, nici tabela din perspectiva apelantului.
 *
 * ## Ce se caută, și unde
 *
 * Toate trei se uită în ACELEAȘI fișiere livrate, iar ce înseamnă „livrat" e
 * scris o singură dată, în `tests/shipped-files.ts`: `app/`, `lib/`, `bin/`,
 * `migrations/` — recursiv — plus fișierele din RĂDĂCINA proiectului, cu
 * extensiile `.ts`, `.tsx`, `.js`, `.mjs`, `.cjs`, `.sql`.
 *
 * Lista a crescut de două ori, fiindcă de două ori i-a lipsit ceva:
 *
 *   * era doar TypeScript din primele trei directoare, iar jobul de retenție
 *     care va tăia tabela asta se scrie în SQL, în `migrations/` — inclusiv un
 *     `TRUNCATE`, care golește starea celor trei plafoane fără nicio eroare;
 *   * **nu cuprindea rădăcina.** În Next.js, `middleware.ts` trebuie să stea
 *     acolo, și e locul în care ajunge de obicei apărarea unui panou. Un
 *     `middleware.ts` cu un `INSERT` în tabela asta ar fi trecut toate cele nouă
 *     reguli de mai jos. Vezi `tests/shipped-files.ts`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { checkThrottles } from "../lib/auth/ratelimit";
import { logAttempt } from "../lib/auth/users";
import { readClientIp } from "../lib/auth/client-ip";
import { FakeAuthDb } from "./auth-harness";
import { readShipped, shippedFiles, shippedMatching } from "./shipped-files";
import type { ThrottlePass } from "../lib/auth/gate";

/**
 * Fișierele care au voie să atingă tabela DIN SQL, fiecare cu motivul.
 *
 * O intrare în plus care nu mai corespunde niciunui fișier pică la fel ca una
 * lipsă: o scutire moartă e o scutire care într-o zi acoperă altceva.
 */
const MAY_NAME_THE_TABLE: Record<string, string> = {
  "lib/auth/users.ts": "singurul loc care citește și scrie tabela; scrierea cere " +
                       "permisul emis de checkThrottles",
};

/**
 * Tabela FOLOSITĂ într-o instrucțiune, nu tabela pomenită într-un comentariu.
 *
 * Regula se uită la clauza SQL, nu la nume, fiindcă jumătate din fișierele
 * `lib/auth/` explică în proză de ce NU scriu acolo — iar o gardă care le-ar
 * număra pe alea ar fi ștearsă de primul om care o citește. Ce nu se poate
 * scrie fără să se potrivească aici e o instrucțiune care atinge tabela.
 *
 * Trei lucruri au fost adăugate pe 17 august 2026, după ce garda a rămas VERDE
 * pentru două rute care își scriau singure rândul:
 *
 *   * **fanionul `i`.** `insert into login_attempts (…)` cu minuscule e forma
 *     obișnuită în JavaScript, iar tiparul o rata;
 *   * **accentele grave.** ``INSERT INTO `login_attempts` `` e acceptat de
 *     MariaDB, iar `\s+login_attempts` nu supraviețuiește ghilimelei;
 *   * **ștergerile în masă.** `TRUNCATE` și `DROP TABLE` nu ating un rând, ating
 *     TOATE rândurile — adică golesc starea celor trei plafoane fără nicio
 *     eroare. Jobul de retenție e locul din care asta va veni.
 *
 * Ce NU se numără, dinadins: `CREATE TABLE` și `ALTER TABLE`. Alea nu sunt căi
 * spre RÂNDURI, iar `migrations/0008_auth.sql` și `0009_auth_bounds.sql` sunt
 * chiar fișierele care definesc tabela.
 */
const SQL_TOUCH =
  /(INSERT\s+INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?|DROP\s+TABLE|FROM|JOIN)\s+[`"]?login_attempts\b/i;

/** Fișierele care au voie să atingă emiterea permisului. */
const MAY_TOUCH_THE_PASS: Record<string, string> = {
  "lib/auth/gate.ts": "îl definește",
  "lib/auth/ratelimit.ts": "îl emite, pe ramura care PERMITE a lui checkThrottles",
};

/**
 * Fișierele livrate care au voie să POMENEASCĂ `logAttempt`, fiecare cu motivul.
 *
 * Recensământ pe NUME, nu pe forma apelului: `logAttempt(` ar fi un
 * recunoscător, iar un alias (`const write = logAttempt`) ar trece pe lângă el.
 * Ce se apără e „cine are voie să ajungă la singura scriere", iar aia e o
 * proprietate a depozitului.
 */
const MAY_CALL_LOG_ATTEMPT: Record<string, string> = {
  "lib/auth/users.ts": "o definește; e singura scriere în tabelă",
  "lib/auth/login.ts": "singurul apelant: politica de autentificare",
  "lib/auth/gate.ts": "o pomenește în proză, ca să explice ce cere permisul",
};

const matching = shippedMatching;

test("căutarea chiar umblă prin tot codul livrat, inclusiv prin subdirectoare", () => {
  // Fără aserțiunea asta, un walker care sare peste subdirectoare ar face
  // regulile de mai jos verzi pentru totdeauna — o listă goală care trece.
  // `lib/auth/` și `app/login/` sunt amândouă la al doilea nivel.
  //
  // `migrations/0008_auth.sql` e în listă fiindcă e proba că se citește și
  // ALTCEVA decât TypeScript: cât timp filtrul era `/\.tsx?$/`, o cale de
  // scriere într-un `.sql` (un job de retenție, o curățare de mână pusă în
  // migrații) era invizibilă pentru toate regulile de mai jos.
  //
  // `next.config.mjs` e proba pentru RĂDĂCINĂ, și e cea care lipsea: e singurul
  // fișier de nivel întâi din depozit azi, iar `middleware.ts` — care ar sta
  // lângă el — e locul în care ajunge apărarea unui panou Next.js.
  const files = shippedFiles();
  assert.ok(files.length >= 24, `prea puține fișiere livrate găsite: ${files.length}`);
  for (const expected of ["lib/auth/users.ts", "lib/auth/gate.ts", "app/login/route.ts",
                          "app/api/sentinel/sync/route.ts", "bin/migrate.ts",
                          "migrations/0008_auth.sql", "next.config.mjs"]) {
    assert.ok(files.includes(expected), `căutarea nu vede ${expected}`);
  }
});

test("tiparul care caută instrucțiuni chiar deosebește SQL-ul de proză", () => {
  // Verificat în AMBELE direcții, fiindcă amândouă greșelile sunt tăcute: un
  // tipar care nu potrivește nimic e o gardă verde pe vecie, iar unul care
  // potrivește orice comentariu e o gardă pe care o scoate primul om grăbit.
  //
  // Formele cu minuscule și cele cu accente grave sunt aici fiindcă garda a fost
  // VERDE pentru amândouă: două rute puse în `app/`, fiecare cu rândul ei scris
  // de mână, n-au fost văzute niciodată.
  for (const shipped of [
    'await db.write("INSERT INTO login_attempts (at, username) VALUES (?, ?)")',
    "  \"SELECT COUNT(*) AS n FROM login_attempts \" +",
    'db.write("DELETE FROM  login_attempts WHERE at < ?")',
    "sql = `UPDATE login_attempts SET detail = ?`",
    'db.write("insert into login_attempts (at, username) values (?, ?)")',
    "db.write('INSERT INTO `login_attempts` (at) VALUES (?)')",
    "db.write('delete from `login_attempts` where at < ?')",
    // Ștergerile în masă: golesc starea celor trei plafoane fără nicio eroare.
    "-- TRUNCATE TABLE login_attempts",
    "DROP TABLE login_attempts;",
    // Cuvântul-cheie despărțit de nume printr-o linie nouă, ca într-un SQL
    // formatat pe mai multe rânduri.
    "DELETE FROM\n  login_attempts\n WHERE at < ?",
  ]) {
    assert.ok(SQL_TOUCH.test(shipped), `tiparul nu vede instrucțiunea: ${shipped}`);
  }
  for (const prose of [
    " * Un refuz de limitare nu intră în `login_attempts`.",
    "// rândul din login_attempts nu capătă nimic cu care să se autentifice",
    " * `login_attempts` e STAREA celor trei limitatoare, nu doar o urmă.",
    "-- @guard table login_attempts",
    "CREATE TABLE login_attempts (",
    "ALTER TABLE login_attempts COMMENT = '...'",
  ]) {
    assert.ok(!SQL_TOUCH.test(prose), `tiparul potrivește proză sau DDL: ${prose}`);
  }
});

test("SQL care atinge `login_attempts` există într-un SINGUR fișier livrat", () => {
  // O rută nouă care își scrie singură rândul — cu `db.write`, cu altă funcție,
  // sau cu SQL lipit — nu trece prin permis și hrănește plafonul care tocmai a
  // refuzat pe toată lumea.
  const found = matching(SQL_TOUCH);
  assert.deepEqual(found, Object.keys(MAY_NAME_THE_TABLE).sort(),
                   "fișierele livrate care ating `login_attempts` din SQL nu sunt " +
                   "exact cele declarate în MAY_NAME_THE_TABLE. O cale nouă spre " +
                   "tabela asta trebuie să treacă prin `logAttempt`, care cere " +
                   "permisul de la checkThrottles — vezi lib/auth/gate.ts");
});

test("în fișierul ăla, o SINGURĂ instrucțiune scrie, și e în `logAttempt`", () => {
  // Citirile (cele trei numărători) sunt legitime; scrierea e cea care hrănește
  // plafonul. O a doua scriere, oriunde altundeva în modul, ar fi o cale care nu
  // trece prin gardă chiar dacă rămâne în fișierul declarat.
  const source = readShipped("lib/auth/users.ts");
  const writes = source.match(
    /(INSERT INTO|UPDATE|DELETE FROM|REPLACE INTO)\s+login_attempts/g) ?? [];
  assert.deepEqual(writes, ["INSERT INTO login_attempts"],
                   `scrierile găsite în lib/auth/users.ts: ${JSON.stringify(writes)}`);

  // Și e ÎN funcția care cere permisul, nu într-una vecină care n-ar cere nimic.
  const from = source.indexOf("export async function logAttempt");
  assert.ok(from > 0, "logAttempt nu mai e o funcție exportată la nivel de modul");
  const rest = source.slice(from + 1);
  const to = rest.indexOf("\nexport ");
  const body = to < 0 ? rest : rest.slice(0, to);
  assert.ok(body.includes("INSERT INTO login_attempts"),
            "singurul INSERT nu mai e în `logAttempt`, deci nu mai e cel păzit " +
            "de permis");
});

test("permisul se emite dintr-un singur loc, pe ramura care PERMITE", () => {
  // Permisul e o cheie: dacă a doua rută și-o emite singură, regula devine o
  // convenție. TypeScript n-are vizibilitate de pachet, deci „cine are voie să
  // emită" se ține AICI.
  assert.deepEqual(matching("grantThrottlePass"),
                   Object.keys(MAY_TOUCH_THE_PASS).sort(),
                   "cineva în plus atinge emiterea permisului");

  const ratelimit = readShipped("lib/auth/ratelimit.ts");
  assert.equal((ratelimit.match(/grantThrottlePass\(\)/g) ?? []).length, 1,
               "permisul se emite de mai multe ori în ratelimit.ts; fiecare " +
               "emitere e o cale pe care se poate scrie în login_attempts");
});

test("`logAttempt` se cheamă dintr-un SINGUR loc din codul livrat", () => {
  // Eșecul pe care îl previne, și e cel pe care permisul NU îl poate opri: un
  // modul livrat care cheamă `checkThrottles` o dată, ține permisul într-o
  // variabilă de modul și scrie apoi cu el oricâte rânduri. Permisul e valid —
  // chiar a fost emis de limitator —, tipul e mulțumit, verificarea la execuție
  // trece. Măsurat cu un astfel de modul pus în arbore: 500 de rânduri cu un
  // singur permis, iar garda asta era verde, 8/8.
  //
  // Deci întrebarea pe care o pune recensământul nu e „e permisul bun?", ci
  // „CINE ajunge la singura scriere?". Piesa 3 aduce rute noi care vor vrea să
  // logheze; fiecare pică aici până când e scrisă în MAY_CALL_LOG_ATTEMPT, iar
  // scrierea ei acolo e declarația.
  assert.deepEqual(matching("logAttempt"), Object.keys(MAY_CALL_LOG_ATTEMPT).sort(),
                   "fișierele livrate care ating `logAttempt` nu sunt exact cele " +
                   "declarate în MAY_CALL_LOG_ATTEMPT. Un apelant nou scrie în " +
                   "tabela care E starea celor trei plafoane — vezi lib/auth/gate.ts");

  // Și, în fișierul care are voie s-o cheme, se cheamă O SINGURĂ dată. Un al
  // doilea apel în `login.ts` n-ar fi prins de recensământ (fișierul e declarat),
  // dar ar fi un al doilea drum spre tabelă în chiar politica de autentificare.
  const login = readShipped("lib/auth/login.ts");
  assert.equal((login.match(/\blogAttempt\(/g) ?? []).length, 1,
               "lib/auth/login.ts cheamă `logAttempt` de mai multe ori; fiecare " +
               "apel e o cale pe care se scrie în login_attempts");
  const users = readShipped("lib/auth/users.ts");
  assert.equal((users.match(/\blogAttempt\(/g) ?? []).length, 1,
               "lib/auth/users.ts are mai mult de o `logAttempt(` — definiția ei " +
               "e singura de acolo");
});

test("regula chiar refuză un fișier nedeclarat — declanșată izolat", () => {
  // Regula de CITIRE, văzută picând singură. Ca `assertChildDeclarable` din
  // `tests/subrows.test.ts`: o regulă a cărei declanșare n-a fost văzută e o
  // regulă despre care nu se știe pe ce pică.
  const pretend = [...Object.keys(MAY_NAME_THE_TABLE), "app/panou/route.ts"].sort();
  assert.throws(
    () => assert.deepEqual(pretend, Object.keys(MAY_NAME_THE_TABLE).sort()),
    /panou/);
});

// ---------------------------------------------------------------------------
// A doua jumătate: permisul, probat prin EFECT
// ---------------------------------------------------------------------------
const RECORD = {
  username: "operator", ip: null, userAgent: null,
  result: "bad_password", stage: "password",
} as const;

test("un permis FABRICAT nu scrie nimic — aruncă", async () => {
  // Tipul singur ar fi o afirmație: `{} as ThrottlePass` trece de compilator.
  // Ce trebuie să nu treacă e execuția, altfel prima rută a piesei 3 care „știe
  // ce face" își fabrică unul și regula dispare fără ca nimic să pice.
  const db = new FakeAuthDb();
  await assert.rejects(
    () => logAttempt(db, { gate: "checkThrottles" } as ThrottlePass, RECORD),
    /checkThrottles/,
    "un permis fabricat a fost acceptat");
  assert.equal(db.loginAttempts.length, 0,
               "rândul s-a scris totuși; refuzul a fost doar un mesaj");
});

test("permisul de la `checkThrottles` scrie, iar refuzul nu poartă niciunul",
     async () => {
  // Cele două jumătăți ale aceleiași reguli, în același test: calea permisă
  // CHIAR funcționează (altfel primul test ar putea trece pentru că nimic nu
  // scrie vreodată), iar ramura care refuză nu are ce da mai departe.
  const db = new FakeAuthDb();
  const ip = readClientIp(new Headers());

  const allowed = await checkThrottles(db, ip);
  assert.equal(allowed.allowed, true);
  await logAttempt(db, (allowed as { pass: ThrottlePass }).pass, RECORD);
  assert.equal(db.loginAttempts.length, 1, "calea permisă nu a scris rândul");

  for (let i = 0; i < 200; i++) {
    db.loginAttempts.push({
      at: db.nowMs, username: `u${i}`, ip: null, user_agent: null,
      result: "bad_password", stage: "password", session_id: null, detail: null,
    });
  }
  const refused = await checkThrottles(db, ip);
  assert.equal(refused.allowed, false, "plafonul global nu a refuzat");
  assert.ok(!("pass" in refused),
            "ramura care refuză poartă un permis: de pe ea s-ar putea scrie " +
            "chiar rândul care prelungește refuzul");
});
