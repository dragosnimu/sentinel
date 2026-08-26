/**
 * Dublul de bază de date, probat el însuși.
 *
 * `auth-harness.ts` e infrastructură de test, dar deciziile lui sunt aceleași
 * decizii: dacă el răspunde „da" acolo unde MariaDB răspunde „nu", atunci
 * testele de sesiune și de TOTP sunt verzi despre cod care în producție nu face
 * nimic. Regulile de mai jos sunt exact cele pe care le susține docstring-ul lui,
 * și niciuna nu fusese văzută picând — trei dintre ele erau chiar false.
 *
 * Ce se strică pentru operator, în ordinea în care apar mai jos:
 *
 *   * o instrucțiune pe care dublul n-o înțelege, trecută ca operație nulă, e
 *     cod nelivrabil raportat verde: revocarea, promovarea TOTP și consumul de
 *     contor sunt toate un `UPDATE` condiționat, iar „n-a făcut nimic" e chiar
 *     răspunsul lor de succes-parțial;
 *   * un parametru rămas nelegat înseamnă o condiție ștearsă din `WHERE`, adică
 *     o revocare care atinge mai multe sesiuni decât cea cerută;
 *   * o inegalitate pe o coloană goală, adevărată aici și falsă la MariaDB, e
 *     forma prin care garda de reluare a codului TOTP ar putea fi scoasă „pe
 *     baza testelor".
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { FakeAuthDb } from "./auth-harness";
import type { AttemptRow } from "./auth-harness";

/** Proiecția pe care o cere dublul de la orice `SELECT` din `sessions`. */
const SELECT = "SELECT id, user_id, pending_totp, csrf_token, created_at, " +
               "last_seen_at, expires_at, created_ip FROM sessions";

test("o condiție nerecunoscută e o EROARE și pe o tabelă goală", async () => {
  // Gramatica se evalua per rând candidat, deci pe o tabelă fără rânduri nu se
  // evalua deloc: forma nerecunoscută se întorcea ca „0 rânduri afectate".
  // Verificat: `users` și `sessions` sunt goale aici.
  const db = new FakeAuthDb();
  assert.equal(db.users.length, 0);
  assert.equal(db.sessions.length, 0);

  await assert.rejects(
    () => db.write("UPDATE users SET totp_last_counter = ? WHERE id = ? AND " +
                   "totp_last_counter LIKE ?", [5, 1, "%"]),
    /nu recunoaște condiția/,
    "o condiție necunoscută pe o tabelă goală a trecut ca operație nulă");

  await assert.rejects(
    () => db.write("UPDATE users SET totp_last_counter = NOW() WHERE id = ?", [1]),
    /nu recunoaște valoarea/,
    "o valoare necunoscută pe o tabelă goală a trecut ca operație nulă");

  await assert.rejects(
    () => db.all(`${SELECT} WHERE id LIKE ?`, ["%"]),
    /nu recunoaște condiția/,
    "o condiție necunoscută într-un SELECT fără rânduri a trecut ca „niciun rând”");
});

test("un parametru rămas nelegat e o EROARE, nu un WHERE mai larg", async () => {
  // Verificarea exista doar pe ramura `INSERT`. Un `UPDATE` cu un parametru în
  // plus e o condiție ștearsă din `WHERE`; MariaDB refuză instrucțiunea, dublul
  // o executa mai larg și raporta rândurile atinse ca succes.
  const db = new FakeAuthDb();
  db.addUser(1);

  await assert.rejects(
    () => db.write("UPDATE users SET totp_last_counter = ? WHERE id = ?", [5, 1, 99]),
    /parametri neconsumați/,
    "un UPDATE cu un parametru în plus a fost executat");

  await assert.rejects(
    () => db.all(`${SELECT} WHERE id = ?`, ["s1", "s2"]),
    /parametri neconsumați/,
    "un SELECT cu un parametru în plus a fost executat");

  // Iar forma corectă chiar trece — altfel regulile de sus ar fi mulțumite de un
  // dublu care refuză tot.
  assert.equal(
    await db.write("UPDATE users SET totp_last_counter = ? WHERE id = ?", [5, 1]), 1);
  assert.equal(db.users[0].totp_last_counter, 5);
  assert.deepEqual(await db.all(`${SELECT} WHERE id = ?`, ["s1"]), []);
});

test("o comparație cu NULL nu potrivește rândul, ca la MariaDB", async () => {
  // `Number(null) === 0` făcea `col < ?` adevărat pe o coloană goală, unde SQL
  // dă NULL — adică nicio potrivire. Coloanele pe care le aduce piesa 2
  // (`users.locked_until`, `users.totp_confirmed_at`) sunt exact forma asta:
  // NULL-abile și comparate cu inegalități.
  const db = new FakeAuthDb();
  const user = db.addUser(1);
  assert.equal(user.totp_last_counter, null, "contorul pornește gol");

  assert.equal(
    await db.write("UPDATE users SET totp_last_counter = ? " +
                   "WHERE id = ? AND totp_last_counter < ?", [9, 1, 9]), 0,
    "o inegalitate pe o coloană NULL a potrivit rândul; la MariaDB nu ar fi " +
    "potrivit nimic, deci codul livrat ar fi verde aici și mort în producție");
  assert.equal(user.totp_last_counter, null);

  // Forma pe care o scrie chiar `consumeTotpCounter` — cu garda `IS NULL OR` —
  // trebuie să potrivească. Ea e motivul pentru care limita de mai sus n-a fost
  // niciodată un defect livrat.
  assert.equal(
    await db.write("UPDATE users SET totp_last_counter = ? WHERE id = ? AND " +
                   "(totp_last_counter IS NULL OR totp_last_counter < ?)", [9, 1, 9]), 1);
  assert.equal(user.totp_last_counter, 9);

  // Și, odată scris contorul, inegalitatea decide singură: un contor reluat nu
  // mai potrivește.
  assert.equal(
    await db.write("UPDATE users SET totp_last_counter = ? WHERE id = ? AND " +
                   "(totp_last_counter IS NULL OR totp_last_counter < ?)", [9, 1, 9]), 0);
  assert.equal(
    await db.write("UPDATE users SET totp_last_counter = ? WHERE id = ? AND " +
                   "(totp_last_counter IS NULL OR totp_last_counter < ?)", [10, 1, 10]), 1);
});

test("un parametru care nu e finit e REFUZAT, ca `ERROR 1054` la MariaDB",
     async () => {
  // Eșecul pe care îl previne, și e unul care se ascunde într-un test verde:
  // `mysql2` scrie un număr în textul instrucțiunii, deci `NaN` ajunge la server
  // ca `WHERE id = NaN`, iar acolo `NaN` e un NUME DE COLOANĂ — „Unknown column
  // 'NaN'", măsurat pe MariaDB 10.5.29. Dublul îl compara ca valoare și
  // răspundea liniștit „zero rânduri".
  //
  // Ce se strică pentru operator dacă dublul rămâne mai îngăduitor: garda de
  // formă din `lib/data/incidents.ts` (`Number.isSafeInteger`) se poate scoate
  // fără ca nimic să se înroșească, iar pe gazdă `/api/panel/incidents/abc`
  // devine 503 în timp ce `/api/panel/incidents/999999` rămâne 404. Diferența
  // aia e chiar oracolul care spune care id-uri există.
  const db = new FakeAuthDb();
  db.addUser(1);

  for (const value of [Number("abc"), Number("1e999"), -Infinity]) {
    await assert.rejects(
      () => db.all("SELECT id, username FROM users WHERE id = ?", [value]),
      /Unknown column/,
      `dublul a acceptat parametrul ${String(value)}, pe care serverul îl refuză`);
  }

  // Și un întreg obișnuit trece — altfel regula de mai sus ar fi „nicio
  // interogare nu merge", ceea ce ar trece la fel de bine.
  assert.equal((await db.all("SELECT id, username FROM users WHERE id = ?", [1]))
    .length, 1);
});

// ---------------------------------------------------------------------------
// Gramatica adăugată de piesa 2, probată separat
// ---------------------------------------------------------------------------
//
// Numărătorile limitatorului de rată se sprijină pe formele de mai jos. Dacă
// dublul le evaluează altfel decât MariaDB, testele de limitare din
// `tests/auth-routes.test.ts` sunt verzi despre praguri care în producție ar
// număra altceva — sau nimic.

/** Un rând de încercare, cu implicitele care nu contează pentru testul curent. */
function attempt(over: Partial<AttemptRow> = {}): AttemptRow {
  return { at: 0, username: "u", ip: null, user_agent: null, result: "bad_password",
           stage: "password", session_id: null, detail: null, ...over };
}

test("`<>` exclude rândurile egale, iar un NULL nu se potrivește", async () => {
  // Limitatorul numără `result <> 'ok'`. Dacă dublul ar trata condiția ca mereu
  // adevărată, autentificările REUȘITE ar intra în numărătoare și pragul s-ar
  // atinge singur; dacă ar trata-o ca mereu falsă, n-ar număra nimic niciodată.
  const db = new FakeAuthDb();
  db.loginAttempts.push(attempt({ result: "ok" }),
                        attempt({ result: "bad_password" }),
                        attempt({ result: "bad_totp" }),
                        attempt({ result: null as unknown as string }));

  const rows = await db.all(
    "SELECT COUNT(*) AS n FROM login_attempts WHERE result <> 'ok' AND at >= ?", [-1]);
  assert.equal(rows[0].n, "2",
               "„<>” nu a exclus rândul egal, sau a potrivit rândul NULL — la " +
               "MariaDB, NULL <> 'ok' e NECUNOSCUT, deci nu se numără");
});

test("`COUNT(*)` întoarce un ȘIR, ca `bigNumberStrings`", async () => {
  // Driverul chiar face asta (`lib/db.ts`). Un cod care presupune un număr —
  // `n >= LIMIT` pe un șir compară altfel — trebuie să pice aici, nu pe gazdă.
  const db = new FakeAuthDb();
  db.loginAttempts.push(attempt());
  const rows = await db.all("SELECT COUNT(*) AS n FROM login_attempts WHERE at >= ?",
                            [-1]);
  assert.equal(typeof rows[0].n, "string");
});

test("fereastra `- INTERVAL ? MINUTE` chiar taie rândurile vechi", async () => {
  // Fereastra alunecătoare e tot ce face limitarea să se autorepare. Dacă
  // dublul ar ignora scăderea, un prag atins o dată ar rămâne atins pentru
  // totdeauna în teste, iar în producție s-ar comporta invers.
  const db = new FakeAuthDb();
  db.loginAttempts.push(attempt({ at: db.nowMs - 20 * 60_000 }),
                        attempt({ at: db.nowMs - 60_000 }));
  const rows = await db.all(
    "SELECT COUNT(*) AS n FROM login_attempts " +
    " WHERE at >= UTC_TIMESTAMP(6) - INTERVAL ? MINUTE", [15]);
  assert.equal(rows[0].n, "1", "fereastra nu a exclus rândul de acum 20 de minute");
});

test("`col + 1` citește valoarea din RÂND, nu o constantă", async () => {
  // Incrementul contorului de încercări. Scris ca `failed_attempts = 1`, contul
  // n-ar ajunge niciodată la prag, iar blocarea per utilizator — singurul strat
  // care ține fără o sursă de încredere — n-ar mai exista.
  const db = new FakeAuthDb();
  db.addUser(1, { failed_attempts: 4 });
  assert.equal(
    await db.write("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
                   [1]), 1);
  assert.equal(db.users[0].failed_attempts, 5);
});

test("un `INSERT` într-o tabelă necunoscută e o EROARE, nu un rând pierdut", async () => {
  // Un dublu care înghite scrierea într-o tabelă pe care n-o are raportează
  // verde pentru cod care în producție ar da „Table doesn't exist".
  const db = new FakeAuthDb();
  await assert.rejects(
    () => db.write("INSERT INTO inexistenta (a) VALUES (?)", [1]),
    /nu cunoaște tabela/);
});
