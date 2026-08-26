/**
 * Sesiunile: ce ajunge în bază, ce se întâmplă la promovare, ce mai deschide un
 * jeton vechi.
 *
 * Testele rulează peste `FakeAuthDb` — un MODEL al bazei, nu o bază. Ce
 * modelează (triggerele și cheia unică) e legat de `migrations/0008_auth.sql`
 * printr-o aserțiune, iar ce NU dovedește e scris în capul lui
 * `tests/auth-harness.ts`: că MariaDB acceptă construcțiile și că refuzul e chiar
 * ERROR 1062 se probează pe gazdă, nu de aici.
 *
 * Ce se strică pentru operator dacă lipsesc:
 *
 *   * jetonul în clar în bază — un dump (backup citibil, panoul găzduirii,
 *     personalul furnizorului) devine o listă de sesiuni gata de folosit;
 *   * jetonul nerotit la promovare — cookie-ul etapei întâi, scăpat între cele
 *     două etape, rămâne valabil după ce al doilea factor a trecut;
 *   * revocarea fără efect — „deconectează toate sesiunile", după un telefon
 *     pierdut, nu deconectează nimic, și nimic nu spune asta.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  PENDING_TOTP_TTL_S, SESSION_TOKEN_BYTES, createSession, hashToken, newToken,
  promoteSession, revokeAllForUser, revokeSession, sessionByToken, touchSession,
} from "../lib/auth/session";
import { FakeAuthDb } from "./auth-harness";

const TTL = 43_200;   // 12 ore, ca `web.session_ttl_s` de pe server

async function loggedIn(db: FakeAuthDb, pendingTotp = false) {
  return await createSession(db, {
    userId: 7, ip: "203.0.113.10", userAgent: "curl/8", ttlS: TTL, pendingTotp,
  });
}

test("jetonul are 256 de biți și se întoarce o singură dată", async () => {
  assert.equal(SESSION_TOKEN_BYTES, 32);
  // base64url fără umplutură: 32 de octeți = 43 de caractere.
  assert.equal(newToken().length, 43);
  assert.notEqual(newToken(), newToken());

  const db = new FakeAuthDb();
  const { token, session } = await loggedIn(db);
  assert.equal(token.length, 43);
  assert.equal(session.userId, 7);
  assert.equal(session.pendingTotp, false);
  // Rândul se citește ÎNAPOI după inserare, nu se fabrică din ce s-a trimis: o
  // inserare care raportează succes fără să lase un rând ar întoarce altfel un
  // jeton pentru o sesiune care nu există.
  assert.equal(session.id.length, 32);
  assert.equal(session.csrfToken.length, 43);
});

test("jetonul în clar nu ajunge în nicio coloană", async () => {
  // Cerința e verificată pe ce a PLECAT spre bază, nu pe ce s-a stocat în model:
  // dacă cineva ar adăuga o coloană `token` la `INSERT`, aici s-ar vedea.
  const db = new FakeAuthDb();
  const { token } = await loggedIn(db);

  for (const { sql, params } of db.statements) {
    for (const param of params) {
      assert.notEqual(param, token,
                      `jetonul în clar a plecat spre bază ca parametru: ${sql}`);
    }
    assert.ok(!sql.includes(token), `jetonul în clar e lipit în SQL: ${sql}`);
  }
  // Și ce s-a stocat e chiar hashul lui — altfel testul de mai sus ar trece și
  // dacă nu s-ar stoca nimic.
  assert.equal(db.sessions[0].token_hash, hashToken(token));
  assert.equal(db.sessions[0].token_hash.length, 64);
  assert.match(db.sessions[0].token_hash, /^[0-9a-f]{64}$/);
});

test("jetonul deschide sesiunea; orice altă valoare nu", async () => {
  const db = new FakeAuthDb();
  const { token, session } = await loggedIn(db);
  const found = await sessionByToken(db, token);
  assert.equal(found?.id, session.id);

  for (const wrong of ["", newToken(), hashToken(token)]) {
    assert.equal(await sessionByToken(db, wrong), null,
                 `„${wrong.slice(0, 12)}…” a deschis o sesiune`);
  }
});

test("o sesiune expirată e la fel de tăcută ca una inexistentă", async () => {
  // Filtrarea e în SQL, deci apelantul nu poate deosebi „expirată" de „n-a
  // existat niciodată" — cine încearcă jetoane n-are ce afla din răspuns.
  const db = new FakeAuthDb();
  const { token } = await loggedIn(db);
  db.nowMs += (TTL - 1) * 1000;
  assert.notEqual(await sessionByToken(db, token), null, "a expirat prea devreme");
  db.nowMs += 2000;
  assert.equal(await sessionByToken(db, token), null, "sesiunea expirată încă deschide");
});

test("o sesiune în așteptarea TOTP trăiește 5 minute, nu 12 ore", async () => {
  // O jumătate de login abandonată nu are voie să stea douăsprezece ore
  // așteptând să fie ridicată de altcineva.
  assert.equal(PENDING_TOTP_TTL_S, 300);
  const db = new FakeAuthDb();
  const { token, session } = await loggedIn(db, true);
  assert.equal(session.pendingTotp, true);
  db.nowMs += (PENDING_TOTP_TTL_S + 1) * 1000;
  assert.equal(await sessionByToken(db, token), null,
               "sesiunea pe jumătate autentificată a primit TTL-ul întreg");
});

test("promovarea rotește jetonul, iar cel vechi nu mai deschide nimic", async () => {
  // Dacă jetonul etapei întâi a scăpat între cele două etape — terminal
  // partajat, jurnal de proxy, istoricul browserului — valoarea scursă trebuie să
  // devină inutilă în clipa în care al doilea factor trece. Fără rotire, ea
  // deschide o sesiune ACUM COMPLET autentificată.
  const db = new FakeAuthDb();
  const { token: pending, session } = await loggedIn(db, true);

  const rotated = await promoteSession(db, session.id, TTL);
  assert.ok(rotated, "promovarea nu a întors un jeton nou");
  assert.notEqual(rotated, pending, "jetonul NU a fost rotit la promovare");

  assert.equal(await sessionByToken(db, pending), null,
               "jetonul dinaintea promovării încă deschide sesiunea");
  const now = await sessionByToken(db, rotated as string);
  assert.equal(now?.id, session.id);
  assert.equal(now?.pendingTotp, false);
  // Și jetonul CSRF s-a schimbat odată cu el, din același motiv.
  assert.notEqual(now?.csrfToken, session.csrfToken);
  // Iar TTL-ul e acum cel întreg, nu cel de cinci minute.
  db.nowMs += (PENDING_TOTP_TTL_S + 60) * 1000;
  assert.notEqual(await sessionByToken(db, rotated as string), null);
});

test("o sesiune deja promovată nu se mai poate promova a doua oară", async () => {
  // Ce se strică fără condiția `pending_totp = 1`: o cerere reluată spre `/totp`
  // ar roti jetonul unei sesiuni complet autentificate, deconectând un om care
  // n-a făcut nimic. `null` înseamnă „n-am promovat nimic", nu „a mers".
  const db = new FakeAuthDb();
  const { session } = await loggedIn(db, true);
  assert.ok(await promoteSession(db, session.id, TTL));
  assert.equal(await promoteSession(db, session.id, TTL), null);
  assert.equal(await promoteSession(db, "id-care-nu-exista", TTL), null);
});

test("revocarea închide sesiunea, și spune dacă chiar era deschisă", async () => {
  const db = new FakeAuthDb();
  const { token, session } = await loggedIn(db);
  assert.equal(await revokeSession(db, session.id, "logout"), true);
  assert.equal(await sessionByToken(db, token), null, "sesiunea revocată încă deschide");
  // A doua oară nu mai era nimic de închis. `false` nu e un eșec, e răspunsul.
  assert.equal(await revokeSession(db, session.id, "logout"), false);
  assert.equal(db.sessions[0].revoked_reason, "logout");
});

test("revocarea în masă închide toate sesiunile omului, și numai ale lui", async () => {
  // Se cheamă la schimbarea parolei și când operatorul pierde un dispozitiv. O
  // resetare care lasă sesiunile vechi în viață n-a scos pe nimeni afară.
  const db = new FakeAuthDb();
  const mine = [await loggedIn(db), await loggedIn(db)];
  const other = await createSession(db, {
    userId: 8, ip: null, userAgent: null, ttlS: TTL, pendingTotp: false });

  assert.equal(await revokeAllForUser(db, 7, "parola schimbata"), 2);
  for (const { token } of mine) {
    assert.equal(await sessionByToken(db, token), null);
  }
  assert.notEqual(await sessionByToken(db, other.token), null,
                  "revocarea a atins sesiunea altui utilizator");
  assert.equal(await revokeAllForUser(db, 7), 0);
});

test("două sesiuni ACTIVE cu același jeton sunt refuzate de bază", async () => {
  // Invariantul emulat prin `active_token_hash` + trigger + cheie unică. Cod
  // livrat nu poate produce coliziunea (jetoanele au 256 de biți), deci se
  // forțează — altfel regula n-ar fi fost văzută niciodată aplicându-se.
  //
  // ATENȚIE la ce dovedește: MODELUL din `auth-harness.ts` refuză, iar modelul e
  // legat de textul migrației. Că MariaDB refuză cu ERROR 1062 se probează pe
  // gazdă.
  const db = new FakeAuthDb();
  const { token, session } = await loggedIn(db);
  const duplicate = () => db.insertRow({
    id: "b".repeat(32), user_id: 7, token_hash: hashToken(token),
    active_token_hash: null, csrf_token: "c".repeat(43), pending_totp: 0,
    created_ip: null, user_agent: null, created_at: db.nowMs, last_seen_at: db.nowMs,
    expires_at: db.nowMs + TTL * 1000, revoked_at: null, revoked_reason: null,
  });
  assert.throws(duplicate, /uk_sessions_active_token/,
                "al doilea rând ACTIV cu același jeton a fost acceptat");

  // Iar revocarea ELIBEREAZĂ jetonul: `active_token_hash` devine NULL, iar
  // NULL-urile nu se ciocnesc. Fără partea asta, un jeton revocat ar rămâne
  // ocupat pentru totdeauna de un rând mort.
  assert.equal(await revokeSession(db, session.id, "test"), true);
  assert.doesNotThrow(duplicate, "revocarea nu a eliberat jetonul");

  // Și două rânduri REVOCATE cu același jeton trec: duplicatele de NULL sunt
  // acceptate de un index unic.
  assert.equal(await revokeSession(db, "b".repeat(32), "test"), true);
  assert.doesNotThrow(duplicate, "două rânduri revocate cu același jeton au fost refuzate");
});

test("ultima activitate se notează fără să împingă expirarea", async () => {
  // O expirare glisantă înseamnă că un cookie furat rămâne valabil cât îl
  // folosește hoțul. Una absolută pune un plafon pe pagubă.
  const db = new FakeAuthDb();
  const { token, session } = await loggedIn(db);
  const expiresAt = db.sessions[0].expires_at;
  db.nowMs += 60_000;
  await touchSession(db, session.id);
  assert.equal(db.sessions[0].expires_at, expiresAt, "expirarea a fost împinsă");
  assert.equal(db.sessions[0].last_seen_at, db.nowMs);
  assert.notEqual(await sessionByToken(db, token), null);
});

test("un TTL fără sens e o eroare, nu o sesiune eternă sau moartă", async () => {
  // `ttlS = 0` ar da o sesiune expirată la naștere (omul „nu se poate
  // autentifica"), iar un negativ una expirată în trecut. Amândouă arată ca o
  // parolă greșită.
  const db = new FakeAuthDb();
  for (const bad of [0, -1, 1.5, Number.NaN]) {
    await assert.rejects(() => createSession(db, {
      userId: 7, ip: null, userAgent: null, ttlS: bad, pendingTotp: false }));
  }
  const { session } = await loggedIn(db, true);
  await assert.rejects(() => promoteSession(db, session.id, 0));
});
