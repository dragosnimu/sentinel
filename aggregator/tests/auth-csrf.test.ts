/**
 * Jetoanele CSRF, la nivelul primitivei.
 *
 * `tests/auth-routes.test.ts` probează că RUTA le cere. Aici se probează că
 * lucrul cerut chiar înseamnă ceva: un jeton pe care oricine îl poate fabrica e
 * un formular fără nicio apărare, iar o comparație care aruncă pe o lungime
 * greșită e un 500 pe o cale pe care o poate atinge oricine.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  PREAUTH_CSRF_TTL_S, PreAuthCsrf, constantTimeEquals, csrfValid,
} from "../lib/auth/csrf";

const SECRET = "secret-de-sesiune-doar-pentru-teste-0123456789abcdef0123456789ab";

test("perechea emisă se validează, și numai împreună", async () => {
  // Cookie-ul singur nu ajunge: cookie-urile pleacă și de pe o pagină ostilă.
  // Câmpul singur nu ajunge: el e text pe care îl poate scrie oricine.
  const csrf = new PreAuthCsrf(SECRET);
  const [cookie, form] = csrf.issue();

  assert.equal(csrf.validate(cookie, form), true);
  assert.equal(csrf.validate(cookie, null), false);
  assert.equal(csrf.validate(null, form), false);
  assert.equal(csrf.validate(cookie, ""), false);
});

test("nonce-ul dintr-o pereche nu merge cu cookie-ul altei perechi", async () => {
  // Fără egalitatea asta, un singur cookie valid ar accepta ORICE nonce — adică
  // exact ce are o pagină ostilă: cookie-ul victimei plus un câmp ales de ea.
  const csrf = new PreAuthCsrf(SECRET);
  const [cookieA] = csrf.issue();
  const [, formB] = csrf.issue();
  assert.equal(csrf.validate(cookieA, formB), false);
});

test("un cookie cu semnătura umblată e refuzat", async () => {
  // Dacă nonce-ul s-ar putea rescrie fără să pice semnătura, oricine ar putea
  // fabrica perechea întreagă și verificarea n-ar mai însemna nimic.
  const csrf = new PreAuthCsrf(SECRET);
  const [cookie] = csrf.issue();
  const [nonce, issued, signature] = cookie.split(".");

  assert.equal(csrf.validate(`${nonce}x.${issued}.${signature}`, `${nonce}x`), false,
               "nonce-ul a fost schimbat fără ca semnătura să pice");
  assert.equal(csrf.validate(`${nonce}.${issued}.${signature}x`, nonce), false);
  assert.equal(csrf.validate(`${nonce}.${issued}`, nonce), false,
               "un cookie fără semnătură a trecut");
});

test("un jeton semnat cu alt secret nu e al nostru", async () => {
  // Rotirea lui SENTINEL_SESSION_SECRET trebuie să invalideze formularele
  // deschise, nu să le lase valabile.
  const [cookie, form] = new PreAuthCsrf(`${SECRET}-altul`).issue();
  assert.equal(new PreAuthCsrf(SECRET).validate(cookie, form), false);
});

test("un jeton expirat, și unul din VIITOR, sunt amândouă refuzate", async () => {
  // Expirat: un cookie rămas într-un browser de pe o mașină comună nu are voie
  // să trăiască la nesfârșit. Din viitor: un ceas dat înainte pe mașina care l-a
  // emis ar produce altfel jetoane care nu expiră niciodată.
  const csrf = new PreAuthCsrf(SECRET);
  const now = Date.now();

  const [fresh, freshForm] = csrf.issue(now - (PREAUTH_CSRF_TTL_S - 5) * 1000);
  assert.equal(csrf.validate(fresh, freshForm, now), true,
               "un jeton încă valabil a fost refuzat");

  const [stale, staleForm] = csrf.issue(now - (PREAUTH_CSRF_TTL_S + 1) * 1000);
  assert.equal(csrf.validate(stale, staleForm, now), false, "un jeton expirat a trecut");

  const [ahead, aheadForm] = csrf.issue(now + 60_000);
  assert.equal(csrf.validate(ahead, aheadForm, now), false,
               "un jeton datat în viitor a trecut");
});

test("data se citește DUPĂ semnătură, deci nu se poate întinde", async () => {
  // Dacă vârsta s-ar verifica pe o valoare nesemnată, oricine ar putea rescrie
  // momentul emiterii și ar avea un jeton veșnic.
  const csrf = new PreAuthCsrf(SECRET);
  const now = Date.now();
  const [stale] = csrf.issue(now - (PREAUTH_CSRF_TTL_S + 1) * 1000);
  const [nonce, , signature] = stale.split(".");
  const rewritten = `${nonce}.${Math.floor(now / 1000)}.${signature}`;
  assert.equal(csrf.validate(rewritten, nonce, now), false,
               "momentul emiterii a fost rescris și jetonul a redevenit valabil");
});

test("comparația în timp constant nu ARUNCĂ pe lungimi diferite", async () => {
  // `timingSafeEqual` aruncă dacă tampoanele au lungimi diferite, iar lungimea o
  // alege cine trimite. Fără gardă, un jeton mai scurt ar fi 500 în mijlocul
  // rutei în loc de un refuz — pe o cale pe care o poate atinge oricine.
  assert.equal(constantTimeEquals("abc", "abcd"), false);
  assert.equal(constantTimeEquals("", ""), false, "două valori goale nu sunt „egale”");
  assert.equal(constantTimeEquals("abc", "abc"), true);
  assert.equal(constantTimeEquals(null, "abc"), false);
});

test("jetonul de sesiune se compară cu el însuși, nu cu nimic", async () => {
  // O sesiune fără jeton (coloană golită, rând citit pe jumătate) nu are voie să
  // accepte un formular gol: aia ar fi CSRF „trecut” pentru orice cerere.
  assert.equal(csrfValid("jeton-de-sesiune", "jeton-de-sesiune"), true);
  assert.equal(csrfValid("jeton-de-sesiune", "altceva-de-16b"), false);
  assert.equal(csrfValid(null, null), false);
  assert.equal(csrfValid("", ""), false);
});
