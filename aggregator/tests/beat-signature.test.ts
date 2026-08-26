/**
 * Verificarea semnăturii: ce trebuie acceptat și, mai ales, ce trebuie refuzat.
 *
 * Dacă verificarea acceptă un corp modificat, oricine poate injecta un semnal
 * fals „totul e în regulă" în martor, iar martorul devine exact minciuna
 * pentru care a fost construit ca antidot. Dacă crapă în loc să refuze, o
 * semnătură de lungime greșită — pe care o dă orice scanner care lovește ruta —
 * transformă un 401 într-un 500 și umple jurnalul până când nimeni nu-l mai
 * citește.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";

import { canonical, signatureValid } from "@/lib/verify";

const KEY = "cheie-buna-test";
const OTHER_KEY = "cheie-gresita-test";

const BODY = canonical({ seq: 7, sent_at: "2026-08-12T09:00:00+00:00", last_event_id: 5 });
const GOOD = crypto.createHmac("sha256", KEY).update(BODY, "utf8").digest("hex");

test("semnătura corectă e acceptată", () => {
  assert.equal(signatureValid(BODY, GOOD, KEY), true);
});

test("corpul modificat e refuzat", () => {
  // Un octet schimbat în conținut, semnătura rămâne cea originală. Ăsta e
  // atacul: contoare umflate ca să pară că ingestia merge.
  const tampered = BODY.replace('"last_event_id":5', '"last_event_id":999999');
  assert.notEqual(tampered, BODY, "fixtura nu a modificat nimic — testul nu ar dovedi nimic");
  assert.equal(signatureValid(tampered, GOOD, KEY), false);
});

test("semnătura modificată e refuzată", () => {
  // Un singur caracter hexa schimbat, aceeași lungime — cazul pe care o
  // comparație pe lungime l-ar rata.
  const flipped = (GOOD[0] === "a" ? "b" : "a") + GOOD.slice(1);
  assert.equal(flipped.length, GOOD.length);
  assert.equal(signatureValid(BODY, flipped, KEY), false);
});

test("cheia greșită e refuzată", () => {
  const withOther = crypto.createHmac("sha256", OTHER_KEY).update(BODY, "utf8").digest("hex");
  assert.equal(signatureValid(BODY, withOther, KEY), false);
  assert.equal(signatureValid(BODY, GOOD, OTHER_KEY), false);
});

test("o semnătură de altă lungime e refuzată, nu aruncă excepție", () => {
  // `crypto.timingSafeEqual` ARUNCĂ dacă tampoanele au lungimi diferite. Fără
  // verificarea de lungime dinainte, orice cerere cu antetul scurt sau lipsă —
  // adică orice scanner — ar da 500 în loc de 401.
  for (const bad of ["", "gresit", "a", GOOD + "00", GOOD.slice(0, 63)]) {
    assert.doesNotThrow(() => signatureValid(BODY, bad, KEY));
    assert.equal(signatureValid(BODY, bad, KEY), false, `a acceptat ${JSON.stringify(bad)}`);
  }
});

test("un antet lipsă (undefined) e tratat ca refuz, nu ca excepție", () => {
  // Ruta trimite `req.headers.get(...) || ""`, dar funcția nu are voie să
  // depindă de asta.
  assert.doesNotThrow(() => signatureValid(BODY, undefined as unknown as string, KEY));
  assert.equal(signatureValid(BODY, undefined as unknown as string, KEY), false);
});
