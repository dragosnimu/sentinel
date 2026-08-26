/**
 * Adresa clientului: când se poate sprijini o decizie pe ea, și când nu.
 *
 * Ce se strică dacă modulul ăsta greșește, în ambele direcții:
 *
 *   * **prea încrezător** — limitarea per sursă se aplică pe o valoare aleasă de
 *     client. Nu doar inutilă: cine trimite douăzeci de eșecuri cu adresa
 *     operatorului în antet blochează operatorul, din afară, fără să știe nicio
 *     parolă. Iar coloanele `INET6` din registru se umplu cu adrese inventate,
 *     adică o urmă de audit care minte;
 *   * **prea sceptic** — operatorul a măsurat antetul, l-a declarat, și tot nu
 *     se aplică nimic. Stratul cerut de plan lipsește în tăcere.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CLIENT_IP_HEADER_ENV, ipNote, normalizeAddress, readClientIp,
} from "../lib/auth/client-ip";

const HEADER = "x-hcdn-client-ip";
const CONFIGURED = { [CLIENT_IP_HEADER_ENV]: HEADER };

function headers(values: Record<string, string>): Headers {
  return new Headers(values);
}

test("IPv4 se scrie mapat, fiindcă coloana e INET6", async () => {
  // Că MariaDB acceptă un literal IPv4 punctat direct într-un `INET6` NU s-a
  // măsurat — nu există bază de date pe mașina asta. Forma mapată e IPv6 valid
  // în orice lectură, deci trece în ambele lumi; alternativa ar fi o eroare de
  // inserare la fiecare autentificare, pe care nimeni n-ar lega-o de un tip de
  // coloană.
  assert.equal(normalizeAddress("192.0.2.5"), "::ffff:192.0.2.5");
  assert.equal(normalizeAddress("2001:DB8::1"), "2001:db8::1");
  assert.equal(normalizeAddress(" 2001:db8::1 "), "2001:db8::1");
});

test("ce nu e o adresă nu devine una", async () => {
  // O valoare care ajunge într-o coloană `INET6` fără să fie adresă e o eroare
  // de inserare în mijlocul autentificării — sub un `sql_mode` nestrict, mai
  // rău: un rând scris cu altceva.
  for (const bad of ["", "   ", "nu-e-adresa", "192.0.2.300", "192.0.2.5:443",
                     "fe80::1%eth0", "::ffff:192.0.2", "<script>"]) {
    assert.equal(normalizeAddress(bad), null, `„${bad}” a fost acceptat ca adresă`);
  }
});

test("fără antet declarat, nu există adresă de încredere — ăsta e implicitul",
     async () => {
  // Implicitul e „nu știu", nu „ia ce scrie în X-Forwarded-For". Pe găzduirea
  // asta nu s-a putut măsura ce pune marginea și dacă îl curăță.
  const ip = readClientIp(headers({ "x-forwarded-for": "192.0.2.5" }), {});
  assert.equal(ip.trusted, false);
  assert.equal(ip.address, null, "o adresă necontrolată a devenit de încredere");
  assert.equal(ip.reason, "unconfigured");
  // Pretenția se păstrează, dar ca pretenție: e mai mult decât nimic într-o
  // investigație, atâta timp cât nu e confundată cu un fapt.
  assert.equal(ip.claimed, "192.0.2.5");
  assert.match(String(ipNote(ip)), /ip-pretins\(unconfigured\)=192\.0\.2\.5/);
});

test("antetul declarat, sosit ca o singură adresă validă, e de încredere", async () => {
  const ip = readClientIp(headers({ [HEADER]: "192.0.2.5" }), CONFIGURED);
  assert.equal(ip.trusted, true);
  assert.equal(ip.address, "::ffff:192.0.2.5");
  assert.equal(ip.claimed, null);
  assert.equal(ipNote(ip), null, "o sursă de încredere n-are ce nota ca pretenție");
});

test("antetul declarat sosit ca LISTĂ e dovadă că marginea nu-l curăță", async () => {
  // Verificarea EFECTULUI, nu a declarației: o listă înseamnă că marginea a
  // adăugat la ce era, deci ce e în față e ales de client. Configurația spune
  // „e curățat"; antetul spune că nu e; câștigă antetul.
  const ip = readClientIp(headers({ [HEADER]: "192.0.2.5, 203.0.113.9" }), CONFIGURED);
  assert.equal(ip.trusted, false);
  assert.equal(ip.address, null);
  assert.equal(ip.reason, "list");
  assert.match(String(ipNote(ip)), /ip-pretins\(list\)/);
});

test("antetul declarat, dar absent sau nevalid, nu se înlocuiește cu altceva",
     async () => {
  // Căderea tăcută pe `x-forwarded-for` ar fi exact gaura: operatorul crede că
  // a legat limitarea de antetul măsurat, iar ea ar sta pe unul pe care îl scrie
  // clientul.
  const missing = readClientIp(headers({ "x-forwarded-for": "192.0.2.5" }), CONFIGURED);
  assert.equal(missing.trusted, false);
  assert.equal(missing.address, null);
  assert.equal(missing.reason, "missing");

  const junk = readClientIp(headers({ [HEADER]: "nu-e-adresa" }), CONFIGURED);
  assert.equal(junk.trusted, false);
  assert.equal(junk.address, null);
  assert.equal(junk.reason, "not-an-address");
});

test("numele antetului nu e sensibil la majuscule", async () => {
  // Antetele HTTP nu sunt, iar un operator care scrie `X-Hcdn-Client-IP` în
  // panoul găzduirii nu trebuie să obțină tăcut „niciun strat per sursă".
  const ip = readClientIp(headers({ [HEADER]: "192.0.2.5" }),
                          { [CLIENT_IP_HEADER_ENV]: "X-Hcdn-Client-IP" });
  assert.equal(ip.trusted, true);
  assert.equal(ip.address, "::ffff:192.0.2.5");
});

test("pretenția se taie, ca să încapă în `detail`", async () => {
  // `login_attempts.detail` are 255 de caractere și mai poartă și altceva. Un
  // antet lung n-are voie să împingă afară motivul real al încercării.
  const ip = readClientIp(headers({ "x-forwarded-for": "9".repeat(500) }), {});
  assert.ok(String(ip.claimed).length <= 64,
            `pretenția are ${String(ip.claimed).length} caractere`);
});
