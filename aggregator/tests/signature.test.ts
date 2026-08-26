/**
 * Verificarea semnăturii unui lot: ce se acceptă și, mai ales, ce se refuză.
 *
 * Ce se strică pentru operator dacă greșește:
 *
 *   * acceptă un corp modificat → oricine poate scrie în arhiva de audit a
 *     oricărui server istorie inventată, adică poate falsifica exact dovada care
 *     există ca să nu poată fi falsificată de pe mașina monitorizată;
 *   * crapă în loc să refuze → o semnătură de lungime greșită, pe care o dă orice
 *     scanner care lovește ruta, transformă un 401 într-un 500 și umple jurnalul
 *     până când nu-l mai citește nimeni.
 *
 * Aici nu se falsifică nimic: `node:crypto` e implementarea reală.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { signatureValid } from "../lib/signature";

const KEY = "cheie-buna-test";
const OTHER_KEY = "cheie-gresita-test";

const BODY = Buffer.from(
  '{"batch_seq":7,"cursors":{"audit_log":5},"instance_id":"a1b2c3"}', "utf8");
const GOOD = crypto.createHmac("sha256", KEY).update(BODY).digest("hex");

test("semnătura corectă e acceptată", () => {
  assert.equal(signatureValid(BODY, GOOD, KEY), true);
});

test("corpul modificat e refuzat", () => {
  // Ăsta e atacul: un filigran umflat, ca expeditorul să treacă peste rânduri
  // care n-au fost scrise niciodată.
  const tampered = Buffer.from(
    BODY.toString("utf8").replace('"audit_log":5', '"audit_log":9'), "utf8");
  assert.notEqual(tampered.toString("utf8"), BODY.toString("utf8"),
                  "fixtura nu a modificat nimic — testul n-ar dovedi nimic");
  assert.equal(signatureValid(tampered, GOOD, KEY), false);
});

test("semnătura modificată e refuzată", () => {
  // Un singur caracter hexa schimbat, aceeași lungime — cazul pe care o
  // comparație pe lungime l-ar rata.
  const flipped = (GOOD[0] === "a" ? "b" : "a") + GOOD.slice(1);
  assert.equal(flipped.length, GOOD.length);
  assert.equal(signatureValid(BODY, flipped, KEY), false);
});

test("cheia greșită e refuzată în ambele sensuri", () => {
  const withOther = crypto.createHmac("sha256", OTHER_KEY).update(BODY).digest("hex");
  assert.equal(signatureValid(BODY, withOther, KEY), false);
  assert.equal(signatureValid(BODY, GOOD, OTHER_KEY), false);
});

test("o semnătură de altă lungime e refuzată, nu aruncă excepție", () => {
  // `crypto.timingSafeEqual` ARUNCĂ pe lungimi diferite. Fără verificarea
  // dinainte, orice cerere cu antetul scurt sau lipsă ar da 500 în loc de 401.
  let probed = 0;
  for (const bad of ["", "gresit", "a", GOOD + "00", GOOD.slice(0, 63), "ă".repeat(64)]) {
    assert.doesNotThrow(() => signatureValid(BODY, bad, KEY));
    assert.equal(signatureValid(BODY, bad, KEY), false, `a acceptat ${JSON.stringify(bad)}`);
    probed++;
  }
  // Bucla goală ar trece verde; lista e scrisă în cod, deci numărul e fix.
  assert.equal(probed, 6, "nu s-au probat toate formele");
});

// ---------------------------------------------------------------------------
// Vectorul de aur: octeți produși de capătul Python
// ---------------------------------------------------------------------------
/**
 * Corpul exact pe care `sentinel/report/signing.py::canonical` îl produce pentru
 * un lot de sincronizare realist, și semnătura lui.
 *
 * Generat cu:
 *
 *     from sentinel.report.signing import canonical, sign
 *     canonical(payload); sign(payload, "cheie-de-expediere-test")
 *
 * Ce dovedește, și de ce merită scris de mână:
 *
 *   1. **Că un lot de sincronizare TRECE contractul de semnare.** Nu e evident:
 *      `signing.py` refuză `float`, întregi peste 2^53-1, chei în afara ASCII
 *      tipăribil și surogați neîmperecheați. `params` pleacă drept ȘIR (nu obiect
 *      despachetat) tocmai fiindcă un `float` dinăuntru ar bloca fluxul definitiv.
 *      Dacă vreodată forma lotului iese din contract, expeditorul nu mai poate
 *      semna nimic, iar simptomul e tăcere — nu o eroare la agregator.
 *   2. **Că verificarea de aici acceptă chiar octeții aceia**, inclusiv
 *      diacriticele și liniuța lungă, care în canonic trec neescapate.
 *
 * Vectorul e independent de ceas dinadins: dovedește pasul de semnătură, nu
 * prospețimea. Un lot cu `sent_at` fix ar fi expirat a doua zi, iar testul ar fi
 * început să pice din alt motiv decât cel pe care îl numește.
 */
const GOLDEN_BODY =
  '{"batch_seq":4471,"cursors":{"audit_log":91233},"instance_id":"a1b2c3d4e5f60718",' +
  '"max_age_s":300,"rows":{"audit_log":[{"actor":"telegram:operator",' +
  '"at":"2026-08-15T09:13:58.104211+00:00","detail":null,' +
  '"entry_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",' +
  '"id":91232,"operation":"incident.close","params":"{\\"reason\\": \\"fals pozitiv\\"}",' +
  '"prev_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",' +
  '"result":"ok","source":"telegram","target":"incident:8812"},' +
  '{"actor":"system","at":"2026-08-15T09:14:01.998000+00:00",' +
  '"detail":"trei intrări expirate — nimic de făcut",' +
  '"entry_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",' +
  '"id":91233,"operation":"blocklist.expire","params":"{\\"n\\": 3}",' +
  '"prev_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",' +
  '"result":"ok","source":"scheduler","target":null}]},' +
  '"sent_at":"2026-08-15T09:14:02.512345+00:00"}';

const GOLDEN_SIGNATURE =
  "0672e448b3c5c52ce49efbec2bb670917be1bb7d0d5fe227256c342f520db557";

const GOLDEN_KEY = "cheie-de-expediere-test";

test("vector de aur: octeții produși de capătul Python se verifică aici", () => {
  const body = Buffer.from(GOLDEN_BODY, "utf8");
  // Lungimea e scrisă separat fiindcă e faptul care prinde o „reparare" a
  // literalului de mai sus — o ghilimea scăpată altfel, o linie lipită greșit.
  assert.equal(body.length, 934, "corpul nu mai are octeții pe care i-a semnat Python");
  assert.equal(signatureValid(body, GOLDEN_SIGNATURE, GOLDEN_KEY), true,
               "semnătura produsă de sentinel/report/signing.py nu se mai verifică aici");
});

test("vectorul de aur e chiar un lot de sincronizare, nu un șir oarecare", () => {
  // Fără asta, cineva ar putea „repara" vectorul cu orice octeți care se
  // potrivesc semnăturii, iar prima aserțiune ar rămâne verde peste un corp care
  // nu mai are nimic de-a face cu protocolul.
  const parsed = JSON.parse(GOLDEN_BODY);
  assert.equal(parsed.instance_id, "a1b2c3d4e5f60718");
  assert.equal(parsed.batch_seq, 4471);
  assert.equal(parsed.cursors.audit_log, 91233);
  assert.equal(parsed.rows.audit_log.length, 2);
  // Filigranul E cel mai mare id din rânduri — regula pe care ruta o impune.
  assert.equal(Math.max(...parsed.rows.audit_log.map((r: { id: number }) => r.id)),
               parsed.cursors.audit_log);
  // `params` e un ȘIR, nu un obiect: expeditorul e un transport, nu un
  // re-codificator (vezi `encode_value` din shipper.py).
  assert.equal(typeof parsed.rows.audit_log[0].params, "string");
  // Diacriticele și liniuța lungă trec neescapate prin forma canonică.
  assert.match(parsed.rows.audit_log[1].detail, /intrări expirate — nimic/);
});
