/**
 * Cifrarea secretelor de instanță în repaus.
 *
 * Ce se strică pentru operator dacă modulul ăsta greșește: cheia cu care un
 * server își semnează loturile ajunge citibilă dintr-un dump al bazei. Cine o
 * are poate trimite agregatorului istorie de audit inventată în numele acelui
 * server — adică poate falsifica exact dovada care există ca să nu poată fi
 * falsificată de pe mașina monitorizată.
 *
 * Aici nu se falsifică nimic: `node:crypto` e implementarea reală, nu un dublu.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { CryptoConfigError, SecretBox, deriveKey } from "../lib/crypto";

const MASTER = "0".repeat(32) + "abcdefabcdefabcdefabcdefabcdef12";
const OTHER_MASTER = "9".repeat(64);
const SCOPE = { owner: "a1b2c3d4e5f60718293a4b5c6d7e8f90", field: "ship_secret_enc" };
const SECRET = "7f".repeat(32);

test("ce se scrie în bază nu conține textul în clar", () => {
  // Eșecul evident, și cel pe care o implementare „aproape corectă" îl trece:
  // un format care ține secretul lângă un antet.
  const token = new SecretBox(MASTER).seal(SECRET, SCOPE);
  assert.ok(!token.includes(SECRET), token);
  assert.ok(token.startsWith("sag1."), token);
});

test("dus-întors", () => {
  const box = new SecretBox(MASTER);
  assert.equal(box.open(box.seal(SECRET, SCOPE), SCOPE), SECRET);
});

test("același secret cifrat de două ori dă text diferit", () => {
  // Cu un nonce fix, două instanțe cu aceeași cheie ar avea același text
  // cifrat, iar cine citește baza ar afla asta fără să decripteze nimic. Și,
  // mai rău, GCM cu nonce reutilizat pierde cheia de autentificare.
  const box = new SecretBox(MASTER);
  const seen = new Set<string>();
  for (let i = 0; i < 50; i++) seen.add(box.seal(SECRET, SCOPE));
  assert.equal(seen.size, 50);
});

test("un blob mutat pe rândul ALTEI instanțe nu se deschide", () => {
  // Proprietatea pentru care există AAD, și pe care Fernet nu o are. Fără ea,
  // cine poate scrie în bază copiază textul cifrat al instanței A pe rândul lui
  // B, iar B începe să autentifice cu cheia lui A — adică „root pe A nu poate
  // fabrica date pentru B" se pierde fără ca nimic să pară stricat.
  const box = new SecretBox(MASTER);
  const token = box.seal(SECRET, SCOPE);
  assert.equal(box.open(token, { ...SCOPE, owner: "b".repeat(32) }), null);
});

test("un blob mutat în ALTĂ coloană nu se deschide", () => {
  const box = new SecretBox(MASTER);
  const token = box.seal(SECRET, SCOPE);
  assert.equal(box.open(token, { ...SCOPE, field: "alt_secret_enc" }), null);
});

test("un secret principal diferit nu deschide nimic", () => {
  const token = new SecretBox(MASTER).seal(SECRET, SCOPE);
  assert.equal(new SecretBox(OTHER_MASTER).open(token, SCOPE), null);
});

test("un scop (info) diferit dă o cheie diferită", () => {
  // Separarea subcheilor e chiar motivul pentru care există HKDF aici: aceeași
  // construcție ține cheia secretelor de instanță separată de cea a secretelor
  // TOTP ale panoului (`lib/auth/totp.ts`, `TOTP_SECRET_INFO`). O slăbiciune
  // într-un context nu trebuie să devină una în celălalt.
  const token = new SecretBox(MASTER, "scop-a").seal(SECRET, SCOPE);
  assert.equal(new SecretBox(MASTER, "scop-b").open(token, SCOPE), null);
  assert.notDeepEqual(deriveKey(MASTER, "scop-a"), deriveKey(MASTER, "scop-b"));
});

test("orice bit schimbat în jeton îl invalidează", () => {
  // GCM autentifică; un rând umblat trebuie să fie refuzat, nu decriptat parțial.
  const box = new SecretBox(MASTER);
  const token = box.seal(SECRET, SCOPE);
  const parts = token.split(".");
  let checked = 0;
  for (let part = 1; part < 4; part++) {
    for (let i = 0; i < parts[part].length; i++) {
      const ch = parts[part][i];
      const swapped = ch === "A" ? "B" : "A";
      const broken = [...parts];
      broken[part] = parts[part].slice(0, i) + swapped + parts[part].slice(i + 1);
      assert.equal(box.open(broken.join("."), SCOPE), null,
                   `partea ${part}, poziția ${i} a trecut`);
      checked++;
    }
  }
  // Fără asta, o buclă care nu iterează ar trece verde — chiar tiparul „listă
  // parametrizată ieșită goală și sărită tăcut" din CLAUDE.md.
  assert.ok(checked > 100, `doar ${checked} variante probate`);
});

const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Un „frate canonic": alt ȘIR, aceiași octeți după decodare.
 *
 * Se CAUTĂ, nu se presupune. Ultimul caracter al unei părți base64 poartă biți
 * de umplutură când lungimea în octeți nu se împarte la 3, iar `Buffer.from`
 * îi ignoră — deci mai multe caractere diferite dau exact aceiași octeți.
 * Testul de mai sus, care schimbă fiecare caracter în `"A"` sau `"B"`, nu
 * nimerește niciodată perechea asta: la poziția cu umplutură, `A` și `B` CHIAR
 * schimbă octeții, deci GCM îi respinge, iar proba trece cu sau fără gardă.
 */
function canonicalSibling(part: string): string | null {
  const original = Buffer.from(part, "base64url");
  const last = part.length - 1;
  for (const ch of ALPHABET) {
    if (ch === part[last]) continue;
    const variant = part.slice(0, last) + ch;
    if (Buffer.compare(Buffer.from(variant, "base64url"), original) === 0) {
      return variant;
    }
  }
  return null;
}

test("un jeton NECANONIC — alt șir, aceiași octeți — e refuzat", () => {
  // Eșecul pe care îl previne, măsurat cu garda scoasă: jetonul variant e
  // DIFERIT ca text de cel din bază, iar `open()` întoarce secretul. Adică
  // există mai multe reprezentări ale aceleiași chei, iar orice cod care le
  // compară, deduplică sau indexează ca șiruri vede două valori unde e una.
  //
  // Fraților li se caută existența, nu li se presupune: dacă vreodată nu se mai
  // găsește niciunul (alt format, altă lungime), testul trebuie să PICE, nu să
  // treacă pe o buclă goală.
  const box = new SecretBox(MASTER);
  const parts = box.seal(SECRET, SCOPE).split(".");

  // Partea 1 e IV-ul: 12 octeți = exact 16 caractere, fără biți de umplutură,
  // deci NU are frate. Scris ca aserțiune fiindcă e motivul pentru care partea
  // aia e în siguranță, și fiindcă un IV de altă lungime ar schimba faptul.
  assert.equal(canonicalSibling(parts[1]), null,
               "IV-ul are un frate canonic; presupunerea despre lungime nu mai ține");

  let found = 0;
  for (const part of [2, 3]) {
    const sibling = canonicalSibling(parts[part]);
    assert.ok(sibling, `partea ${part}: n-am găsit niciun frate canonic de probat`);
    assert.notEqual(sibling, parts[part]);
    assert.equal(
      Buffer.compare(Buffer.from(sibling as string, "base64url"),
                     Buffer.from(parts[part], "base64url")), 0,
      `partea ${part}: fratele nu decodează la aceiași octeți`);

    const variant = [...parts];
    variant[part] = sibling as string;
    assert.equal(box.open(variant.join("."), SCOPE), null,
                 `partea ${part}: un jeton necanonic a fost acceptat`);
    found++;
  }
  assert.equal(found, 2, "n-au fost probate ambele părți");
});

test("un caracter din afara alfabetului, pe care Node îl ignoră tăcut, e refuzat", () => {
  // `Buffer.from("ab*cd", "base64url")` nu aruncă: sare peste ce nu cunoaște.
  // Deci un jeton cu gunoi în el decodează la aceiași octeți ca originalul și,
  // fără verificarea de canonicitate, s-ar deschide. Aserțiunea e pe PURTARE,
  // nu pe mecanism: nu contează dacă îl respinge un filtru de alfabet sau
  // re-codificarea, contează că e respins.
  const box = new SecretBox(MASTER);
  const parts = box.seal(SECRET, SCOPE).split(".");
  let probed = 0;
  for (const junk of ["*", "!", "=", "\n", " "]) {
    const dirty = parts[3].slice(0, 4) + junk + parts[3].slice(4);
    // Proba are sens doar dacă Node chiar ignoră caracterul, adică dacă octeții
    // rămân identici. Altfel n-ar demonstra nimic despre alfabet.
    if (Buffer.compare(Buffer.from(dirty, "base64url"),
                       Buffer.from(parts[3], "base64url")) !== 0) continue;
    const variant = [...parts];
    variant[3] = dirty;
    assert.equal(box.open(variant.join("."), SCOPE), null,
                 `un jeton cu "${junk}" în el a fost acceptat`);
    probed++;
  }
  assert.ok(probed > 0, "niciun caracter probat chiar ignorat de Node — proba n-a testat nimic");
});

test("o etichetă GCM TRUNCHIATĂ e refuzată", () => {
  // Cel mai serios dintre eșecurile apărate de fișierul ăsta, și cel care a
  // scăpat unei runde întregi de falsificare.
  //
  // Măsurat pe Node: `setAuthTag` acceptă etichete de 4, 8 și 12–15 octeți, iar
  // trunchierea GCM e definită ca primii biți ai etichetei întregi — deci
  // primii 4 octeți ai unei etichete valide SUNT eticheta validă de 32 de biți
  // pentru același mesaj. Probat: cu verificarea de lungime scoasă, un jeton cu
  // eticheta tăiată la 4 octeți DESCHIDE secretul.
  //
  // Ce se strică pentru operator: cine poate scrie în coloană (o injecție, un
  // panou al găzduirii, o restaurare parțială) taie eticheta și coboară efortul
  // unei falsificări de cheie de la 2^128 la 2^32. Cu cheia aia se pot trimite
  // agregatorului rânduri de audit inventate în numele oricărui server.
  const box = new SecretBox(MASTER);
  const parts = box.seal(SECRET, SCOPE).split(".");
  const tag = Buffer.from(parts[3], "base64url");
  assert.equal(tag.length, 16, "eticheta de referință nu are 16 octeți");

  let probed = 0;
  for (const n of [4, 8, 12, 13, 14, 15]) {
    const variant = [...parts];
    variant[3] = tag.subarray(0, n).toString("base64url");
    assert.equal(box.open(variant.join("."), SCOPE), null,
                 `o etichetă de ${n} octeți a fost acceptată`);
    probed++;
  }
  // Bucla goală ar trece verde; lista e scrisă în cod, deci numărul e fix.
  assert.equal(probed, 6, "nu s-au probat toate lungimile");
});

test("prefixul de versiune e chiar verificat", () => {
  // Un jeton altfel PERFECT valid, cu alt prefix. Fără el, `"sag2.a.b.c"` era
  // respins de verificarea de lungime a IV-ului, nu de cea de versiune — deci
  // ștergerea verificării de versiune trecea neobservată. Contează fiindcă
  // prefixul e ce face ca o schimbare viitoare de algoritm să fie o migrare, nu
  // o ghicire: un jeton `sag2` citit de codul `sag1` trebuie să fie refuzat, nu
  // decriptat cu regulile vechi.
  const box = new SecretBox(MASTER);
  const parts = box.seal(SECRET, SCOPE).split(".");
  assert.equal(box.open(parts.join("."), SCOPE), SECRET, "jetonul de referință nu se deschide");
  parts[0] = "sag2";
  assert.equal(box.open(parts.join("."), SCOPE), null);
});

test("jetoanele malformate se refuză, nu aruncă", () => {
  // Ruta de ingestie nu are voie să cadă cu 500 pe un rând stricat: un
  // agregator care nu mai poate răspunde nu mai poate nici să spună de ce.
  const box = new SecretBox(MASTER);
  for (const bad of ["", "sag1", "sag1.a.b", "sag1.a.b.c.d", "sag2.a.b.c",
                     "sag1.!!!.abcd.abcd", "sag1.YWJj.YWJj.YWJj",
                     "nici măcar nu seamănă"]) {
    assert.equal(box.open(bad, SCOPE), null, `"${bad}" nu a fost refuzat`);
  }
});

test("un secret principal prea scurt e refuzat la construcție", () => {
  // Aceeași limită ca `_derive_key` din `sentinel/web/security.py`. Refuzat la
  // pornire, nu la prima decriptare: o instalare configurată greșit trebuie să
  // se vadă imediat.
  assert.throws(() => new SecretBox("scurt"), CryptoConfigError);
  assert.throws(() => new SecretBox("x".repeat(31)), CryptoConfigError);
  assert.doesNotThrow(() => new SecretBox("x".repeat(32)));
});

test("cifrarea fără proprietar sau fără coloană e refuzată", () => {
  // Un AAD care se poate uita nu e un AAD. De-aia e argument, nu implicit.
  const box = new SecretBox(MASTER);
  assert.throws(() => box.seal(SECRET, { owner: "", field: "x" }), CryptoConfigError);
  assert.throws(() => box.seal(SECRET, { owner: "a", field: "" }), CryptoConfigError);
});

test("un jeton sigilat de o versiune anterioară se deschide și acum", () => {
  // Ce se strică fără testul ăsta: secretele de expediere ale instanțelor sunt
  // DEJA sigilate în baza de producție. Orice atingere a formatului — versiunea
  // `sag1`, ordinea bucăților, octeții AAD — le face indescifrabile, iar
  // simptomul nu e o eroare de format: e `CHEIE ILIZIBILĂ` la `instance -- list`
  // și 500 „nu sunt configurat" pentru fiecare lot al fiecărei instanțe. Adică
  // sincronizarea tuturor serverelor, oprită de o redenumire.
  //
  // Jetonul de mai jos a fost produs de codul livrat ÎNAINTE ca `SecretScope`
  // să-și redenumească primul câmp din `instanceId` în `owner` (piesa E3b/1).
  // Se deschide și acum: redenumirea a atins tipul, nu octeții.
  const box = new SecretBox("m".repeat(64));
  const sealedBefore =
    "sag1.x0TCFgQGhwd6cPI4.5e4CAQmeVexMqFGMuw5jH4foc3Q.w5mEt-0uyh9yjefOR9L_nA";
  // `SCOPE`, nu încă un literal: jetonul a fost sigilat chiar cu perechea aia,
  // iar o a doua copie scrisă de mână ar putea diverge de la ea în tăcere.
  assert.equal(box.open(sealedBefore, SCOPE), "secret-de-proba-1234");
});

test("HKDF e determinist pentru aceeași pereche (secret, scop)", () => {
  // Altfel, o repornire a procesului ar face secretele din bază indescifrabile,
  // iar simptomul ar fi „toate instanțele au început să fie refuzate".
  assert.deepEqual(deriveKey(MASTER, "scop-a"), deriveKey(MASTER, "scop-a"));
  assert.equal(deriveKey(MASTER, "scop-a").length, 32);
});
