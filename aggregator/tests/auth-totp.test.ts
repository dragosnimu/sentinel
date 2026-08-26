/**
 * Al doilea factor: fereastra, reluarea, și secretul în repaus.
 *
 * Ce se strică pentru operator, pe rând:
 *
 *   * o fereastră greșită — codul de pe telefon e refuzat, iar mesajul spune
 *     „cod incorect"; omul își schimbă parola, apoi cere ajutor;
 *   * o reluare acceptată — cine a citit codul peste umăr, sau a capturat
 *     cererea, intră cu el în aceleași 30 de secunde. Al doilea factor devine o
 *     formalitate exact în cazul pentru care există;
 *   * un secret necifrat — un dump al bazei dă al doilea factor al tuturor, deci
 *     nu mai e un al doilea factor.
 *
 * Acordul de ALGORITM cu `pyotp` (digest, contor, trunchiere) se probează în
 * `tests/unit/test_aggregator_auth_parity.py`, care cere aceleași cifre de la
 * ambele implementări. Aici se probează comportamentul.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  TOTP_DIGITS, TOTP_INTERVAL_S, TOTP_VALID_WINDOW, TotpCipher, TotpError,
  base32Decode, base32Encode, codeForCounter, consumeTotpCounter, counterAt,
  generateSecret, provisioningUri, verifyCode,
} from "../lib/auth/totp";
import { FakeAuthDb } from "./auth-harness";

const SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const SESSION_SECRET = "s".repeat(64);
const AT = 1_760_000_000;   // un moment fix, ca testele să nu depindă de ceas

test("un secret nou are forma pe care o citește orice aplicație de autentificare", () => {
  // 32 de caractere base32, ca `pyotp.random_base32()`. Un secret pe care
  // aplicația de pe telefon nu-l poate importa se descoperă la înrolare, în fața
  // operatorului, cu un cod QR care nu funcționează.
  const secret = generateSecret();
  assert.equal(secret.length, 32);
  assert.match(secret, /^[A-Z2-7]+$/);
  assert.notEqual(generateSecret(), secret);
  // Și chiar se decodează: 20 de octeți.
  assert.equal(base32Decode(secret).length, 20);
});

test("base32 face dus-întors, și refuză ce nu e base32", () => {
  // `Buffer.from(x, "base64")` ar fi sărit tăcut peste caracterele necunoscute și
  // ar fi produs ALȚI octeți — adică un cod greșit fără nicio eroare, imposibil
  // de deosebit de un ceas derapat. Aceeași lecție ca `decodeStrict` din
  // `lib/crypto.ts`.
  const bytes = Buffer.from([0, 1, 127, 128, 255, 42, 17]);
  assert.deepEqual(base32Decode(base32Encode(bytes)), bytes);
  // Iertător cu ce copiază un om dintr-un panou: spații, umplutură, litere mici.
  assert.deepEqual(base32Decode("jbsw y3dp ehpk 3pxp"), base32Decode("JBSWY3DPEHPK3PXP"));
  assert.deepEqual(base32Decode("JBSWY3DPEHPK3PXP===="), base32Decode("JBSWY3DPEHPK3PXP"));
  // „SECRET” lipsește dinadins din lista asta: orice șir de litere mari E
  // base32 valid. Formele refuzate sunt cele cu caractere din afara
  // alfabetului (`!`, cifrele 0, 1, 8, 9) și secretul gol.
  for (const bad of ["", "  ", "JBSW!Y3DP", "0189", "jbsw-y3dp"]) {
    assert.throws(() => base32Decode(bad), TotpError, `„${bad}” a fost acceptat`);
  }
});

test("codul are 6 cifre și se schimbă la fiecare 30 de secunde", () => {
  assert.equal(TOTP_DIGITS, 6);
  assert.equal(TOTP_INTERVAL_S, 30);
  const counter = counterAt(AT);
  assert.equal(counter, Math.floor(AT / 30));
  const code = codeForCounter(SECRET, counter);
  assert.match(code, /^[0-9]{6}$/);
  assert.notEqual(codeForCounter(SECRET, counter + 1), code);
  // Zerourile din față se păstrează: un cod tăiat la 5 cifre e refuzat de
  // comparație, iar simptomul ar fi „uneori nu merge codul", o dată din zece.
  let padded = 0;
  for (let i = 0; i < 400; i++) {
    const value = codeForCounter(SECRET, counter + i);
    assert.equal(value.length, 6, value);
    if (value.startsWith("0")) padded++;
  }
  assert.ok(padded > 0, "niciun cod cu zero în față în 400 de încercări");
});

test("codurile se potrivesc cu vectorii din RFC 6238", () => {
  // Vectorii standardului, cu secretul lui (cifrele de la 1 la 0 repetate de
  // două ori în ASCII, scrise mai jos în base32) și cu SHA-1.
  //
  // Ce apără, și nu apăra nimic din fișierul ăsta până acum: implementarea putea
  // fi schimbată pe alt digest sau pe altă trunchiere, iar toate testele de
  // COMPORTAMENT ar fi rămas verzi — codurile ar fi fost consecvente cu ele
  // însele. Măsurat: `sha1` schimbat în `sha256` lăsa tot fișierul verde, și
  // pica doar testul trans-limbaj din Python. Un vector de aur închide gaura
  // aici, unde e ieftin de rulat.
  //
  // RFC 6238 dă coduri de 8 cifre; ale noastre au 6, adică aceeași valoare
  // trunchiată modulo un milion — ultimele șase cifre.
  const rfc = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const vectors: [number, string][] = [
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
  ];
  for (const [seconds, eightDigits] of vectors) {
    assert.equal(codeForCounter(rfc, counterAt(seconds)), eightDigits.slice(-6),
                 `vectorul RFC 6238 de la t=${seconds}`);
  }
});

test("fereastra e ±1, și se întoarce CONTORUL care s-a potrivit", () => {
  // Ceasurile telefoanelor derapează, iar cine tastează un cod fix când se
  // rotește nu trebuie să audă că parola lui e greșită. Fereastra e ±1, nu mai
  // mult: fiecare pas în plus e încă 30 de secunde în care un cod capturat e
  // valabil.
  assert.equal(TOTP_VALID_WINDOW, 1);
  const now = counterAt(AT);
  for (const offset of [-1, 0, 1]) {
    assert.equal(verifyCode(SECRET, codeForCounter(SECRET, now + offset), AT), now + offset,
                 `codul de la offsetul ${offset} nu a fost acceptat`);
  }
  for (const offset of [-2, 2, 10]) {
    assert.equal(verifyCode(SECRET, codeForCounter(SECRET, now + offset), AT), null,
                 `codul de la offsetul ${offset} a fost acceptat`);
  }
});

test("ce nu e un cod de șase cifre se refuză înainte de orice calcul", () => {
  const now = counterAt(AT);
  const good = codeForCounter(SECRET, now);
  for (const bad of ["", "12345", "1234567", "12345a", "abcdef", " ", good + "0"]) {
    assert.equal(verifyCode(SECRET, bad, AT), null, `„${bad}” a fost acceptat`);
  }
  // Spațiile din interior se taie: aplicațiile arată codul ca „123 456".
  assert.equal(verifyCode(SECRET, ` ${good.slice(0, 3)} ${good.slice(3)} `, AT), now);
});

test("un cod REUTILIZAT în aceeași fereastră e refuzat de bază", async () => {
  // Proprietatea centrală a coloanei `totp_last_counter`, și una dintre cele
  // patru cerute explicit în plan. Fără ea, același cod merge de două ori
  // înăuntrul ferestrei lui — destul pentru cineva care l-a citit peste umăr sau
  // care reia o cerere capturată.
  //
  // Comparația e `<` STRICT și se face în SQL: dacă ar fi `<=`, al doilea consum
  // ar reuși; dacă ar fi în TypeScript (citește, compară, scrie), două cereri
  // simultane ar citi amândouă valoarea veche.
  const db = new FakeAuthDb();
  db.addUser(7);
  const counter = counterAt(AT);

  assert.equal(await consumeTotpCounter(db, 7, counter), true);
  assert.equal(await consumeTotpCounter(db, 7, counter), false,
               "același contor a fost consumat de două ori: reluare acceptată");
  // Fereastra dinainte, la fel: un cod mai VECHI nu redevine valabil.
  assert.equal(await consumeTotpCounter(db, 7, counter - 1), false);
  // Următorul cod trece.
  assert.equal(await consumeTotpCounter(db, 7, counter + 1), true);
  assert.equal(db.users[0].totp_last_counter, counter + 1);
});

test("consumul atinge doar utilizatorul cerut", async () => {
  // Un `UPDATE` fără `WHERE id = ?` ar consuma contorul tuturor, iar simptomul ar
  // fi „nimeni nu se mai poate autentifica după ce intră cineva".
  const db = new FakeAuthDb();
  db.addUser(1);
  db.addUser(2);
  assert.equal(await consumeTotpCounter(db, 1, counterAt(AT)), true);
  assert.equal(db.users[1].totp_last_counter, null);
  assert.equal(await consumeTotpCounter(db, 99, counterAt(AT)), false,
               "un utilizator inexistent a raportat consum reușit");
});

test("secretul stă cifrat, legat de utilizatorul lui", () => {
  // Un dump al bazei nu are voie să dea al doilea factor. Iar AAD-ul leagă
  // textul cifrat de RÂND: cine poate scrie în bază nu-și poate muta propriul
  // secret pe contul altcuiva.
  const cipher = new TotpCipher(SESSION_SECRET);
  const sealed = cipher.encrypt(SECRET, 7);
  assert.ok(!sealed.includes(SECRET), sealed);
  assert.ok(sealed.startsWith("sag1."), sealed);
  assert.equal(cipher.decrypt(sealed, 7), SECRET);
  assert.equal(cipher.decrypt(sealed, 8), null,
               "secretul s-a deschis pe rândul altui utilizator");
});

test("un secret care nu se poate descifra întoarce null, nu o excepție", () => {
  // Se întâmplă când `SENTINEL_SESSION_SECRET` a fost rotit, sau când rândul a
  // fost umblat. Niciuna nu se repară reîncercând, deci operatorului trebuie să i
  // se poată spune ALTCEVA decât „cod greșit" — pe server asta e
  // `totp_undecryptable`. O excepție aici ar da 500 pe pagina de login.
  const sealed = new TotpCipher(SESSION_SECRET).encrypt(SECRET, 7);
  assert.equal(new TotpCipher("a".repeat(64)).decrypt(sealed, 7), null);
  for (const broken of ["", "sag1.", "nu-e-un-jeton", `${sealed}x`]) {
    assert.equal(new TotpCipher(SESSION_SECRET).decrypt(broken, 7), null, broken);
  }
});

test("cifrarea fără utilizator e refuzată, nu făcută cu un AAD gol", () => {
  // Un AAD care se poate uita nu e un AAD (`lib/crypto.ts`). Aici forma prin care
  // s-ar uita e un id lipsă sau zero.
  const cipher = new TotpCipher(SESSION_SECRET);
  for (const bad of [0, -1, 1.5, Number.NaN]) {
    assert.throws(() => cipher.encrypt(SECRET, bad), TotpError, `id-ul ${bad} a trecut`);
  }
});

test("URI-ul de înrolare poartă chiar parametrii noștri", () => {
  // Dacă URI-ul spune alt număr de cifre sau altă perioadă decât verifică
  // serverul, telefonul generează coduri corecte pentru altceva — iar omul vede
  // „cod incorect" la fiecare încercare, pentru totdeauna.
  const uri = provisioningUri(SECRET, "operator", "Sentinel Agregator");
  assert.ok(uri.startsWith("otpauth://totp/"), uri);
  const parsed = new URL(uri);
  assert.equal(parsed.searchParams.get("secret"), SECRET);
  assert.equal(parsed.searchParams.get("digits"), String(TOTP_DIGITS));
  assert.equal(parsed.searchParams.get("period"), String(TOTP_INTERVAL_S));
  assert.equal(parsed.searchParams.get("algorithm"), "SHA1");
  assert.equal(parsed.searchParams.get("issuer"), "Sentinel Agregator");
  assert.ok(decodeURIComponent(parsed.pathname).includes("operator"), uri);
});
