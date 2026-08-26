/**
 * Plicul de transport, văzut de partea care îl deschide.
 *
 * Ce apără fișierul ăsta, în termeni de ce se strică pentru operator:
 *
 *   * **plicul produs de partea Python trebuie citit AICI, la octet.** Dacă nu
 *     e, semnătura se calculează peste alți octeți și lotul primește 401 — care
 *     de pe gazdă arată identic cu o cheie greșită. Vectorul comun din
 *     `tests/fixtures/transport-envelope.json` e produs de
 *     `sentinel/report/envelope.py`, nu fabricat aici: un plic fabricat de
 *     TypeScript ar proba că modulul e invers cu el însuși;
 *   * **decomprimarea trebuie să se OPREASCĂ la plafon, nu să verifice după.**
 *     Ruta e publică pentru cine cunoaște un identificator de instanță, iar
 *     plicul se deschide ÎNAINTEA verificării semnăturii — nu poate fi altfel,
 *     fiindcă semnătura e peste ce iese din el. Un plafon verificat după
 *     decomprimare dă exact același verdict pe un gigaoctet deja alocat, adică
 *     agregatorul cade și abia apoi refuză;
 *   * **un corp care nu e plic trebuie să treacă neatins**, fiindcă agregatorul
 *     se publică înaintea gazdei și trebuie să accepte expeditorul de azi.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

import {
  ENVELOPE_ENCODING, ENVELOPE_PREFIX, ENVELOPE_VERSION, INFLATE_CHUNK,
  MAX_INFLATED_BYTES, MAX_INFLATE_RATIO, inflateBounded, looksWrapped, unwrap,
} from "../lib/envelope";
import { MAX_BODY_BYTES } from "../lib/ingest";

function repoRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, "sentinel", "report", "envelope.py"))) return dir;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  // Nu e motiv de skip: fără depozit vectorul comun nu se poate citi, iar
  // tăcerea aici ar însemna „geamănul e verificat" fără să fi fost.
  throw new Error("nu găsesc rădăcina depozitului pornind de la " + process.cwd());
}

const VECTOR: { secret: string; signature: string; inner: string; wire: string } =
  JSON.parse(fs.readFileSync(
    path.join(repoRoot(), "tests", "fixtures", "transport-envelope.json"), "utf8"));

/** Un plic construit după aceleași reguli ca `envelope.py:wrap`, pentru cazurile
 *  pe care vectorul comun nu le poate purta (bombe, versiuni greșite). */
function envelopeOf(packed: Buffer, over: Record<string, unknown> = {}): Buffer {
  const fields: Record<string, unknown> = {
    enc: ENVELOPE_ENCODING, v: ENVELOPE_VERSION, pad: "",
    body: packed.toString("base64"), ...over,
  };
  // Scris cu mâna, în ordinea din contract: `JSON.stringify` pe un obiect ar
  // păstra ordinea de inserare, dar contractul e prefixul, nu obiceiul lui V8.
  const parts = Object.entries(fields).map(
    ([k, v]) => `${JSON.stringify(k)}:${JSON.stringify(v)}`);
  return Buffer.from(`{${parts.join(",")}}`, "utf8");
}

// ---------------------------------------------------------------------------
// Vectorul comun: octeți produși de partea Python
// ---------------------------------------------------------------------------
test("plicul produs de expeditor se deschide aici la octet", async () => {
  const wire = Buffer.from(VECTOR.wire, "ascii");
  assert.ok(looksWrapped(wire), "prefixul nu s-a recunoscut");

  const opened = await unwrap(wire);
  assert.ok(opened.ok, opened.ok ? "" : opened.detail);
  assert.ok(opened.wrapped);
  assert.deepEqual(opened.body, Buffer.from(VECTOR.inner, "utf8"));
});

test("semnătura vectorului verifică peste CONȚINUT, nu peste plic", async () => {
  // Ordinea din protocol, jumătatea de aici: HMAC-ul e peste octeții care ies
  // din plic. Semnat peste plic, `lib/verify.ts` n-ar mai fi geamăn cu
  // `sentinel/report/signing.py`, iar fiecare lot ar primi 401.
  const wire = Buffer.from(VECTOR.wire, "ascii");
  const opened = await unwrap(wire);
  assert.ok(opened.ok);

  const overContent = crypto.createHmac("sha256", VECTOR.secret)
    .update(opened.body).digest("hex");
  assert.equal(overContent, VECTOR.signature);

  const overWire = crypto.createHmac("sha256", VECTOR.secret)
    .update(wire).digest("hex");
  assert.notEqual(overWire, VECTOR.signature);
});

test("textul comenzilor NU e în octeții plicului, dar E în conținut", async () => {
  // Proprietatea care repară pana: marginea punctează conținutul cererii, iar
  // la al patrulea-al șaselea tipar de linie de comandă răspunde 403.
  const wire = Buffer.from(VECTOR.wire, "ascii");
  for (const needle of ["python3 /tmp/mkbody.py", "wc -c", "session_commands"]) {
    assert.equal(wire.includes(needle), false, `„${needle}" a plecat în clar`);
    assert.ok(VECTOR.inner.includes(needle), `vectorul nu mai conține „${needle}"`);
  }
});

// ---------------------------------------------------------------------------
// Amândouă formele, în timpul rulării
// ---------------------------------------------------------------------------
test("un corp care nu e plic se întoarce NEATINS", async () => {
  // Agregatorul se publică înaintea gazdei. Dacă ramura asta ar atinge ceva,
  // expeditorul aflat azi în producție s-ar opri în ziua publicării.
  const plain = Buffer.from(VECTOR.inner, "utf8");
  assert.equal(looksWrapped(plain), false);
  const opened = await unwrap(plain);
  assert.ok(opened.ok);
  assert.equal(opened.wrapped, false);
  assert.equal(opened.body, plain, "corpul în clar a fost copiat sau transformat");
});

test("forma canonică nu poate fi confundată cu un plic", async () => {
  // Discriminatorul e prefixul. Payload-ul canonic începe cu `{"batch_seq":`
  // fiindcă cheile se emit sortate pe puncte de cod.
  assert.ok(VECTOR.inner.startsWith('{"batch_seq":'));
  assert.equal(ENVELOPE_PREFIX, '{"enc":"gzip+base64"');
  assert.equal(looksWrapped(Buffer.from(VECTOR.inner, "utf8")), false);
});

test("un plic cu alt `enc` e REFUZAT, chiar dacă octeții încep cu prefixul bun",
     async () => {
  // Garda pe `enc` nu era ținută în viață de nimic: `if (env.enc !== …)` putea
  // fi înlocuit cu `if (false)` fără ca vreun test să se schimbe la față.
  // `looksWrapped` cere prefixul, deci pare că spune același lucru — dar
  // prefixul sunt OCTEȚII de la începutul corpului, iar `env.enc` e ce iese din
  // `JSON.parse`, și cele două se pot despărți. Aici se despart cu o cheie
  // duplicată, fiindcă `JSON.parse` o păstrează pe ULTIMA.
  //
  // Nu e un bug azi: nimic nu ramifică pe `enc`. E gaura de sub locul în care
  // s-ar adăuga a doua codare — moment în care „cunosc prefixul" ar începe să
  // însemne altceva decât „știu ce transformare poartă", iar corpul s-ar
  // desface cu regulile altei codări sub aceeași semnătură.
  const packed = zlib.gzipSync(Buffer.from('{"batch_seq":1}'));
  const b64 = JSON.stringify(packed.toString("base64"));
  const wire = Buffer.from(
    `{"enc":"gzip+base64","enc":"gzip","v":${ENVELOPE_VERSION},"pad":"",` +
    `"body":${b64}}`, "utf8");

  assert.ok(looksWrapped(wire), "cazul nu mai trece de discriminatorul de prefix");
  assert.equal((JSON.parse(wire.toString("utf8")) as { enc: string }).enc, "gzip",
               "cheia duplicată nu mai schimbă valoarea citită");

  const opened = await unwrap(wire);
  assert.equal(opened.ok, false, "un plic cu altă codare a fost desfăcut");
  assert.equal(opened.ok ? 0 : opened.status, 400);
  assert.match(opened.ok ? "" : opened.detail, /enc="gzip"/);

  // Și că refuzul vine de la gardă, nu de la conținut: exact aceiași octeți
  // dinăuntru, cu `enc` cel bun, se deschid.
  const bun = await unwrap(envelopeOf(packed));
  assert.ok(bun.ok, bun.ok ? "" : bun.detail);
  assert.deepEqual(bun.body, Buffer.from('{"batch_seq":1}'));
});

test("un plic de altă versiune e REFUZAT cu mesaj, nu citit cât se poate",
     async () => {
  // Citit „cât se poate", un plic v2 ar produce alți octeți sub aceeași
  // semnătură — adică un lot acceptat cu alt conținut decât cel semnat.
  const wire = envelopeOf(zlib.gzipSync(Buffer.from("{}")), { v: 2 });
  const opened = await unwrap(wire);
  assert.equal(opened.ok, false);
  assert.equal(opened.ok ? 0 : opened.status, 400);
  assert.match(opened.ok ? "" : opened.detail, /versiunea 1/);
});

test("un `body` care nu e base64 valid e refuzat, nu decodat „cât se poate”",
     async () => {
  // `Buffer.from(s, "base64")` SARE peste ce nu recunoaște — măsurat pe Node 24:
  // `Buffer.from("aGVsbG8=" + "!", "base64")` întoarce vesel „hello”. Deci un
  // plic care a fost umblat pe drum se decodează cu succes, iar semnătura — care
  // e peste octeții DINĂUNTRU — trece. Rezultatul: agregatorul acceptă un corp
  // care nu e cel emis, fără ca nimic să spună asta.
  //
  // Amândouă jumătățile verificării au propriul caz, fiindcă prind lucruri
  // diferite: lungimea multiplu de 4 și alfabetul.
  const good = zlib.gzipSync(Buffer.from('{"batch_seq":1}')).toString("base64");
  // Un al doilea vector, ales ca base64-ul lui să iasă FĂRĂ umplutură: acolo un
  // caracter în plus e din alfabetul bun, deci numai regula de lungime îl vede.
  // Fără cazul ăsta, regula de lungime ar putea fi scoasă și suita ar rămâne
  // verde — măsurat, nu presupus.
  let bare = "";
  for (let n = 1; n < 400 && bare === ""; n++) {
    const packed = zlib.gzipSync(Buffer.from(`{"batch_seq":${"1".repeat(n)}}`));
    if (packed.length % 3 === 0) bare = packed.toString("base64");
  }
  assert.notEqual(bare, "", "n-am găsit un base64 fără umplutură");
  assert.equal(bare.includes("="), false);

  const cases: [string, string][] = [
    ["un caracter în plus, alfabet bun", bare + "x"],  // numai lungimea îl vede
    ["un caracter în plus", good + "x"],          // lungime %4 == 1
    ["patru caractere străine", good + "!!!!"],   // lungime %4 == 0, alfabet greșit
  ];
  for (const [why, body] of cases) {
    // Întâi se arată că decodarea îngăduitoare CHIAR ar fi acceptat: altfel
    // proba n-ar deosebi verificarea de norocul că gzip pică oricum.
    const intact = body.startsWith(bare) ? bare : good;
    assert.deepEqual(Buffer.from(body, "base64"), Buffer.from(intact, "base64"),
                     `„${why}" nu e cazul îngăduitor pe care îl credeam`);
    const opened = await unwrap(envelopeOf(Buffer.alloc(0), { body }));
    assert.equal(opened.ok, false, `„${why}" a fost acceptat`);
    assert.equal(opened.ok ? 0 : opened.status, 400);
    assert.match(opened.ok ? "" : opened.detail, /base64/);
  }
  // Și un `body` gol, care n-are nici măcar ce decoda.
  const empty = await unwrap(envelopeOf(Buffer.alloc(0), { body: "" }));
  assert.equal(empty.ok, false);
  assert.equal(empty.ok ? 0 : empty.status, 400);
});

test("un plic care nu se poate decomprima dă 400, nu 413", async () => {
  // Două cauze diferite, două reacții diferite: „prea mare" cere un lot mai mic,
  // „stricat" cere căutat pe drum. Contopite, operatorul micșorează loturile la
  // nesfârșit pe o problemă de transport.
  const wire = envelopeOf(Buffer.from("nu sunt gzip, dar sunt base64"));
  const opened = await unwrap(wire);
  assert.equal(opened.ok, false);
  assert.equal(opened.ok ? 0 : opened.status, 400);
});

// ---------------------------------------------------------------------------
// Plafonul: bombă adevărată, oprită ÎN TIMPUL decomprimării
// ---------------------------------------------------------------------------
test("o bombă adevărată se oprește la plafon, fără să se producă restul",
     async () => {
  // 256 MB dintr-un singur octet, comprimați cu adevărat — nu un plic care
  // pretinde o mărime. `produced` e numărul de octeți care CHIAR au ieșit din
  // zlib: aici e toată proba. Un plafon verificat DUPĂ decomprimare ar întoarce
  // exact același verdict, dar `produced` ar fi 256 MB, iar agregatorul i-ar fi
  // alocat pe toți înainte să refuze.
  const bomb = zlib.gzipSync(Buffer.alloc(256 * 1024 * 1024), { level: 9 });
  assert.ok(bomb.length < 1024 * 1024, `bomba are ${bomb.length} octeți`);

  const out = await inflateBounded(bomb, MAX_INFLATED_BYTES);
  assert.equal(out.ok, false, "bomba a fost decomprimată până la capăt");
  if (out.ok) return;
  assert.equal(out.kind, "over-cap");
  assert.ok(out.produced <= MAX_INFLATED_BYTES + INFLATE_CHUNK,
            `s-au produs ${out.produced} octeți pentru un plafon de ` +
            `${MAX_INFLATED_BYTES}: decomprimarea NU s-a oprit la plafon`);
});

test("plicul-bombă e refuzat cu 413 și cu plafonul în mesaj", async () => {
  const bomb = zlib.gzipSync(Buffer.alloc(64 * 1024 * 1024), { level: 9 });
  const opened = await unwrap(envelopeOf(bomb));
  assert.equal(opened.ok, false);
  assert.equal(opened.ok ? 0 : opened.status, 413);
  // Mesajul ajunge în jurnalul de pe gazdă (primii 200 de octeți ai corpului),
  // care e singurul diagnostic al operatorului când loturile nu intră.
  assert.match(opened.ok ? "" : opened.detail, /raportul acceptat e 64|plafonul de corp/);
});

test("plafonul absolut e ACELAȘI cu cel al căii în clar", () => {
  // Plicul poartă același corp pe alt drum. Alt număr aici ar însemna că fluxul
  // se oprește pe un lot pe care `sentinel/config.py` îl declară legal — iar de
  // pe gazdă un 413 arată ca orice alt non-2xx.
  assert.equal(MAX_INFLATED_BYTES, MAX_BODY_BYTES);
});

test("raportul se măsoară față de octeții PRIMIȚI, nu față de cei comprimați",
     async () => {
  // Inegalitatea pe care expeditorul o respectă umplând plicul. Un plic
  // neumplut — cum ar fi unul fabricat de altcineva — se oprește aici, iar
  // plafonul rămâne cel mic, nu cel absolut.
  const payload = Buffer.alloc(4 * 1024 * 1024, 0x41);
  const wire = envelopeOf(zlib.gzipSync(payload, { level: 9 }));
  assert.ok(payload.length > wire.length * MAX_INFLATE_RATIO,
            "plicul de probă e prea mare ca să treacă de plafonul de raport");

  const opened = await unwrap(wire);
  assert.equal(opened.ok, false);
  assert.equal(opened.ok ? 0 : opened.status, 413);
  assert.match(opened.ok ? "" : opened.detail, /raportul acceptat e 64/);

  // Iar același conținut într-un plic UMPLUT ca la expeditor trece: plafonul nu
  // poate opri un lot pe care expeditorul l-a împachetat corect.
  const packed = zlib.gzipSync(payload, { level: 9 });
  const needed = Math.ceil(payload.length / MAX_INFLATE_RATIO);
  const bare = envelopeOf(packed);
  const padded = envelopeOf(packed, { pad: "0".repeat(Math.max(0, needed - bare.length)) });
  const second = await unwrap(padded);
  assert.ok(second.ok, second.ok ? "" : second.detail);
  assert.equal(second.body.length, payload.length);
});
