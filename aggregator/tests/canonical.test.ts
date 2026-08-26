/**
 * Vectorul de aur: `canonical()` din TypeScript și `canonical()` din Python
 * trebuie să producă ACEIAȘI OCTEȚI.
 *
 * Contractul ăsta e tot mecanismul. Semnătura se calculează peste octeții
 * serializați, deci dacă cele două capete serializează diferit — o cheie
 * sortată altfel, un spațiu în plus, un diacritic scris `ă` la un capăt și
 * `ă` la celălalt — semnătura nu se verifică NICIODATĂ. Iar simptomul e un 401,
 * adică exact ce ai vedea la o cheie greșită: pierzi o zi căutând în locul
 * nepotrivit, timp în care martorul nu primește niciun semnal și nu are de unde
 * să știe că tăcerea e a lui, nu a serverului.
 *
 * Testul are trei jumătăți, și toate sunt necesare:
 *
 *  1. **Constante fixe** — octeții și semnătura hexa scriși aici și în
 *     `tests/fixtures/canonical-corpus.json`. Prind orice schimbare la ORICARE
 *     dintre capete, chiar dacă celălalt nu e disponibil. Amândouă capetele se
 *     compară cu constantele, nu unul cu celălalt: două implementări care se
 *     verifică reciproc pot deriva împreună.
 *  2. **Refuzurile** — ce e ÎN AFARA contractului trebuie să arunce, la ambele
 *     capete. Fără jumătatea asta, contractul ar fi „merge pe ce am încercat",
 *     ceea ce ține până când adaugă cineva un câmp.
 *  3. **Rularea reală a Python-ului** — dovedește că geamănul chiar e geamăn
 *     azi, nu că a fost cândva. Dacă nu pornește niciun interpretor, testul
 *     PICĂ; vezi `runPython` pentru de ce nu mai e un skip.
 *
 * ## Ce nu poate trece prin corpusul comun
 *
 * `60.0` e cazul limpede: în fișier JSON e textul `60.0`, iar `JSON.parse` îl
 * dă înapoi ca `60`, adică un întreg exact pe care partea asta îl ACCEPTĂ, în
 * timp ce Python vede un `float` și îl refuză. Asimetria e reală și e chiar
 * motivul pentru care `_coerce` din `sentinel/config.py` a fost reparat: în
 * JavaScript nu există un `60.0` de refuzat. La fel `NaN`, `Infinity` ca
 * literal, `undefined`, `BigInt` și adâncimea. Toate sunt mai jos, nativ.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "child_process";
import fs from "fs";
import path from "path";

import { canonical, signatureValid, CanonicalError } from "@/lib/verify";
import crypto from "crypto";

// Cheie evident falsă. Un secret real nu are ce căuta într-o fixtură.
const HMAC_KEY = "cheie-de-test-0123456789abcdef";

/** Un semnal cu forma reală produsă de `collect()` din beacon.py. */
const GOLDEN_BEAT = {
  seq: 4471,
  sent_at: "2026-08-12T09:15:04.512345+00:00",
  max_age_s: 120,
  interval_s: 60,
  last_event_id: 918273,
  detect_cursor: 918200,
  incidents_open: 2,
  blocklist_size: 37,
  audit_head: "3f9c1d0e6b2a48f7c5e0d1a2b3c4d5e60718293a4b5c6d7e8f90a1b2c3d4e5f6",
  selfcheck: { worst: "ok", checks: 33, bad: 0, ran_at: "2026-08-12T09:14:31+00:00" },
};

const GOLDEN_BEAT_CANONICAL =
  '{"audit_head":"3f9c1d0e6b2a48f7c5e0d1a2b3c4d5e60718293a4b5c6d7e8f90a1b2c3d4e5f6",'
  + '"blocklist_size":37,"detect_cursor":918200,"incidents_open":2,"interval_s":60,'
  + '"last_event_id":918273,"max_age_s":120,'
  + '"selfcheck":{"bad":0,"checks":33,"ran_at":"2026-08-12T09:14:31+00:00","worst":"ok"},'
  + '"sent_at":"2026-08-12T09:15:04.512345+00:00","seq":4471}';

const GOLDEN_BEAT_HMAC = "b3f8963f91c4d71eb8d2129f85f46b54d8d16e584e3132c2afece900eed37bfd";

/**
 * Cazurile în care două serializatoare chiar diferă: diacritice (Python ar
 * scrie `ă` fără `ensure_ascii=False`), obiect imbricat, tablou cu obiect
 * înăuntru, `null`, `true`/`false`, șir gol.
 */
const GOLDEN_EDGE = {
  z: null,
  a: "diacritice: ăâîșț ĂÂÎȘȚ",
  nested: { b: [3, { y: 1, x: 2 }], a: "" },
  m: true,
  n: false,
  ident: "",
};

const GOLDEN_EDGE_CANONICAL =
  '{"a":"diacritice: ăâîșț ĂÂÎȘȚ","ident":"","m":true,"n":false,'
  + '"nested":{"a":"","b":[3,{"x":2,"y":1}]},"z":null}';

const GOLDEN_EDGE_HMAC = "69b55ba6647e42d9b5c6fd2ef49b61de7af9e71fc73b7aa7c13b03f14046dcbf";

// ---------------------------------------------------------------------------

function repoRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, "sentinel", "report", "signing.py"))) return dir;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  // Nu e un motiv de skip: fără depozit nu se poate rula testul, dar tăcerea
  // aici ar însemna „geamănul e verificat" fără să fi fost.
  throw new Error("nu găsesc rădăcina depozitului pornind de la " + process.cwd());
}

type Case = {
  name: string;
  why: string;
  expect: "accept" | "reject";
  payload: Record<string, unknown>;
  canonical?: string;
  hmac?: string;
  python_reason?: string;
};

const CORPUS: { secret: string; cases: Case[] } = JSON.parse(
  fs.readFileSync(
    path.join(repoRoot(), "tests", "fixtures", "canonical-corpus.json"),
    "utf8",
  ),
);

const ACCEPTED = CORPUS.cases.filter((c) => c.expect === "accept");
const REJECTED = CORPUS.cases.filter((c) => c.expect === "reject");

// ---------------------------------------------------------------------------
// 1. Constante fixe.

test("canonical() produce exact octeții din vectorul de aur", () => {
  assert.equal(canonical(GOLDEN_BEAT), GOLDEN_BEAT_CANONICAL);
  assert.equal(canonical(GOLDEN_EDGE), GOLDEN_EDGE_CANONICAL);
});

test("semnătura hexa peste vectorul de aur e cea calculată de beacon.py", () => {
  const hmac = (p: Record<string, unknown>) =>
    crypto.createHmac("sha256", HMAC_KEY).update(canonical(p), "utf8").digest("hex");
  assert.equal(hmac(GOLDEN_BEAT), GOLDEN_BEAT_HMAC);
  assert.equal(hmac(GOLDEN_EDGE), GOLDEN_EDGE_HMAC);
  // Și pe drumul real de verificare, nu doar pe cel de calcul.
  assert.equal(signatureValid(canonical(GOLDEN_BEAT), GOLDEN_BEAT_HMAC, HMAC_KEY), true);
});

test("canonical() sortează în adâncime, nu doar la primul nivel", () => {
  // Eșecul pe care îl previne: o sortare doar la rădăcină trece toate testele
  // pe un payload plat, și cade abia pe `selfcheck` — adică pe semnalul real.
  const out = canonical({ b: { z: 1, a: 2 }, a: 1 });
  assert.equal(out, '{"a":1,"b":{"a":2,"z":1}}');
});

// Corpusul, caz cu caz. Lista e ÎNTREAGĂ și e duplicată la celălalt capăt
// (`tests/unit/test_signing.py`) dinadins: fixtura e generată, deci un prag de
// tipul „cel puțin zece" lasă loc să dispară tăcut cazuri, iar ștergerea unui
// caz șterge exact acoperirea pe care o aducea. Prima versiune a testului ăstuia
// avea praguri sub realitate, și cu ele se puteau șterge `escape-uri`,
// `astral-si-separatori` și `surogat-neimperecheat` — adică TOATĂ acoperirea
// tabelului de escape C0/DEL și a lui U+2028/U+2029 — după care o schimbare a
// hexa-ului de escape la AMBELE capete trecea verde la ambele suite.
const EXPECTED_ACCEPTED = [
  "beat-real", "chei-intregi", "chei-intregi-imbricate", "chei-mixte-ascii",
  "diacritice", "sir-gol-si-null", "obiect-gol-si-tablou-gol",
  "intreg-mare-exact", "booleeni", "escape-uri", "astral-si-separatori",
  "chei-la-marginea-ascii", "adancime-la-limita", "imbricare-adanca",
];
const EXPECTED_REJECTED = [
  "cheie-non-ascii", "cheie-diacritic", "cheie-control", "cheie-del",
  "cheie-sub-limita", "adancime-peste-limita", "float-fractionar",
  "float-exponent", "intreg-peste-limita", "surogat-neimperecheat",
];

test("corpusul conține EXACT cazurile pe care trebuie să le conțină", () => {
  // Eșecul pe care îl previne, măsurat: ștergerea a trei cazuri și schimbarea
  // hexa-ului de escape la ambele capete trecea verde la ambele suite — adică
  // exact deriva comună despre care restul fișierului spune că e imposibilă.
  assert.deepEqual(ACCEPTED.map((c) => c.name), EXPECTED_ACCEPTED);
  assert.deepEqual(REJECTED.map((c) => c.name), EXPECTED_REJECTED);
  assert.equal(CORPUS.cases.length, EXPECTED_ACCEPTED.length + EXPECTED_REJECTED.length);
});

// ---------------------------------------------------------------------------
// Ce ESTE fiecare caz, nu doar cum îl cheamă.
//
// A treia oară când același tipar se mută cu un nivel mai jos. Întâi un prag
// `len(CORPUS) >= 20` care lăsa ștergibile exact cazurile care contau; apoi
// praguri `>= 10`/`>= 6` peste 12/7; reparate cu lista de nume — după care se
// puteau GOLI payload-urile: `escape-uri` devenit `{"raw":"nimic special"}`,
// `astral-si-separatori` devenit `{"emoji":"a"}`, fixtura regenerată cinstit,
// nume și număr neatinse, ambele suite verzi, iar aceeași mutație de hexa la
// ambele capete trecea din nou.
//
// Fixtura e GENERATĂ, deci orice s-ar fixa în ea se poate regenera. Ce nu se
// poate regenera e afirmația de aici despre ce trebuie să conțină.
//
// Geamănul e `CASE_PROPERTIES` din `tests/unit/test_signing.py`.
// ---------------------------------------------------------------------------
const MAX_DEPTH_CONTRACT = 32;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

function depth(value: unknown): number {
  if (Array.isArray(value)) {
    return 1 + Math.max(0, ...value.map(depth));
  }
  if (value !== null && typeof value === "object") {
    return 1 + Math.max(0, ...Object.values(value as Record<string, unknown>).map(depth));
  }
  return 0;
}

function keysOf(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(keysOf);
  if (value !== null && typeof value === "object") {
    const o = value as Record<string, unknown>;
    return Object.keys(o).concat(Object.values(o).flatMap(keysOf));
  }
  return [];
}

function stringsOf(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringsOf);
  if (value !== null && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).flatMap(stringsOf);
  }
  return [];
}

function numbersOf(value: unknown): number[] {
  if (typeof value === "number") return [value];
  if (Array.isArray(value)) return value.flatMap(numbersOf);
  if (value !== null && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).flatMap(numbersOf);
  }
  return [];
}

function has(haystack: string, needle: string): void {
  assert.ok(haystack.includes(needle), `lipsește ${JSON.stringify(needle)}`);
}

function inOrder(text: string, ...needles: string[]): void {
  const positions = needles.map((n) => {
    const i = text.indexOf(n);
    assert.ok(i >= 0, `${JSON.stringify(n)} lipsește din ${text}`);
    return i;
  });
  const sorted = [...positions].sort((a, b) => a - b);
  assert.deepEqual(positions, sorted, `ordinea ${needles.join(",")} e greșită în ${text}`);
}

/** Punctele de cod ale unui șir, nu unitățile lui UTF-16. */
function codePoints(s: string): number[] {
  return Array.from(s, (c) => c.codePointAt(0) as number);
}

/** Unități UTF-16, singurul mod de a vedea un surogat rămas singur. */
function codeUnits(s: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
  return out;
}

const CASE_PROPERTIES: Record<string, (c: Case) => void> = {
  // --- acceptate: proprietatea se citește din octeții ÎNREGISTRAȚI ----------
  "beat-real": (c) => {
    for (const f of ["audit_head", "blocklist_size", "detect_cursor", "incidents_open",
      "instance_id", "instance_label", "interval_s", "last_event_id", "max_age_s",
      "selfcheck", "sent_at", "seq"]) {
      has(c.canonical as string, `"${f}":`);
    }
    assert.ok((c.canonical as string).startsWith('{"audit_head":'), "cheile nu sunt sortate");
  },

  // DIVERGENȚA 1: ordinea punctelor de cod, nu cea numerică pe care o impunea
  // `Object.fromEntries`.
  "chei-intregi": (c) => {
    inOrder(c.canonical as string, '"1":', '"10":', '"2":', '"20":', '"3":');
    assert.equal(Object.keys(c.payload).length, 5, "cheile care se reașază au dispărut");
  },

  // DIVERGENȚA 2: aceeași cauză SUB rădăcină.
  "chei-intregi-imbricate": (c) => {
    has(c.canonical as string, '{"10":1,"2":2}');
    has(c.canonical as string, '[{"100":1,"20":2}]');
  },

  "chei-mixte-ascii": (c) => inOrder(c.canonical as string,
    '" ":', '"0":', '"A":', '"Z":', '"_x":', '"a":', '"z.y":', '"z_y":'),

  "diacritice": (c) => {
    for (const ch of "ăâîșțĂÂÎȘȚ") has(c.canonical as string, ch);
    assert.ok(!(c.canonical as string).includes("\\u"), "un diacritic a fost escapat");
  },

  "sir-gol-si-null": (c) => {
    has(c.canonical as string, ":null");
    has(c.canonical as string, '"":');
    has(c.canonical as string, '"instance_label":""');
  },

  "obiect-gol-si-tablou-gol": (c) => {
    has(c.canonical as string, "{}");
    has(c.canonical as string, "[]");
    has(c.canonical as string, "[[],{}]");
  },

  "intreg-mare-exact": (c) => {
    has(c.canonical as string, String(MAX_SAFE));
    has(c.canonical as string, "-" + String(MAX_SAFE));
    assert.ok(numbersOf(c.payload).includes(MAX_SAFE), "limita a dispărut");
  },

  "booleeni": (c) => {
    has(c.canonical as string, ":true");
    has(c.canonical as string, ":false");
    has(c.canonical as string, '"unu":1');
    has(c.canonical as string, '"zero":0');
  },

  // Tabelul de escape C0/DEL, singura lui acoperire din tot depozitul.
  "escape-uri": (c) => {
    for (const e of ["\\u0000", "\\u0001", "\\u001f", "\\t", "\\n", "\\r", "\\b",
      "\\f", '\\"', "\\\\"]) {
      has(c.canonical as string, e);
    }
    // DEL nu se escapează — se scrie brut. Cealaltă jumătate a regulii.
    has(c.canonical as string, String.fromCodePoint(0x7f));
    assert.ok(!(c.canonical as string).includes("\\u007f"), "DEL a fost escapat");
  },

  // U+2028/U+2029 sunt exact ce conține textul din jurnalele web, și singurul
  // lor loc din corpus. Toate ies BRUTE.
  "astral-si-separatori": (c) => {
    for (const cp of [0x1f600, 0x2028, 0x2029, 0xe000, 0xfffd]) {
      has(c.canonical as string, String.fromCodePoint(cp));
    }
    assert.ok(!(c.canonical as string).includes("\\u"), "ceva peste 0x20 a fost escapat");
  },

  "chei-la-marginea-ascii": (c) => {
    const ks = Object.keys(c.payload);
    assert.ok(ks.includes(" "), "marginea de jos (0x20) a dispărut");
    assert.ok(ks.includes("~"), "marginea de sus (0x7E) a dispărut");
    assert.ok((c.canonical as string).startsWith('{" ":'), "spațiul nu mai e prima cheie");
  },

  "adancime-la-limita": (c) => {
    assert.equal(depth(c.payload), MAX_DEPTH_CONTRACT, "adâncimea cazului s-a schimbat");
    has(c.canonical as string, "[");
    has(c.canonical as string, "{");
  },

  "imbricare-adanca": (c) => {
    has(c.canonical as string, '"audit_log":[');
    assert.ok(depth(c.payload) >= 4, "structura s-a aplatizat");
  },

  // --- refuzate: proprietatea se citește din PAYLOAD ------------------------
  "cheie-non-ascii": (c) => {
    const cps = keysOf(c.payload).flatMap(codePoints);
    assert.ok(cps.some((cp) => cp > 0x7f), "nicio cheie non-ASCII");
    // DIVERGENȚA 4 cere una PESTE BMP: acolo unitățile UTF-16 se despart de
    // punctele de cod.
    assert.ok(cps.some((cp) => cp > 0xffff),
      "nicio cheie peste BMP — cazul nu mai acoperă divergența 4");
  },

  "cheie-diacritic": (c) => assert.ok(
    keysOf(c.payload).flatMap(codePoints).some((cp) => cp > 0x7f && cp < 0x2000),
    "nicio cheie cu diacritic"),

  "cheie-control": (c) => assert.ok(
    keysOf(c.payload).flatMap(codePoints).some((cp) => cp < 0x20),
    "nicio cheie cu un control C0"),

  "cheie-del": (c) => assert.ok(
    keysOf(c.payload).some((k) => k.includes(String.fromCodePoint(0x7f))),
    "marginea de sus (DEL) a dispărut din caz"),

  "cheie-sub-limita": (c) => assert.ok(
    keysOf(c.payload).some((k) => k.includes(String.fromCodePoint(0x1f))),
    "marginea de jos (0x1F) a dispărut din caz"),

  "adancime-peste-limita": (c) => assert.equal(
    depth(c.payload), MAX_DEPTH_CONTRACT + 1, "adâncimea cazului s-a schimbat"),

  "float-fractionar": (c) => assert.ok(
    numbersOf(c.payload).some((v) => Number.isFinite(v) && !Number.isInteger(v)),
    "niciun număr cu parte fracționară"),

  // DIVERGENȚA 3: `1e-7` aici, `1e-07` în Python. Cazul trebuie să rămână un
  // număr pe care ambele limbaje îl scriu cu exponent.
  "float-exponent": (c) => assert.ok(
    numbersOf(c.payload).some((v) => String(v).includes("e")),
    "niciun număr scris cu exponent — DIVERGENȚA 3 nu mai e acoperită"),

  "intreg-peste-limita": (c) => assert.ok(
    numbersOf(c.payload).some((v) => Number.isInteger(v) && Math.abs(v) > MAX_SAFE),
    "niciun întreg peste limita exactă"),

  "surogat-neimperecheat": (c) => assert.ok(
    stringsOf(c.payload).some((s) => codeUnits(s).some(
      (u, i) => u >= 0xd800 && u <= 0xdbff
        ? !(s.charCodeAt(i + 1) >= 0xdc00 && s.charCodeAt(i + 1) <= 0xdfff)
        : u >= 0xdc00 && u <= 0xdfff
          ? !(s.charCodeAt(i - 1) >= 0xd800 && s.charCodeAt(i - 1) <= 0xdbff)
          : false)),
    "niciun surogat neîmperecheat"),
};

test("fiecare caz din corpus declară pentru ce există", () => {
  // Eșecul pe care îl previne: cineva adaugă un caz și nu spune ce apără, sau
  // scoate proprietatea unuia existent. Fixtura fiind generată, ce e ÎN ea se
  // poate regenera oricând; ce nu se poate regenera e afirmația de aici.
  assert.deepEqual(
    Object.keys(CASE_PROPERTIES).sort(),
    CORPUS.cases.map((c) => c.name).sort(),
  );
});

for (const c of CORPUS.cases) {
  test(`corpus [proprietate] ${c.name}: cazul e încă ce trebuie să fie`, () => {
    // Măsurat: `escape-uri` golit la {"raw":"nimic special"} și
    // `astral-si-separatori` la {"emoji":"a"}, cu `canonical`/`hmac` regenerate
    // cinstit și cu numele și numărul neatinse, treceau ambele suite — după care
    // aceeași schimbare de hexa la AMBELE emitente trecea și ea.
    CASE_PROPERTIES[c.name](c);
  });
}

for (const c of ACCEPTED) {
  test(`corpus [accept] ${c.name}: octeții și semnătura din fixtură`, () => {
    // Eșecul pe care îl previne: unul dintre capete deviază singur. Ambele se
    // compară cu ȘIRUL din fixtură, deci o derivă comună cere schimbare de cod
    // la amândouă ȘI regenerarea fixturii.
    assert.equal(canonical(c.payload), c.canonical, c.why);
    const hmac = crypto.createHmac("sha256", CORPUS.secret)
      .update(canonical(c.payload), "utf8").digest("hex");
    assert.equal(hmac, c.hmac);
  });
}

for (const c of REJECTED) {
  test(`corpus [reject] ${c.name}: refuzat și aici, nu doar în Python`, () => {
    // Eșecul pe care îl previne: contractul e impus la un singur capăt.
    // Atunci expeditorul refuză și receptorul acceptă (sau invers), iar
    // dezacordul se descoperă pe un payload viitor, în producție.
    assert.throws(() => canonical(c.payload), CanonicalError, c.why);
  });
}

// ---------------------------------------------------------------------------
// 2. Refuzurile pe care JSON nu le poate purta.

test("numerele cu parte fracționară sunt refuzate", () => {
  // DIVERGENȚA 3, din partea asta: `JSON.stringify(1e-7)` dă `1e-7`, Python dă
  // `1e-07`. Niciunul nu e greșit, și de-asta niciunul nu e semnabil.
  for (const bad of [1.5, 1e-7, 0.1, -2.5]) {
    assert.throws(() => canonical({ n: bad }), CanonicalError, `${bad} a fost acceptat`);
  }
});

test("NaN și Infinity sunt refuzate", () => {
  // `JSON.stringify(NaN)` scrie `null` — un contor pierdut, tăcut, în octeții
  // peste care se semnează.
  for (const bad of [NaN, Infinity, -Infinity]) {
    assert.throws(() => canonical({ n: bad }), CanonicalError, `${bad} a fost acceptat`);
  }
});

test("întregii peste limita exactă sunt refuzați, iar limita însăși e acceptată", () => {
  assert.equal(canonical({ n: 9007199254740991 }), '{"n":9007199254740991}');
  assert.equal(canonical({ n: -9007199254740991 }), '{"n":-9007199254740991}');
  assert.throws(() => canonical({ n: 9007199254740992 }), CanonicalError);
});

test("minus zero se scrie ca zero, la fel ca în Python", () => {
  // Python nu are `-0` întreg. Dacă partea asta ar scrie `-0`, orice câmp
  // calculat printr-o scădere ar putea produce octeți pe care Python nu-i scrie.
  assert.equal(canonical({ n: -0 }), '{"n":0}');
});

test("un `undefined` nu dispare tăcut din octeții semnați", () => {
  // `JSON.stringify({a: undefined})` dă `{}`: un câmp care nu mai există în
  // ce se semnează, dar există în ce citește codul de deasupra.
  assert.throws(() => canonical({ a: undefined }), CanonicalError);
});

test("BigInt, Date, Map și instanțele de clasă sunt refuzate", () => {
  // `Object.keys(new Date())` e `[]`, deci fără verificarea de obiect simplu o
  // dată s-ar fi scris `{}` — un câmp golit fără ca nimic să se plângă.
  class Oarecare { constructor(public a = 1) {} }
  assert.throws(() => canonical({ n: BigInt(5) } as never), CanonicalError);
  assert.throws(() => canonical({ d: new Date(0) }), CanonicalError);
  assert.throws(() => canonical({ m: new Map() }), CanonicalError);
  assert.throws(() => canonical({ o: new Oarecare() }), CanonicalError);
  // O funcție: `JSON.stringify` o omite, la fel ca `undefined`.
  assert.throws(() => canonical({ f: () => 1 }), CanonicalError);
});

test("rădăcina trebuie să fie un obiect", () => {
  for (const bad of [[1, 2], "text", 5, null]) {
    assert.throws(() => canonical(bad as never), CanonicalError);
  }
});

/**
 * `n` containere imbricate, cel din afară mereu obiect.
 *
 * Alternează obiect/tablou ca să treacă prin ambele ramuri ale verificării de
 * adâncime. Geamănul e `_nest` din `tests/unit/test_signing.py`.
 */
function nest(n: number): Record<string, unknown> {
  let v: unknown = 1;
  for (let i = 0; i < n; i++) {
    v = (i === n - 1 || i % 2 === 1) ? { a: v } : [v];
  }
  return v as Record<string, unknown>;
}

test("limita de adâncime e fixată PE margine, nu lângă ea", () => {
  // Eșecul pe care îl previne, măsurat: `depth >= MAX_DEPTH` schimbat în
  // `depth > MAX_DEPTH` doar în Python. Cele două capete se despart cu exact un
  // nivel, iar un test care încearcă 34 și 31 nu vede nimic. Valoarea 32 e
  // `MAX_DEPTH` din `sentinel/report/signing.py` și din verify.ts — dacă se
  // schimbă, se schimbă ÎN AMBELE, iar testul ăsta o cere explicit.
  assert.doesNotThrow(() => canonical(nest(32)));
  assert.throws(() => canonical(nest(33)), CanonicalError);

  // Și motivul pentru care limita există: fluxurile din E2 duc blob-uri JSON
  // influențate de atacator, iar o recursie nemărginită în primitiva de semnare
  // oprește chiar procesul care există ca să raporteze că procesele trăiesc.
});

// Caracterele de control se scriu ca ESCAPE, nu brut: un fișier care poartă
// un U+0001 real îl pierde la prima unealtă care îl „cureăță", iar testul ar
// deveni verde verificând altceva. Aceeași regulă ca în gen_corpus.py.
test("intervalul de chei e fixat pe AMBELE margini", () => {
  // Eșecul pe care îl previne, măsurat: `_KEY_MAX = 0x7F` în loc de `0x7E`, doar
  // în Python. Python semnează atunci o cheie cu DEL în ea, partea asta o
  // refuză, și dezacordul apare abia pe câmpul care o folosește.
  assert.equal(canonical({ " ": 1 }), '{" ":1}');
  assert.equal(canonical({ "~": 1 }), '{"~":1}');
  for (const bad of ["\u001f", "\u007f", "\u0000"]) {
    assert.throws(() => canonical({ [`a${bad}b`]: 1 }), CanonicalError,
      `cheia cu U+${bad.charCodeAt(0).toString(16)} a fost acceptată`);
  }
});

test("un surogat neîmperecheat e refuzat, dar o pereche validă trece", () => {
  assert.throws(() => canonical({ s: "\ud800" }), CanonicalError);
  assert.throws(() => canonical({ s: "a\udc00b" }), CanonicalError);
  // Perechea validă e un singur punct de cod și se scrie brut, ca în Python.
  assert.equal(canonical({ s: "😀" }), '{"s":"\u{1f600}"}');
});

test("`60.0` nu există în JavaScript — și de-asta e reparat în config.py", () => {
  // Asimetria scrisă pe față. Aici `60.0` E `60` și se acceptă; în Python e un
  // `float` și se refuză. Contractul nu se închide din partea asta, ci la sursă:
  // `_coerce` din `sentinel/config.py` transformă floatul din YAML în `int`,
  // deci `collect()` nu mai poate pune unul în payload.
  assert.equal(canonical({ interval_s: 60.0 }), '{"interval_s":60}');
  assert.equal(canonical({ interval_s: 60 }), '{"interval_s":60}');
});

test("cheile de tip index NU se mai reașază numeric", () => {
  // DIVERGENȚA 1 și 2, direct. `Object.keys` le dă deja în ordine numerică, iar
  // vechiul `Object.fromEntries` le fixa acolo; acum se scriu octeții direct,
  // după un comparator pe puncte de cod.
  const o: Record<string, unknown> = {};
  o["10"] = 1; o["2"] = 2; o["1"] = 3;
  assert.deepEqual(Object.keys(o), ["1", "2", "10"], "premisa testului s-a schimbat");
  assert.equal(canonical(o), '{"1":3,"10":1,"2":2}');
  assert.equal(canonical({ a: o }), '{"a":{"1":3,"10":1,"2":2}}');
});

test("cheile non-ASCII sunt refuzate, deci ordinea lor nu mai poate diverge", () => {
  // DIVERGENȚA 4. `Array.sort()` compară unități UTF-16, Python puncte de cod,
  // și diferă peste BMP. Cheile sunt nume de câmp dintr-un protocol scris de
  // noi: în afara ASCII e o greșeală, nu o cerință.
  assert.throws(() => canonical({ "\ue000": 1, "\u{1f600}": 2 }), CanonicalError);
  assert.throws(() => canonical({ "notă": 1 }), CanonicalError);
  assert.throws(() => canonical({ "a\u0001b": 1 }), CanonicalError);
  // Valorile, în schimb, pot fi orice: alertele poartă text românesc.
  assert.equal(canonical({ nota: "reușită" }), '{"nota":"reușită"}');
});

// ---------------------------------------------------------------------------
// 3. Jumătatea care rulează Python-ul.

// Payload-urile intră pe STDIN, nu ca argument de linie de comandă.
//
// Măsurat pe gazda asta: `spawnSync` cu un argument de 40000 de caractere
// întoarce `ENAMETOOLONG`. Corpusul de azi are ~1400 de caractere, adică vreo
// 400 de cazuri până acolo — iar tot fișierul ăsta îndeamnă pe cineva să adauge
// cazuri. Eșecul ar veni exact când face cineva lucrul recomandat, și ar veni
// prin `r.error`, adică pe drumul care înainte se traducea într-un skip tăcut.
const PY_SCRIPT = `
import json, sys
sys.path.insert(0, ".")
from sentinel.report.signing import CanonicalError, canonical, sign
payloads = json.loads(sys.stdin.buffer.read().decode("utf-8"))
key = sys.argv[1]
out = []
for p in payloads:
    try:
        out.append({"ok": True, "hex": canonical(p).hex(), "hmac": sign(p, key)})
    except CanonicalError as exc:
        out.append({"ok": False, "error": str(exc)})
print(json.dumps(out))
`;

type PyResult = { ok: boolean; hex?: string; hmac?: string; error?: string };

/**
 * Rulează geamănul. **Aruncă** dacă nu pornește niciun interpretor.
 *
 * Înainte întorcea `null`, iar testele făceau `t.skip()`. Consecința măsurată:
 * pe o mașină fără Python — adică pe oricare alta decât a autorului — `npm test`
 * tipărea `pass 185, fail 0, skipped 2` și ieșea cu 0, iar nimic din `scripts/`,
 * `deploy/` sau CI nu citește numărul de sărituri. „N-a rulat" și „a trecut"
 * ajungeau la același ecran, ceea ce e chiar defectul după care e numit
 * depozitul ăsta. Singura dovadă că cele două capete sunt de acord AZI e rularea
 * asta; dacă nu se poate face, suita nu are voie să spună că e verde.
 */
function runPython(
  payloads: unknown[],
  key: string,
  exes: string[] = ["python", "python3", "py"],
): PyResult[] {
  const root = repoRoot();
  const input = JSON.stringify(payloads);
  const tried: string[] = [];
  for (const exe of exes) {
    const r = spawnSync(exe, ["-c", PY_SCRIPT, key], {
      cwd: root,
      encoding: "utf8",
      input,
      env: { ...process.env, PYTHONIOENCODING: "utf-8" },
    });
    if (r.error) {
      tried.push(`${exe}: ${(r.error as Error).message}`);
      continue;
    }
    if (r.status !== 0) {
      throw new Error(`${exe} a eșuat (${r.status}): ${r.stderr}`);
    }
    return JSON.parse(r.stdout);
  }
  throw new Error(
    "niciun interpretor Python nu a pornit, deci contractul dintre limbaje NU a "
    + "fost verificat. Instalează Python și rulează din nou; un skip aici ar "
    + "însemna „verificat\" fără să fi fost.\n  " + tried.join("\n  "),
  );
}

test("un interpretor Python care nu pornește e un EȘEC, nu un test sărit", () => {
  // Eșecul pe care îl previne: `npm test` verde pe o mașină fără Python, cu
  // jumătatea care dovedește contractul nerulată și necontabilizată nicăieri.
  assert.throws(
    () => runPython([{ a: 1 }], "k", ["sentinel-interpretor-care-nu-exista"]),
    /NU a fost verificat/,
  );
  // Și invers: cu interpretorul real, chiar întoarce rezultate.
  assert.equal(runPython([{ a: 1 }], "k").length, 1);
});

test("geamănul din Python produce ACEIAȘI octeți și ACEEAȘI semnătură", () => {
  const got = runPython([GOLDEN_BEAT, GOLDEN_EDGE], HMAC_KEY);

  const expected = [
    { payload: GOLDEN_BEAT, canonical: GOLDEN_BEAT_CANONICAL, hmac: GOLDEN_BEAT_HMAC },
    { payload: GOLDEN_EDGE, canonical: GOLDEN_EDGE_CANONICAL, hmac: GOLDEN_EDGE_HMAC },
  ];

  for (let i = 0; i < expected.length; i++) {
    assert.equal(got[i].ok, true, `Python a refuzat vectorul ${i}: ${got[i].error}`);
    const pyBytes: Buffer = Buffer.from(got[i].hex as string, "hex");
    const jsBytes: Buffer = Buffer.from(canonical(expected[i].payload), "utf8");
    assert.deepEqual(
      pyBytes, jsBytes,
      `octeți diferiți la vectorul ${i}: python=${pyBytes.toString("utf8")} js=${jsBytes.toString("utf8")}`,
    );
    assert.equal(pyBytes.toString("utf8"), expected[i].canonical);
    assert.equal(got[i].hmac, expected[i].hmac);
  }
});

test("tot corpusul, trecut LIVE prin ambele implementări", () => {
  // Constantele din fixtură prind deriva unui singur capăt. Asta prinde altceva:
  // că fixtura mai descrie codul de azi. Fără ea, un corpus regenerat greșit ar
  // trece la ambele capete și n-ar mai însemna nimic.
  const payloads = CORPUS.cases.map((c) => c.payload);
  const got = runPython(payloads, CORPUS.secret);
  assert.equal(got.length, CORPUS.cases.length);

  const disagree: string[] = [];
  for (let i = 0; i < CORPUS.cases.length; i++) {
    const c = CORPUS.cases[i];
    let jsBytes: Buffer | null = null;
    let jsError: string | null = null;
    try {
      jsBytes = Buffer.from(canonical(c.payload), "utf8");
    } catch (exc) {
      jsError = (exc as Error).message;
    }

    if (c.expect === "accept") {
      if (!got[i].ok) { disagree.push(`${c.name}: Python a refuzat (${got[i].error})`); continue; }
      if (jsError !== null) { disagree.push(`${c.name}: JS a refuzat (${jsError})`); continue; }
      const pyBytes = Buffer.from(got[i].hex as string, "hex");
      if (!pyBytes.equals(jsBytes as Buffer)) {
        disagree.push(
          `${c.name}: octeți diferiți py=${pyBytes.toString("utf8")} js=${(jsBytes as Buffer).toString("utf8")}`,
        );
        continue;
      }
      if (pyBytes.toString("utf8") !== c.canonical) {
        disagree.push(`${c.name}: ambele diferă de fixtură (${pyBytes.toString("utf8")})`);
      }
    } else {
      if (got[i].ok) disagree.push(`${c.name}: Python a ACCEPTAT un caz de refuzat`);
      if (jsError === null) disagree.push(`${c.name}: JS a ACCEPTAT un caz de refuzat`);
    }
  }
  assert.deepEqual(disagree, [], disagree.join("\n"));
});
