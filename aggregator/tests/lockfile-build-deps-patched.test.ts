/**
 * `postcss` și `source-map-js` rămân la versiunile reparate.
 *
 * Eșecul pe care îl previne: ambele sunt dependențe tranzitive de CONSTRUCȚIE ale
 * lui Next, iar Next își fixează `postcss` la exact `8.4.31`. Fără un `override`,
 * orice `npm install` care regenerează lockfile-ul coboară înapoi la versiunea cu
 * XSS prin `</style>` și citire arbitrară de fișiere prin `sourceMappingURL`
 * (`postcss <= 8.5.22`), respectiv la DoS prin `source-map-js <= 1.2.1`. Nimic nu
 * se strică și nimic nu spune că s-a întâmplat: `npm audit` doar redevine roșu,
 * iar cine îl rulează abia peste luni află.
 *
 * Două fapte, verificate separat, fiindcă pot să se strice separat:
 *   * `package.json` cere versiunea reparată (`overrides`) — fără asta, următoarea
 *     regenerare a lockfile-ului o pierde;
 *   * `package-lock.json` chiar o rezolvă — ce instalează `npm ci` pe găzduire e
 *     lockfile-ul, nu intenția din `package.json`.
 *
 * Pragurile vin din advisory-uri (câmpul „patched"), nu din ce se instalează
 * azi: un prag luat din lockfile n-ar prinde niciodată o coborâre.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..");

/** Prima versiune FĂRĂ defectele raportate de `npm audit` pe 7 octombrie 2026. */
const PATCHED: Record<string, string> = {
  // GHSA-qx2v-qp2m-jg93, GHSA-6g55-p6wh-862q, GHSA-fxqj-rqcc-2cmp, GHSA-r28c-9q8g-f849
  postcss: "8.5.23",
  // GHSA-68fv-2mgg-jv7q
  "source-map-js": "1.2.2",
};

function triple(version: string): [number, number, number] {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  assert.ok(m, `versiune pe care n-o înțeleg: ${JSON.stringify(version)}`);
  return [Number(m![1]), Number(m![2]), Number(m![3])];
}

function atLeast(version: string, floor: string): boolean {
  const a = triple(version);
  const b = triple(floor);
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return true;
}

function readJson(name: string): any {
  return JSON.parse(readFileSync(join(ROOT, name), "utf8"));
}

test("comparatorul de versiuni deosebește reparat de nereparat", () => {
  // Control pentru celelalte două: un comparator care întoarce mereu `true` le-ar
  // face verzi indiferent ce conține lockfile-ul.
  assert.equal(atLeast("8.4.31", "8.5.23"), false);
  assert.equal(atLeast("8.5.22", "8.5.23"), false);
  assert.equal(atLeast("8.5.23", "8.5.23"), true);
  assert.equal(atLeast("8.5.29", "8.5.23"), true);
  assert.equal(atLeast("9.0.0", "8.5.23"), true);
  assert.equal(atLeast("1.2.1", "1.2.2"), false);
});

test("package.json cere versiunile reparate prin `overrides`", () => {
  const pkg = readJson("package.json");
  assert.ok(pkg.overrides && typeof pkg.overrides === "object",
            "package.json n-are `overrides`: Next fixează postcss la 8.4.31, deci " +
            "fără ele următoarea regenerare a lockfile-ului coboară înapoi");
  for (const [name, floor] of Object.entries(PATCHED)) {
    const spec = pkg.overrides[name];
    assert.equal(typeof spec, "string", `lipsește override-ul pentru ${name}`);
    // Un interval ca `^8.4.0` ar lăsa lockfile-ul să rămână pe versiunea
    // vulnerabilă: limita de jos a intervalului trebuie să fie ea însăși reparată.
    const lower = /(\d+\.\d+\.\d+)/.exec(spec);
    assert.ok(lower, `override-ul ${name}=${spec} nu are o limită de jos citibilă`);
    assert.ok(atLeast(lower![1], floor),
              `override-ul ${name}=${spec} admite versiuni dinaintea ${floor}, ` +
              "adică exact cele vulnerabile");
  }
});

test("package-lock.json rezolvă versiunile reparate", () => {
  const lock = readJson("package-lock.json");
  for (const [name, floor] of Object.entries(PATCHED)) {
    // Toate aparițiile, nu doar cea din rădăcină: o copie imbricată sub `next`
    // ar rămâne instalată și ar fi cea pe care o folosește construcția.
    const seen = Object.entries<any>(lock.packages)
      .filter(([path]) => path === `node_modules/${name}` || path.endsWith(`/node_modules/${name}`));
    assert.ok(seen.length > 0, `${name} lipsește din lockfile — testul n-ar vedea nimic`);
    for (const [path, entry] of seen) {
      assert.ok(atLeast(entry.version, floor),
                `${path} e ${entry.version}, sub ${floor}: lockfile-ul a coborât la o versiune vulnerabilă`);
    }
  }
});

/**
 * `next` însuși. Intervalul `^15.1.0` de dinainte admitea 15.5.23 — versiunea cu
 * cele două critice (RCE în optimizatorul de imagini cu AVIF, RCE pe servere
 * Windows) — și o regenerare a lockfile-ului sau un `npm install` fără lockfile
 * o putea instala la loc, fără nicio eroare. Prima versiune reparată pe linia 15 e
 * 15.5.24 (GHSA-2xp9-vwfh-vxw4, GHSA-p293-qw3h-jr36), nu un salt la 16.
 *
 * Ce ajunge pe găzduire e lockfile-ul, deci se verifică și el, nu doar intervalul.
 */
const NEXT_PATCHED = "15.5.24";

test("comparatorul deosebește și versiunile lui next", () => {
  assert.equal(atLeast("15.5.23", NEXT_PATCHED), false);
  assert.equal(atLeast("15.5.24", NEXT_PATCHED), true);
  assert.equal(atLeast("15.5.27", NEXT_PATCHED), true);
});

test("package.json nu mai admite o versiune de next cu cele două critice", () => {
  const spec: string = readJson("package.json").dependencies?.next;
  assert.equal(typeof spec, "string", "package.json nu declară `next`");
  const lower = /(\d+\.\d+\.\d+)/.exec(spec);
  assert.ok(lower, `intervalul next=${spec} nu are o limită de jos citibilă`);
  assert.ok(atLeast(lower![1], NEXT_PATCHED),
            `next=${spec} admite versiuni dinaintea ${NEXT_PATCHED}, adică cele cu RCE`);
});

test("package-lock.json rezolvă un next reparat", () => {
  const entry = readJson("package-lock.json").packages["node_modules/next"];
  assert.ok(entry, "next lipsește din lockfile — testul n-ar vedea nimic");
  assert.ok(atLeast(entry.version, NEXT_PATCHED),
            `lockfile-ul rezolvă next ${entry.version}, sub ${NEXT_PATCHED}: ce instalează ` +
            "`npm ci` pe găzduire e versiunea cu cele două RCE");
});
