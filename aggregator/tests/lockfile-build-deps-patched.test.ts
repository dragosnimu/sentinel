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
 *
 * La sfârșit, aceeași garanție pentru `sharp` — cu o deosebire: acela nu are
 * `override`, fiindcă intervalul lui Next (`^0.34.3 || ^0.35.4`) îl admite deja.
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

/**
 * `sharp` — apărare în adâncime, nu închiderea unei căi deschise.
 *
 * Eșecul pe care îl previne: `sharp` (cu libvips, libheif și librsvg) e
 * dependență OPȚIONALĂ a lui Next, deci o regenerare a lockfile-ului sau un
 * `npm install` îl poate lăsa pe 0.34.x fără nicio eroare — `npm audit` doar
 * redevine roșu (trei avertizări high, CVSS până la 8,9). Două dintre ele
 * (libheif, libvips) spun literal că afectează „cine procesează intrare
 * nesigură"; a treia (librsvg) nu: o leagă de „anumite condiții de execuție" și
 * cere, pentru RCE, un binar `node` compilat fără PIE. Azi nu procesăm intrare:
 * `/_next/image` e închis (`images.unoptimized`, vezi
 * `image-optimizer-closed.test.ts`). Dar linia aia e una singură; dacă o șterge
 * cineva, versiunea lui `sharp` contează din nou, iar ăsta e testul care o ține
 * sus până atunci.
 *
 * Pragul e cel mai mare dintre cele trei „reparat în": GHSA-wq5f-xc86-pv6w
 * (librsvg, 0.35.5), GHSA-rgj7-g3m4-5g8c (libheif, 0.35.4), GHSA-f88m-g3jw-g9cj
 * (libvips, 0.35.0).
 *
 * Ce se verifică, separat: lockfile-ul (ce instalează `npm ci`) pentru TREI
 * pachete diferite, fiindcă un lockfile mixt le poate desface unul de altul:
 *   * `sharp` — API-ul JavaScript;
 *   * `@img/sharp-<platformă>` (ex. `sharp-linux-x64`) — doar bindingul Node,
 *     ~415 kB, un `.node` subțire care leagă `sharp` de biblioteca nativă;
 *   * `@img/sharp-libvips-<platformă>` — AICI stă codul vulnerabil: ~18,7 MB,
 *     `libvips-cpp.so` cu libheif și librsvg înăuntru. Cele trei avertizări sunt
 *     despre ce conține pachetul ăsta, nu bindingul. Saltul `sharp` 0.35.4 →
 *     0.35.5 ESTE saltul libvips 1.3.3 → 1.3.4 (librsvg 2.63.2, libheif 1.23.5);
 *     avizul GHSA-wq5f-xc86-pv6w spune literal că 0.35.5 „provides librsvg 2.63.2".
 *
 * O versiune anterioară a testului sărea peste `@img/sharp-libvips-*`, cu
 * motivația că „poartă bibliotecile, nu codul nativ" — afirmația e inversă, și a
 * lăsat neacoperit exact cazul declarat mai sus: `sharp` și bindingul la 0.35.5,
 * libvips la 1.2.4, test verde, vulnerabil. NU reintroduceți excluderea.
 *
 * Numerotarea libvips e a ei (1.x, nu 0.35.x), deci are prag propriu. Se ia din
 * sursă: `sharp@0.35.5` își fixează exact `@img/sharp-libvips-*` la 1.3.4 în
 * `optionalDependencies` (un test de mai jos verifică asta în lockfile).
 */
const SHARP_PATCHED = "0.35.5";
const LIBVIPS_PATCHED = "1.3.4";

function tailOf(path: string): string {
  return path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
}

function isLibvips(path: string): boolean {
  return tailOf(path).startsWith("@img/sharp-libvips-");
}

/** `sharp`, bindingurile lui și bibliotecile `libvips`, fiecare cu pragul lui. */
function sharpEntries(lock: any): Array<[string, any, string]> {
  return Object.entries<any>(lock.packages)
    .filter(([path]) => tailOf(path) === "sharp" || tailOf(path).startsWith("@img/sharp-"))
    .map(([path, entry]): [string, any, string] =>
      [path, entry, isLibvips(path) ? LIBVIPS_PATCHED : SHARP_PATCHED]);
}

test("comparatorul deosebește și versiunile lui sharp", () => {
  assert.equal(atLeast("0.34.5", SHARP_PATCHED), false);
  assert.equal(atLeast("0.35.4", SHARP_PATCHED), false);
  assert.equal(atLeast("0.35.5", SHARP_PATCHED), true);
  assert.equal(atLeast("0.36.0", SHARP_PATCHED), true);
  // libvips are numerotare proprie; 1.2.4 e cea din `sharp@0.34.5`.
  assert.equal(atLeast("1.2.4", LIBVIPS_PATCHED), false);
  assert.equal(atLeast("1.3.3", LIBVIPS_PATCHED), false);
  assert.equal(atLeast("1.3.4", LIBVIPS_PATCHED), true);
  assert.equal(atLeast("1.4.0", LIBVIPS_PATCHED), true);
});

test("package.json nu fixează `sharp` sub versiunea reparată", () => {
  // Nu e cerut: Next îl aduce singur. Dar dacă cineva îl declară (dependență,
  // opțională sau `override`), limita lui de jos nu are voie să fie cea veche.
  const pkg = readJson("package.json");
  const declared: Array<[string, unknown]> = [
    ["dependencies", pkg.dependencies?.sharp],
    ["optionalDependencies", pkg.optionalDependencies?.sharp],
    ["devDependencies", pkg.devDependencies?.sharp],
    ["overrides", pkg.overrides?.sharp],
  ];
  for (const [where, spec] of declared) {
    if (spec === undefined) continue;
    assert.equal(typeof spec, "string", `${where}.sharp are o formă pe care n-o înțeleg`);
    const lower = /(\d+\.\d+\.\d+)/.exec(spec as string);
    assert.ok(lower, `${where}.sharp=${spec} nu are o limită de jos citibilă`);
    assert.ok(atLeast(lower![1], SHARP_PATCHED),
              `${where}.sharp=${spec} admite versiuni dinaintea ${SHARP_PATCHED}, adică cele vulnerabile`);
  }
});

test("package-lock.json rezolvă un sharp reparat, cu binarele și cu libvips", () => {
  const seen = sharpEntries(readJson("package-lock.json"));
  // Controale: fiecare grup trebuie să fie nevid, altfel bucla de mai jos trece pe
  // gol pentru el. Al treilea e chiar gaura găsită: fără el, libvips putea lipsi
  // din listă și testul rămânea verde.
  assert.ok(seen.some(([path]) => path === "node_modules/sharp"),
            "sharp lipsește din lockfile — testul n-ar vedea nimic");
  assert.ok(seen.some(([path]) => tailOf(path).startsWith("@img/sharp-") && !isLibvips(path)),
            "binarele @img/sharp-<platformă> lipsesc din lockfile — testul ar acoperi doar `sharp`");
  assert.ok(seen.some(([path]) => isLibvips(path)),
            "bibliotecile @img/sharp-libvips-* lipsesc din lockfile — ele poartă codul vulnerabil");
  for (const [path, entry, floor] of seen) {
    assert.ok(atLeast(entry.version, floor),
              `${path} e ${entry.version}, sub ${floor}: lockfile-ul instalează ` +
              "versiunea cu cele trei avertizări high");
  }
});

test("pragul libvips e cel pe care `sharp` reparat îl fixează în lockfile", () => {
  // Pragul 1.3.4 nu e scris din imaginație: e ce pune `sharp@0.35.5` în
  // `optionalDependencies`. Dacă o regenerare aduce un `sharp` care fixează mai
  // jos, pragul din test ar fi o afirmație fără sursă — așa că se verifică.
  const sharp = readJson("package-lock.json").packages["node_modules/sharp"];
  assert.ok(sharp, "sharp lipsește din lockfile — testul n-ar vedea nimic");
  const pins = Object.entries<string>(sharp.optionalDependencies ?? {})
    .filter(([name]) => name.startsWith("@img/sharp-libvips-"));
  assert.ok(pins.length > 0,
            "sharp nu mai listează @img/sharp-libvips-* în optionalDependencies — " +
            "pragul libvips n-ar mai avea sursă");
  for (const [name, spec] of pins) {
    assert.ok(atLeast(spec, LIBVIPS_PATCHED),
              `sharp fixează ${name}=${spec}, sub ${LIBVIPS_PATCHED}: lockfile-ul ar ` +
              "instala libvips cu cele trei avertizări chiar cu `sharp` reparat");
  }
});
