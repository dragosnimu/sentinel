/**
 * QR-ul de înrolare: că desenul din terminal codifică EXACT URI-ul tipărit.
 *
 * ## Ce se strică dacă nu e corect
 *
 * Un QR care arată perfect și codifică alt șir — sau același șir, desenat
 * inversat sau în oglindă — lasă operatorul cu un cont pe care nu-l poate
 * confirma, iar el afla abia când codul din aplicație nu se potrivește niciodată.
 * Un test care verifică doar că „s-au tipărit blocuri” ar trece pe toate
 * variantele greșite. Deci aici QR-ul se DECODEAZĂ ÎNAPOI, din ieșirea tipărită
 * (nu din matrice), și se compară cu URI-ul octet cu octet.
 *
 * ## Cum se decodează — și de ce emulatorul e aici, nu în cod
 *
 * `emulate` de mai jos citește rândurile tipărite ca un terminal: urmărește
 * secvențele de culoare și ține socoteala fiecărei jumătăți de celulă (un rând
 * de text are două rânduri de pixeli: `▀` e sus-închis, `▄` jos-închis, `█`
 * ambele). Semnificația glifelor e scrisă AICI, din punctele de cod Unicode, nu
 * importată din cod: dacă desenul ar pune `▀` în loc de `▄`, un emulator care ar
 * împrumuta tabelul din cod ar citi corect o greșeală. Imaginea rezultată se
 * dă decodorului bibliotecii `qr` — același care verifică în producție —, dar
 * ASTA nu e singura dovadă: la scrierea testului, 30 de ecrane emulate (cele patru
 * stiluri, ambele teme, cinci utilizatori) au fost decodate și cu ZXing
 * (`zxing-cpp`, familia decodorului din multe aplicații de autentificare) și cu
 * OpenCV — toate 30, octet cu octet. Scriptul acela NU e în depozit, deci proba
 * aia nu se repetă singură. Decodorul de aici poate avea aceleași puncte oarbe ca
 * encoderul.
 *
 * Temele: un terminal are propriul fundal. Stilurile cu culori explicite se
 * citesc pe tema ÎNCHISĂ și pe cea DESCHISĂ, iar colțul zonei libere trebuie să
 * fie ALB în ambele — polaritatea nu o lasă testul pe seama decodorului, care ar
 * putea citi și un cod inversat.
 *
 * ## Ce NU probează
 *
 *   * că un terminal ADEVĂRAT (Windows Terminal, conhost, PowerShell) afișează
 *     glifele și culorile ca emulatorul de aici. Aici nu există un TTY real, iar
 *     modul de ieșire pe Windows se alege după `isTTY`/`platform`, nu se
 *     observă;
 *   * că o aplicație de pe telefon scanează un ecran, nu o imagine. Contrastul,
 *     lumina și moarea sunt ale camerei.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync, mkdtempSync, readFileSync, readdirSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { decodeQR } from "qr/decode.js";
import { encodeQR } from "qr";

import {
  QR_VARIABLE, buildVerifiedMatrix, chooseQr, enrolmentLines, qrWidth,
  renderQrLines,
} from "../bin/enrolment-display";
import type { QrLibs, QrStyle, TerminalInfo } from "../bin/enrolment-display";
import { generateSecret, provisioningUri } from "../lib/auth/totp";
import { ROOT } from "./shipped-files";

// ---------------------------------------------------------------------------
// Emulatorul de terminal — scris aici, din standard, nu din cod
// ---------------------------------------------------------------------------
const GLYPH_UPPER = 0x2580;   // UPPER HALF BLOCK
const GLYPH_LOWER = 0x2584;   // LOWER HALF BLOCK
const GLYPH_FULL = 0x2588;    // FULL BLOCK

type Theme = { fg: number; bg: number };   // luminanță 0..255
const DARK_THEME: Theme = { fg: 204, bg: 12 };
const LIGHT_THEME: Theme = { fg: 20, bg: 250 };

/** Culoarea din paleta xterm de 256, doar cele două care se folosesc: orice altă
 *  valoare e un cod pe care emulatorul nu-l cunoaște, deci o eroare, nu o ghicire. */
function luminance256(n: number): number {
  if (n === 16) return 0;
  if (n === 231) return 255;
  throw new Error(`culoarea ${n} din paleta de 256 nu e cunoscută emulatorului`);
}

type Picture = { width: number; height: number; data: Uint8ClampedArray };

const ESCAPES = /\u001b\[([0-9;]*)m/g;
const visible = (line: string): string => line.replace(ESCAPES, "");

/** Cele două jumătăți ale unei celule, după glif și culori. `ink` = culoarea
 *  de prim-plan. Un glif necunoscut e o eroare. */
function halves(ch: string, fg: number, bg: number): [number, number] {
  const code = ch.codePointAt(0)!;
  if (ch === " ") return [bg, bg];
  if (ch === "#") return [fg, fg];
  if (code === GLYPH_FULL) return [fg, fg];
  if (code === GLYPH_UPPER) return [fg, bg];
  if (code === GLYPH_LOWER) return [bg, fg];
  throw new Error(`glif necunoscut emulatorului: U+${code.toString(16)}`);
}

/** Rândurile QR ca imagine: o celulă = 1 px lățime × 2 px înălțime (cele două
 *  jumătăți), fiecare pixel mărit de 4 ori pe fiecare axă pentru decodor. */
function emulate(lines: string[], theme: Theme): Picture {
  const cells = lines.map((line) => {
    let fg = theme.fg;
    let bg = theme.bg;
    const row: Array<[number, number]> = [];
    let last = 0;
    const stepTo = (end: number): void => {
      for (const ch of line.slice(last, end)) row.push(halves(ch, fg, bg));
    };
    for (const match of line.matchAll(ESCAPES)) {
      stepTo(match.index!);
      last = match.index! + match[0].length;
      const params = match[1] === "" ? [0] : match[1].split(";").map(Number);
      for (let i = 0; i < params.length; i++) {
        if (params[i] === 0) { fg = theme.fg; bg = theme.bg; }
        else if (params[i] === 38 && params[i + 1] === 5) { fg = luminance256(params[i + 2]); i += 2; }
        else if (params[i] === 48 && params[i + 1] === 5) { bg = luminance256(params[i + 2]); i += 2; }
        else throw new Error(`secvență de culoare necunoscută emulatorului: ${match[0]}`);
      }
    }
    stepTo(line.length);
    return row;
  });
  const cols = Math.max(...cells.map((row) => row.length));
  assert.ok(cells.every((row) => row.length === cols), "rânduri de lățimi diferite");
  const scale = 4;
  const width = cols * scale;
  const height = cells.length * 2 * scale;
  const data = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < cells.length * 2; y++) {
    for (let x = 0; x < cols; x++) {
      const lum = cells[y >> 1][x][y & 1] < 128 ? 0 : 255;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const at = ((y * scale + dy) * width + x * scale + dx) * 4;
          data[at] = data[at + 1] = data[at + 2] = lum;
          data[at + 3] = 255;
        }
      }
    }
  }
  return { width, height, data };
}

/** Rândurile care alcătuiesc desenul în ieșirea întreagă: cel mai lung șir de
 *  rânduri de aceeași lățime vizibilă, indentate și făcute doar din caractere de
 *  desen. Proza are litere, deci nu intră. */
function qrRegion(output: string[]): string[] {
  const drawing = /^ {6}[ █▀▄#]{29,}$/;
  let best: string[] = [];
  let run: string[] = [];
  for (const line of output) {
    const seen = visible(line);
    if (drawing.test(seen) && (run.length === 0 || visible(run[0]).length === seen.length)) {
      run.push(line);
    } else {
      run = drawing.test(seen) ? [line] : [];
    }
    if (run.length > best.length) best = [...run];
  }
  return best.map((line) => line.slice(6));
}

function decode(picture: Picture): string {
  return decodeQR(picture);
}

// ---------------------------------------------------------------------------
// Cele patru stiluri, obținute din terminale, nu alese de mână
// ---------------------------------------------------------------------------
const WINDOWS_TTY: TerminalInfo = { isTTY: true, platform: "win32", env: {}, columns: 120 };
const POSIX_TTY_C: TerminalInfo = {
  isTTY: true, platform: "linux", env: { LANG: "C" }, columns: 160,
};
const UNICODE_PLAIN: TerminalInfo = {
  isTTY: false, platform: "linux", env: { LANG: "en_US.UTF-8", [QR_VARIABLE]: "unicode" },
};
const ASCII_PLAIN: TerminalInfo = {
  isTTY: false, platform: "win32", env: { [QR_VARIABLE]: "ascii" },
};

const STYLES: Array<{ name: string; term: TerminalInfo; themes: Theme[] }> = [
  { name: "glife + culori (Windows, TTY)", term: WINDOWS_TTY,
    themes: [DARK_THEME, LIGHT_THEME] },
  { name: "ASCII + culori (consolă fără UTF-8)", term: POSIX_TTY_C,
    themes: [DARK_THEME, LIGHT_THEME] },
  { name: "glife fără culori (forțat)", term: UNICODE_PLAIN, themes: [LIGHT_THEME] },
  { name: "ASCII fără culori (forțat)", term: ASCII_PLAIN, themes: [LIGHT_THEME] },
];

/** Zona liberă din standard (ISO/IEC 18004, 4 module). Scrisă AICI, nu importată
 *  din cod: o constantă împrumutată ar face testul să urmeze o greșeală. */
const SPEC_QUIET_ZONE = 4;

/** Un secret nou la fiecare rulare, nu un literal: o valoare base32 de 32 de
 *  caractere scrisă în depozit e exact ce caută `test_repo_is_sanitised.py`, iar
 *  una de probă nu merită o scutire. Testele nu depind de valoarea ei. */
const SECRET = generateSecret();

function uriFor(username: string): string {
  return provisioningUri(SECRET, username, "Sentinel Agregator");
}

async function output(uri: string, term: TerminalInfo, secret = SECRET): Promise<string[]> {
  return await enrolmentLines({ username: "proba", uri, secret }, term);
}

// ---------------------------------------------------------------------------
// Dovada centrală: ce se tipărește se decodează înapoi la URI
// ---------------------------------------------------------------------------
const USERNAMES = ["a", "dragos", "ana-maria.popescu", "x".repeat(40),
                   "Ștefan Ionescu", "o@adresa.ro"];

for (const style of STYLES) {
  test(`QR-ul tipărit (${style.name}) se decodează înapoi la URI-ul tipărit`, async () => {
    // Eșecul pe care îl previne: un QR care nu codifică ce spune rândul de
    // deasupra — glife puse invers, matrice transpusă, polaritate greșită, zonă
    // liberă prea mică, module nepătrate. Operatorul ar scana, ar vedea un cont
    // în aplicație și niciun cod care să se potrivească. Ieșirea e CEA a
    // funcției pe care o cheamă `bin/user.ts`, nu a unei piese din ea.
    for (const username of USERNAMES) {
      const uri = uriFor(username);
      const lines = await output(uri, style.term);
      assert.ok(lines.includes(`      ${uri}`), "URI-ul nu e tipărit ca atare");
      const region = qrRegion(lines);
      assert.ok(region.length >= 15, `${username}: nu s-a găsit desenul (${region.length} rânduri)`);
      for (const theme of style.themes) {
        const picture = emulate(region, theme);
        assert.equal(decode(picture), uri, `${username} pe tema ${JSON.stringify(theme)}`);
      }
    }
  });
}

test("desenul nu se rupe pentru nicio lungime de utilizator", async () => {
  // Eșecul pe care îl previne: un defect care apare doar la o versiune de QR —
  // lungimea numelui schimbă versiunea simbolului, deci tabelele de aliniere,
  // blocurile de corecție și biții de versiune. Un nume de 6 litere și unul de 40
  // nu trec prin aceleași ramuri; operatorul are doar al lui. Toate lungimile
  // 1..220, pe stilul de pe Windows, cu un secret aleator de fiecare dată.
  const versions = new Set<number>();
  for (let length = 1; length <= 220; length++) {
    const secret = generateSecret();
    const uri = provisioningUri(secret, "u".repeat(length), "Sentinel Agregator");
    const lines = await output(uri, WINDOWS_TTY, secret);
    const region = qrRegion(lines);
    assert.ok(region.length > 0, `lungimea ${length}: fără desen — ` +
              lines.filter((line) => line.includes("QR omis")).join(" "));
    assert.equal(decode(emulate(region, DARK_THEME)), uri, `lungimea ${length}`);
    versions.add((visible(region[0]).length - 2 * SPEC_QUIET_ZONE - 17) / 4);
  }
  assert.ok(versions.size >= 4, `doar versiunile ${[...versions]} — baleiajul nu acoperă nimic`);
});

test("un URI cu litere din afara ASCII-ului se decodează la aceiași octeți", async () => {
  // Eșecul pe care îl previne: diacritice codificate cu altă codare decât
  // UTF-8 — URI-ul din aplicație ar purta alt nume, sau alt secret dacă literele
  // ar atinge parametrii. Comparația e pe OCTEȚI, nu pe șir.
  const uri = `otpauth://totp/Sentinel:Ștefan?secret=${SECRET}&issuer=Țară`;
  const region = qrRegion(await output(uri, WINDOWS_TTY));
  const back = decode(emulate(region, DARK_THEME));
  assert.deepEqual(Buffer.from(back, "utf8"), Buffer.from(uri, "utf8"));
});

// ---------------------------------------------------------------------------
// Modul cu modul, și orientarea — ce un decodor îngăduitor nu vede
// ---------------------------------------------------------------------------
/** Cuvintele de format valide pentru un nivel de corecție (ISO/IEC 18004, 7.9):
 *  5 biți de date, BCH(15,5) cu polinomul 0x537, XOR 0x5412. */
function formatWords(eccBits: number): number[] {
  const words: number[] = [];
  for (let mask = 0; mask < 8; mask++) {
    const data = (eccBits << 3) | mask;
    let rem = data << 10;
    for (let bit = 14; bit >= 10; bit--) {
      if (rem & (1 << bit)) rem ^= 0x537 << (bit - 10);
    }
    words.push(((data << 10) | rem) ^ 0x5412);
  }
  return words;
}

/** Grila de module recuperată din imagine: se măsoară modulul din finderul de sus,
 *  apoi se citește centrul fiecărui modul. */
function gridOf(picture: Picture): boolean[][] {
  const dark = (x: number, y: number): boolean =>
    picture.data[(y * picture.width + x) * 4] === 0;
  let minX = picture.width, maxX = -1, minY = picture.height, maxY = -1;
  for (let y = 0; y < picture.height; y++) {
    for (let x = 0; x < picture.width; x++) {
      if (!dark(x, y)) continue;
      minX = Math.min(minX, x); maxX = Math.max(maxX, x);
      minY = Math.min(minY, y); maxY = Math.max(maxY, y);
    }
  }
  let run = 0;
  while (dark(minX + run, minY)) run++;
  const unit = run / 7;
  const n = (maxX - minX + 1) / unit;
  assert.equal(n, (maxY - minY + 1) / unit, "simbolul nu e pătrat");
  assert.ok(Number.isInteger(n), `simbolul are ${n} module`);
  return Array.from({ length: n }, (_, y) => Array.from({ length: n }, (_, x) =>
    dark(Math.floor(minX + (x + 0.5) * unit), Math.floor(minY + (y + 0.5) * unit))));
}

test("cuvintele de format calculate aici dau valorile din standard", () => {
  // Controlul pozitiv al testului de mai jos: o formulă greșită ar face testul de
  // orientare să pice (sau, mai rău, să treacă) din motive care nu țin de desen.
  // 0x5412 e cuvântul pentru M / masca 0; 0x77C4 pentru L / masca 0 (tabelul din
  // standard, ca în orice implementare).
  assert.equal(formatWords(0)[0], 0x5412);
  assert.equal(formatWords(1)[0], 0x77c4);
  assert.equal(new Set(formatWords(1)).size, 8);
});

for (const style of STYLES) {
  test(`${style.name}: grila desenată e matricea encoderului, modul cu modul, și nu în oglindă`,
       async () => {
    // Eșecul pe care îl previne: un desen care se decodează DAR nu e cel produs —
    // (1) transpus: un QR în oglindă se citește doar de decodoarele care încearcă
    // și oglinda (opțional în standard), deci poate merge pe laptop și nu pe
    // telefonul operatorului; (2) cu câteva module greșite: corecția de erori le
    // repară, deci decodorul nu se plânge, dar desenul are deja un defect pe care
    // o a doua scădere de lumină îl face fatal. Aici: fiecare modul se compară cu
    // matricea encoderului, iar orientarea se dovedește SEPARAT, din biții de
    // format citiți în pozițiile standard (două copii, același cuvânt valid pentru
    // nivelul L) — oglindirea schimbă ordinea biților și cuvântul iese invalid.
    const uri = uriFor("dragos");
    const region = qrRegion(await output(uri, style.term));
    const grid = gridOf(emulate(region, style.themes[style.themes.length - 1]));

    const expected = encodeQR(uri, "raw", { ecc: "low", border: 1 })
      .slice(1, -1).map((row) => row.slice(1, -1));
    assert.equal(grid.length, expected.length);
    let wrong = 0;
    for (let y = 0; y < grid.length; y++) {
      for (let x = 0; x < grid.length; x++) if (grid[y][x] !== expected[y][x]) wrong++;
    }
    assert.equal(wrong, 0, `${wrong} module diferă de matricea encoderului`);

    const n = grid.length;
    const read = (cells: Array<[number, number]>): number =>
      cells.reduce((word, [x, y]) => (word << 1) | (grid[y][x] ? 1 : 0), 0);
    const first: Array<[number, number]> = [];
    for (let x = 0; x <= 5; x++) first.push([x, 8]);
    first.push([7, 8], [8, 8], [8, 7]);
    for (let y = 5; y >= 0; y--) first.push([8, y]);
    const second: Array<[number, number]> = [];
    for (let y = n - 1; y >= n - 7; y--) second.push([8, y]);
    for (let x = n - 8; x < n; x++) second.push([x, 8]);
    const valid = formatWords(1);   // nivelul L
    assert.ok(valid.includes(read(first)),
              `prima copie a formatului (${read(first).toString(2)}) nu e un cuvânt valid`);
    assert.equal(read(second), read(first), "cele două copii ale formatului diferă");
  });
}

// ---------------------------------------------------------------------------
// Polaritate și zonă liberă — fără decodor, ca un decodor îngăduitor să nu le ascundă
// ---------------------------------------------------------------------------
for (const style of STYLES.slice(0, 2)) {
  test(`${style.name}: colțul zonei libere e ALB pe orice temă, simbolul e închis`, async () => {
    // Eșecul pe care îl previne: culori puse invers sau lipsă — pe un terminal
    // întunecat QR-ul iese inversat (alb pe negru), iar multe aplicații nu
    // scanează un cod inversat. Decodorul bibliotecii poate citi și inversat,
    // deci polaritatea se verifică DIRECT, pe pixeli.
    const region = qrRegion(await output(uriFor("dragos"), style.term));
    for (const theme of style.themes) {
      const picture = emulate(region, theme);
      assert.equal(picture.data[0], 255, "colțul zonei libere nu e alb");
      const last = (picture.width * picture.height - 1) * 4;
      assert.equal(picture.data[last], 255, "colțul opus nu e alb");
    }
  });
}

for (const style of STYLES) {
  test(`${style.name}: zona liberă are cel puțin ${SPEC_QUIET_ZONE} module pe fiecare latură`, async () => {
    // Eșecul pe care îl previne: un cod lipit de marginea desenului, pe care
    // camera îl găsește greu sau deloc. Se măsoară pe pixeli, fără decodor: un
    // decodor pe o imagine sintetică ar citi un cod fără nicio margine.
    const region = qrRegion(await output(uriFor("dragos"), style.term));
    const picture = emulate(region, style.themes[style.themes.length - 1]);
    const dark = (x: number, y: number): boolean =>
      picture.data[(y * picture.width + x) * 4] === 0;
    let minX = picture.width, maxX = -1, minY = picture.height, maxY = -1;
    for (let y = 0; y < picture.height; y++) {
      for (let x = 0; x < picture.width; x++) {
        if (!dark(x, y)) continue;
        minX = Math.min(minX, x); maxX = Math.max(maxX, x);
        minY = Math.min(minY, y); maxY = Math.max(maxY, y);
      }
    }
    assert.ok(maxX > minX, "nu există niciun pixel închis");
    // Mărimea modulului în pixeli, din marginea de sus a simbolului: primul rând
    // al unui simbol QR începe cu cele șapte module închise ale finderului.
    let run = 0;
    while (dark(minX + run, minY)) run++;
    assert.equal(run % 7, 0, `rândul de sus al simbolului începe cu ${run} px închiși`);
    const unit = run / 7;
    const margins = [minX, picture.width - 1 - maxX, minY, picture.height - 1 - maxY]
      .map((px) => px / unit);
    for (const margin of margins) {
      assert.ok(margin >= SPEC_QUIET_ZONE, `zona liberă are ${margins} module (laturile)`);
    }
  });
}

// ---------------------------------------------------------------------------
// Alegerea stilului: ce poate lua terminalul
// ---------------------------------------------------------------------------
function style(term: TerminalInfo): QrStyle | null {
  const choice = chooseQr(term);
  return choice.kind === "render" ? choice.style : null;
}

test("pe Windows, un TTY primește glife și culori; o ieșire redirecționată NU primește glife", () => {
  // Eșecul pe care îl previne, cel observat: randarea cu `█` pe o consolă cp1252
  // a dat `UnicodeEncodeError`. Un TTY de Windows primește textul prin API-ul
  // consolei (UTF-16), deci pagina de coduri nu contează. O ieșire redirecționată
  // primește octeți UTF-8 pe care cititorul îi decodează cum vrea — acolo nu se
  // presupune nimic: fără culori nu se desenează automat.
  assert.deepEqual(style(WINDOWS_TTY), { glyphs: "unicode", color: true });
  const piped: TerminalInfo = { isTTY: false, platform: "win32", env: {} };
  assert.equal(style(piped), null);
  // Forțat de operator pe o ieșire redirecționată: ASCII, niciodată glife.
  assert.deepEqual(style({ ...piped, env: { [QR_VARIABLE]: "ascii" } },),
                   { glyphs: "ascii", color: false });
  // Dacă totuși cere glife pe ieșirea redirecționată, o primește — cu un avertisment
  // despre octeții UTF-8, fiindcă acolo cititorul decide cum îi afișează.
  const forced = chooseQr({ ...piped, env: { [QR_VARIABLE]: "unicode" } });
  assert.equal(forced.kind, "render");
  assert.match(forced.notes.join(" "), /UTF-8/);
});

test("pe un sistem nu-Windows, glifele cer un local UTF-8", () => {
  // Eșecul pe care îl previne: glife trimise unui terminal cu localul `C` sau
  // `POSIX`, care le arată ca `?` sau ca octeți rupți. `LC_ALL` bate `LC_CTYPE`,
  // care bate `LANG` — ordinea din `locale(7)`.
  const base: TerminalInfo = { isTTY: true, platform: "linux", env: {} };
  assert.deepEqual(style({ ...base, env: { LANG: "en_US.UTF-8" } }),
                   { glyphs: "unicode", color: true });
  assert.deepEqual(style({ ...base, env: { LANG: "C" } }), { glyphs: "ascii", color: true });
  assert.deepEqual(style({ ...base, env: {} }), { glyphs: "ascii", color: true });
  assert.deepEqual(style({ ...base, env: { LC_ALL: "C", LANG: "en_US.UTF-8" } }),
                   { glyphs: "ascii", color: true });
  assert.deepEqual(style({ ...base, env: { LC_ALL: "ro_RO.utf8", LANG: "C" } }),
                   { glyphs: "unicode", color: true });
});

test("fără culori, QR-ul NU se desenează singur (polaritatea nu se poate ști)", () => {
  // Eșecul pe care îl previne: un QR desenat fără culori e „negru pe fundalul
  // temei” — inversat pe un terminal întunecat, iar multe aplicații nu scanează
  // un cod inversat. Nu se desenează unul care POATE fi inversat și arată la fel de
  // bine ca unul corect; se spune de ce lipsește.
  for (const env of [{ NO_COLOR: "1" }, { TERM: "dumb" }]) {
    const choice = chooseQr({ isTTY: true, platform: "win32", env });
    assert.equal(choice.kind, "skip", JSON.stringify(env));
    assert.match((choice as { why: string }).why, /polaritatea/);
  }
  assert.equal(chooseQr({ isTTY: false, platform: "linux",
                          env: { LANG: "en_US.UTF-8" } }).kind, "skip");
});

test("SENTINEL_QR: off oprește, unicode/ascii forțează, o valoare necunoscută se spune", () => {
  // Eșecul pe care îl previne: o comutare care nu face nimic (o valoare scrisă
  // greșit tratată ca `auto`, fără un cuvânt) — omul crede că a forțat ASCII-ul și
  // primește glife rupte.
  const tty = (value: string): TerminalInfo => ({
    isTTY: true, platform: "win32", env: { [QR_VARIABLE]: value } });
  assert.equal(chooseQr(tty("off")).kind, "skip");
  assert.deepEqual(style(tty("ascii")), { glyphs: "ascii", color: true });
  assert.deepEqual(style(tty("UNICODE")), { glyphs: "unicode", color: true });
  const wrong = chooseQr(tty("asci"));
  assert.equal(wrong.kind, "render");
  assert.match(wrong.notes.join(" "), /nu e recunoscut/);
});

test("un QR forțat fără culori spune că polaritatea e pentru fundal deschis", () => {
  // Eșecul pe care îl previne: QR-ul forțat, desenat în tăcere, care pe un fundal
  // întunecat nu se scanează, fără nicio cheie pentru ce să încerce.
  const choice = chooseQr(ASCII_PLAIN);
  assert.equal(choice.kind, "render");
  assert.match(choice.notes.join(" "), /fundal DESCHIS/);
});

// ---------------------------------------------------------------------------
// Ce NU se desenează, și ce rămâne
// ---------------------------------------------------------------------------
test("pe un terminal prea îngust QR-ul nu se desenează, dar URI-ul și secretul rămân", async () => {
  // Eșecul pe care îl previne: rânduri care se rup la marginea ferestrei —
  // desenul devine un grilaj care nu se scanează, dar arată ca un QR. Limita e
  // exactă: cu o coloană în plus se desenează.
  const uri = uriFor("dragos");
  const full = await output(uri, WINDOWS_TTY);
  const width = visible(qrRegion(full)[0]).length + 6;
  const fits = await output(uri, { ...WINDOWS_TTY, columns: width });
  assert.ok(qrRegion(fits).length > 0, "la lățimea exactă ar fi trebuit să se deseneze");
  const narrow = await output(uri, { ...WINDOWS_TTY, columns: width - 1 });
  assert.equal(qrRegion(narrow).length, 0, "s-a desenat pe un terminal prea îngust");
  assert.ok(narrow.some((line) => line.includes("QR omis")), narrow.join("\n"));
  assert.ok(narrow.includes(`      ${uri}`) && narrow.includes(`      secret: ${SECRET}`));
});

test("un QR care NU se decodează la URI nu se desenează, iar URI-ul rămâne", async () => {
  // Eșecul pe care îl previne, cel din cauza căruia există verificarea: un
  // encoder care codifică ALT șir produce un QR perfect de frumos care înrolează
  // altceva. Aici biblioteca MINTE (codifică un URI cu alt secret): desenul
  // trebuie refuzat, cu un rând care spune de ce.
  const real = await import("qr");
  const decoder = await import("qr/decode.js");
  const lying: QrLibs = {
    encodeQR: ((text: string, out: never, opts: never) =>
      real.encodeQR(text.replace(SECRET, "A".repeat(SECRET.length)), out, opts)) as QrLibs["encodeQR"],
    decodeQR: decoder.decodeQR,
  };
  const uri = uriFor("dragos");
  const built = await buildVerifiedMatrix(uri, async () => lying);
  assert.ok("failed" in built, "un QR care codifică alt șir a fost acceptat");
  assert.match((built as { failed: string }).failed, /NU dă URI-ul/);

  const lines = await enrolmentLines({ username: "proba", uri, secret: SECRET },
                                     WINDOWS_TTY, async () => lying);
  assert.equal(qrRegion(lines).length, 0, "s-a desenat un QR care codifică altceva");
  assert.ok(lines.some((line) => line.includes("QR omis")));
  assert.ok(lines.includes(`      ${uri}`), "URI-ul trebuie să rămână");
  assert.ok(!lines.join("\n").includes("A".repeat(SECRET.length)),
            "secretul fals al encoderului a ajuns în ieșire");
});

test("un decodor care nu poate rula înseamnă QR omis, nu QR nedovedit", async () => {
  // Eșecul pe care îl previne: verificarea care, când pică, lasă desenul să treacă
  // „fiindcă n-am putut verifica”. Necunoscut nu e bine.
  const real = await import("qr");
  const broken: QrLibs = {
    encodeQR: real.encodeQR,
    decodeQR: (() => { throw new Error("decodor stricat"); }) as QrLibs["decodeQR"],
  };
  const built = await buildVerifiedMatrix(uriFor("dragos"), async () => broken);
  assert.ok("failed" in built);
  assert.match((built as { failed: string }).failed, /nu pot dovedi/);
});

test("fără pachetul `qr` instalat, ieșirea are URI-ul, secretul și spune de ce lipsește QR-ul",
     () => {
  // Eșecul pe care îl previne: o instalare cu `--omit=dev` (ce face
  // `npm ci --omit=dev` de pe documentația găzduirii) în care `enroll-totp` moare
  // la import, DUPĂ ce secretul a fost scris în bază și ÎNAINTE să fie tipărit —
  // cont blocat, fără secret de scanat. Mecanismul e cel real: un director fără
  // `node_modules` deasupra, deci `import("qr")` dă `ERR_MODULE_NOT_FOUND`.
  const dir = mkdtempSync(path.join(os.tmpdir(), "sentinel-noqr-"));
  copyFileSync(path.join(ROOT, "bin", "enrolment-display.ts"),
               path.join(dir, "enrolment-display.ts"));
  writeFileSync(path.join(dir, "driver.ts"), [
    'import { enrolmentLines } from "./enrolment-display";',
    "async function main() {",
    '  const lines = await enrolmentLines({ username: "proba", uri: "otpauth://totp/x?secret=ABC", secret: "ABC" },',
    '    { isTTY: true, platform: "win32", env: {}, columns: 200 });',
    "  process.stdout.write(JSON.stringify(lines));",
    "}",
    "main();",
  ].join("\n"));
  const run = spawnSync(process.execPath, [
    "--import", pathToFileURL(path.join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href,
    path.join(dir, "driver.ts"),
  ], { cwd: dir, encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const lines: string[] = JSON.parse(run.stdout);
  assert.ok(lines.includes("      otpauth://totp/x?secret=ABC"), lines.join("\n"));
  assert.ok(lines.includes("      secret: ABC"));
  assert.equal(qrRegion(lines).length, 0);
  assert.match(lines.join("\n"), /pachetul `qr` nu e instalat/);
});

// ---------------------------------------------------------------------------
// Ce intră în instalarea de pe găzduire
// ---------------------------------------------------------------------------
test("`qr` e dependență de DEZVOLTARE, nu de producție, și nimic livrat nu o importă", () => {
  // Eșecul pe care îl previne: `package.json` ajunge pe găzduire, iar tot ce e în
  // `dependencies` se instalează acolo — pentru o unealtă care nu rulează acolo.
  // Mai rău, un `import "qr"` din `app/` sau `lib/` ar intra în pachetul servit.
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.ok(pkg.devDependencies?.qr, "`qr` nu e în devDependencies");
  // Versiune EXACTĂ, fără `^`/`~`: biblioteca vede secretul TOTP în clar, iar
  // 0.6.0 avea un decodor care refuza simboluri valide (lungimi de utilizator 61,
  // 122, ... — vezi sweep-ul de mai sus), deci o versiune care plutește nu e a
  // noastră. Se schimbă deliberat, cu sweep-ul verde.
  assert.match(pkg.devDependencies.qr, /^\d+\.\d+\.\d+$/,
               `\`qr\` nu e fixat la o versiune exactă: ${pkg.devDependencies.qr}`);
  assert.equal(pkg.dependencies?.qr, undefined, "`qr` e în dependencies: ajunge în producție");
  assert.equal(Object.keys(pkg.dependencies).sort().join(","),
               "hash-wasm,mysql2,next,react,react-dom",
               "lista dependențelor de producție s-a schimbat");

  // Și în fișierul de blocare, marcat ca dev: `npm ci --omit=dev` îl sare.
  const lock = JSON.parse(readFileSync(path.join(ROOT, "package-lock.json"), "utf8"));
  assert.equal(lock.packages["node_modules/qr"]?.dev, true,
               "`qr` nu e marcat `dev` în package-lock.json");
  assert.equal(lock.packages["node_modules/qr"]?.dependencies, undefined,
               "`qr` a adus dependențe tranzitive");

  const importers: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.(tsx?|mjs|jsx?)$/.test(entry.name) &&
               /from\s+["']qr(\/|["'])|import\(\s*["']qr(\/|["'])|require\(\s*["']qr/
                 .test(readFileSync(full, "utf8"))) importers.push(path.relative(ROOT, full));
    }
  };
  for (const dir of ["app", "lib"]) walk(path.join(ROOT, dir));
  assert.deepEqual(importers, [], `cod livrat pe găzduire importă \`qr\`: ${importers}`);
  // Control pozitiv: tiparul chiar vede un import acolo unde există.
  assert.match(readFileSync(path.join(ROOT, "bin", "enrolment-display.ts"), "utf8"),
               /import\(\s*["']qr["']\)/);
});

test("`enroll-totp` tipărește prin `enrolmentLines` și nu duce secretul altundeva", () => {
  // Eșecul pe care îl previne: revenirea la un `console.log` direct (fără QR) sau
  // un secret care ia o cale nouă — fișier, `argv`, jurnal. Pe text, și se spune
  // pe față: `main()` are nevoie de o bază reală, deci legătura de aici se vede
  // prima dată pe gazdă. Ce se prinde e calea scrisă din greșeală.
  const cli = readFileSync(path.join(ROOT, "bin", "user.ts"), "utf8");
  assert.equal([...cli.matchAll(/await showEnrolment\(/g)].length, 2,
               "ambele căi de înrolare (`create --totp` și `enroll-totp`) trebuie să tipărească");
  assert.match(cli, /enrolmentLines\(enrolment,/);
  for (const file of ["bin/user.ts", "bin/enrolment-display.ts"]) {
    const text = readFileSync(path.join(ROOT, file), "utf8");
    for (const forbidden of ["writeFile", "appendFile", "createWriteStream",
                             "child_process", "process.argv[", "console.error(enrolment"]) {
      assert.ok(!text.includes(forbidden), `${file} conține ${forbidden}`);
    }
  }
  assert.ok(!readFileSync(path.join(ROOT, "bin", "enrolment-display.ts"), "utf8")
              .includes("console."), "modulul de afișare scrie direct în consolă");
});

test("sursa spune glifele prin puncte de cod, nu le poartă ca litere", () => {
  // Eșecul pe care îl previne: o sursă salvată într-o codare care mănâncă `█` — pe
  // un editor sau o consolă cu altă pagină de coduri — iar desenul ar ieși cu `?`.
  // Comentariile au voie să le arate; codul nu.
  const code = readFileSync(path.join(ROOT, "bin", "enrolment-display.ts"), "utf8")
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("/*"))
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join("\n");
  assert.ok(code.includes("\\u2588"), "glifele nu se mai scriu prin cod Unicode");
  assert.ok(!/[\u2580-\u259f]/.test(code), "un glif de bloc e scris literal în cod");
});
