/**
 * API-ul de optimizare de imagini al lui Next trebuie să rămână închis.
 *
 * Eșecul pe care îl previne: `/_next/image` există IMPLICIT în orice aplicație
 * Next, chiar dacă nu folosește `next/image`, iar agregatorul nu o folosește.
 * Prin el ajunge `sharp` (libvips, libheif, librsvg) să proceseze intrare
 * controlată de un vizitator neautentificat — inclusiv RCE-ul din libheif pentru
 * AVIF. O suprafață fără beneficiar, deschisă pe un panou de securitate. Dacă
 * cineva scoate `images: { unoptimized: true }` din `next.config.mjs`, sau o
 * versiune viitoare de Next îi schimbă sensul, nimic din aplicație nu se strică
 * și nimic nu spune că ruta a revenit.
 *
 * DE CE PORNEȘTE UN SERVER, în loc să citească configurația. O aserțiune pe
 * `nextConfig.images.unoptimized === true` verifică un NUME, nu decizia luată din
 * el: ar rămâne verde și dacă Next ar citi cheia altfel. Aici se cere un răspuns
 * HTTP real. Serverul de dezvoltare, nu `next build` + `next start`: aceeași
 * rută (`handleNextImageRequest`, în `next-server`), dar pornește în ~2 s, iar
 * regula suitei (`run-tests.mjs`) e că un test scump e un test pe care cineva îl
 * scoate. Ce NU acoperă: serverul de producție al găzduirii. Acela a fost
 * măsurat o dată de mână, cu build real — vezi `next.config.mjs`.
 *
 * CONTROLUL. Un 404 poate însemna „ruta e închisă" sau „serverul n-a ajuns să
 * rutizeze nimic". De aceea primul test pornește același server cu o
 * configurație goală (`export default {}`) și cere ca ruta să RĂSPUNDĂ — 200 pe
 * un PNG, 400 fără parametri. Fără el, un harness orb ar face al doilea test
 * verde pe lângă ruta deschisă: exact testul care „verifică" fără să vadă.
 *
 * Proiectul de probă e într-un director temporar, cu `node_modules` legat printr-o
 * joncțiune: dev-ul scrie în `.next/`, iar asta ar strica un build local.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import {
  existsSync, lstatSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { deflateSync } from "node:zlib";

const ROOT = join(import.meta.dirname, "..");
const REAL_CONFIG = join(ROOT, "next.config.mjs");

/**
 * PNG de 1x1, CONSTRUIT aici, nu lipit ca șir base64: un literal de 96 de
 * caractere arată ca o valoare generată, iar `tests/security/test_repo_is_sanitised.py`
 * îl numește pe bună dreptate un posibil secret. Valid, deci `sharp` are ce
 * procesa dacă ruta e deschisă — controlul de mai jos cere exact asta.
 */
function pngPixel(): Buffer {
  const table = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc32 = (buf: Buffer): number => {
    let c = 0xffffffff;
    for (const byte of buf) c = table[(c ^ byte) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type: string, data: Buffer): Buffer => {
    const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
    const out = Buffer.alloc(12 + data.length);
    out.writeUInt32BE(data.length, 0);
    body.copy(out, 4);
    out.writeUInt32BE(crc32(body), 8 + data.length);
    return out;
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(1, 0);   // lățime
  header.writeUInt32BE(1, 4);   // înălțime
  header[8] = 8;                // adâncime de bit
  header[9] = 2;                // RGB
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(Buffer.from([0, 255, 0, 0]))),  // filtru 0 + un pixel
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

const PNG_1X1 = pngPixel();

const IMAGE_URL = "/_next/image?url=%2Fprobe.png&w=64&q=75";

interface Answer { status: number; type: string }

interface Probe {
  /** Cererea către serverul pornit; aruncă dacă serverul nu răspunde deloc. */
  get(path: string): Promise<Answer>;
}

function stop(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.pid === undefined) return resolve();
    child.once("exit", () => resolve());
    // Tot arborele, nu doar părintele: un copil rămas ar ține portul și ar
    // lăsa un proces orfan după o suită verde.
    if (process.platform === "win32") {
      spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    } else {
      try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
    }
    setTimeout(resolve, 5_000).unref();
  });
}

/**
 * Pornește `next dev` pe un proiect minimal a cărui configurație e `configSource`
 * și rulează `body` peste el. Oprește serverul și șterge directorul orice ar fi.
 */
async function withDevServer(
  configSource: string,
  body: (probe: Probe) => Promise<void>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-image-probe-"));
  const link = join(dir, "node_modules");
  let child: ChildProcess | undefined;
  try {
    mkdirSync(join(dir, "app"));
    mkdirSync(join(dir, "public"));
    writeFileSync(join(dir, "package.json"), '{"name":"probe","private":true}\n');
    writeFileSync(join(dir, "app", "layout.js"),
      "export default function L({ children }) { return <html><body>{children}</body></html>; }\n");
    writeFileSync(join(dir, "app", "page.js"),
      "export default function P() { return <p>probe</p>; }\n");
    writeFileSync(join(dir, "public", "probe.png"), PNG_1X1);
    writeFileSync(join(dir, "next.config.mjs"), configSource);
    symlinkSync(join(ROOT, "node_modules"), link, "junction");

    // `-p 0`: portul îl alege Next și îl tipărește. Un port „liber" aflat dinainte
    // (bind pe 0, închis, apoi dat serverului) poate fi luat între timp de alt
    // fișier de test pornit în paralel de `node --test` — măsurat: o rulare din
    // cinci a picat cu `connect ETIMEDOUT` pe un port care nu era al serverului.
    let log = "";
    child = spawn(
      process.execPath,
      [join(ROOT, "node_modules", "next", "dist", "bin", "next"),
       "dev", "-p", "0", "-H", "127.0.0.1"],
      {
        cwd: dir,
        stdio: ["ignore", "pipe", "pipe"],
        detached: process.platform !== "win32",
        env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" },
      });
    child.stdout!.on("data", (d) => { log += d; });
    child.stderr!.on("data", (d) => { log += d; });

    const portOf = (): number | undefined => {
      const found = /Local:\s+http:\/\/127\.0\.0\.1:(\d+)/.exec(log);
      return found ? Number(found[1]) : undefined;
    };

    // Se reîncearcă DOAR când cererea nu a ajuns la server (conexiune refuzată,
    // resetată, timp depășit) — serverul de dezvoltare compilează la prima cerere
    // și, cu zeci de fișiere de test în paralel, poate fi lent să accepte. Un
    // răspuns, orice cod ar avea, nu se reîncearcă niciodată: verdictul vine doar
    // dintr-un răspuns primit.
    const get = async (path: string): Promise<Answer> => {
      let failure: unknown;
      for (let attempt = 0; attempt < 4; attempt++) {
        const port = portOf();
        if (port === undefined) { await new Promise((r) => setTimeout(r, 500)); continue; }
        try {
          const res = await fetch(`http://127.0.0.1:${port}${path}`,
                                  { signal: AbortSignal.timeout(30_000) });
          await res.arrayBuffer();
          return { status: res.status, type: res.headers.get("content-type") ?? "" };
        } catch (err) {
          failure = err;
          await new Promise((r) => setTimeout(r, 1_000));
        }
      }
      throw new Error(`serverul de probă nu a răspuns la ${path}: ${String(failure)}\n${log.slice(-800)}`);
    };

    // Gata = un fișier static se servește. Un server care nu pornește iese cu
    // eroare, nu cu 404, și testul trebuie să pice cu jurnalul lui, nu să
    // „treacă" fiindcă nimic n-a răspuns 200.
    let ready = false;
    const deadline = Date.now() + 40_000;
    while (!ready && Date.now() < deadline && child.exitCode === null) {
      if (portOf() === undefined) { await new Promise((r) => setTimeout(r, 250)); continue; }
      try { ready = (await get("/probe.png")).status === 200; }
      catch { await new Promise((r) => setTimeout(r, 500)); }
    }
    assert.ok(ready, `serverul de probă nu a pornit; jurnalul lui:\n${log.slice(-1500)}`);

    await body({ get });
  } finally {
    if (child) await stop(child);
    // Joncțiunea se scoate ÎNTÂI și separat: `rmSync` recursiv peste un director
    // care conține o legătură spre `node_modules`-ul real e genul de greșeală
    // care costă o reinstalare. Dacă legătura nu s-a putut scoate, directorul
    // temporar rămâne — mai bine un director uitat decât unul șters prea adânc.
    let linkGone = !existsSync(link) && !isLink(link);
    if (!linkGone) {
      try { unlinkSync(link); linkGone = true; } catch { /* rămâne, vezi mai sus */ }
    }
    if (linkGone) rmSync(dir, { recursive: true, force: true });
  }
}

function isLink(path: string): boolean {
  try { return lstatSync(path).isSymbolicLink(); } catch { return false; }
}

test("control: fără nicio configurație, ruta de imagini RĂSPUNDE", async () => {
  // Dacă asta pică, harness-ul nu poate vedea ruta deschisă, iar testul de mai
  // jos nu dovedește nimic.
  await withDevServer("export default {};\n", async ({ get }) => {
    const image = await get(IMAGE_URL);
    assert.equal(image.status, 200,
      `ruta implicită a lui Next nu a procesat un PNG (HTTP ${image.status}): harness-ul ` +
      "nu poate deosebi „închisă” de „nu merge”");
    assert.ok(image.type.startsWith("image/"), `tip neașteptat: ${image.type}`);

    const bare = await get("/_next/image");
    assert.equal(bare.status, 400,
      `fără parametri, handlerul deschis răspunde 400; a răspuns ${bare.status}`);
  });
});

test("configurația livrată închide /_next/image: 404, nu o imagine, nu o eroare de parametri", async () => {
  // Importă FIȘIERUL real, nu o copie a lui: ce citește Next aici e ce citește
  // pe găzduire. Reintroduci defectul scoțând `images: { unoptimized: true }`
  // din `next.config.mjs` — și ruta de mai jos începe să dea 200.
  const source = `export { default } from ${JSON.stringify(pathToFileURL(REAL_CONFIG).href)};\n`;
  await withDevServer(source, async ({ get }) => {
    // Un fișier static se servește în continuare: serverul funcționează și
    // `public/` nu a fost luat odată cu ruta.
    const asset = await get("/probe.png");
    assert.equal(asset.status, 200);

    const image = await get(IMAGE_URL);
    assert.equal(image.status, 404,
      `/_next/image a răspuns HTTP ${image.status} (${image.type}) pe un PNG valid: ` +
      "optimizatorul de imagini e din nou deschis, iar `sharp` primește intrare de la " +
      "oricine");
    assert.ok(!image.type.startsWith("image/"),
      "ruta a întors o imagine: a trecut prin `sharp`");

    // Fără parametri, un handler viu răspunde 400 („url” lipsește). 404 înseamnă
    // că nici măcar validarea nu mai e atinsă.
    const bare = await get("/_next/image");
    assert.equal(bare.status, 404,
      `/_next/image fără parametri a răspuns ${bare.status}; închis înseamnă 404`);
  });
});
