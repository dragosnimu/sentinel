/**
 * Încărcarea lui `.env.local` — de ce stă în spatele fiecărui `npm run`, și ce
 * face când fișierul nu e cum trebuie.
 *
 * ## Ce se strică fără ea, pe rând
 *
 *   * **niciun script nu citește fișierul.** Operatorul rulează exact comanda din
 *     README și primește „`SENTINEL_SESSION_SECRET` lipsește”, cu o explicație
 *     lungă și corectă despre ce înseamnă variabila — iar variabila stă în
 *     `.env.local` de la început. Cauza (nimeni n-a citit fișierul) e prezentată
 *     ca altceva (n-ai pus variabila). Probat pe cele șase comenzi REALE din
 *     `package.json`, nu pe un script care seamănă cu ele;
 *   * **un fișier salvat de PowerShell 5** (`>`) e UTF-16: parserul Node citește
 *     gunoi, nu găsește nicio variabilă, iar eroarea de mai târziu spune iar
 *     „lipsește”. Un BOM UTF-8 e mai rău: prima variabilă din fișier devine una
 *     cu ALT NUME, fără nicio eroare;
 *   * **shellul acoperă tăcut fișierul.** Operatorul rotește un secret în fișier,
 *     un `export` vechi rămâne în sesiune, uneltele rulează cu valoarea veche;
 *   * **un fișier cerut explicit care nu există** nu are voie să cadă pe unul
 *     implicit: cine a numit un fișier vrea ACEL fișier.
 *
 * ## Ce NU probează
 *
 * Că `npm run` pe găzduire (Node 20) se poartă la fel: aici rulează Node 24, iar
 * cele șase scripturi nu rulează pe găzduire. `util.parseEnv` există din Node
 * 20.12; sub el încărcătorul refuză, nu continuă (ramura nu e probată — n-am un
 * Node mai vechi). Nici fișierul REAL al operatorului: probele folosesc fișiere
 * de probă, ca nicio comandă să nu ajungă la baza de date reală.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  DEFAULT_ENV_FILE, ENV_FILE_VARIABLE, loadEnvFile, reportFor,
} from "../bin/env-file";
import type { EnvFileResult, EnvTarget } from "../bin/env-file";
import { ROOT } from "./shipped-files";

/** O valoare care NU are voie să apară în nicio ieșire a încărcătorului. */
const SECRET_VALUE = "valoare-secreta-care-nu-se-tipareste-9f3a";

const OPERATOR_SCRIPTS = [
  "migrate", "user", "instance", "verify-chain", "purge-automation",
  "relink-session-commands",
];
const NOT_OPERATOR_SCRIPTS = ["dev", "build", "start", "test", "typecheck",
                              "generate-migrations-manifest"];

const scripts: Record<string, string> =
  JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8")).scripts;

function scratch(): string {
  return mkdtempSync(path.join(os.tmpdir(), "sentinel-env-"));
}

function fixture(name: string, content: string | Buffer): string {
  const file = path.join(scratch(), name);
  writeFileSync(file, content);
  return file;
}

function load(file: string, env: EnvTarget = {}, explicit = false): EnvFileResult {
  return loadEnvFile({ file, explicit, env });
}

function loaded(result: EnvFileResult) {
  assert.equal(result.state, "loaded", JSON.stringify(result));
  return result as Extract<EnvFileResult, { state: "loaded" }>;
}

/** Mediul unui copil, fără nicio variabilă a proiectului: valorile reale ale
 *  operatorului n-au voie să se amestece în ce se măsoară. */
function cleanEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(AGGREGATOR_|SENTINEL_)/i.test(key)) delete env[key];
  }
  return { ...env, ...extra };
}

// ---------------------------------------------------------------------------
// Fiecare comandă reală încarcă fișierul
// ---------------------------------------------------------------------------
for (const name of OPERATOR_SCRIPTS) {
  test(`\`npm run ${name}\` încarcă fișierul de mediu înaintea uneltei`, () => {
    // Eșecul pe care îl previne: scriptul chemat exact ca în README nu vede
    // nimic din `.env.local`. Comanda e CEA din `package.json`, cu `bin/<unealta>`
    // înlocuit de un copil care tipărește mediul — deci se probează efectul
    // (variabila e în mediu), nu prezența unui steag în text.
    const original = scripts[name];
    assert.ok(original, `scriptul ${name} nu mai există în package.json`);
    const probe = original.replace(/ bin\/[\w-]+\.ts$/, " tests/env-probe.ts");
    assert.notEqual(probe, original,
                    `comanda lui ${name} nu se termină cu bin/<unealta>.ts: ${original}`);

    const file = fixture("mediu.env", "SENTINEL_PROBE_VAR=din-fisier\n");
    const run = spawnSync(probe, {
      shell: true, cwd: ROOT, encoding: "utf8",
      env: cleanEnv({ [ENV_FILE_VARIABLE]: file }),
    });
    assert.equal(run.status, 0, run.stderr + run.stdout);
    assert.deepEqual(JSON.parse(run.stdout), { probe: "din-fisier", other: null },
                     `comanda ${name} nu a încărcat fișierul: ${run.stdout} ${run.stderr}`);
  });
}

test("scripturile care nu sunt unelte de operator NU încarcă fișierul de mediu", () => {
  // Eșecul pe care îl previne: `build`, `start`, `test` sau `typecheck` cu
  // `--env-file`. Un fișier cu secretele de producție ar intra în mediul unui
  // build sau al suitei de teste — iar pe găzduire `start` rulează cu mediul
  // panoului, nu cu fișierul unei stații. Pe text, fiindcă efectul („nu se
  // încarcă”) nu se poate proba fără a rula `next build`.
  for (const name of NOT_OPERATOR_SCRIPTS) {
    const command = scripts[name];
    assert.ok(command, `scriptul ${name} nu mai există`);
    assert.ok(!/env-file|preload-env/.test(command),
              `\`${name}\` încarcă un fișier de mediu: ${command}`);
  }
});

test("fiecare comandă `npm run X` documentată există în package.json", () => {
  // Eșecul pe care îl previne: README-ul sau un mesaj de eroare care cere o
  // comandă ce nu merge. Exact asta a trimis operatorul să caute un secret
  // „lipsă” care era în fișier. Recensământul numără și ce a găsit: un tipar care
  // n-ar potrivi nimic ar trece verde.
  const sources = ["README.md", "bin/user.ts", "bin/instance.ts", "bin/migrate.ts",
                   "bin/verify-chain.ts", "bin/purge-automation-commands.ts",
                   "bin/relink-session-commands.ts", "lib/auth/accounts.ts",
                   "lib/register.ts"];
  let seen = 0;
  for (const source of sources) {
    const text = readFileSync(path.join(ROOT, source), "utf8");
    for (const match of text.matchAll(/npm run ([a-z][a-z-]*)/g)) {
      seen++;
      assert.ok(match[1] in scripts,
                `${source} cere \`npm run ${match[1]}\`, care nu există`);
    }
  }
  assert.ok(seen > 30, `doar ${seen} comenzi găsite — recensământul nu citește ce trebuie`);
  // Și nicio documentație nu cere unealta fără cârlig, direct prin node.
  const readme = readFileSync(path.join(ROOT, "README.md"), "utf8");
  assert.ok(!/node --import tsx bin\//.test(readme),
            "README-ul cere o unealtă prin `node --import tsx bin/...`, fără cârlig");
});

// ---------------------------------------------------------------------------
// Capăt la capăt, cu comanda reală a operatorului
// ---------------------------------------------------------------------------
function npmUser(extraEnv: Record<string, string>): { out: string; status: number | null } {
  // `enroll-totp` citește secretul de sesiune ÎNAINTE de conexiune, iar conexiunea
  // citește configurația bazei ÎNAINTE de rețea: deci fără nicio variabilă de
  // bază, ultima eroare posibilă e cea de configurație și nu se atinge niciun
  // server. NICIODATĂ cu fișierul real al operatorului: `SENTINEL_ENV_FILE` e
  // mereu un fișier de probă, iar mediul copilului nu poartă nicio variabilă
  // `AGGREGATOR_*` a operatorului.
  const run = spawnSync("npm run user -- enroll-totp proba", {
    shell: true, cwd: ROOT, encoding: "utf8", env: cleanEnv(extraEnv),
  });
  return { out: run.stdout + run.stderr, status: run.status };
}

test("`npm run user -- enroll-totp` găsește secretul de sesiune din fișier", () => {
  // Eșecul pe care îl previne, exact cel raportat: comanda din README spune că
  // `SENTINEL_SESSION_SECRET` lipsește deși e în fișier. Dovada că fișierul a
  // fost citit: eroarea NU mai e despre secretul de sesiune, ci despre PRIMA
  // variabilă pe care o cere pasul următor (utilizatorul bazei).
  const file = fixture("mediu.env", `SENTINEL_SESSION_SECRET=${"s".repeat(40)}\n`);
  const run = npmUser({ [ENV_FILE_VARIABLE]: file });
  assert.match(run.out, /AGGREGATOR_DB_USER lipsește/, run.out);
  assert.doesNotMatch(run.out, /SENTINEL_SESSION_SECRET lipsește/, run.out);
  assert.notEqual(run.status, 0);
});

test("fără secretul nicăieri, eroarea precisă a uneltei rămâne, nu una de Node", () => {
  // Eșecul pe care îl previne: înlocuirea mesajului „variabila asta lipsește și
  // iată de ce contează” cu un text de Node. Fișierul există dar n-o definește.
  const file = fixture("mediu.env", "ALTCEVA=1\n");
  const run = npmUser({ [ENV_FILE_VARIABLE]: file });
  assert.match(run.out, /SENTINEL_SESSION_SECRET lipsește \(sau e goală\)/, run.out);
  assert.match(run.out, /Din el se derivă cheia cu care sunt cifrate secretele TOTP/,
               "explicația specifică variabilei a dispărut: " + run.out);
  assert.doesNotMatch(run.out, /not found|ERR_|\(node:/, run.out);
});

/** Un pachet în miniatură, în afara depozitului: cele două fișiere ale
 *  cârligului, cu `.env.local` (dacă e dat) lângă „package.json”-ul lui. */
function miniPackage(envLocal: string | null): string {
  const root = scratch();
  mkdirSync(path.join(root, "bin"));
  for (const file of ["preload-env.ts", "env-file.ts"]) {
    copyFileSync(path.join(ROOT, "bin", file), path.join(root, "bin", file));
  }
  if (envLocal !== null) writeFileSync(path.join(root, DEFAULT_ENV_FILE), envLocal);
  return root;
}

/** Cârligul din pachetul în miniatură, ca la `npm run`: `tsx` întâi. `tsx` și
 *  cârligul se dau ca URL-uri `file:` — o cale `C:\...` ar fi luată drept schemă. */
function runWithHook(root: string, cwd: string, env: NodeJS.ProcessEnv) {
  return spawnSync(process.execPath, [
    "--import", pathToFileURL(path.join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href,
    "--import", pathToFileURL(path.join(root, "bin", "preload-env.ts")).href,
    path.join(ROOT, "tests", "env-probe.ts"),
  ], { cwd, encoding: "utf8", env });
}

test("fișierul implicit e cel de lângă pachet, nu cel din directorul curent", () => {
  // Eșecul pe care îl previne: un cârlig care caută `.env.local` relativ la
  // directorul curent. Unealta se poate chema din alt loc (`npm --prefix`, un
  // script de cron), iar atunci ar rula fără nicio variabilă, fără nicio eroare
  // despre fișier. Directorul curent are DINADINS propriul `.env.local`, cu altă
  // valoare, ca „n-a găsit nimic” să nu poată trece drept „a găsit ce trebuie”.
  const root = miniPackage("SENTINEL_PROBE_VAR=de-langa-pachet\n");
  const elsewhere = scratch();
  writeFileSync(path.join(elsewhere, DEFAULT_ENV_FILE), "SENTINEL_PROBE_VAR=din-cwd\n");
  const run = runWithHook(root, elsewhere, cleanEnv());
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { probe: "de-langa-pachet", other: null },
                   run.stderr);
});

test("fișierul implicit lipsește: unealta rulează și SPUNE că nu l-a găsit", () => {
  // Eșecul pe care îl previne: o clonă proaspătă (fără `.env.local`) care pică cu
  // `node: .env.local: not found`, sau, invers, una care continuă tăcută și lasă
  // eroarea de configurație să pară că vine de nicăieri. Variabila din shell
  // rămâne bună, iar nota vine pe `stderr`.
  const root = miniPackage(null);
  const run = runWithHook(root, ROOT, cleanEnv({ SENTINEL_PROBE_VAR: "din-shell" }));
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { probe: "din-shell", other: null });
  assert.match(run.stderr, /\.env\.local nu există/, run.stderr);
});

test("un fișier cerut explicit și lipsă OPREȘTE unealta, înainte de orice altceva", () => {
  // Eșecul pe care îl previne: un `SENTINEL_ENV_FILE` cu o greșeală de tastare după
  // care unealta pornește oricum, cu mediul gol sau cu alte valori, și îi cere
  // operatorului o variabilă „lipsă”. Cârligul trebuie să iasă nenul, cu mesajul
  // lui, iar copilul (unealta) să nu apuce să ruleze.
  const root = miniPackage(null);
  const missing = path.join(scratch(), "nu-exista.env");
  const run = runWithHook(root, ROOT, cleanEnv({ [ENV_FILE_VARIABLE]: missing }));
  assert.equal(run.status, 1, run.stderr + run.stdout);
  assert.equal(run.stdout, "", "unealta a rulat deși fișierul cerut lipsește");
  assert.match(run.stderr, /EȘUAT/, run.stderr);
});

// ---------------------------------------------------------------------------
// Logica, pe fișiere reale
// ---------------------------------------------------------------------------
test("valorile din fișier ajung în mediu, cu CRLF și ghilimele tratate", () => {
  // Eșecul pe care îl previne: un `\r` rămas la capătul unei parole dintr-un fișier
  // salvat cu CRLF (cazul normal pe Windows) — autentificare refuzată pe o parolă
  // corectă, fără nimic care să spună de ce.
  const file = fixture("crlf.env", "A=unu\r\nB=\"doi cu spatiu\"\r\nexport C=trei\r\n");
  const env: EnvTarget = {};
  const result = loaded(load(file, env));
  assert.deepEqual(env, { A: "unu", B: "doi cu spatiu", C: "trei" });
  assert.deepEqual([...result.applied].sort(), ["A", "B", "C"]);
  assert.deepEqual(result.shadowed, []);
});

test("un BOM UTF-8 nu schimbă numele primei variabile", () => {
  // Eșecul pe care îl previne: PowerShell (`Out-File -Encoding utf8` în 5.1) scrie
  // un BOM, iar parserul Node îl lipește de prima cheie: variabila devine
  // `\uFEFFPRIMA`, adică ALTA, fără nicio eroare — iar mesajul de mai târziu ar
  // spune „lipsește”.
  const file = fixture("bom.env", Buffer.concat([
    Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("PRIMA=valoare\nA_DOUA=x\n")]));
  const env: EnvTarget = {};
  loaded(load(file, env));
  assert.equal(env.PRIMA, "valoare", JSON.stringify(Object.keys(env)));
});

test("un fișier UTF-16 sau cu octeți nuli e REFUZAT, nu citit ca gol", () => {
  // Eșecul pe care îl previne: `PowerShell 5 > .env.local` scrie UTF-16. Citit ca
  // UTF-8 nu dă nicio variabilă și nicio eroare, iar unealta spune apoi
  // „lipsește” despre o variabilă care e în fișier.
  const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]),
                               Buffer.from("A=1\n", "utf16le")]);
  for (const bytes of [utf16, Buffer.from("A=1\0\n")]) {
    const env: EnvTarget = {};
    const result = load(fixture("u16.env", bytes), env);
    assert.equal(result.state, "failed", JSON.stringify(result));
    assert.deepEqual(env, {}, "o valoare a fost pusă în mediu din fișier refuzat");
    assert.equal(reportFor(result).fatal, true);
  }
});

test("un fișier care nu e UTF-8 valid e refuzat", () => {
  // Eșecul pe care îl previne: o parolă cu diacritice, salvată în cp1252, citită
  // cu caracterul de înlocuire în loc de literă — altă parolă, fără eroare.
  const file = fixture("cp1252.env", Buffer.from([0x50, 0x3d, 0x63, 0xe9, 0x0a]));
  const result = load(file);
  assert.equal(result.state, "failed", JSON.stringify(result));
});

test("o cale care nu se poate citi e eroare, nu «fișier lipsă»", () => {
  // Eșecul pe care îl previne: `EACCES`/`EISDIR` tratate ca `ENOENT`. „Nu pot
  // citi” nu e „nu conține nimic”: unealta ar continua fără variabilele din
  // fișier. Un DIRECTOR în locul fișierului dă `EISDIR` pe orice sistem.
  const result = load(scratch());
  assert.equal(result.state, "failed", JSON.stringify(result));
  assert.equal(reportFor(result).fatal, true);
});

test("fișierul implicit lipsă continuă; cel cerut explicit lipsă oprește", () => {
  // Eșecul pe care îl previne: un `SENTINEL_ENV_FILE` cu o greșeală de tastare care
  // cade în tăcere pe mediul gol (sau pe alt fișier).
  const missing = path.join(scratch(), "nu-exista.env");
  const implicit = load(missing, {}, false);
  assert.equal(implicit.state, "absent");
  assert.equal(reportFor(implicit).fatal, false);
  const explicit = load(missing, {}, true);
  assert.equal(explicit.state, "failed");
  assert.equal(reportFor(explicit).fatal, true);
});

test("mediul shellului câștigă, iar diferența se spune pe NUME", () => {
  // Eșecul pe care îl previne: operatorul rotește un secret în fișier, un
  // `export` vechi rămâne în sesiune, iar uneltele rulează cu valoarea veche. Un
  // fișier pe disc nu e dovadă că a fost încărcat. Valoarea nu se tipărește.
  const file = fixture("m.env", `ROTIT=${SECRET_VALUE}\nIDENTIC=la-fel\nNOU=n\n`);
  const env: EnvTarget = { ROTIT: "valoarea-veche-din-shell", IDENTIC: "la-fel" };
  const result = loaded(load(file, env));
  assert.equal(env.ROTIT, "valoarea-veche-din-shell", "fișierul a acoperit mediul");
  assert.equal(env.NOU, "n");
  assert.deepEqual(result.shadowed, ["ROTIT"], "doar diferența se raportează");
  const text = reportFor(result).lines.join("\n");
  assert.match(text, /ROTIT/);
  assert.ok(!text.includes(SECRET_VALUE) && !text.includes("valoarea-veche"),
            "o valoare a ajuns în mesaj: " + text);
});

test("o variabilă din shell setată GOALĂ tot câștigă, ca la --env-file", () => {
  // Fixează semantica în loc s-o lase la voia întâmplării: `--env-file` nu
  // acoperă o variabilă prezentă în mediu, nici goală. Dacă aici s-ar schimba,
  // două feluri de a încărca același fișier ar da valori diferite.
  const file = fixture("g.env", "GOALA=din-fisier\n");
  const env: EnvTarget = { GOALA: "" };
  const result = loaded(load(file, env));
  assert.equal(env.GOALA, "");
  assert.deepEqual(result.shadowed, ["GOALA"]);
});

test("o cheie scrisă de două ori se raportează; se ia ultima", () => {
  // Eșecul pe care îl previne: `AGGREGATOR_DB_HOST` scris de două ori într-un
  // fișier real (găzduirea, apoi de-afară), cu valori posibil diferite — alege
  // tăcut una dintre ele, iar operatorul nu știe care.
  const file = fixture("d.env", "HOST=prima\nOK=1\nHOST=ultima\n");
  const env: EnvTarget = {};
  const result = loaded(load(file, env));
  assert.equal(env.HOST, "ultima");
  assert.deepEqual(result.duplicated, ["HOST"]);
  const text = reportFor(result).lines.join("\n");
  assert.match(text, /HOST/);
  assert.ok(!text.includes("prima") && !text.includes("ultima"), text);
});

test("un fișier fără nicio variabilă se spune, nu se tratează ca reușit", () => {
  // Eșecul pe care îl previne: un `.env.local` gol sau doar cu comentarii (sau cu
  // rânduri fără `=`) raportat ca „încărcat”.
  const result = loaded(load(fixture("gol.env", "# nimic aici\n\nfara egal\n")));
  assert.deepEqual(result.names, []);
  assert.match(reportFor(result).lines.join("\n"), /nu definește nicio variabilă/);
});

test("niciun mesaj al încărcătorului nu poartă o valoare din fișier", () => {
  // Eșecul pe care îl previne: secretul operatorului în ieșirea unei unelte, deci
  // într-un jurnal sau într-o captură de ecran. Toate formele de raport, cu
  // aceeași valoare în fișier — iar un control pozitiv: raportul chiar are
  // conținut, ca „nu conține valoarea” să nu fie „nu conține nimic”.
  const file = fixture("v.env", `S=${SECRET_VALUE}\nS=${SECRET_VALUE}x\n`);
  const results = [
    load(file, { S: "altceva" }),
    load(file, {}),
    load(fixture("v16.env", Buffer.from([0xff, 0xfe, 0x53])), {}),
    load(path.join(scratch(), "lipsa.env"), {}, true),
  ];
  for (const result of results) {
    const lines = reportFor(result).lines;
    assert.ok(lines.length > 0 || result.state === "loaded", JSON.stringify(result));
    assert.ok(!JSON.stringify(lines).includes(SECRET_VALUE), JSON.stringify(lines));
  }
  assert.ok(reportFor(results[0]).lines.length > 0, "raportul de control e gol");
});

test("cârligul nu scrie pe disc și nu citește argv", () => {
  // Proprietate a DEPOZITULUI, pe text — și se spune pe față: nu prinde un apel
  // ascuns în spatele altui nume. Prinde calea scrisă din greșeală: un jurnal al
  // valorilor încărcate sau o copie a fișierului de secrete.
  for (const file of ["bin/env-file.ts", "bin/preload-env.ts"]) {
    const text = readFileSync(path.join(ROOT, file), "utf8");
    assert.ok(text.length > 1000, `${file} pare gol`);
    for (const forbidden of ["writeFile", "appendFile", "createWriteStream",
                             "process.argv", "console.", "child_process"]) {
      assert.ok(!text.includes(forbidden), `${file} conține ${forbidden}`);
    }
  }
});
