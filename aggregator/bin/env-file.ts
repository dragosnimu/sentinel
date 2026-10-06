/**
 * Încărcarea fișierului de mediu al operatorului (`aggregator/.env.local`),
 * înaintea oricărei unelte de linie de comandă.
 *
 * ## Ce s-a stricat fără ea
 *
 * Niciun script `npm run ...` nu citea fișierul. Operatorul a rulat exact ce
 * spunea README-ul — `npm run user -- enroll-totp dragos` — și a primit
 * `SENTINEL_SESSION_SECRET lipsește (sau e goală)`, urmat de o explicație lungă,
 * corectă și, în cazul ăsta, înșelătoare: variabila stătea în `.env.local` de la
 * început, iar nimic nu o citise. Mesajul numea efectul (lipsește din MEDIU) ca
 * pe o cauză (n-ai pus-o nicăieri).
 *
 * ## De ce nu `--env-file` simplu
 *
 *   * pe Node 20 (găzduirea) și pe Node 24 (stația) un `--env-file` cu fișier
 *     lipsă iese cu `node: .env.local: not found`, cod 9 — un text care nu spune
 *     nimic despre ce variabile lipsesc sau de ce contează. `--env-file-if-exists`
 *     există abia din Node 22;
 *   * un fișier salvat de PowerShell 5 cu `>` e UTF-16. Parserul Node nu se
 *     plânge: citește gunoi, nu găsește nicio variabilă, iar eroarea de mai
 *     târziu spune „lipsește" — exact aceeași îndrumare greșită ca mai sus. Un
 *     BOM UTF-8 e mai rău: lipește `﻿` de prima cheie, deci prima variabilă
 *     din fișier devine o variabilă cu ALT NUME, fără nicio eroare;
 *   * mediul shellului câștigă în fața fișierului (la fel ca la `--env-file`),
 *     iar câștigul tăcut e o capcană: operatorul rotește un secret în fișier, un
 *     `export` vechi din sesiune rămâne în picioare, iar uneltele rulează cu
 *     valoarea veche. Un fișier de pe disc nu e dovadă că a fost încărcat.
 *
 * ## Ce face
 *
 *   * fișier implicit lipsă: continuă (variabilele pot veni din shell) și SPUNE
 *     că nu l-a găsit, ca eroarea următoare — cea precisă, în română, a lui
 *     `lib/env.ts` — să se citească în contextul potrivit;
 *   * fișier cerut explicit (`SENTINEL_ENV_FILE`) și lipsă: eroare, nu
 *     continuare — cine a numit un fișier vrea ACEL fișier;
 *   * fișier ilizibil, UTF-16, cu octeți nuli sau care nu e UTF-8 valid: eroare.
 *     „Nu pot citi" nu e „n-are nimic";
 *   * o variabilă din fișier acoperită de o valoare DIFERITĂ din mediu, și o
 *     cheie scrisă de două ori în fișier, se raportează PE NUME. Valorile nu se
 *     tipăresc niciodată, nici măcar în eroare.
 *
 * Nimic din fișierul ăsta nu scrie pe disc, nu cheamă rețeaua și nu citește
 * `argv`.
 */

import { readFileSync } from "node:fs";
import util from "node:util";

export const DEFAULT_ENV_FILE = ".env.local";

/** Numele variabilei prin care operatorul indică ALT fișier. Un nume dat
 *  explicit trebuie să existe. */
export const ENV_FILE_VARIABLE = "SENTINEL_ENV_FILE";

export type EnvTarget = Record<string, string | undefined>;

export type EnvFileResult =
  | {
      state: "loaded";
      file: string;
      /** Numele definite în fișier. */
      names: string[];
      /** Cele puse efectiv în mediu. */
      applied: string[];
      /** Din fișier, dar acoperite de o valoare DIFERITĂ din mediu. */
      shadowed: string[];
      /** Scrise de mai multe ori în fișier; parserul ia ultima. */
      duplicated: string[];
    }
  | { state: "absent"; file: string }
  | { state: "failed"; file: string; detail: string };

export type LoadOptions = {
  /** Calea absolută. */
  file: string;
  /** Numit de operator (true) sau fișierul implicit (false). */
  explicit: boolean;
  /** Unde se pun variabilele: `process.env` în producție. */
  env: EnvTarget;
};

// Aceeași formă pe care o recunoaște parserul Node pentru o atribuire: un nume,
// `=`, opțional precedat de `export`. Numără apariții, nu parsează valori — un
// rând dintr-o valoare pe mai multe linii care seamănă a atribuire dă cel mult o
// avertizare de prisos, niciodată o valoare greșită.
const ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=/;

function duplicatedNames(text: string): string[] {
  const seen = new Map<string, number>();
  for (const line of text.split(/\r\n|\r|\n/)) {
    const match = ASSIGNMENT.exec(line);
    if (match) seen.set(match[1], (seen.get(match[1]) ?? 0) + 1);
  }
  return [...seen].filter(([, count]) => count > 1).map(([name]) => name);
}

export function loadEnvFile(options: LoadOptions): EnvFileResult {
  const { file, explicit, env } = options;
  const fail = (detail: string): EnvFileResult => ({ state: "failed", file, detail });

  if (typeof util.parseEnv !== "function") {
    return fail(`Node ${process.version} nu are \`util.parseEnv\` (cere 20.12 sau ` +
                "mai nou), deci fișierul nu se poate citi. Nu se continuă fără el: " +
                "variabilele din el ar lipsi, iar eroarea de mai târziu ar spune " +
                "doar „lipsește”.");
  }

  let bytes: Buffer;
  try {
    bytes = readFileSync(file);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return explicit
        ? fail("fișierul cerut prin " + ENV_FILE_VARIABLE + " nu există.")
        : { state: "absent", file };
    }
    return fail(`nu se poate citi (${code ?? "eroare necunoscută"}). „Nu pot ` +
                "citi” nu e „nu conține nimic”, deci nu se continuă.");
  }

  const utf16 = (bytes[0] === 0xff && bytes[1] === 0xfe) ||
                (bytes[0] === 0xfe && bytes[1] === 0xff);
  if (utf16 || bytes.includes(0)) {
    return fail("pare salvat UTF-16 (sau e binar): conține octeți nuli. Asta se " +
                "întâmplă când PowerShell 5 scrie cu `>`. Parserul ar citi gunoi " +
                "și n-ar găsi nicio variabilă. Salvează-l UTF-8 " +
                "(`Set-Content -Encoding utf8` sau un editor).");
  }

  let text: string;
  try {
    // `TextDecoder` taie singur un BOM UTF-8 de la început (`ignoreBOM` e fals
    // implicit) — exact ce trebuie, fiindcă altfel prima cheie ar purta `﻿`.
    // `fatal`: un fișier cp1252 cu o diacritică într-o parolă ar deveni, fără el,
    // o parolă cu caracterul de înlocuire, adică alta, fără nicio eroare.
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return fail("nu e UTF-8 valid (probabil salvat în cp1252). O valoare cu " +
                "diacritice ar fi citită ca alta, fără nicio eroare. " +
                "Salvează-l UTF-8.");
  }

  const parsed = util.parseEnv(text);
  const names = Object.keys(parsed);
  const applied: string[] = [];
  const shadowed: string[] = [];
  for (const name of names) {
    const value = parsed[name];
    const current = env[name];
    if (current !== undefined) {
      // Mediul câștigă, chiar și gol. Doar o diferență se raportează: aceeași
      // valoare în ambele locuri nu înșală pe nimeni.
      if (current !== value) shadowed.push(name);
      continue;
    }
    env[name] = value;
    applied.push(name);
  }
  return { state: "loaded", file, names, applied, shadowed,
           duplicated: duplicatedNames(text) };
}

/**
 * Ce se spune operatorului, și dacă se continuă. Toate pe `stderr`: ieșirea
 * uneltelor trebuie să rămână redirecționabilă. Doar NUME de variabile, niciodată
 * valori.
 */
export function reportFor(result: EnvFileResult): { lines: string[]; fatal: boolean } {
  const tag = "[env]";
  if (result.state === "failed") {
    return {
      fatal: true,
      lines: [`${tag} EȘUAT: ${result.file} — ${result.detail}`],
    };
  }
  if (result.state === "absent") {
    return {
      fatal: false,
      lines: [`${tag} ${result.file} nu există: variabilele se iau doar din ` +
              "mediul shellului. Dacă lipsește vreuna, eroarea de mai jos o numește."],
    };
  }
  const lines: string[] = [];
  if (result.names.length === 0) {
    lines.push(`${tag} ${result.file} nu definește nicio variabilă (gol, doar ` +
               "comentarii, sau rânduri fără `NUME=valoare`).");
  }
  if (result.shadowed.length) {
    lines.push(`${tag} ATENȚIE: ${result.shadowed.join(", ")} — din ${result.file} ` +
               "NU s-a aplicat: mediul shellului are altă valoare și câștigă. " +
               "Scoate variabila din shell (`unset NUME` / `Remove-Item Env:NUME`) " +
               "sau din fișier, ca să știi care valoare rulează.");
  }
  if (result.duplicated.length) {
    lines.push(`${tag} ATENȚIE: ${result.duplicated.join(", ")} — scrisă de mai ` +
               `multe ori în ${result.file}; se ia ULTIMA.`);
  }
  return { lines, fatal: false };
}
