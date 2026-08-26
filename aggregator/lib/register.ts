/**
 * Înregistrarea unei instanțe în agregator: cine are voie să trimită, și cu ce cheie.
 *
 * ## Ce lipsea, și de ce ruta era inutilizabilă fără asta
 *
 * `app/api/sentinel/sync/route.ts` caută cheia în tabela `instances`, coloana
 * `ship_secret_enc`. Nimic din depozit nu scria vreodată un asemenea rând, deci
 * pe gazda reală ruta răspundea `500 nu sunt configurat` pentru ORICE instanță,
 * la infinit, iar nicio configurare pe serverul monitorizat nu o schimba.
 *
 * ## Ce se sigilează, exact
 *
 * Valoarea lui `SENTINEL_SHIP_SECRET` din `/etc/sentinel/secrets.env` de pe
 * serverul monitorizat — cheia cu care `sentinel/report/shipper.py` semnează
 * loturile. **Nu** `SENTINEL_BEACON_SECRET`: motivul e la `shipper.py:7-10`, o
 * cheie comună înseamnă că root pe A poate fabrica loturi pentru B, iar
 * separarea aia e chiar proprietatea pentru care există chei per instanță.
 *
 * ## Forma valorii: se REFUZĂ, nu se repară
 *
 * `sentinel/config.py::load_secrets` citește fișierul, taie spațiile de la
 * capete și scoate o pereche de ghilimele care înconjoară valoarea. Deci ce
 * SEMNEAZĂ serverul e forma aia, nu ce a scris omul în fișier. Dacă instrumentul
 * ăsta ar sigila `"abc"` cu ghilimele cu tot, în timp ce serverul semnează cu
 * `abc`, fiecare lot ar primi 401 — imposibil de deosebit de o cheie greșită,
 * la nesfârșit.
 *
 * Nu se normalizează tăcut, se refuză: un instrument care repară e al doilea
 * parser de secrete, de ținut în acord cu primul pentru totdeauna. Refuzul spune
 * CE e în neregulă cu forma (spații, ghilimele) fără să arate valoarea, iar
 * operatorul o corectează într-o secundă.
 *
 * „Aceeași formă" nu e o presupunere despre două limbaje care par să facă același
 * lucru: `str.strip()` și `String.prototype.trim` NU taie aceleași caractere, iar
 * diferența a costat deja o scăpare (vezi `PY_SPACE_CLASS`). Acordul e ținut de
 * `tests/unit/test_aggregator_secret_form.py::test_what_the_tool_seals_is_what_the_server_signs`,
 * care trece un corpus comun prin `load_secrets` REAL și prin funcțiile de aici,
 * și cere ca tot ce acceptă instrumentul să fie octet cu octet ce semnează
 * serverul.
 *
 * ## Ce dovedește succesul
 *
 * Nu că `INSERT`-ul nu a aruncat. După fiecare scriere, secretul se citește
 * înapoi **pe drumul rutei** (`lookupInstanceKey`) și se compară cu ce s-a
 * sigilat. Un rând scris în altă coloană, un AAD greșit, un secret principal
 * diferit între instrument și aplicație — toate ies aici, la înregistrare, în
 * loc să iasă ca 401 sau 500 peste o săptămână, când nimeni nu mai leagă
 * simptomul de comanda asta.
 */

import { timingSafeEqual } from "node:crypto";

import { SHIP_SECRET_FIELD, isValidInstanceId, lookupInstanceKey } from "./ship-keys";
import type { SecretBox } from "./crypto";
import type { Db } from "./migrate";

/**
 * Lungimea minimă a secretului de expediere.
 *
 * Aceeași cifră ca `MIN_MASTER_LENGTH` din `lib/crypto.ts` și din
 * `sentinel/web/security.py`, și din același motiv: sub atât nu e un secret.
 * Cheile generate pentru gazdă se fac cu `openssl rand -hex 32`, adică 64 de
 * caractere, deci limita nu refuză nimic din ce produce procedura.
 *
 * Constrângere pusă de RECEPTOR pe o valoare împărțită cu expeditorul — dar,
 * spre deosebire de plafoanele de lot, o încălcare se vede ACUM, ca un refuz cu
 * mesaj la înregistrare, nu ca un flux oprit definitiv peste săptămâni.
 */
export const MIN_SHIP_SECRET_LENGTH = 32;

/**
 * Cât încape în `ship_secret_enc`, în caractere.
 *
 * `VARCHAR(255)` din `migrations/0001_core.sql`. Măsurat aici: un secret de 64
 * de caractere — forma pe care o produce `openssl rand -hex 32` — dă un jeton de
 * 131; unul de 128 dă 216; unul de 256 dă 387, adică NU încape.
 *
 * Verificat ÎNAINTE de scriere, nu lăsat pe seama bazei, fiindcă la ROTIRE
 * paguba e ireversibilă: un jeton tăiat de MariaDB ar înlocui o cheie
 * funcțională cu una care nu se mai deschide niciodată, iar instanța ar fi
 * moartă până la o a doua rotire. Citirea înapoi ar raporta corect eșecul — dar
 * după ce cheia bună a dispărut.
 */
export const MAX_SEALED_LENGTH = 255;

/** Coloanele arătate de `list`. `ship_secret_enc` NU e printre ele — vezi
 *  `listInstances`. */
export const LIST_COLUMNS =
  "instance_id, label, enabled, ship_secret_set_at, first_seen_at, " +
  "last_batch_at, last_batch_seq";

export const USAGE = `Utilizare:
  npm run instance -- list
  npm run instance -- register <instance_id> [--label "text"]
  npm run instance -- rotate   <instance_id>
  npm run instance -- disable  <instance_id>
  npm run instance -- enable   <instance_id>

Secretul de expediere (SENTINEL_SHIP_SECRET de pe serverul monitorizat) se dă
prin mediu, prin conductă, sau la promptul ascuns — niciodată ca argument.`;

export type ParsedArgv =
  | { ok: true; command: string; id: string; label: string | null }
  | { ok: false; detail: string };

/**
 * Argumentele, verificate strict.
 *
 * Stă în `lib/`, nu în `bin/`, ca să poată fi probată fără să pornească
 * instrumentul: `bin/instance.ts` cheamă `main()` la încărcare, exact ca
 * `bin/migrate.ts`.
 *
 * Un flag scris greșit e o eroare, nu ceva de ignorat: cine a scris `--lable`
 * crede că a pus o etichetă. Un argument pozițional în plus la fel — dacă cineva
 * încearcă totuși să dea secretul pe linia de comandă, trebuie să afle ACUM, cu
 * instrucțiunea de a-l roti, nu după ce valoarea a ajuns în lista de procese și
 * în istoricul shellului.
 */
export function parseArgv(argv: string[]): ParsedArgv {
  const commands = ["list", "register", "rotate", "disable", "enable"];
  const [command, ...rest] = argv;
  if (!command || !commands.includes(command)) {
    return { ok: false, detail: command ? `comandă necunoscută: ${command}` : "" };
  }

  let label: string | null = null;
  const positional: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg === "--label") {
      if (command !== "register") {
        return { ok: false, detail: "--label se dă doar la `register`" };
      }
      const value = rest[++i];
      if (value === undefined) return { ok: false, detail: "--label cere o valoare" };
      label = value;
      continue;
    }
    if (arg.startsWith("--")) return { ok: false, detail: `flag necunoscut: ${arg}` };
    positional.push(arg);
  }

  const wantsId = command !== "list";
  if (wantsId && positional.length !== 1) {
    return {
      ok: false,
      detail: positional.length === 0
        ? `\`${command}\` cere identitatea instanței`
        : `\`${command}\` cere EXACT un argument, am primit ${positional.length}. ` +
          "Dacă al doilea e secretul: nu se dă pe linia de comandă, `argv` se " +
          "vede în lista de procese. Rotește-l imediat dacă tocmai l-ai scris acolo.",
    };
  }
  if (!wantsId && positional.length) {
    return { ok: false, detail: "`list` nu ia argumente" };
  }
  return { ok: true, command, id: positional[0] ?? "", label };
}

/**
 * Ce rupe o linie pentru `str.splitlines()`, adică pentru `load_secrets`.
 *
 * `secrets.env` e un format PE LINII. O valoare care conține oricare dintre
 * caracterele astea ar fi citită de server DOAR până la primul dintre ele, în
 * timp ce instrumentul ar sigila valoarea întreagă — încă o nepotrivire tăcută,
 * din aceeași familie cu cea de spațiu alb.
 *
 * Lista e a lui Python, nu a lui JavaScript: `splitlines()` rupe și la U+000B,
 * U+000C, U+001C–U+001E și U+0085, pe care nimic din JS nu le tratează ca
 * sfârșit de linie. Scrise prin cod, nu ca litere în sursă: un caracter
 * invizibil într-un diff e chiar felul în care se pierde o zi.
 */
const LINE_BREAK_CHARS = [10, 13, 0x0b, 0x0c, 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029]
  .map((code) => String.fromCharCode(code));

export type SecretShape =
  | { ok: true; secret: string }
  | { ok: false; detail: string };

/**
 * Spațiul alb al lui PYTHON (`str.isspace()`), care NU e cel al lui JavaScript.
 *
 * Diferența a fost măsurată, nu presupusă, și cade în amândouă direcțiile:
 *
 *   * Python taie și U+001C–U+001F (separatorii de fișier, grup, înregistrare
 *     și unitate) și U+0085 (NEL). `String.prototype.trim` nu — alea nu sunt
 *     nici `WhiteSpace`, nici `LineTerminator` în ECMAScript;
 *   * JavaScript taie U+FEFF (BOM). Python nu: pentru el nu e spațiu alb.
 *
 * Caracterele sunt scrise prin cod, nu ca octeți în comentariu: unul invizibil
 * într-un diff e chiar felul în care se pierde o zi.
 *
 * Prima direcție e cea periculoasă, și e chiar cea care scăpase: un secret
 * terminat în U+001C trecea de verificarea de formă, se sigila CU el, iar
 * serverul semna FĂRĂ el. Adică 401 la fiecare lot, imposibil de deosebit de o
 * cheie greșită, la nesfârșit.
 *
 * Lista e închisă și scrisă pe față fiindcă e un contract cu alt limbaj; e
 * ținută în acord cu `str.isspace()` de
 * `tests/unit/test_aggregator_secret_form.py::test_what_the_tool_seals_is_what_the_server_signs`,
 * care trece același corpus prin `load_secrets` REAL și prin funcția asta.
 */
const PY_SPACE_CLASS =
  "[\\t\\n\\u000b\\f\\r\\u001c-\\u001f \\u0085\\u00a0\\u1680" +
  "\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const PY_EDGE = new RegExp(`^(?:${PY_SPACE_CLASS})+|(?:${PY_SPACE_CLASS})+$`, "gu");

/**
 * Forma în care `sentinel/config.py::load_secrets` ar citi valoarea asta.
 *
 * Oglindește exact acele două operații, în aceeași ordine: `strip()` cu clasa de
 * spațiu alb a lui Python, apoi scoaterea unei singure perechi de ghilimele
 * identice (`"` sau `'`) care înconjoară restul. Nimic altceva — parserul de
 * acolo nu interpretează escape-uri și nu scoate ghilimele interioare.
 *
 * Se folosește ca DETECTOR, nu ca reparație: dacă rezultatul diferă de intrare,
 * valoarea dată nu e cea pe care ar semna-o serverul.
 */
export function serverSecretForm(raw: string): string {
  const trimmed = raw.replace(PY_EDGE, "");
  if (trimmed.length >= 2 && trimmed[0] === trimmed[trimmed.length - 1]
      && (trimmed[0] === '"' || trimmed[0] === "'")) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/**
 * Secretul e exact ce ar folosi serverul, și e destul de lung.
 *
 * Mesajele descriu forma, NICIODATĂ valoarea: instrumentul ăsta nu tipărește
 * secretul nici la confirmare, nici într-o eroare. Un secret ajuns pe ecran
 * ajunge în scrollback, în captura de ecran a tichetului și în jurnalul
 * terminalului.
 */
export function checkSecretShape(raw: string): SecretShape {
  // `secrets.env` e un format PE LINII: `load_secrets` îl citește cu
  // `splitlines()`, deci dintr-o valoare care conține un sfârșit de linie
  // serverul ar semna doar bucata dinaintea lui. Din conductă nu poate veni
  // (`readShipSecret` taie la prima linie), dar dintr-o variabilă de mediu, da.
  if (LINE_BREAK_CHARS.some((ch) => raw.includes(ch))) {
    return {
      ok: false,
      detail: "valoarea conține un sfârșit de linie. `secrets.env` se citește " +
              "linie cu linie, deci serverul ar semna doar bucata dinaintea lui.",
    };
  }
  const canonical = serverSecretForm(raw);
  if (canonical === "") {
    return { ok: false, detail: "valoarea e goală" };
  }
  // Două comparații, nu una: `serverSecretForm` folosește clasa de spațiu alb a
  // lui PYTHON (ce ar tăia serverul), iar `trim()` pe cea a lui JavaScript.
  // Prima direcție e cea care produce nepotrivirea tăcută; a doua prinde ce ar
  // tăia orice alt cititor (BOM-ul, de pildă) și se refuză tot, fiindcă un
  // caracter invizibil la capătul unei chei e o greșeală de copiere, nu o
  // intenție. Vezi `PY_SPACE_CLASS`.
  if (canonical !== raw || raw.trim() !== raw) {
    return {
      ok: false,
      detail: "valoarea are spații (uneori invizibile) la capete sau e " +
              "înconjurată de ghilimele. Serverul citește secrets.env tăindu-le " +
              "(sentinel/config.py::load_secrets), deci ar semna cu ALTĂ valoare " +
              "decât cea sigilată aici, iar fiecare lot ar primi 401. Dă exact " +
              "valoarea, fără ghilimele și fără spații.",
    };
  }
  if (canonical.length < MIN_SHIP_SECRET_LENGTH) {
    return {
      ok: false,
      detail: `secretul are ${canonical.length} caractere, minimul e ` +
              `${MIN_SHIP_SECRET_LENGTH}. Generează-l cu \`openssl rand -hex 32\`.`,
    };
  }
  return { ok: true, secret: canonical };
}

export type WriteResult =
  | { ok: true; action: "registered" | "rotated" | "enabled" | "disabled"; note?: string }
  | { ok: false; detail: string };

/**
 * Compară secretul citit înapoi cu cel sigilat, fără să scurgă vreunul.
 *
 * În timp constant, ca peste tot unde se compară secrete: aici miza e mică (cine
 * rulează comanda are deja valoarea), dar o comparație obișnuită într-un
 * instrument devine modelul pentru una dintr-o rută.
 */
/**
 * Sigilează, sau spune de ce nu se poate scrie ce a ieșit.
 *
 * Un jeton mai lung decât coloana e respins de MariaDB sub modul strict pe care
 * `lib/db.ts` îl pune pe fiecare sesiune — dar TĂIAT sub oricare altul, iar
 * tăiat nu se mai deschide NICIODATĂ. Refuzul de aici e cel care spune ce e de
 * făcut, și e singurul care nu depinde de ce răspunde serverul: se refuză
 * înainte să atingă baza.
 */
function sealForColumn(
  secret: string, id: string, box: SecretBox,
): { ok: true; sealed: string } | { ok: false; detail: string } {
  const sealed = box.seal(secret, { owner: id, field: SHIP_SECRET_FIELD });
  if (sealed.length > MAX_SEALED_LENGTH) {
    return {
      ok: false,
      detail: `secretul e prea lung: cifrat ar ocupa ${sealed.length} caractere, ` +
              `iar coloana ține ${MAX_SEALED_LENGTH}. Nimic nu a fost scris. ` +
              "Folosește o cheie de 64 de caractere (`openssl rand -hex 32`).",
    };
  }
  return { ok: true, sealed };
}

function sameSecret(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Faptul, nu intenția: secretul scris se deschide pe DRUMUL RUTEI.
 *
 * `lookupInstanceKey` e chiar funcția pe care o cheamă
 * `app/api/sentinel/sync/route.ts`. Verificarea prin ea leagă cele două capete
 * ale sigiliului — dacă AAD-ul, coloana sau secretul principal diferă între
 * instrument și aplicație, se vede ACUM.
 *
 * `ignoreDisabled` pentru rotire: o instanță oprită trebuie să-și poată roti
 * cheia (e chiar ce faci după o compromitere), iar dovada că blobul se deschide
 * nu are legătură cu politica de `enabled`.
 */
async function verifyStoredSecret(
  db: Db, id: string, secret: string, box: SecretBox, ignoreDisabled: boolean,
): Promise<string | null> {
  const found = await lookupInstanceKey(db, id, box, { ignoreDisabled });
  if (!found.ok) {
    return `scrierea a ieșit fără eroare, dar citirea înapoi spune „${found.reason}”.`;
  }
  if (!sameSecret(found.secret, secret)) {
    return "secretul citit înapoi nu e cel sigilat.";
  }
  return null;
}

/**
 * Pune cheia veche la loc după o rotire care nu s-a confirmat, și spune ce a ieșit.
 *
 * Se verifică prin citirea coloanei, nu prin absența unei erori: un `UPDATE` de
 * restaurare care n-a potrivit niciun rând iese tot cu succes, iar atunci
 * mesajul ar liniști pe cineva a cărui instanță e moartă.
 *
 * Se compară textul CIFRAT, nu cel în clar — pe cel vechi nu-l știe nimeni aici,
 * și nici nu trebuie.
 */
async function restorePrevious(
  db: Db, id: string, previous: string | null,
): Promise<string> {
  if (previous === null) {
    return "Nu exista o cheie anterioară de pus la loc, deci instanța rămâne " +
           "fără una utilizabilă.";
  }
  try {
    await db.run("UPDATE instances SET ship_secret_enc = ? WHERE instance_id = ?",
                 [previous, id]);
    // Citirea de confirmare stă în ACELAȘI `try`: dacă baza cade între scriere
    // și citire, „nu știu dacă s-a pus la loc" trebuie să iasă pe ramura de
    // eșec, nu ca excepție care lasă operatorul fără nicio propoziție despre
    // starea rândului.
    if (await readSealed(db, id) !== previous) {
      return "ȘI cheia veche NU a putut fi pusă la loc: instanța NU mai poate " +
             "autentifica până la o rotire reușită.";
    }
  } catch (err) {
    return "ȘI restaurarea cheii vechi nu s-a putut confirma " +
           `(${String((err as Error).message).slice(0, 120)}): instanța poate să NU ` +
           "mai autentifice până la o rotire reușită.";
  }
  return "Cheia veche a fost pusă la loc și verificată — instanța funcționează " +
         "în continuare cu ea.";
}

/** Textul cifrat din coloană, așa cum e. `null` = nu e acolo sau nu e un șir. */
async function readSealed(db: Db, id: string): Promise<string | null> {
  const rows = await db.all(
    "SELECT ship_secret_enc FROM instances WHERE instance_id = ?", [id]);
  if (rows.length !== 1) return null;
  const token = rows[0].ship_secret_enc;
  return typeof token === "string" && token !== "" ? token : null;
}

/**
 * Înregistrează o instanță nouă.
 *
 * O identitate deja înregistrată NU se suprascrie. Cine rulează comanda a doua
 * oară — fiindcă n-a văzut prima ieșire, fiindcă a pierdut terminalul — nu are
 * voie să invalideze o cheie care funcționează. Rotirea e o comandă separată,
 * cerută explicit.
 *
 * Verificarea prealabilă e pentru MESAJ; garanția e cheia unică din schemă,
 * fiindcă între `SELECT` și `INSERT` încape altcineva.
 */
export async function registerInstance(
  db: Db, id: string, secret: string, box: SecretBox, label: string | null = null,
): Promise<WriteResult> {
  if (!isValidInstanceId(id)) return { ok: false, detail: badIdentity(id) };

  const existing = await db.all(
    "SELECT instance_id FROM instances WHERE instance_id = ?", [id]);
  if (existing.length) return { ok: false, detail: alreadyRegistered(id) };

  const sealed = sealForColumn(secret, id, box);
  if (!sealed.ok) return { ok: false, detail: sealed.detail };
  try {
    await db.run(
      "INSERT INTO instances (instance_id, label, enabled, ship_secret_enc, " +
      "ship_secret_set_at) VALUES (?, ?, 1, ?, UTC_TIMESTAMP(6))",
      [id, label, sealed.sealed]);
  } catch (err) {
    // Cheia unică e garanția reală. `SELECT`-ul de mai sus dă mesajul bun în
    // cazul obișnuit; asta prinde cursa.
    if (isDuplicate(err)) return { ok: false, detail: alreadyRegistered(id) };
    throw err;
  }

  const problem = await verifyStoredSecret(db, id, secret, box, false);
  if (problem) {
    // Rândul EXISTĂ acum, cu o cheie care nu se poate folosi. Se spune, fiindcă
    // altfel următoarea comandă a operatorului ar fi `register` din nou, iar aia
    // ar răspunde „e deja înregistrată" — un mesaj corect care ar părea o
    // contrazicere. Nu se șterge rândul: ștergerea nu e o operație a
    // instrumentului ăstuia (vezi `setEnabled`).
    return {
      ok: false,
      detail: `${problem} Rândul a rămas creat, cu o cheie inutilizabilă — ` +
              `corectează cu:\n    npm run instance -- rotate ${id}`,
    };
  }
  return { ok: true, action: "registered" };
}

/**
 * Rotește secretul unei instanțe deja înregistrate.
 *
 * Nu creează nimic: o identitate necunoscută e o eroare care trimite la
 * `register`. Altfel, o literă greșită în identificator ar înregistra tăcut o
 * instanță nouă, iar cea reală ar rămâne cu cheia veche — două rânduri, niciun
 * mesaj, și un flux care nu pornește.
 *
 * ## Dacă scrierea nu se confirmă, cheia veche se pune LA LOC
 *
 * O rotire care eșuează la citirea înapoi lăsa înainte instanța moartă: cheia
 * funcțională fusese deja înlocuită, iar mesajul spunea „nu s-a confirmat
 * nimic" — fals, se făcuse ceva, și anume paguba. `MAX_SEALED_LENGTH` există
 * tocmai fiindcă paguba aia e ireversibilă; simetria se termină aici.
 *
 * Restaurarea se DOVEDEȘTE la rândul ei — se citește coloana înapoi și se cere
 * să fie exact textul cifrat dinainte —, fiindcă altfel ar fi încă o intenție
 * raportată ca efect. Din cele trei stări posibile, mesajul spune limpede pe
 * care o are operatorul: rotire reușită, rotire eșuată cu cheia veche pusă la
 * loc, sau rotire eșuată ȘI restaurare eșuată — ultima e singura în care
 * instanța chiar nu mai poate autentifica.
 */
export async function rotateSecret(
  db: Db, id: string, secret: string, box: SecretBox,
): Promise<WriteResult> {
  if (!isValidInstanceId(id)) return { ok: false, detail: badIdentity(id) };

  const rows = await db.all(
    "SELECT enabled FROM instances WHERE instance_id = ?", [id]);
  if (rows.length !== 1) return { ok: false, detail: notRegistered(id) };
  const disabled = Number(rows[0].enabled) !== 1;

  const sealed = sealForColumn(secret, id, box);
  if (!sealed.ok) return { ok: false, detail: sealed.detail };
  // Textul cifrat de dinainte, citit ÎNAINTE de scriere: e singura copie a
  // cheii vechi, iar după `UPDATE` nu mai există nicăieri.
  const previous = await readSealed(db, id);
  await db.run(
    "UPDATE instances SET ship_secret_enc = ?, ship_secret_set_at = UTC_TIMESTAMP(6) " +
    "WHERE instance_id = ?", [sealed.sealed, id]);

  let problem: string | null;
  try {
    problem = await verifyStoredSecret(db, id, secret, box, disabled);
  } catch (err) {
    // Baza a căzut exact între scriere și citirea înapoi. Nu se restaurează
    // nimic, dinadins: nu se știe dacă scrierea a prins, iar punerea la loc a
    // cheii vechi ar ANULA o rotire care poate a reușit — exact pe dos față de
    // ce vrei după o compromitere. Starea reziduală e benignă (rândul are ori
    // cheia nouă, ori pe cea veche, ambele deschizându-se), dar ramura trebuie
    // s-o SPUNĂ: altfel operatorul vede doar mesajul driverului și nimic despre
    // ce a rămas în bază.
    return {
      ok: false,
      detail: `cheia nouă a fost scrisă, dar citirea înapoi nu s-a putut face ` +
              `(${String((err as Error).message).slice(0, 120)}). Nu s-a pierdut ` +
              `nimic — rândul are ori cheia nouă, ori pe cea veche — dar nu s-a ` +
              `confirmat care. Rulează din nou, cu ACEEAȘI valoare:\n` +
              `    npm run instance -- rotate ${id}`,
    };
  }
  if (problem) {
    return { ok: false, detail: `${problem} ${await restorePrevious(db, id, previous)}` };
  }
  return {
    ok: true,
    action: "rotated",
    // Rotirea a reușit, dar starea rămâne cea de dinainte. Spus pe față, ca
    // nimeni să nu creadă că a repornit fluxul.
    note: disabled
      ? "instanța rămâne DEZACTIVATĂ, deci loturile ei se refuză în continuare " +
        "cu 401. Folosește `enable` când vrei să reia."
      : undefined,
  };
}

/**
 * Pornește sau oprește ingestia pentru o instanță.
 *
 * Semantica e deja definită în `lib/ship-keys.ts` și impusă de rută: `enabled =
 * 0` înseamnă 401 pentru loturile ei, iar istoria rămâne. Aici doar se scrie
 * coloana și se DOVEDEȘTE efectul prin aceeași funcție pe care o cheamă ruta.
 *
 * Nu există ștergere, dinadins: `migrations/0001_core.sql` scrie că oprirea
 * păstrează istoria. Un `DELETE` ar lăsa `audit_entries` cu rânduri ale unei
 * instanțe despre care nimic nu mai spune nimic — iar arhiva e chiar lucrul care
 * nu trebuie să poată fi șters.
 */
export async function setEnabled(
  db: Db, id: string, enabled: boolean, box: SecretBox,
): Promise<WriteResult> {
  if (!isValidInstanceId(id)) return { ok: false, detail: badIdentity(id) };

  const rows = await db.all(
    "SELECT instance_id FROM instances WHERE instance_id = ?", [id]);
  if (rows.length !== 1) return { ok: false, detail: notRegistered(id) };

  await db.run("UPDATE instances SET enabled = ? WHERE instance_id = ?",
               [enabled ? 1 : 0, id]);

  // Efectul, prin drumul rutei: după `disable`, ruta TREBUIE să spună
  // `disabled`; după `enable`, trebuie să dea o cheie care se deschide.
  const found = await lookupInstanceKey(db, id, box);
  if (enabled && !found.ok) {
    return { ok: false, detail:
      `am pornit ingestia, dar ruta tot spune „${found.reason}”. Nu s-a ` +
      "confirmat nimic." };
  }
  if (!enabled && (found.ok || found.reason !== "disabled")) {
    return { ok: false, detail:
      "am oprit ingestia, dar ruta nu o refuză ca dezactivată. Nu s-a " +
      "confirmat nimic." };
  }
  return { ok: true, action: enabled ? "enabled" : "disabled" };
}

/** Ce se poate spune despre cheia unei instanțe fără să se arate. */
export type KeyState = "ok" | "unreadable" | "missing";

export type InstanceSummary = {
  instanceId: string;
  label: string | null;
  enabled: boolean;
  key: KeyState;
  secretSetAt: string | null;
  firstSeenAt: string | null;
  lastBatchAt: string | null;
  lastBatchSeq: number | null;
};

/**
 * Ce e înregistrat. NICIODATĂ secretele.
 *
 * Coloana `ship_secret_enc` se citește — altfel nu s-ar putea spune dacă cheia
 * se mai poate deschide, iar aia e chiar diagnosticul pentru `500 nu sunt
 * configurat` de la rută — dar textul cifrat nu iese din funcția asta: din el
 * rămâne o singură etichetă, `ok` / `unreadable` / `missing`. Un `SELECT *`
 * întors ca atare ar fi ajuns pe ecran, în scrollback și în tichet.
 *
 * `unreadable` e starea care se descoperă altfel abia când un server real
 * încearcă să trimită: secretul principal al agregatorului a fost rotit, sau
 * rândul a fost umblat.
 */
export async function listInstances(db: Db, box: SecretBox): Promise<InstanceSummary[]> {
  const rows = await db.all(
    `SELECT ${LIST_COLUMNS}, ship_secret_enc FROM instances ORDER BY instance_id`);
  return rows.map((row) => {
    const id = String(row.instance_id);
    const token = row.ship_secret_enc;
    let key: KeyState = "missing";
    if (typeof token === "string" && token !== "") {
      key = box.open(token, { owner: id, field: SHIP_SECRET_FIELD }) === null
        ? "unreadable" : "ok";
    }
    return {
      instanceId: id,
      label: row.label === null || row.label === undefined ? null : String(row.label),
      enabled: Number(row.enabled) === 1,
      key,
      secretSetAt: asText(row.ship_secret_set_at),
      firstSeenAt: asText(row.first_seen_at),
      lastBatchAt: asText(row.last_batch_at),
      lastBatchSeq: row.last_batch_seq === null || row.last_batch_seq === undefined
        ? null : Number(row.last_batch_seq),
    };
  });
}

function asText(value: unknown): string | null {
  return value === null || value === undefined ? null : String(value);
}

function isDuplicate(err: unknown): boolean {
  const e = err as { code?: string; errno?: number };
  return e?.code === "ER_DUP_ENTRY" || e?.errno === 1062;
}

function badIdentity(id: string): string {
  // Identificatorul NU se pune în mesaj: valoarea vine din linia de comandă a
  // operatorului, dar mesajul ajunge în terminal și în tichete, iar regula
  // „identitatea nu se scrie decât unde trebuie" e mai ieftin de ținut fără
  // excepții. Lungimea e destulă ca să se vadă un copy-paste rupt.
  return `identificatorul (${id.length} caractere) nu are forma acceptată: ` +
         "începe cu o literă sau cifră, apoi cel mult 63 de caractere din " +
         "[a-zA-Z0-9._-]. E aceeași regulă ca în ruta de sincronizare și la " +
         "martor; un identificator pe care ruta îl refuză înseamnă 401 " +
         "permanent. Valoarea se citește cu: cat /etc/sentinel/instance_id";
}

function alreadyRegistered(id: string): string {
  return `instanța e deja înregistrată. Înregistrarea NU suprascrie o cheie ` +
         `care poate fi funcțională. Dacă chiar vrei altă cheie, cere-o ` +
         `explicit:\n    npm run instance -- rotate ${id}`;
}

function notRegistered(id: string): string {
  return `instanța nu e înregistrată. Dacă e una nouă:\n` +
         `    npm run instance -- register ${id}`;
}
