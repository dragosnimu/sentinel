/**
 * Crearea conturilor panoului, înrolarea celui de-al doilea factor, și
 * repartizarea instanțelor.
 *
 * ## De ce există fișierul ăsta
 *
 * Fiindcă până acum NU EXISTA NICIO CALE de a crea un cont, deci nimeni nu se
 * putea autentifica, deci tot ce s-a construit în piesele 1 și 2 — Argon2id,
 * TOTP, CSRF, cele trei limitatoare, sesiunile cu jeton rotit — nu fusese
 * niciodată parcurs capăt la capăt de nimeni. O apărare care n-a lăsat pe nimeni
 * să treacă prin ea nu e o apărare probată, e o apărare presupusă.
 *
 * ## De ce pe linia de comandă, și nu în panou
 *
 * Același argument ca pe serverul monitorizat
 * (`sentinel/services/web_service.py`): un panou care poate crea conturi și
 * schimba roluri transformă o compromitere a interfeței într-o preluare. Cine
 * fură un cookie capătă atunci dreptul de a-și face un al doilea cont, cu rol
 * `owner`, care supraviețuiește revocării sesiunii furate. Pe linia de comandă,
 * aceleași operații cer acces la găzduire.
 *
 * ## Parola nu vine NICIODATĂ din `argv`
 *
 * `argv` se vede în lista de proceselor altor utilizatori ai găzduirii
 * partajate, rămâne în istoricul shellului și ajunge în copiile de siguranță ale
 * directorului home. Argumentul întreg e în `lib/secret-input.ts`, care are deja
 * mecanica; aici se refolosește, nu se rescrie. `parseUserArgv` REFUZĂ o linie
 * de comandă care conține un argument care arată a parolă, în loc s-o ignore:
 * cine a scris-o o dată a publicat-o deja, și trebuie să afle asta acum, nu
 * după.
 *
 * ## Nimic nu ocolește `hashPassword`
 *
 * `hashPassword` e singura cale prin care o parolă ajunge într-o coloană, și e
 * și singurul loc care aplică `MIN_PASSWORD_LENGTH` / `MAX_PASSWORD_LENGTH`
 * (`verifyPassword` NU le aplică — vezi `lib/auth/password.ts`). Consecința
 * dacă cineva ar scrie un hash pe lângă ea: o parolă de peste 1024 de caractere
 * s-ar stoca, iar la autentificare `lib/auth/login.ts` ar refuza-o pe motiv de
 * lungime ÎNAINTE de orice verificare — adică un 401 permanent, pe un cont cu
 * parola corectă, fără nimic în jurnal care să spună de ce.
 *
 * De-aia ordinea din `createAccount` e hash ÎNTÂI, inserare pe urmă: o parolă
 * refuzată nu lasă în urmă niciun rând, nici măcar unul pe jumătate scris.
 *
 * ## Ce NU face
 *
 * **Nu șterge conturi.** `migrations/0008_auth.sql` spune de ce: `user_instances`
 * n-are cheie străină spre `users`, deci un rând rămas în urmă ar da drepturi
 * unui `user_id` reciclat. Un cont scos din uz se dezactivează.
 *
 * **Nu scrie în `audit_entries`.** Tabela aia e REPLICA jurnalului serverului
 * monitorizat, cu lanț de hash-uri peste ea (`lib/chain.ts`): un rând local
 * inserat în ea ar rupe lanțul, iar verificarea l-ar raporta ca falsificare.
 * Urma operațiilor de aici e `user_instances.granted_by` plus jurnalul
 * procesului. Că agregatorul n-are un jurnal de audit propriu e o lipsă reală,
 * și e scrisă aici ca să fie o decizie, nu o scăpare.
 *
 * **Nu desenează codul QR.** Serverul o face cu `qrcode`; aici ar însemna o
 * dependență nouă pentru o operație care se face de câteva ori în viața unei
 * instalări. Se tipărește URI-ul `otpauth://` și secretul base32 — amândouă se
 * pot lipi de mână în orice aplicație de autentificare.
 */

import { TotpCipher, generateSecret, provisioningUri, verifyCode } from "./totp";
import { hashPassword } from "./password";
import { revokeAllForUser } from "./session";
import {
  MAX_USERNAME_LENGTH, UsernamePolicyError, assertAsciiUsername, findById,
  findByUsername, normalizeUsername, setPasswordHash,
} from "./users";
import { INSTANCE_ROLES } from "./scope";
import { isValidInstanceId } from "../ship-keys";
import { readerFor } from "../secret-input";
import type { AuthDb } from "./db";
import type { ErrorStream, InputStream } from "../secret-input";

/** Ce apare în aplicația de autentificare, lângă numele contului. */
export const TOTP_ISSUER = "Sentinel Aggregator";

/** Cine a făcut operația, în `user_instances.granted_by`. */
const GRANTED_BY = "cli";

export const USAGE =
  "Utilizare:\n" +
  "  npm run user -- create <utilizator> --role owner|operator|viewer [--totp]\n" +
  "  npm run user -- enroll-totp <utilizator>\n" +
  "  npm run user -- drop-totp   <utilizator>\n" +
  "  npm run user -- passwd      <utilizator>\n" +
  "  npm run user -- grant  <utilizator> <instanță> [--role owner|operator|viewer]\n" +
  "  npm run user -- revoke <utilizator> <instanță>\n" +
  "  npm run user -- list\n" +
  "\n" +
  "Parola NU se dă pe linia de comandă: `argv` se vede în lista de procese și\n" +
  "rămâne în istoricul shellului. Se cere la tastatură sau se dă printr-o\n" +
  "conductă:  pass show panou | npm run user -- create ana --role owner\n" +
  "\n" +
  "Fără `--totp`, contul are UN SINGUR factor: parola. Pe găzduire partajată\n" +
  "asta e singurul control care rămâne, fiindcă acolo nu există nftables,\n" +
  "fail2ban de-al nostru sau sandbox systemd.\n" +
  "\n" +
  "CU `--totp`, comanda mai cere ceva DUPĂ parolă: codul din aplicația de\n" +
  "autentificare, pentru confirmarea înrolării — și abia el face al doilea\n" +
  "factor activ. Codul se poate produce doar după ce se afișează secretul,\n" +
  "deci o conductă care se termină odată cu parola nu are cum să-l aducă.\n" +
  "Atunci contul rămâne creat și NECONFIRMAT — adică intră cu parola\n" +
  "singură — iar confirmarea se face separat:\n" +
  "  npm run user -- enroll-totp ana        (dintr-un terminal)";

// ---------------------------------------------------------------------------
// Linia de comandă
// ---------------------------------------------------------------------------
export type UserCommand =
  | { ok: true; command: "create"; username: string; role: string; totp: boolean }
  | { ok: true; command: "enroll-totp"; username: string }
  | { ok: true; command: "drop-totp"; username: string }
  | { ok: true; command: "passwd"; username: string }
  | { ok: true; command: "grant"; username: string; instanceId: string; role: string }
  | { ok: true; command: "revoke"; username: string; instanceId: string }
  | { ok: true; command: "list" }
  | { ok: false; detail: string | null };

/**
 * Argumentele care sunt refuzate din prima, oricare ar fi comanda.
 *
 * Se caută PREFIXUL, nu egalitatea: `--password=ceva` e chiar forma în care
 * cineva ar scrie asta, și e cea care ajunge întreagă în `ps`. Refuzul e
 * zgomotos fiindcă valoarea e deja publicată în momentul în care programul o
 * vede — a o ignora tăcut ar lăsa pe cineva să creadă că n-a pățit nimic.
 */
const FORBIDDEN_ARGS = ["--password", "--parola", "--pass", "--pw", "--secret"];

export function parseUserArgv(argv: string[]): UserCommand {
  for (const arg of argv) {
    for (const forbidden of FORBIDDEN_ARGS) {
      if (arg === forbidden || arg.startsWith(`${forbidden}=`)) {
        return {
          ok: false,
          detail:
            `argumentul \`${forbidden}\` nu e acceptat, și valoarea pe care ai ` +
            "dat-o trebuie considerată compromisă: `argv` e vizibil în lista de " +
            "procese a găzduirii partajate și rămâne în istoricul shellului. " +
            "Parola se cere la tastatură sau vine printr-o conductă.",
        };
      }
    }
  }

  const positional: string[] = [];
  let role: string | null = null;
  let totp = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--role") {
      const value = argv[++i];
      if (value === undefined) return { ok: false, detail: "`--role` fără valoare" };
      role = value;
      continue;
    }
    const inline = /^--role=(.*)$/.exec(arg);
    if (inline) { role = inline[1]; continue; }
    // `--totp` e OPT-IN de pe 19 august 2026. Înainte, înrolarea era impusă de
    // `create` și nu se putea sări. Fanionul nu ia valoare: `--totp=nu` ar
    // părea că oprește ceva, dar ar fi citit ca opțiune necunoscută, iar un
    // refuz e mai bun decât un „nu" care porneşte.
    if (arg === "--totp") { totp = true; continue; }
    if (arg.startsWith("-")) {
      return { ok: false, detail: `opțiune necunoscută: ${arg}` };
    }
    positional.push(arg);
  }

  if (role !== null && !(INSTANCE_ROLES as readonly string[]).includes(role)) {
    return { ok: false,
             detail: `rol necunoscut: ${role} (${INSTANCE_ROLES.join(", ")})` };
  }

  const [command, first, second] = positional;
  if (positional.length > 3) return { ok: false, detail: "prea multe argumente" };

  switch (command) {
    case "create":
      if (!first) return { ok: false, detail: "`create` cere un nume de utilizator" };
      // Rolul e OBLIGATORIU, fără implicit. Un implicit `viewer` ar face ca
      // primul cont al unei instalări să nu poată face nimic, iar unul `owner`
      // ar da rolul cel mai mare unei comenzi tastate în grabă. Nu există o a
      // treia variantă care să nu fie o ghicire despre ce voia cineva.
      if (role === null) {
        return { ok: false, detail: "`create` cere `--role owner|operator|viewer`" };
      }
      return { ok: true, command: "create", username: first, role, totp };
    case "enroll-totp":
      if (!first) return { ok: false, detail: "`enroll-totp` cere un utilizator" };
      return { ok: true, command: "enroll-totp", username: first };
    case "drop-totp":
      if (!first) return { ok: false, detail: "`drop-totp` cere un utilizator" };
      return { ok: true, command: "drop-totp", username: first };
    case "passwd":
      if (!first) return { ok: false, detail: "`passwd` cere un utilizator" };
      return { ok: true, command: "passwd", username: first };
    case "grant":
      if (!first || !second) {
        return { ok: false, detail: "`grant` cere un utilizator și o instanță" };
      }
      return { ok: true, command: "grant", username: first, instanceId: second,
               role: role ?? "viewer" };
    case "revoke":
      if (!first || !second) {
        return { ok: false, detail: "`revoke` cere un utilizator și o instanță" };
      }
      return { ok: true, command: "revoke", username: first, instanceId: second };
    case "list":
      return { ok: true, command: "list" };
    default:
      return { ok: false, detail: command ? `comandă necunoscută: ${command}` : null };
  }
}

// ---------------------------------------------------------------------------
// Citirea parolei
// ---------------------------------------------------------------------------
export type PasswordIo = { stdin?: InputStream; stderr?: ErrorStream };

export type PasswordRead =
  | { ok: true; password: string }
  | { ok: false; detail: string };

/**
 * Parola nouă: de la tastatură (fără ecou, cu repetare) sau de la o conductă.
 *
 * Nu există cale prin mediu, spre deosebire de `readShipSecret`. Diferența e
 * intenționată: secretul de expediere e pus de un script de instalare, care are
 * nevoie de o cale neinteractivă; o parolă de panou o alege un om, iar o
 * variabilă de mediu se moștenește de fiecare proces-copil și se citește din
 * `/proc/<pid>/environ`.
 *
 * Pe conductă nu există repetare — n-ar avea ce compara — și nici nu e nevoie:
 * valoarea vine dintr-un depozit de parole, nu de sub degete.
 *
 * Citirea trece prin `readerFor(stdin)`, nu prin ascultători proprii, și ăsta e
 * miezul: DUPĂ parolă mai citește cineva de pe același flux — codul de
 * confirmare a înrolării, din `bin/user.ts`. Cele două citiri trebuie să
 * împartă un tampon și o stare de curgere, altfel a doua fie atârnă (terminal),
 * fie pierde o valoare deja sosită (conductă). Vezi `lib/secret-input.ts`.
 */
export async function readNewPassword(io: PasswordIo = {}): Promise<PasswordRead> {
  const stdin = io.stdin ?? process.stdin;
  const stderr = io.stderr ?? process.stderr;
  const reader = readerFor(stdin);

  if (stdin.isTTY) {
    const first = await reader.readHidden("Parolă (nu se afișează): ", stderr);
    if (first === null) return { ok: false, detail: "întrerupt" };
    const again = await reader.readHidden("Repetă parola: ", stderr);
    if (again === null) return { ok: false, detail: "întrerupt" };
    if (first !== again) {
      return { ok: false, detail: "parolele nu corespund; nu s-a scris nimic" };
    }
    return { ok: true, password: first };
  }

  const piped = await reader.readLine();
  if (piped === null) {
    return {
      ok: false,
      detail: "nu am de unde lua parola: intrarea nu e un terminal și de la " +
              "intrarea standard nu a venit nimic. Dă-o printr-o conductă " +
              "(`... | npm run user -- create ...`) sau rulează comanda dintr-un " +
              "terminal. Pe linia de comandă NU se poate: `argv` se vede în lista " +
              "de procese.",
    };
  }
  return { ok: true, password: piped };
}

/**
 * O linie obișnuită de la intrare — codul TOTP, care nu e un secret de păstrat.
 *
 * `null` înseamnă „nu mai vine nimic de acolo", și e o stare pe care apelantul
 * TREBUIE s-o deosebească de un cod greșit: pe o conductă care s-a închis după
 * parolă, nicio reîncercare n-o să aducă vreodată un cod. Vezi `bin/user.ts`.
 */
export async function readLine(io: PasswordIo = {}): Promise<string | null> {
  const line = await readerFor(io.stdin ?? process.stdin).readLine();
  return line === null ? null : line.trim();
}

// ---------------------------------------------------------------------------
// Crearea contului
// ---------------------------------------------------------------------------
export type CreateInput = {
  username: string;
  role: string;
  password: string;
  /**
   * `SENTINEL_SESSION_SECRET`; cu el se cifrează secretul TOTP în repaus.
   * Se citește doar când `enrolTotp` e adevărat, deci un cont cu un singur
   * factor se poate crea fără secretul de sesiune în mediu.
   */
  sessionSecret: string;
  /**
   * Al doilea factor e OPȚIONAL de pe 19 august 2026, cerut de operator.
   * Fără fanion nu se generează niciun secret, iar `totp_secret_enc` rămâne
   * `NULL` — exact starea pe care `login()` o citește ca „intră cu parola".
   */
  enrolTotp: boolean;
};

export type Enrolment = {
  userId: number;
  username: string;
  /** Secretul în clar. Se arată O SINGURĂ DATĂ și nu se stochează nicăieri
   *  descifrabil fără `SENTINEL_SESSION_SECRET`. */
  secret: string;
  uri: string;
};

export type AccountResult<T> =
  | { ok: true; value: T }
  | { ok: false; detail: string };

/**
 * Un cont nou, cu secretul TOTP generat și cifrat. NECONFIRMAT încă.
 *
 * Ordinea e ce contează, și fiecare pas e acolo dintr-un motiv:
 *
 *   1. **numele**, validat în cod. `users.username` e `ascii`, iar un nume cu
 *      diacritice e refuzat de MariaDB doar sub `STRICT_TRANS_TABLES` — sub alt
 *      `sql_mode` ar deveni un `?` și un cont pe care nimeni nu-l mai poate
 *      tasta (`lib/auth/users.ts`). Modul strict îl pune `lib/db.ts` pe fiecare
 *      sesiune; validarea de aici e cea care dă un MESAJ, nu o eroare a bazei;
 *   2. **contul existent**, verificat prin citire. `uk_users_username` e
 *      apărarea reală; asta e mesajul omenesc dinaintea ei;
 *   3. **hashul**, ÎNAINTE de orice scriere. O parolă refuzată de politică nu
 *      lasă în urmă niciun rând;
 *   4. **inserarea**, apoi **recitirea**. `AuthDb.write` dă numărul de rânduri
 *      afectate, nu `insertId`, iar un `insertId` presupus ar fi id-ul greșit
 *      pentru cifrarea de la pasul 5. Recitirea e și dovada de efect: un
 *      `INSERT` care raportează succes fără rând e chiar tiparul din `CLAUDE.md`;
 *   5. **secretul TOTP**, cifrat cu `user.id` în AAD — deci nu se poate cifra
 *      înainte ca rândul să existe. Un blob mutat pe alt rând nu se mai deschide.
 *
 * Ce rămâne după: un cont care NU se poate autentifica (`login.ts` cere
 * `totp_confirmed_at`). Confirmarea e `confirmEnrolment`, și cere o dovadă că
 * cineva chiar poate produce un cod din secret.
 */
export async function createAccount(
  db: AuthDb, input: CreateInput,
): Promise<AccountResult<Enrolment | null>> {
  const username = normalizeUsername(input.username);
  if (username === "") return { ok: false, detail: "numele de utilizator e gol" };
  if (input.username.trim().length > MAX_USERNAME_LENGTH) {
    // Tăierea tăcută ar crea un cont cu alt nume decât cel cerut, iar omul l-ar
    // tasta la nesfârșit pe cel scris de el.
    return { ok: false,
             detail: `numele de utilizator depășește ${MAX_USERNAME_LENGTH} de caractere` };
  }
  try {
    assertAsciiUsername(username);
  } catch (err) {
    if (!(err instanceof UsernamePolicyError)) throw err;
    return { ok: false, detail: err.message };
  }
  if (!(INSTANCE_ROLES as readonly string[]).includes(input.role)) {
    return { ok: false, detail: `rol necunoscut: ${input.role}` };
  }
  if (await findByUsername(db, username) !== null) {
    return { ok: false, detail: `utilizatorul ${username} există deja` };
  }

  let passwordHash: string;
  try {
    passwordHash = await hashPassword(input.password);
  } catch (err) {
    // `PasswordPolicyError` — prea scurtă sau peste plafon. Se întoarce ca refuz,
    // nu ca excepție: e o greșeală a operatorului, nu un defect al programului.
    // Și, mai important, se întâmplă ÎNAINTE de orice `INSERT`.
    return { ok: false, detail: (err as Error).message };
  }

  await db.write(
    "INSERT INTO users (username, password_hash, role, disabled, totp_secret_enc, " +
    "                   totp_confirmed_at, totp_last_counter, password_changed_at, " +
    "                   created_at) " +
    "VALUES (?, ?, ?, 0, NULL, NULL, NULL, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
    [username, passwordHash, input.role]);

  const created = await findByUsername(db, username);
  if (created === null) {
    throw new Error(
      `contul ${username} a fost inserat și nu se poate citi înapoi; nu se ` +
      "continuă cu înrolarea unui cont care nu s-a dovedit că există");
  }

  // `null` NU e un eșec: e un cont cu un singur factor, iar cel care apelează
  // trebuie să deosebească „n-am înrolat, așa s-a cerut" de „am înrolat".
  if (!input.enrolTotp) return { ok: true, value: null };

  const enrolment = await freshSecret(db, created.id, username, input.sessionSecret);
  return { ok: true, value: enrolment };
}

/**
 * Un secret TOTP nou pentru un cont care există. Confirmarea se pierde.
 *
 * Se cheamă la reînrolare (dispozitiv pierdut sau înlocuit) și de
 * `createAccount`. `totp_confirmed_at` se pune pe `NULL` DINADINS: până când
 * cineva dovedește că poate produce un cod din secretul NOU, contul nu are un al
 * doilea factor — iar dacă ar rămâne „confirmat", ar cere un cod pe care nu-l
 * mai poate produce nimeni.
 */
async function freshSecret(
  db: AuthDb, userId: number, username: string, sessionSecret: string,
): Promise<Enrolment> {
  const secret = generateSecret();
  const affected = await db.write(
    "UPDATE users SET totp_secret_enc = ?, totp_confirmed_at = NULL, " +
    "                 totp_last_counter = NULL " +
    " WHERE id = ?",
    [new TotpCipher(sessionSecret).encrypt(secret, userId), userId]);
  if (affected !== 1) {
    throw new Error(
      `scrierea secretului TOTP pentru ${username} a atins ${affected} rânduri, ` +
      "nu unul; nu se arată un secret care poate să nu fie stocat");
  }
  return { userId, username, secret,
           uri: provisioningUri(secret, username, TOTP_ISSUER) };
}

export async function enrollTotp(
  db: AuthDb, username: string, sessionSecret: string,
): Promise<AccountResult<Enrolment & { revokedSessions: number }>> {
  const user = await findByUsername(db, normalizeUsername(username));
  if (user === null) return { ok: false, detail: `utilizatorul ${username} nu există` };

  const enrolment = await freshSecret(db, user.id, user.username, sessionSecret);
  // Reînrolarea înseamnă de obicei că dispozitivul vechi s-a pierdut sau a fost
  // compromis. Sesiunile existente s-au deschis cu factorul vechi și n-au voie
  // să-i supraviețuiască.
  const revokedSessions = await revokeAllForUser(db, user.id, "totp-reenrolled");
  return { ok: true, value: { ...enrolment, revokedSessions } };
}

/**
 * Scoate al doilea factor dintr-un cont care există.
 *
 * Există fiindcă schimbarea din 19 august 2026 a lăsat o stare fără ieșire: un
 * cont creat pe vremea când înrolarea era impusă are un secret neconfirmat, iar
 * `login()` refuză exact starea aia — dinadins. Singura reparație era
 * `enroll-totp`, adică fix lucrul pe care operatorul l-a scos. Fără comanda
 * asta, „al doilea factor e opțional" era adevărat doar pentru conturile noi.
 *
 * Verificarea e prin CITIRE ÎNAPOI, nu prin rândurile afectate: un `UPDATE`
 * care pune `NULL` peste `NULL` raportează zero rânduri schimbate, iar o gardă
 * scrisă pe numărul ăla ar transforma o operație deja-făcută într-o eroare.
 *
 * Sesiunile se revocă, ca la reînrolare. Coborârea nivelului de autentificare
 * n-are voie să fie moștenită de o sesiune deschisă sub cel vechi.
 */
export async function dropTotp(
  db: AuthDb, username: string,
): Promise<AccountResult<{
  username: string; revokedSessions: number; hadSecret: boolean;
}>> {
  const user = await findByUsername(db, normalizeUsername(username));
  if (user === null) return { ok: false, detail: `utilizatorul ${username} nu există` };
  const hadSecret = user.totpSecretEnc !== null;

  await db.write(
    "UPDATE users SET totp_secret_enc = NULL, totp_confirmed_at = NULL, " +
    "                 totp_last_counter = NULL " +
    " WHERE id = ?",
    [user.id]);

  const after = await findByUsername(db, user.username);
  if (after === null || after.totpSecretEnc !== null) {
    throw new Error(
      `al doilea factor al lui ${user.username} e ÎNCĂ în bază după ștergere; ` +
      "contul rămâne blocat, și nu se raportează o reparație care nu s-a făcut");
  }

  const revokedSessions = await revokeAllForUser(db, user.id, "totp-dropped");
  return { ok: true, value: { username: user.username, revokedSessions, hadSecret } };
}

/**
 * Parolă nouă pentru un cont care există.
 *
 * Lipsea cu totul până pe 19 august 2026: nici unealta, nici panoul n-aveau
 * vreo cale de schimbare, deci o parolă uitată sau tastată greșit la creare
 * însemna un cont pierdut definitiv. S-a descoperit exact așa — `create` pe un
 * nume existent cere parola, apoi refuză, iar parola tastată NU se aplică; cine
 * n-a citit cu atenție crede că tocmai a pus-o.
 *
 * Hashul se calculează prin `hashPassword`, ca la creare, fiindcă acolo se
 * aplică plafoanele de lungime. O unealtă care și-ar calcula singură hashul ar
 * putea stoca o parolă peste plafon, pe care `login()` o refuză apoi pe lungime,
 * înainte de orice verificare — 401 permanent, pe un cont cu parola corectă.
 *
 * Sesiunile se revocă: o schimbare de parolă înseamnă de obicei că cea veche nu
 * mai e de încredere, iar o sesiune deschisă cu ea n-are voie să-i
 * supraviețuiască.
 */
export async function setPassword(
  db: AuthDb, username: string, password: string,
): Promise<AccountResult<{ username: string; revokedSessions: number }>> {
  const user = await findByUsername(db, normalizeUsername(username));
  if (user === null) return { ok: false, detail: `utilizatorul ${username} nu există` };

  let passwordHash: string;
  try {
    passwordHash = await hashPassword(password);
  } catch (err) {
    // Prea scurtă sau peste plafon: greșeală de operator, nu defect de program,
    // și se întâmplă ÎNAINTE de orice scriere.
    return { ok: false, detail: (err as Error).message };
  }

  await setPasswordHash(db, user.id, passwordHash);

  const after = await findByUsername(db, user.username);
  if (after === null || after.passwordHash !== passwordHash) {
    throw new Error(
      `parola lui ${user.username} NU s-a schimbat în bază; nu se raportează o ` +
      "schimbare care n-a avut loc, fiindcă atunci contul rămâne cu parola veche " +
      "și nimeni nu mai caută cauza");
  }

  const revokedSessions = await revokeAllForUser(db, user.id, "password-changed");
  return { ok: true, value: { username: user.username, revokedSessions } };
}

/**
 * Înrolarea, dusă la capăt: cineva a dovedit că poate produce un cod.
 *
 * Fără pasul ăsta, o scanare întreruptă lasă un cont care CERE un al doilea
 * factor pe care nu-l are nimeni — adică un cont blocat definitiv, pe o găzduire
 * fără altă ușă. De-aia confirmarea nu e un fanion pus de unealtă, ci consecința
 * unui cod verificat.
 *
 * Contorul se scrie odată cu confirmarea: fără el, chiar codul folosit la
 * înrolare ar mai merge o dată, în aceeași fereastră de 30 s.
 */
export async function confirmEnrolment(
  db: AuthDb, userId: number, secret: string, code: string,
): Promise<boolean> {
  const counter = verifyCode(secret, code);
  if (counter === null) return false;

  const affected = await db.write(
    "UPDATE users SET totp_confirmed_at = UTC_TIMESTAMP(6), totp_last_counter = ? " +
    " WHERE id = ?",
    [counter, userId]);
  if (affected !== 1) return false;

  // Verificare de EFECT: `affectedRows` spune că instrucțiunea a atins un rând,
  // nu că rândul e acum confirmat. Diferența contează — un cont raportat
  // „înrolat" care nu e chiar înrolat e un cont care nu se mai poate autentifica
  // niciodată, iar operatorul ar căuta cauza în aplicația de autentificare.
  const user = await findById(db, userId);
  return user !== null && user.totpConfirmed;
}

// ---------------------------------------------------------------------------
// Drepturile pe instanțe
// ---------------------------------------------------------------------------
export type GrantResult = { username: string; instanceId: string; role: string;
                            created: boolean };

/**
 * Dă (sau schimbă) dreptul unui cont pe o instanță.
 *
 * Instanța trebuie să existe în `instances`. Fără verificarea asta, o greșeală
 * de tastare ar scrie un rând care nu se potrivește cu nimic: comanda ar
 * raporta succes, operatorul ar crede că a dat dreptul, iar omul ar vedea în
 * continuare un panou gol — un eșec tăcut, exact clasa pe care `CLAUDE.md` o
 * numește. Schema n-are chei străine (`0001_core.sql`), deci verificarea e a
 * codului sau a nimănui.
 */
export async function grantInstance(
  db: AuthDb, username: string, instanceId: string, role: string,
): Promise<AccountResult<GrantResult>> {
  if (!(INSTANCE_ROLES as readonly string[]).includes(role)) {
    return { ok: false, detail: `rol necunoscut: ${role}` };
  }
  if (!isValidInstanceId(instanceId)) {
    return { ok: false, detail: `identificator de instanță nevalid: ${instanceId}` };
  }
  const user = await findByUsername(db, normalizeUsername(username));
  if (user === null) return { ok: false, detail: `utilizatorul ${username} nu există` };

  const known = await db.all(
    "SELECT instance_id FROM instances WHERE instance_id = ?", [instanceId]);
  if (known.length !== 1) {
    return { ok: false,
             detail: `instanța ${instanceId} nu e înregistrată; vezi ` +
                     "`npm run instance -- list`" };
  }

  const existing = await db.all(
    "SELECT id, role FROM user_instances WHERE user_id = ? AND instance_id = ?",
    [user.id, instanceId]);

  if (existing.length === 0) {
    await db.write(
      "INSERT INTO user_instances (user_id, instance_id, role, granted_at, granted_by) " +
      "VALUES (?, ?, ?, UTC_TIMESTAMP(6), ?)",
      [user.id, instanceId, role, GRANTED_BY]);
  } else {
    await db.write(
      "UPDATE user_instances SET role = ?, granted_at = UTC_TIMESTAMP(6), " +
      "                          granted_by = ? " +
      " WHERE user_id = ? AND instance_id = ?",
      [role, GRANTED_BY, user.id, instanceId]);
  }

  // Confirmat prin citire înapoi, ca la `lib/register.ts`: fără asta, linia de
  // mai jos ar raporta intenția, iar un drept care nu s-a scris arată exact ca
  // unul scris — un panou gol.
  const after = await db.all(
    "SELECT role FROM user_instances WHERE user_id = ? AND instance_id = ?",
    [user.id, instanceId]);
  if (after.length !== 1 || String(after[0].role) !== role) {
    return { ok: false,
             detail: `dreptul pe ${instanceId} nu se citește înapoi cu rolul ${role}` };
  }
  return { ok: true, value: { username: user.username, instanceId, role,
                              created: existing.length === 0 } };
}

/**
 * Ia dreptul unui cont pe o instanță.
 *
 * Rândul se ȘTERGE, nu se marchează: lipsa rândului e chiar felul în care
 * `scopeForUser` citește „nicio instanță" (`migrations/0008_auth.sql`). Ce se
 * pierde odată cu el e `granted_at`/`granted_by`, adică urma dreptului
 * retras — o lipsă reală, scrisă aici ca să fie o decizie: un jurnal de audit
 * propriu al agregatorului nu există încă, iar inventarea unei coloane
 * `revoked_at` aici ar face `scopeForUser` să depindă de ea, deci un `SELECT`
 * care o uită ar reda tăcut dreptul.
 */
export async function revokeInstance(
  db: AuthDb, username: string, instanceId: string,
): Promise<AccountResult<{ username: string; instanceId: string }>> {
  const user = await findByUsername(db, normalizeUsername(username));
  if (user === null) return { ok: false, detail: `utilizatorul ${username} nu există` };

  const affected = await db.write(
    "DELETE FROM user_instances WHERE user_id = ? AND instance_id = ?",
    [user.id, instanceId]);
  if (affected === 0) {
    return { ok: false,
             detail: `${username} nu avea niciun drept pe ${instanceId}` };
  }
  return { ok: true, value: { username: user.username, instanceId } };
}

// ---------------------------------------------------------------------------
// Inventarul
// ---------------------------------------------------------------------------
export type AccountRow = {
  id: number;
  username: string;
  role: string;
  disabled: boolean;
  totpConfirmed: boolean;
  /**
   * Starea reală a celui de-al doilea factor, cu TREI valori. `totpConfirmed`
   * singur nu ajunge de pe 19 august 2026: „nu e confirmat" acoperă și contul
   * care n-are niciun secret (intră cu parola), și pe cel cu o înrolare
   * neterminată (NU intră). Confundate, listarea spune operatorului să repare
   * un cont care merge, sau că merge unul care nu intră.
   */
  totpState: "none" | "unconfirmed" | "active";
  /** Instanțele pe care le vede, cu rolul de pe fiecare. */
  instances: { instanceId: string; role: string }[];
};

/**
 * Toate conturile, cu drepturile lor. Două interogări, niciun `JOIN`.
 *
 * Un `JOIN` ar fi fost forma evidentă și n-ar fi fost greșit AICI (nu e o
 * interogare filtrată pe instanță), dar ar fi fost primul din depozit, iar
 * primul e cel după care se scriu următoarele. Vezi `lib/data/incidents.ts`
 * pentru ce se strică atunci când `instance_id` lipsește dintr-o îmbinare, și
 * `tests/joins.test.ts` pentru garda care numără.
 */
export async function listAccounts(db: AuthDb): Promise<AccountRow[]> {
  const users = await db.all(
    "SELECT id, username, role, disabled, totp_confirmed_at, " +
    "       (totp_secret_enc IS NULL) AS fara_secret FROM users " +
    " ORDER BY username");
  const grants = await db.all(
    "SELECT user_id, instance_id, role FROM user_instances " +
    " ORDER BY user_id, instance_id");

  const byUser = new Map<number, { instanceId: string; role: string }[]>();
  for (const row of grants) {
    const key = Number(row.user_id);
    const list = byUser.get(key) ?? [];
    list.push({ instanceId: String(row.instance_id), role: String(row.role) });
    byUser.set(key, list);
  }

  return users.map((row) => {
    const id = Number(row.id);
    const confirmed = row.totp_confirmed_at !== null
                      && row.totp_confirmed_at !== undefined;
    return {
      id,
      username: String(row.username),
      role: String(row.role),
      // `=== 1`, nu adevăr: `Boolean("0")` e ADEVĂRAT, iar coloana vine ca
      // TINYINT. Aceeași capcană ca `pending_totp`.
      disabled: Number(row.disabled) === 1,
      totpConfirmed: confirmed,
      totpState: Number(row.fara_secret) === 1
        ? "none" : (confirmed ? "active" : "unconfirmed"),
      instances: byUser.get(id) ?? [],
    };
  });
}
