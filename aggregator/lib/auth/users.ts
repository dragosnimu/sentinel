/**
 * Conturile panoului și registrul de încercări. Rânduri, nu politică.
 *
 * Geamănul e `sentinel/db/repo/users.py`, și separarea e aceeași: aici se citesc
 * și se scriu rânduri, iar cine decide dacă o autentificare reușește e
 * `lib/auth/login.ts`. Se pot revizui separat.
 *
 * ## Numele de utilizator se validează AICI, în cod, nu în bază
 *
 * `users.username` e `VARCHAR(64) ascii ascii_bin`. Un nume cu diacritice e
 * refuzat de MariaDB **doar sub `STRICT_TRANS_TABLES`**, iar gazda nu îl avea
 * (măsurat, 17 august 2026); de atunci îl pune aplicația, pe fiecare sesiune
 * (`lib/db.ts`). Validarea de aici rămâne totuși prima, fiindcă e a APLICAȚIEI:
 * are mesaj, și nu depinde de ce răspunde serverul altcuiva. Sub un mod nestrict
 * ce s-ar întâmpla e mai rău decât o eroare: un avertisment, caracterele
 * neconvertibile înlocuite cu `?`, și un cont creat sub un nume pe care nimeni
 * nu-l mai poate retasta — cu o cheie unică peste el, deci al doilea om cu
 * diacritice în nume nici nu se mai poate crea.
 *
 * Deci refuzul e al aplicației, cu mesaj, indiferent ce `sql_mode` are gazda.
 *
 * ## Numărătorile: „nu știu" nu e „zero"
 *
 * Un `COUNT(*)` care nu se poate citi ARUNCĂ. Zero ar fi o propoziție —
 * „n-au fost încercări" — pe care n-am dovedit-o, iar din ea iese exact
 * purtarea pe care limitarea de rată există ca s-o oprească: plafonul dispare
 * tăcut și nimeni nu află. Driverul întoarce `BIGINT` ca ȘIR
 * (`bigNumberStrings` în `lib/db.ts`), deci valoarea se convertește pe față și
 * se verifică, nu se presupune că e număr.
 *
 * ## `login_attempts` e STAREA celor trei limitatoare, nu doar o urmă
 *
 * Toate trei numără rânduri de aici. De-aia scrierea cere un permis
 * (`lib/auth/gate.ts`): un rând scris pe o cale care n-a trecut de
 * `checkThrottles` hrănește chiar numărătoarea care ar fi trebuit s-o
 * oprească. `logAttempt` e SINGURA scriere în tabelă, iar că e singura o
 * păzește o gardă care numără căile, nu una care le recunoaște
 * (`tests/auth-attempts-writers.test.ts`).
 *
 * Consecința pentru `users`: coloanele `failed_attempts` și `locked_until` nu
 * mai sunt citite și nu mai sunt scrise de nicăieri din piesa asta. Blocarea per
 * cont e o fereastră alunecătoare peste `login_attempts`, ca celelalte două
 * straturi (motivul întreg e în `lib/auth/ratelimit.ts`). Coloanele rămân în
 * schemă fiindcă scoaterea lor e o migrație pe o tabelă vie, adică o decizie a
 * operatorului; nimic de aici nu se sprijină pe ele. Cine vrea să oprească un
 * cont are `disabled`, care se citește.
 *
 * Că rămân nu înseamnă că tac: `migrations/0009_auth_bounds.sql` le pune un
 * `COMMENT`. `failed_attempts` e `NOT NULL DEFAULT 0`, deci fără comentariu
 * citește „0 eșecuri" despre orice cont, pentru totdeauna — o valoare falsă cu
 * un consumator evident (orice raport sau unealtă de administrare care se uită
 * în tabelă). Comentariul e singurul loc în care avertismentul ăsta ajunge la
 * cine citește schema, nu codul.
 */

import type { AuthDb } from "./db";
import type { ThrottlePass } from "./gate";
import { isThrottlePass } from "./gate";

export const MAX_USERNAME_LENGTH = 64;
/** `login_attempts.detail` e `VARCHAR(255)`. Ce nu încape se taie AICI, nu de bază. */
export const MAX_DETAIL_LENGTH = 255;
/** `login_attempts.user_agent` și `sessions.user_agent` sunt `VARCHAR(512)`. */
export const MAX_USER_AGENT_LENGTH = 512;

export class UsernamePolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsernamePolicyError";
  }
}

/**
 * Numele tastat, adus la forma în care are voie să atingă baza.
 *
 * Tăierea la 64 e cea din `security.py` (`username[:64]`) și e obligatorie
 * pentru AMBELE coloane: `users.username` are 64, iar `login_attempts.username`
 * tot 64 — și acolo valoarea e CE S-A TASTAT, deci poate fi orice.
 */
export function normalizeUsername(raw: string): string {
  return (raw ?? "").trim().slice(0, MAX_USERNAME_LENGTH);
}

/**
 * ASCII imprimabil, fără spații. Aruncă altfel.
 *
 * Fără spații fiindcă un nume cu spațiu la capăt e un cont pe care omul lui nu
 * poate să-l retasteze, iar unul cu spațiu la mijloc se copiază greșit din orice
 * jurnal. Vocabularul e mai îngust decât `ascii_bin`, dinadins: o coloană
 * permite octeți, o identitate cere să poată fi scrisă de un om.
 */
export function assertAsciiUsername(username: string): void {
  if (!/^[\x21-\x7e]+$/.test(username)) {
    throw new UsernamePolicyError(
      "Numele de utilizator poate conține doar caractere ASCII imprimabile, " +
      "fără spații.");
  }
}

// ---------------------------------------------------------------------------
// Citirea unui cont
// ---------------------------------------------------------------------------
export type AuthUser = {
  id: number;
  username: string;
  passwordHash: string;
  role: string;
  disabled: boolean;
  totpSecretEnc: string | null;
  /** Înrolarea a fost DUSĂ LA CAPĂT. O înrolare întreruptă nu e un al doilea
   *  factor, e un cont care cere ceva ce nimeni nu poate produce. */
  totpConfirmed: boolean;
};

/**
 * Ce se citește despre un cont.
 *
 * `failed_attempts` NU e aici, dinadins: contorul per cont e o fereastră peste
 * `login_attempts`, iar o coloană care nu se mai scrie, citită într-un câmp, ar
 * fi o valoare care spune „zero eșecuri" despre un cont cu cincizeci.
 */
const USER_COLUMNS =
  "id, username, password_hash, role, disabled, totp_secret_enc, " +
  "totp_confirmed_at";

/** O coloană lipsă din `SELECT` ar deveni tăcut `undefined`. Aici e o eroare. */
function present(row: Record<string, unknown>, column: string): unknown {
  if (!(column in row)) {
    throw new Error(
      `interogarea nu a întors coloana ${column}; nu se presupune o valoare ` +
      "pentru ea — un cont citit pe jumătate e o decizie de autentificare luată " +
      "pe jumătate");
  }
  return row[column];
}

/** `TINYINT(1)` vine ca `0`/`1`. `Boolean("0")` e ADEVĂRAT, deci conversia se
 *  face pe față, o singură dată. Aceeași capcană ca `pending_totp`. */
function toBool(value: unknown, column: string): boolean {
  if (value === 0 || value === false) return false;
  if (value === 1 || value === true) return true;
  throw new Error(
    `users.${column} are o valoare pe care nu o pot citi (${String(value)}). ` +
    "Nu se presupune niciuna dintre cele două: amândouă sunt decizii de acces.");
}

function toInt(value: unknown, column: string): number {
  // `BIGINT` vine ca ȘIR (`bigNumberStrings`), deci nu se presupune tipul.
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(
      `users.${column} nu e un întreg citibil (${String(value)}); ` +
      "o valoare pe care nu o pot citi nu se rotunjește la 0");
  }
  return parsed;
}

function toUser(row: Record<string, unknown>): AuthUser {
  const confirmedAt = present(row, "totp_confirmed_at");
  const secret = present(row, "totp_secret_enc");
  return {
    id: toInt(present(row, "id"), "id"),
    username: String(present(row, "username")),
    passwordHash: String(present(row, "password_hash")),
    role: String(present(row, "role")),
    disabled: toBool(present(row, "disabled"), "disabled"),
    totpSecretEnc: secret === null || secret === undefined ? null : String(secret),
    totpConfirmed: confirmedAt !== null && confirmedAt !== undefined,
  };
}

function oneUser(rows: Record<string, unknown>[]): AuthUser | null {
  if (rows.length > 1) {
    // Imposibil cât timp `uk_users_username` există. Dacă se întâmplă, cheia a
    // dispărut, iar tăcerea de aici ar fi o autentificare pe un rând ales la
    // întâmplare.
    throw new Error(
      `${rows.length} conturi cu același nume: cheia unică uk_users_username ` +
      "lipsește din bază");
  }
  return rows.length === 1 ? toUser(rows[0]) : null;
}

export async function findByUsername(db: AuthDb, username: string): Promise<AuthUser | null> {
  return oneUser(await db.all(`SELECT ${USER_COLUMNS} FROM users WHERE username = ?`,
                              [username]));
}

export async function findById(db: AuthDb, id: number): Promise<AuthUser | null> {
  return oneUser(await db.all(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`, [id]));
}

// ---------------------------------------------------------------------------
// Scrieri
// ---------------------------------------------------------------------------
/**
 * Ridică hashul la parametrii curenți, după o autentificare REUȘITĂ.
 *
 * `password_changed_at` se mută odată cu el fiindcă e coloana `NOT NULL` fără
 * implicit din schemă — dar valoarea ei devine atunci „când s-a rescris hashul",
 * nu „când și-a schimbat omul parola". Diferența e reală și e scrisă aici ca să
 * n-o descopere cineva ca surpriză într-un raport; parola nu s-a schimbat, doar
 * costul cu care e stocată.
 */
export async function setPasswordHash(
  db: AuthDb, userId: number, passwordHash: string,
): Promise<void> {
  await db.write(
    "UPDATE users SET password_hash = ?, password_changed_at = UTC_TIMESTAMP(6) " +
    " WHERE id = ?",
    [passwordHash, userId]);
}

/**
 * Autentificare reușită, dusă până la capăt: se consemnează CÂND și DE UNDE.
 *
 * `last_login_ip` primește DOAR o adresă de încredere (vezi `client-ip.ts`);
 * altfel `null`. O coloană `INET6` care conține o adresă aleasă de cine s-a
 * autentificat nu e o urmă, e o afirmație falsă cu index pe ea.
 *
 * Nu mai golește niciun contor, fiindcă nu mai există unul de golit: eșecurile
 * ies din socoteală singure, când ies din fereastră. Golirea de dinainte era
 * jumătatea care nu funcționa — rula abia la capătul etapei TOTP, adică exact
 * acolo unde un cont blocat nu putea ajunge.
 */
export async function recordSuccess(
  db: AuthDb, userId: number, ip: string | null,
): Promise<void> {
  await db.write(
    "UPDATE users SET last_login_at = UTC_TIMESTAMP(6), last_login_ip = ? " +
    " WHERE id = ?",
    [ip, userId]);
}

// ---------------------------------------------------------------------------
// Registrul de încercări
// ---------------------------------------------------------------------------
/** Vocabularul impus de `ck_login_attempts_result`. */
export const ATTEMPT_RESULTS = ["ok", "bad_password", "bad_totp", "locked",
                               "unknown_user"] as const;
export type AttemptResult = (typeof ATTEMPT_RESULTS)[number];

/** Vocabularul impus de `ck_login_attempts_stage`. */
export const ATTEMPT_STAGES = ["password", "totp"] as const;
export type AttemptStage = (typeof ATTEMPT_STAGES)[number];

export type AttemptRecord = {
  username: string | null;
  ip: string | null;
  userAgent: string | null;
  result: AttemptResult;
  stage: AttemptStage | null;
  sessionId?: string | null;
  detail?: string | null;
};

/**
 * Fiecare încercare, reușită sau nu. SINGURA scriere în `login_attempts`.
 *
 * Asta răspunde la „autentificarea aia neobișnuită am fost eu, în deplasare?"
 * înainte ca cineva să-i spună compromitere, iar o serie de `bad_totp` peste o
 * parolă corectă e semnalul că cineva ARE deja parola.
 *
 * ## Permisul nu e decor
 *
 * `pass` se obține DOAR din ramura care permite a lui `checkThrottles`
 * (`lib/auth/gate.ts`). Tipul închide calea la compilare, iar verificarea de mai
 * jos închide și casturile: un obiect fabricat n-a trecut prin niciun limitator,
 * iar rândul lui ar hrăni chiar numărătoarea care ar fi trebuit să-l oprească.
 * Se ARUNCĂ, nu se scrie tăcut și nici nu se sare peste scriere — o urmă care
 * lipsește în tăcere e a doua față a aceleiași minciuni.
 *
 * Vocabularul se verifică ÎNAINTE de scriere, deși baza are `CHECK`-uri: sub un
 * `sql_mode` nestrict un `CHECK` picat e tot o eroare, dar o valoare prea lungă
 * e o TĂIERE tăcută, iar o etichetă tăiată la mijloc („bad_passw") ar rămâne în
 * registru fără ca nimic să pară stricat. Verificarea rămâne și după ce
 * `lib/db.ts` a început să pună modul strict pe fiecare sesiune: aia repară ce
 * face SERVERUL, asta e refuzul nostru, cu numele etichetei în el.
 */
export async function logAttempt(
  db: AuthDb, pass: ThrottlePass, record: AttemptRecord,
): Promise<void> {
  if (!isThrottlePass(pass)) {
    throw new Error(
      "un rând în login_attempts se scrie DOAR de pe o cale care a trecut de " +
      "checkThrottles; permisul primit nu a fost emis de niciun limitator. Vezi " +
      "lib/auth/gate.ts — tabela asta E starea celor trei plafoane, iar un rând " +
      "scris pe lângă ele prelungește la nesfârșit plafonul care tocmai a refuzat.");
  }
  if (!ATTEMPT_RESULTS.includes(record.result)) {
    throw new Error(`rezultat necunoscut pentru login_attempts: ${record.result}`);
  }
  if (record.stage !== null && !ATTEMPT_STAGES.includes(record.stage)) {
    throw new Error(`etapă necunoscută pentru login_attempts: ${record.stage}`);
  }
  await db.write(
    "INSERT INTO login_attempts (at, username, ip, user_agent, result, stage, " +
    "                            session_id, detail) " +
    "VALUES (UTC_TIMESTAMP(6), ?, ?, ?, ?, ?, ?, ?)",
    [record.username === null ? null : normalizeUsername(record.username),
     record.ip,
     record.userAgent === null ? null
       : record.userAgent.slice(0, MAX_USER_AGENT_LENGTH) || null,
     record.result,
     record.stage,
     record.sessionId ?? null,
     record.detail ? record.detail.slice(0, MAX_DETAIL_LENGTH) : null]);
}

/** Bucățile unui `detail`, lipite și tăiate o singură dată, la capăt. */
export function detailOf(...parts: (string | null | undefined)[]): string | null {
  const text = parts.filter((part) => part).join("; ");
  return text ? text.slice(0, MAX_DETAIL_LENGTH) : null;
}

// ---------------------------------------------------------------------------
// Numărători pentru limitarea de rată
// ---------------------------------------------------------------------------
function toCount(rows: Record<string, unknown>[], what: string): number {
  if (rows.length !== 1) {
    throw new Error(
      `numărătoarea de încercări (${what}) nu a întors exact un rând, ci ` +
      `${rows.length}. „Nu știu" nu e „zero": un plafon care se rotunjește la ` +
      "zero e un plafon dispărut, tăcut.");
  }
  const raw = rows[0].n;
  const value = typeof raw === "number" ? raw : Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(
      `numărătoarea de încercări (${what}) a întors ${String(raw)}, ` +
      "care nu e un întreg. Vezi `bigNumberStrings` în lib/db.ts.");
  }
  return value;
}

/** Câte încercări EȘUATE au venit de la adresa asta în fereastră. */
export async function countFailuresFromIp(
  db: AuthDb, ip: string, windowMinutes: number,
): Promise<number> {
  return toCount(await db.all(
    "SELECT COUNT(*) AS n FROM login_attempts " +
    " WHERE ip = ? AND result <> 'ok' AND at >= UTC_TIMESTAMP(6) - INTERVAL ? MINUTE",
    [ip, windowMinutes]), "per sursă");
}

/**
 * Câte încercări EȘUATE s-au făcut pe numele ăsta, la etapa asta, în fereastră.
 *
 * Starea stratului per cont, ținută în aceeași tabelă ca celelalte două — vezi
 * `lib/auth/ratelimit.ts` pentru ce s-a stricat cu un contor monoton într-o
 * coloană, și pentru ce înseamnă `stage`. Numele e cel TASTAT, nu o cheie
 * străină: e tot ce are rândul, iar pentru un cont care există chiar e numele lui.
 *
 * ## Colația: numărat MAI MULT înseamnă refuzat mai mult
 *
 * `login_attempts.username` a fost `utf8mb4_unicode_ci` până la
 * `migrations/0009_auth_bounds.sql`, adică INSENSIBIL la majuscule, în timp ce
 * `users.username` e `ascii_bin` și dublul de test compară octeți. Argumentul
 * scris aici înainte — „pe gazdă se numără cel puțin la fel de multe rânduri,
 * deci limitatorul real nu e mai slab" — MĂSURA PROPRIETATEA GREȘITĂ: eșecul pe
 * care straturile astea există să-l scoată e negarea operatorului legitim, iar
 * a număra mai mult înseamnă a refuza mai mult. Concret, sub `ci`: eșecuri
 * tastate `ADMIN` pe un cont inexistent intrau în fereastra lui `admin`, iar
 * `Admin` și `admin` — două conturi DISTINCTE în `users` — își împărțeau
 * fereastra.
 *
 * `0009` pune coloana în `utf8mb4_bin`: comparație pe octeți ca la geamăna ei,
 * fără să îngusteze setul de caractere (coloana ține ce s-a TASTAT, nu o
 * identitate), și cu `ix_login_attempts_username_at` în continuare folosibil —
 * ceea ce un `COLLATE` pus în `WHERE` ar fi stricat. Până când migrația e
 * aplicată pe gazdă, purtarea de acolo e cea `ci` descrisă mai sus.
 */
export async function countFailuresForUser(
  db: AuthDb, username: string, windowMinutes: number,
  stage: AttemptStage,
): Promise<number> {
  return toCount(await db.all(
    "SELECT COUNT(*) AS n FROM login_attempts " +
    " WHERE username = ? AND stage = ? AND result <> 'ok' " +
    "   AND at >= UTC_TIMESTAMP(6) - INTERVAL ? MINUTE",
    [username, stage, windowMinutes]), "per cont");
}

/**
 * Câte încercări eșuate au venit de ORIUNDE în fereastră.
 *
 * Stratul care nu depinde de identitatea sursei — singurul care mai ține când
 * adresa clientului vine dintr-un antet în care nu se poate avea încredere.
 */
export async function countFailuresGlobal(
  db: AuthDb, windowMinutes: number,
): Promise<number> {
  return toCount(await db.all(
    "SELECT COUNT(*) AS n FROM login_attempts " +
    " WHERE result <> 'ok' AND at >= UTC_TIMESTAMP(6) - INTERVAL ? MINUTE",
    [windowMinutes]), "global");
}
