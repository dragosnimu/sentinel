/**
 * Configurația agregatorului, citită din mediu.
 *
 * Nimic din ce e aici nu are valoare implicită care să identifice instalarea.
 * Numele bazei și al utilizatorului conțin identificatorul de cont al
 * găzduirii, iar depozitul e public: un literal aici e o scurgere de
 * infrastructură, exact clasa păzită de
 * `tests/security/test_repo_is_sanitised.py`. Gazda și portul au implicite
 * (`127.0.0.1:3306`) fiindcă alea nu spun nimic despre nimeni.
 *
 * ## „Nesetat" și „setat la gol" sunt același lucru aici
 *
 * Variabilele se pun de mână într-un panou web (vezi
 * `watcher/INCARCARE-HOSTINGER.md`). O variabilă salvată din greșeală goală e
 * cazul obișnuit, nu cel exotic, iar `process.env.X || "implicit"` o tratează
 * tăcut ca lipsă. Aici lipsa unei valori OBLIGATORII e o eroare care numește
 * variabila, fiindcă e reparabilă într-un singur câmp.
 *
 * ## Numerele nu cad înapoi pe implicit
 *
 * `AGGREGATOR_DB_POOL_SIZE=opt` nu devine 8. Devine o eroare. Un număr scris
 * greșit care se transformă tăcut în implicit e cum ajunge cineva să creadă că
 * a schimbat o limită pe care n-a schimbat-o — și e chiar tiparul „confirmarea
 * intenției în locul efectului".
 */

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export type Env = Record<string, string | undefined>;

export type DbConfig = {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
  connectionLimit: number;
  connectTimeoutMs: number;
};

export const DEFAULT_POOL_SIZE = 8;
export const MAX_POOL_SIZE = 64;

/**
 * De ce e obligatorie fiecare variabilă, în termeni de CE SE STRICĂ fără ea.
 *
 * Un singur text pentru toate a produs un defect observat în producție, la prima
 * rulare a runnerului de migrații de către operator (15 august 2026): lipsa lui
 * `AGGREGATOR_DB_PASSWORD` a fost raportată cu explicația lui
 * `AGGREGATOR_DB_NAME` — „nu pot ghici ce bază de date să folosesc" —, iar
 * operatorul a căutat în direcția greșită. Verificarea era corectă; textul era
 * al altei variabile.
 *
 * Mesajul e PRIMA suprafață pe care o citește cineva blocat. Un mesaj care
 * numește altceva decât realitatea nu e o imprecizie de stil, e o îndrumare
 * greșită.
 *
 * `Map`, nu obiect: `obiect["constructor"]` întoarce ceva pe orice obiect
 * obișnuit, deci o variabilă numită așa ar părea că are un motiv scris. Aceeași
 * alegere ca la registrul fluxurilor din `lib/streams.ts`.
 *
 * Legătura dintre nume și text e ținută de
 * `tests/env.test.ts`, testul „fiecare variabilă obligatorie își spune PROPRIUL
 * motiv" — altfel următorul câmp adăugat moștenește tăcut șablonul vecinului.
 */
const REQUIRED_REASONS = new Map<string, string>([
  ["AGGREGATOR_DB_USER",
   "Fără utilizator nu se poate deschide nicio conexiune. Nu are implicit " +
   "fiindcă numele lui conține identificatorul contului de găzduire, iar " +
   "depozitul e public."],
  ["AGGREGATOR_DB_PASSWORD",
   "Fără parolă serverul refuză autentificarea, iar simptomul e o eroare de " +
   "conectare care nu spune că lipsește o parolă. Nu are implicit: o parolă " +
   "implicită într-un depozit public e o parolă publică."],
  ["AGGREGATOR_DB_NAME",
   "Agregatorul nu poate ghici în ce bază să scrie. Nu are implicit fiindcă " +
   "numele bazei conține identificatorul contului de găzduire, iar depozitul " +
   "e public."],
  ["SENTINEL_AGGREGATOR_SECRET",
   "Din el se derivă cheile cu care sunt cifrate secretele de expediere ale " +
   "instanțelor. Fără el nu se poate înregistra nicio instanță și nu se poate " +
   "deschide niciuna existentă, deci ruta de sincronizare răspunde 500 " +
   "tuturor. Nu are implicit: unul ar face textul cifrat din bază descifrabil " +
   "de oricine are depozitul."],
  ["SENTINEL_SESSION_SECRET",
   "Din el se derivă cheia cu care sunt cifrate secretele TOTP ale panoului. " +
   "Fără el nimeni nu se poate autentifica, iar cu el SCHIMBAT nimeni nu se " +
   "mai poate autentifica niciodată cu vechiul al doilea factor: secretele din " +
   "bază nu se mai descifrează și trebuie reînrolate. E o valoare DIFERITĂ de " +
   "SENTINEL_AGGREGATOR_SECRET, dinadins — rotirea uneia nu are voie să strice " +
   "ce ține cealaltă. Nu are implicit: unul ar face al doilea factor al tuturor " +
   "descifrabil de oricine are depozitul."],
]);

function required(env: Env, name: string): string {
  const value = (env[name] ?? "").trim();
  if (!value) {
    const reason = REQUIRED_REASONS.get(name);
    if (reason === undefined) {
      // Un motiv lipsă e o eroare, nu un text generic. Un implicit aici ar fi
      // chiar defectul de mai sus, doar mutat: variabila nouă ar primi o
      // explicație care nu e a ei.
      throw new ConfigError(
        `${name} lipsește (sau e goală), iar motivul pentru care e obligatorie ` +
        "nu e scris în REQUIRED_REASONS din lib/env.ts. Scrie-l acolo: un mesaj " +
        "care nu spune ce se strică trimite pe cineva în direcția greșită.");
    }
    throw new ConfigError(`${name} lipsește (sau e goală). ${reason}`);
  }
  return value;
}

/** Numele variabilelor obligatorii, pentru testul care leagă fiecare nume de
 *  textul lui. Nu se folosește în producție. */
export function requiredNames(): string[] {
  return [...REQUIRED_REASONS.keys()];
}

function optionalInt(env: Env, name: string, fallback: number,
                     min: number, max: number): number {
  const raw = (env[name] ?? "").trim();
  if (!raw) return fallback;
  // `Number`, nu `parseInt`: `parseInt("8abc")` întoarce 8, adică acceptă o
  // valoare scrisă greșit și o rotunjește la ceva plauzibil.
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ConfigError(
      `${name}=${JSON.stringify(raw)} nu e un întreg între ${min} și ${max}. ` +
      "Nu se cade înapoi pe implicit: ai fi crezut că ai schimbat limita.");
  }
  return value;
}

export function readDbConfig(env: Env = process.env): DbConfig {
  return {
    host: (env.AGGREGATOR_DB_HOST ?? "").trim() || "127.0.0.1",
    port: optionalInt(env, "AGGREGATOR_DB_PORT", 3306, 1, 65535),
    user: required(env, "AGGREGATOR_DB_USER"),
    password: required(env, "AGGREGATOR_DB_PASSWORD"),
    database: required(env, "AGGREGATOR_DB_NAME"),
    connectionLimit: optionalInt(env, "AGGREGATOR_DB_POOL_SIZE",
                                 DEFAULT_POOL_SIZE, 1, MAX_POOL_SIZE),
    connectTimeoutMs: optionalInt(env, "AGGREGATOR_DB_CONNECT_TIMEOUT_MS",
                                  10_000, 1_000, 120_000),
  };
}

/** Secretul principal din care se derivă cheile de cifrare (`lib/crypto.ts`). */
export function readMasterSecret(env: Env = process.env): string {
  return required(env, "SENTINEL_AGGREGATOR_SECRET");
}

/**
 * Secretul de sesiune al PANOULUI: cheia de cifrare a secretelor TOTP
 * (`lib/auth/totp.ts`), și, în piesele următoare, semnarea jetonului CSRF
 * pre-autentificare.
 *
 * Funcție separată de `readMasterSecret`, nu un al doilea câmp în aceeași
 * citire, fiindcă asta ține și separarea de eșec: ruta de sincronizare cere
 * secretul de ingestie și n-are nevoie de ăsta, iar panoul invers. O instalare
 * căreia îi lipsește secretul de sesiune trebuie să primească loturile
 * instanțelor mai departe — altfel o variabilă uitată într-un panou web ar opri
 * arhiva de dovezi a tuturor serverelor, ca să repare autentificarea unuia.
 */
export function readSessionSecret(env: Env = process.env): string {
  return required(env, "SENTINEL_SESSION_SECRET");
}
