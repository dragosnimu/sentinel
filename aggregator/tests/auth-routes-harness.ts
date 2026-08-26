/**
 * Schela testelor de rută pentru autentificare.
 *
 * ## Ce se pune în locul cui
 *
 * Dublul (`FakeAuthDb`) se pune ÎN LOCUL DRIVERULUI, prin `getPool`, exact ca
 * în `tests/sync-harness.ts`. Cererea trece pe urmă prin `authDb`, prin
 * `lib/auth/*` și prin funcția `GET`/`POST` a rutei — cod real, `Request` real,
 * `Response` real. Nimic din ce se afirmă mai jos nu se afirmă despre forma unui
 * handler: antetele, cookie-urile și codurile de stare se citesc din răspuns.
 *
 * ## Ce NU se poate afirma de aici
 *
 *   * că Next.js chiar rutează `/login` la funcțiile astea. Ce se poate proba pe
 *     mașina asta e că `next build` acceptă structura (`npm run build`); că
 *     ruta răspunde pe adresa aia se vede la prima cerere pe gazdă;
 *   * că marginea CDN-ului respectă `no-store`. Proba e cea din
 *     `watcher/INCARCARE-HOSTINGER.md`, pe gazdă, după publicare;
 *   * nimic despre MariaDB — vezi lista din capul lui `auth-harness.ts`.
 *
 * ## Parola de test se hashuiește O SINGURĂ DATĂ
 *
 * Un Argon2id la parametrii livrați costă ~140 ms, iar semaforul din
 * `lib/auth/password.ts` lasă unul singur în zbor. Un hash per test ar fi
 * transformat suita într-un minut de așteptare; memoizat, e o singură dată per
 * proces. Valoarea e un hash REAL, nu unul inventat: probele de mai jos trec
 * prin `argon2Verify`, iar un hash fabricat ar fi făcut ca fiecare autentificare
 * „reușită" din suită să treacă prin ramura de hash ilizibil.
 */

import assert from "node:assert/strict";

import { hashPassword } from "../lib/auth/password";
import { TotpCipher, codeForCounter, counterAt, generateSecret } from "../lib/auth/totp";
import { closePool, getPool } from "../lib/db";
import { FakeAuthDb } from "./auth-harness";
import type { UserRow } from "./auth-harness";

/** 64 de caractere, evident false. `deriveKey` cere cel puțin 32. */
export const SESSION_SECRET =
  "secret-de-sesiune-doar-pentru-teste-0123456789abcdef0123456789ab";

export const PASSWORD = "parola-de-test-lunga";
export const USERNAME = "operator";

/**
 * Ce cere `readDbConfig`. Valorile nu ajung nicăieri: pool-ul e înlocuit, deci
 * nimic nu se conectează. Sunt totuși obligatorii, fiindcă `getPool` citește
 * configurația ÎNAINTE de a chema fabrica.
 */
const DB_ENV = {
  AGGREGATOR_DB_USER: "u",
  AGGREGATOR_DB_PASSWORD: "p",
  AGGREGATOR_DB_NAME: "d",
};

export function setEnv(vars: Record<string, string | undefined>): void {
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

let cachedHash: string | null = null;

/** Hashul parolei de test, calculat o singură dată per proces. */
export async function testPasswordHash(): Promise<string> {
  if (cachedHash === null) cachedHash = await hashPassword(PASSWORD);
  return cachedHash;
}

export type Fixture = {
  db: FakeAuthDb;
  user: UserRow;
  /** Secretul TOTP în clar, ca testele să poată produce coduri valide. */
  totpSecret: string;
};

/**
 * Un dublu curat, cu un cont care CHIAR se poate autentifica.
 *
 * `over` schimbă coloanele contului: `disabled`, `totp_confirmed_at`,
 * `password_hash`. Implicitul e contul bun, ca un test care probează un refuz să
 * nu poată trece din întâmplare.
 *
 * `locked_until` NU mai e printre ele, și nu din scăpare: plafonul per cont e o
 * fereastră peste `login_attempts` (`lib/auth/ratelimit.ts`), deci un cont
 * „blocat" se pregătește punând rânduri de eșec, nu scriind coloana. Coloana mai
 * există în schemă și în dublu, dar nimic din codul livrat n-o mai citește — un
 * test care ar semăna-o ar proba o stare pe care n-o vede nimeni.
 */
export async function useAuthServer(over: Partial<UserRow> = {}): Promise<Fixture> {
  await closePool();
  setEnv({ SENTINEL_SESSION_SECRET: SESSION_SECRET,
           AGGREGATOR_CLIENT_IP_HEADER: undefined });

  const db = new FakeAuthDb();
  const totpSecret = generateSecret();
  const user = db.addUser(1, {
    username: USERNAME,
    password_hash: await testPasswordHash(),
    role: "owner",
    totp_secret_enc: new TotpCipher(SESSION_SECRET).encrypt(totpSecret, 1),
    totp_confirmed_at: db.nowMs,
    ...over,
  });

  getPool(() => db, DB_ENV);
  // Vezi `useFakeServer` din `tests/sync-harness.ts`: dacă `getPool` încetează
  // să înregistreze cârligul `connection`, conexiunile de producție rămân pe
  // `sql_mode`-ul gazdei, iar un nume cu diacritice ajunge în `users.username`
  // ca `?`, sub o cheie unică. Aserțiunea o pune fiecare test de rută.
  assert.ok(db.connectionHandler,
            "getPool nu a înregistrat cârligul `connection`, deci nicio " +
            "conexiune nu mai primește sql_mode strict — vezi lib/db.ts");
  return { db, user, totpSecret };
}

export async function forgetAuthServer(): Promise<void> {
  await closePool();
  setEnv({ AGGREGATOR_CLIENT_IP_HEADER: undefined });
}

/** Un cod TOTP valid ACUM. Ceasul real, nu cel al dublului: `verifyCode`
 *  citește `Date.now()`, iar dublul are ceas propriu doar pentru SQL. */
export function currentCode(secret: string): string {
  return codeForCounter(secret, counterAt(Date.now() / 1000));
}

// ---------------------------------------------------------------------------
// Cereri și răspunsuri
// ---------------------------------------------------------------------------
export const ORIGIN = "https://exemplu.invalid";

export type RequestOptions = {
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
};

export function getRequest(path: string, options: RequestOptions = {}): Request {
  return new Request(`${ORIGIN}${path}`, { headers: buildHeaders(options) });
}

export function formRequest(
  path: string, fields: Record<string, string>, options: RequestOptions = {},
): Request {
  const body = new URLSearchParams(fields).toString();
  const headers = buildHeaders(options);
  headers.set("Content-Type", "application/x-www-form-urlencoded");
  return new Request(`${ORIGIN}${path}`, { method: "POST", body, headers });
}

function buildHeaders(options: RequestOptions): Headers {
  const headers = new Headers(options.headers ?? {});
  const cookies = Object.entries(options.cookies ?? {});
  if (cookies.length) {
    headers.set("cookie", cookies.map(([k, v]) => `${k}=${v}`).join("; "));
  }
  return headers;
}

/** Cookie-urile puse de un răspuns: nume → valoare. Valoarea goală = șters. */
export function cookiesOf(res: Response): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of setCookieLines(res)) {
    const first = line.split(";")[0];
    const eq = first.indexOf("=");
    if (eq < 0) continue;
    out.set(first.slice(0, eq).trim(), first.slice(eq + 1).trim());
  }
  return out;
}

/** Antetele `Set-Cookie` întregi, cu fanioane cu tot. */
export function setCookieLines(res: Response): string[] {
  const headers = res.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  const single = res.headers.get("set-cookie");
  return single ? [single] : [];
}

/** Linia `Set-Cookie` a unui cookie anume, sau `undefined`. */
export function setCookieFor(res: Response, name: string): string | undefined {
  return setCookieLines(res).find((line) => line.startsWith(`${name}=`));
}

/**
 * Jetonul CSRF din formularul servit — citit din HTML-ul RĂSPUNSULUI.
 *
 * Nu se refolosește valoarea calculată în test: ce contează e ce a ajuns în
 * pagină. Un formular servit fără câmp ar trece neobservat printr-un test care
 * își semnează singur jetonul.
 */
export function csrfFromHtml(html: string): string {
  const found = /name="csrf_token" value="([^"]*)"/.exec(html);
  if (!found) throw new Error("formularul servit nu conține un câmp csrf_token");
  return found[1];
}

/** Perechea (cookie pre-auth, câmp din formular), luată dintr-un `GET /login`. */
export async function preauthPair(
  get: (req: Request) => Promise<Response>,
): Promise<{ cookie: string; token: string }> {
  const res = await get(getRequest("/login"));
  const cookie = cookiesOf(res).get("sentinel_csrf");
  if (!cookie) throw new Error("GET /login nu a pus cookie-ul pre-auth");
  return { cookie, token: csrfFromHtml(await res.text()) };
}

/**
 * O autentificare DUSĂ LA CAPĂT, prin rutele reale: parolă, apoi cod TOTP.
 *
 * Întoarce jetonul de sesiune al unei sesiuni ÎNTREGI (`pending_totp = 0`) —
 * singurul cu care se poate cere ceva de la panou. Handlerele se dau ca
 * parametri, ca `preauthPair`: schela nu importă rute, ca să rămână folosibilă
 * și de probele care nu ating niciuna.
 *
 * Fiecare pas e o cerere reală, cu `Request` și `Response` reale, prin funcțiile
 * exportate ale rutelor. Ce se probează cu ea nu e că „autentificarea merge" în
 * abstract, ci că un cont creat de unealtă chiar trece de amândouă etapele —
 * ceea ce, până la piesa asta, nu putuse fi probat de nimeni, fiindcă nu exista
 * nicio cale de a crea un cont.
 */
export type RouteHandlers = {
  loginGet: (req: Request) => Promise<Response>;
  loginPost: (req: Request) => Promise<Response>;
  totpGet: (req: Request) => Promise<Response>;
  totpPost: (req: Request) => Promise<Response>;
};

export async function completeLogin(
  handlers: RouteHandlers,
  // `code` se poate da explicit fiindcă ce contează uneori e CARE cod: contorul
  // anti-reluare face ca un cod deja consumat — de pildă cel cu care s-a
  // confirmat înrolarea — să fie refuzat în aceeași fereastră de 30 s.
  credentials: { username: string; password: string; totpSecret: string;
                 code?: string },
): Promise<string> {
  const pair = await preauthPair(handlers.loginGet);
  const first = await handlers.loginPost(formRequest(
    "/login",
    { username: credentials.username, password: credentials.password,
      csrf_token: pair.token },
    { cookies: { sentinel_csrf: pair.cookie } }));
  if (first.status !== 303) {
    throw new Error(`etapa parolei a răspuns ${first.status}, nu 303`);
  }
  const pending = cookiesOf(first).get("sentinel_session");
  if (!pending) throw new Error("etapa parolei nu a pus cookie-ul de sesiune");

  // Jetonul CSRF al sesiunii se citește din pagina SERVITĂ, nu se calculează
  // aici: un formular servit fără el ar trece neobservat.
  const page = await handlers.totpGet(
    getRequest("/totp", { cookies: { sentinel_session: pending } }));
  if (page.status !== 200) {
    throw new Error(`GET /totp a răspuns ${page.status}, nu 200`);
  }
  const csrf = csrfFromHtml(await page.text());

  const second = await handlers.totpPost(formRequest(
    "/totp",
    { code: credentials.code ?? currentCode(credentials.totpSecret),
      csrf_token: csrf },
    { cookies: { sentinel_session: pending } }));
  if (second.status !== 303) {
    throw new Error(`etapa codului a răspuns ${second.status}, nu 303`);
  }
  const full = cookiesOf(second).get("sentinel_session");
  if (!full) throw new Error("etapa codului nu a rotit cookie-ul de sesiune");
  if (full === pending) {
    throw new Error("jetonul nu s-a rotit după al doilea factor");
  }
  return full;
}

/** Adună `console.warn`. Vezi nota din `tests/sync-harness.ts`. */
export function captureWarn(): { lines: string[][]; restore: () => void } {
  const lines: string[][] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => { lines.push(args.map(String)); };
  return { lines, restore: () => { console.warn = original; } };
}

/** Adună `console.error` — ce e al nostru și n-a mers. */
export function captureError(): { lines: string[][]; restore: () => void } {
  const lines: string[][] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => { lines.push(args.map(String)); };
  return { lines, restore: () => { console.error = original; } };
}
