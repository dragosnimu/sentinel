/**
 * Rutele de autentificare: ce refuză, cu ce cod, și ce antete poartă răspunsul.
 *
 * Fiecare aserțiune de aici se face pe un `Response` REAL, întors de funcția
 * rutei. Nimic nu se citește dintr-o configurație și nimic nu se afirmă despre
 * forma unui handler — aia e chiar greșeala pe care `CLAUDE.md` o numește: „un
 * fișier pe disc nu e dovadă că a fost încărcat".
 *
 * Ce se strică pentru operator, pe categorii:
 *
 *   * **CSRF în etapa pre-auth.** Fără el, o pagină ostilă postează `/login` cu
 *     credențiale ALESE DE EA, iar victima ajunge autentificată în contul
 *     atacatorului fără să observe. Verificările de origine ale Server Actions
 *     nu acoperă etapa asta — rutele sunt Route Handlers;
 *   * **cache.** O pagină autentificată servită din cache-ul CDN-ului e pagina
 *     unui om arătată altuia. Bug de confidențialitate, nu de prospețime;
 *   * **CSP.** Un `unsafe-inline` strecurat aici desface apărarea împotriva
 *     XSS pentru tot panoul;
 *   * **limitare.** Un plafon care se aplică pe o valoare aleasă de client nu e
 *     un plafon, e o armă îndreptată spre operator;
 *   * **coduri de stare.** `PasswordBusyError` întors ca 401 ar bloca un cont
 *     care n-a greșit nimic și ar transforma plafonul cozii în chiar oracolul de
 *     enumerare pe care hashul-fantomă există să-l închidă.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { GET as loginGet, POST as loginPost } from "../app/login/route";
import { GET as totpGet, POST as totpPost } from "../app/totp/route";
import { GET as logoutGet, POST as logoutPost } from "../app/logout/route";
import { CONTENT_SECURITY_POLICY, MAX_FORM_BYTES } from "../lib/auth/http";
import { PREAUTH_CSRF_TTL_S, PreAuthCsrf } from "../lib/auth/csrf";
import { MAX_CONCURRENT_ARGON2, MAX_PASSWORD_LENGTH, MAX_QUEUED_ARGON2 }
  from "../lib/auth/password";
import {
  FAILURE_WINDOW_MINUTES, GLOBAL_FAILURE_LIMIT, IP_FAILURE_LIMIT,
  MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP, MAX_FAILED_LOGINS_WITH_TRUSTED_IP,
} from "../lib/auth/ratelimit";
import { PENDING_TOTP_TTL_S } from "../lib/auth/session";
import { SESSION_TTL_S } from "../lib/auth/login";
import {
  ORIGIN, PASSWORD, SESSION_SECRET, USERNAME, captureError, captureWarn, cookiesOf,
  csrfFromHtml, currentCode, forgetAuthServer, formRequest, getRequest, preauthPair,
  setCookieFor, setEnv, useAuthServer,
} from "./auth-routes-harness";
import type { Fixture, RequestOptions } from "./auth-routes-harness";
import type { AttemptRow, UserRow } from "./auth-harness";

const IP_HEADER = "x-hcdn-client-ip";
const CLIENT_IP = "198.51.100.7";
const CLIENT_IP_STORED = `::ffff:${CLIENT_IP}`;

let fixture: Fixture;
let warn: { lines: string[][]; restore: () => void };
let error: { lines: string[][]; restore: () => void };

async function seed(over: Partial<UserRow> = {}): Promise<Fixture> {
  fixture = await useAuthServer(over);
  return fixture;
}

beforeEach(async () => {
  warn = captureWarn();
  error = captureError();
  await seed();
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetAuthServer();
});

/** Un `POST /login` cu un jeton CSRF pre-auth proaspăt și valid. */
async function login(
  fields: Record<string, string> = {}, options: RequestOptions = {},
): Promise<Response> {
  const pair = await preauthPair(loginGet);
  return await loginPost(formRequest(
    "/login",
    { username: USERNAME, password: PASSWORD, csrf_token: pair.token, ...fields },
    { ...options, cookies: { sentinel_csrf: pair.cookie, ...(options.cookies ?? {}) } }));
}

/** Duce un cont până la sesiunea în așteptare și întoarce jetonul din cookie. */
async function loginToPending(options: RequestOptions = {}): Promise<string> {
  const res = await login({}, options);
  assert.equal(res.status, 303, "prima etapă nu a reușit");
  const token = cookiesOf(res).get("sentinel_session");
  assert.ok(token, "prima etapă nu a pus cookie-ul de sesiune");
  return token as string;
}

/** Rândurile scrise în registrul de încercări. */
function attempts(): AttemptRow[] {
  return fixture.db.loginAttempts;
}

/**
 * Rândurile pe care le NUMĂRĂ cele trei straturi de limitare.
 *
 * Predicatul e chiar cel din `countFailures*` (`result <> 'ok'`), scris o dată:
 * o aserțiune pe „câte rânduri s-au scris" ar trece și dacă rândul scris ar fi
 * unul care nu contează, iar ce apără testele de aici e chiar numărătoarea.
 */
function failures(): AttemptRow[] {
  return attempts().filter((row) => row.result !== "ok");
}

/**
 * Umple fereastra unui cont cu eșecuri, fără să treacă prin rute.
 *
 * Rândurile sunt cele pe care le-ar scrie chiar ruta; ce se probează cu ele e
 * DECIZIA luată din fereastră, nu drumul până la ea.
 */
function seedAccountFailures(count: number, username = USERNAME): void {
  for (let i = 0; i < count; i++) {
    fixture.db.loginAttempts.push({
      at: fixture.db.nowMs, username, ip: null, user_agent: null,
      result: "bad_password", stage: "password", session_id: null, detail: null,
    });
  }
}

// ---------------------------------------------------------------------------
// CSRF — inclusiv etapa pre-autentificare
// ---------------------------------------------------------------------------
test("GET /login servește un formular cu jeton CSRF și cookie-ul lui", async () => {
  // Fără perechea asta, formularul nu se poate trimite deloc: următorul test
  // cere ca lipsa ei să fie un refuz, deci dacă pagina n-o servește, panoul e
  // închis pentru toată lumea.
  const res = await loginGet(getRequest("/login"));
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.ok(csrfFromHtml(html), "formularul nu poartă câmpul csrf_token");
  assert.ok(cookiesOf(res).get("sentinel_csrf"), "răspunsul nu pune cookie-ul pre-auth");
  assert.equal(fixture.db.sessions.length, 0,
               "afișarea formularului a creat un rând de sesiune; un GET în buclă " +
               "ar umple atunci tabela");
});

test("POST /login FĂRĂ jeton CSRF e refuzat — în etapa pre-auth", async () => {
  // Chiar proprietatea pe care verificările de origine ale Server Actions nu o
  // acoperă. Fără ea, o pagină ostilă autentifică victima în contul ei.
  const res = await loginPost(formRequest(
    "/login", { username: USERNAME, password: PASSWORD }));
  assert.equal(res.status, 403);
  assert.equal(cookiesOf(res).get("sentinel_session"), undefined,
               "un POST fără CSRF a primit totuși un cookie de sesiune");
  assert.equal(fixture.db.sessions.length, 0);
  assert.equal(attempts().length, 0,
               "refuzul CSRF a fost numărat ca încercare de autentificare");
});

test("cookie-ul pre-auth singur nu ajunge; nici câmpul singur", async () => {
  // Cookie-urile se trimit și de pe o pagină ostilă. Ce dovedește că formularul
  // e chiar cel servit de noi e PERECHEA.
  const pair = await preauthPair(loginGet);

  const cookieOnly = await loginPost(formRequest(
    "/login", { username: USERNAME, password: PASSWORD },
    { cookies: { sentinel_csrf: pair.cookie } }));
  assert.equal(cookieOnly.status, 403, "cookie-ul singur a trecut");

  const fieldOnly = await loginPost(formRequest(
    "/login", { username: USERNAME, password: PASSWORD, csrf_token: pair.token }));
  assert.equal(fieldOnly.status, 403, "câmpul singur a trecut");
});

test("un jeton pre-auth expirat sau semnat cu alt secret e refuzat", async () => {
  // Un cookie rămas într-un browser de pe o mașină comună nu are voie să
  // trăiască la nesfârșit, iar unul semnat cu alt secret nu e al nostru deloc.
  const own = new PreAuthCsrf(SESSION_SECRET);
  const [staleCookie, staleToken] =
    own.issue(Date.now() - (PREAUTH_CSRF_TTL_S + 1) * 1000);
  const stale = await loginPost(formRequest(
    "/login", { username: USERNAME, password: PASSWORD, csrf_token: staleToken },
    { cookies: { sentinel_csrf: staleCookie } }));
  assert.equal(stale.status, 403, "un jeton expirat a trecut");

  const [foreignCookie, foreignToken] =
    new PreAuthCsrf(`${SESSION_SECRET}-altul`).issue();
  const foreign = await loginPost(formRequest(
    "/login", { username: USERNAME, password: PASSWORD, csrf_token: foreignToken },
    { cookies: { sentinel_csrf: foreignCookie } }));
  assert.equal(foreign.status, 403, "un jeton semnat cu alt secret a trecut");
});

test("POST /totp fără jetonul SESIUNII e refuzat, iar sesiunea rămâne în așteptare",
     async () => {
  // După prima etapă există o sesiune, deci jetonul cerut e al ei — cel pre-auth
  // n-ar fi legat de nimic. Fără verificare, o pagină ostilă ar putea încerca
  // coduri în numele cuiva care e la jumătatea autentificării.
  const token = await loginToPending();
  const pair = await preauthPair(loginGet);

  const res = await totpPost(formRequest(
    "/totp", { code: currentCode(fixture.totpSecret), csrf_token: pair.token },
    { cookies: { sentinel_session: token, sentinel_csrf: pair.cookie } }));
  assert.equal(res.status, 403);
  assert.equal(fixture.db.sessions[0].pending_totp, 1,
               "sesiunea a fost promovată de o cerere fără CSRF valid");
});

// ---------------------------------------------------------------------------
// Antetele: CSP, cache, cookie
// ---------------------------------------------------------------------------
/** Câte un răspuns REAL din fiecare formă de răspuns pe care o dau rutele. */
async function everyKindOfResponse(): Promise<{ what: string; res: Response }[]> {
  const token = await loginToPending();
  const pair = await preauthPair(loginGet);
  return [
    { what: "GET /login", res: await loginGet(getRequest("/login")) },
    { what: "POST /login refuzat",
      res: await loginPost(formRequest("/login", { username: USERNAME })) },
    { what: "POST /login reușit", res: await login() },
    { what: "GET /totp",
      res: await totpGet(getRequest("/totp", { cookies: { sentinel_session: token } })) },
    { what: "POST /totp cu cod greșit",
      res: await totpPost(formRequest(
        "/totp", { code: "000000", csrf_token: fixture.db.sessions[0].csrf_token },
        { cookies: { sentinel_session: token } })) },
    { what: "GET /logout", res: await logoutGet() },
    { what: "POST /logout",
      res: await logoutPost(formRequest(
        "/logout", { csrf_token: pair.token },
        { cookies: { sentinel_csrf: pair.cookie } })) },
  ];
}

test("fiecare răspuns poartă no-store — o pagină autentificată din cache e a altcuiva",
     async () => {
  // Pe un panou autentificat, cache-ul e un bug de CONFIDENȚIALITATE. Antetul e
  // ce se poate dovedi de aici; că marginea CDN-ului îl respectă se dovedește pe
  // gazdă, cu procedura din `watcher/INCARCARE-HOSTINGER.md`.
  const all = await everyKindOfResponse();
  assert.ok(all.length >= 7,
            "lista de răspunsuri a ieșit mai scurtă decât rutele livrate; o listă " +
            "care se golește e un test care nu verifică nimic");
  for (const { what, res } of all) {
    assert.match(String(res.headers.get("cache-control")), /no-store/,
                 `${what} nu poartă no-store`);
  }
});

test("CSP-ul emis n-are unsafe-inline și n-are origini externe", async () => {
  // Panoul e randat pe server tocmai ca politica asta să fie posibilă. Un
  // `unsafe-inline` strecurat aici desface apărarea împotriva XSS pentru tot
  // panoul, iar un nonce servit prin CDN se strică într-un fel care duce chiar
  // la adăugarea lui.
  const all = await everyKindOfResponse();
  assert.ok(all.length >= 7, "lista de răspunsuri s-a golit");
  for (const { what, res } of all) {
    const csp = String(res.headers.get("content-security-policy"));
    assert.equal(csp, CONTENT_SECURITY_POLICY, `${what} are altă politică`);
    assert.ok(!csp.includes("unsafe-inline"), `${what}: CSP cu unsafe-inline`);
    assert.ok(!csp.includes("unsafe-eval"), `${what}: CSP cu unsafe-eval`);
    assert.ok(!/https?:\/\//.test(csp), `${what}: CSP cu o origine externă`);
    for (const directive of ["default-src 'self'", "script-src 'self'",
                             "frame-ancestors 'none'", "form-action 'self'",
                             "base-uri 'none'", "object-src 'none'"]) {
      assert.ok(csp.includes(directive), `${what}: CSP fără „${directive}”`);
    }
  }
});

test("paginile servite n-au niciun script și niciun stil în linie", async () => {
  // Politica de mai sus le-ar bloca oricum — dar atunci simptomul ar fi „pagina
  // nu merge", iar reparația evidentă sub presiune e slăbirea politicii. Mai
  // bine să nu existe.
  const pages = [await (await loginGet(getRequest("/login"))).text()];
  const token = await loginToPending();
  pages.push(await (await totpGet(
    getRequest("/totp", { cookies: { sentinel_session: token } }))).text());
  assert.equal(pages.length, 2);
  for (const html of pages) {
    assert.ok(!/<script/i.test(html), "pagina conține un <script>");
    assert.ok(!/\sstyle\s*=/i.test(html), "pagina conține un atribut style=");
    assert.ok(!/\son[a-z]+\s*=/i.test(html), "pagina conține un handler inline");
  }
});

test("cookie-ul de sesiune e HttpOnly, Secure, SameSite=Strict, Path=/", async () => {
  // Fără `HttpOnly`, un XSS citește sesiunea. Fără `Secure`, o citește oricine e
  // pe rețea. Fără `SameSite=Strict`, o navigare venită de pe o pagină ostilă o
  // trimite cu ea.
  const res = await login();
  const line = setCookieFor(res, "sentinel_session");
  assert.ok(line, "autentificarea reușită nu a pus cookie-ul de sesiune");
  for (const flag of ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"]) {
    assert.ok((line as string).includes(flag), `cookie-ul de sesiune n-are ${flag}: ${line}`);
  }
});

test("cookie-ul sesiunii ÎN AȘTEPTARE trăiește 5 minute, nu 12 ore", async () => {
  // Rândul e mărginit oricum (`session.ts`: `Math.min(PENDING_TOTP_TTL_S, ttlS)`,
  // iar `sessionByToken` filtrează pe `expires_at`), deci un cookie mai lung ar
  // fi doar un jeton MORT ținut într-un browser de pe o mașină comună. Ce apără
  // testul ăsta e ziua în care mărginirea aia se rescrie: atunci cele două
  // numere trebuie să nu poată diverge tăcut, iar 12 ore de sesiune pe jumătate
  // autentificată e chiar al doilea factor amânat o zi de lucru.
  const res = await login();
  assert.equal(res.status, 303);
  const line = setCookieFor(res, "sentinel_session");
  assert.ok(line, "prima etapă nu a pus cookie-ul de sesiune");
  assert.ok(PENDING_TOTP_TTL_S < SESSION_TTL_S, "cele două TTL-uri nu mai diferă");
  assert.match(String(line), new RegExp(`Max-Age=${PENDING_TOTP_TTL_S}\\b`),
               `cookie-ul etapei întâi n-are TTL-ul sesiunii în așteptare: ${line}`);
});

// ---------------------------------------------------------------------------
// Drumul bun
// ---------------------------------------------------------------------------
test("parolă → al doilea factor → sesiune promovată, cu jetonul ROTIT", async () => {
  // Rotirea nu e igienă: dacă jetonul primei etape a scăpat între cele două
  // etape, valoarea scursă nu mai deschide nimic din clipa asta.
  const first = await login();
  assert.equal(first.status, 303);
  assert.equal(first.headers.get("location"), "/totp");
  const pendingToken = cookiesOf(first).get("sentinel_session") as string;
  assert.equal(cookiesOf(first).get("sentinel_csrf"), "",
               "jetonul pre-auth nu a fost șters după ce și-a făcut treaba");
  assert.equal(fixture.db.sessions.length, 1);
  assert.equal(fixture.db.sessions[0].pending_totp, 1);

  const second = await totpPost(formRequest(
    "/totp",
    { code: currentCode(fixture.totpSecret), csrf_token: fixture.db.sessions[0].csrf_token },
    { cookies: { sentinel_session: pendingToken } }));
  assert.equal(second.status, 303);
  assert.equal(second.headers.get("location"), "/panel");

  const fullToken = cookiesOf(second).get("sentinel_session");
  assert.ok(fullToken, "a doua etapă nu a pus cookie-ul");
  assert.notEqual(fullToken, pendingToken, "jetonul NU a fost rotit");
  assert.equal(fixture.db.sessions[0].pending_totp, 0);
  // Reușita se consemnează pe cont: fără asta, „când m-am autentificat ultima
  // dată de aici?" n-are unde să fie citit.
  assert.notEqual(fixture.db.users[0].last_login_at, null,
                  "autentificarea dusă la capăt nu a lăsat nicio urmă pe cont");
});

test("același cod TOTP nu merge de două ori în aceeași fereastră", async () => {
  // Destul pentru cineva care l-a citit peste umăr, sau care reia o cerere
  // capturată. Contorul se consumă în SQL, cu `<` strict.
  const token = await loginToPending();
  const code = currentCode(fixture.totpSecret);
  const csrf = fixture.db.sessions[0].csrf_token;

  const first = await totpPost(formRequest(
    "/totp", { code, csrf_token: csrf }, { cookies: { sentinel_session: token } }));
  assert.equal(first.status, 303);

  // A doua sesiune, același cod: contorul e deja consumat.
  const again = await loginToPending();
  const second = await totpPost(formRequest(
    "/totp", { code, csrf_token: fixture.db.sessions[1].csrf_token },
    { cookies: { sentinel_session: again } }));
  assert.equal(second.status, 401);
  assert.match(await second.text(), /deja folosit/);
  assert.equal(fixture.db.sessions[1].pending_totp, 1);
});

test("GET /totp fără sesiune trimite la /login, nu arată formularul", async () => {
  // Un formular de al doilea factor servit fără prima etapă ar fi o etapă care
  // se poate sări.
  const res = await totpGet(getRequest("/totp"));
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/login?e=expired");
});

// ---------------------------------------------------------------------------
// Parola: plafoane aplicate ÎNAINTE de Argon2
// ---------------------------------------------------------------------------
test("o parolă peste plafon e refuzată ÎNAINTE de Argon2 — dovedit prin timp",
     async () => {
  // `verifyPassword` NU aplică `MAX_PASSWORD_LENGTH`: doar `hashPassword` cheamă
  // `validatePasswordStrength`. Măsurat în piesa 1, o parolă de 50 MB se verifică
  // în 212 ms și costă +76 MiB. Ruta e singurul loc care poate mărgini câmpul.
  //
  // Proba e prin EFECT, nu prin citirea codului: o verificare reală costă ~140 ms,
  // iar refuzul trebuie să fie cu un ordin de mărime mai ieftin. Reperul se
  // măsoară în același test, pe aceeași mașină, ca să nu depindă de nicio cifră
  // scrisă de mână.
  const startReal = Date.now();
  const real = await login({ password: `${PASSWORD}-gresit` });
  const realMs = Date.now() - startReal;
  assert.equal(real.status, 401);

  const before = failures().length;
  const startCapped = Date.now();
  const capped = await login({ password: "x".repeat(MAX_PASSWORD_LENGTH + 1) });
  const cappedMs = Date.now() - startCapped;

  assert.equal(capped.status, 401, "parola peste plafon a primit alt cod decât un refuz");
  assert.ok(cappedMs * 3 < realMs,
            `refuzul a costat ${cappedMs} ms iar o verificare reală ${realMs} ms: ` +
            "parola peste plafon a ajuns totuși la Argon2");

  // Și NU se numără — invers față de cum era până pe 17 august 2026.
  //
  // Argumentul de atunci („altfel plafonul ar fi un mod de a ghici la nesfârșit
  // fără să atingi vreodată fereastra") era greșit în ambele capete: o parolă
  // peste `MAX_PASSWORD_LENGTH` nu poate fi parola nimănui, fiindcă
  // `hashPassword` aplică plafonul la punere — deci nu e o ghicire. Ce era, în
  // schimb, e chiar aserțiunea de deasupra citită invers: un rând într-o tabelă
  // care E starea a trei plafoane, la preț de o inserare, cu un ordin de mărime
  // mai ieftin decât rândul unei încercări adevărate. Adică exact combustibilul
  // cu care se ține panoul închis.
  assert.equal(failures().length, before,
               "refuzul unei parole peste plafon s-a numărat ca încercare eșuată: " +
               "cea mai ieftină cerere din tot fișierul hrănește plafonul global");
  assert.ok(warn.lines.some((line) => line.join(" ").includes("parolă peste plafon")),
            "refuzul n-a lăsat nicio urmă nici în jurnalul procesului: mutat din " +
            "tabelă în nicăieri");
});

test("un corp uriaș e oprit LA CITIRE, nu bufferizat și măsurat după", async () => {
  // Măsurat prin efect: se numără câte bucăți a cerut ruta din corp. Un plafon
  // aplicat după `await req.text()` ar fi citit toate cele 60 MiB — adică memoria
  // e alocată de cineva care n-are niciun cont, iar pe găzduirea partajată
  // procesul ăsta servește și ingestia arhivei tuturor instanțelor.
  let pulled = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulled++;
      if (pulled > 60) { controller.close(); return; }
      controller.enqueue(new Uint8Array(1024 * 1024));
    },
  });
  const req = new Request(`${ORIGIN}/login`, {
    method: "POST",
    body,
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    duplex: "half",
  } as RequestInit);

  const res = await loginPost(req);
  assert.equal(res.status, 413);
  assert.ok(pulled < 10,
            `ruta a cerut ${pulled} bucăți de 1 MiB dintr-un corp pe care l-a ` +
            `refuzat; plafonul e de ${MAX_FORM_BYTES} de octeți`);
  assert.equal(attempts().length, 0,
               "un corp refuzat la citire a fost numărat ca încercare, deși nu " +
               "se știe nici măcar ce nume s-a tastat");
});

test("o parolă goală e refuzată fără să ajungă la Argon2", async () => {
  // Măsurat în piesa 1: parola goală e singura intrare controlată de client pe
  // care `argon2Verify` o refuză ARUNCÂND, iar `verifyPassword` înghite excepția
  // ca „parolă greșită". Refuzul trebuie să fie al nostru, nu un `catch`.
  const startReal = Date.now();
  await login({ password: `${PASSWORD}-gresit` });
  const realMs = Date.now() - startReal;

  const start = Date.now();
  const res = await login({ password: "" });
  const emptyMs = Date.now() - start;
  assert.equal(res.status, 401);
  assert.ok(emptyMs * 3 < realMs,
            `parola goală a costat ${emptyMs} ms față de ${realMs} ms: a ajuns la Argon2`);
});

test("coada Argon2 plină → 503 cu Retry-After, NU 401, și nu se numără", async () => {
  // Un 401 aici ar spune „credențiale greșite" despre o parolă pe care nimeni
  // n-a verificat-o: ar bloca un cont care n-a greșit nimic, printr-o rafală
  // anonimă, și ar transforma plafonul cozii în chiar oracolul de enumerare pe
  // care hashul-fantomă există să-l închidă. Un 500 ar trimite pe cineva să
  // caute un defect care nu există.
  const total = MAX_CONCURRENT_ARGON2 + MAX_QUEUED_ARGON2 + 3;
  const pair = await preauthPair(loginGet);
  const before = failures().length;

  const responses = await Promise.all(Array.from({ length: total }, () =>
    loginPost(formRequest(
      "/login",
      { username: USERNAME, password: `${PASSWORD}-gresit`, csrf_token: pair.token },
      { cookies: { sentinel_csrf: pair.cookie } }))));

  const busy = responses.filter((res) => res.status === 503);
  // Numărul exact nu se afirmă: ruta face câteva await-uri de bază de date
  // înainte de semafor, iar ordinea lor nu e o proprietate a codului livrat. Ce
  // se afirmă e că refuzul EXISTĂ, că are alt cod decât un refuz de credențiale,
  // și că nu costă nimănui o încercare.
  assert.ok(busy.length >= 1,
            `${total} cereri simultane și niciun refuz de supraîncărcare: ` +
            "plafonul cozii nu ajunge la rută");
  for (const res of busy) {
    assert.ok(res.headers.get("retry-after"), "refuzul 503 n-are Retry-After");
  }
  assert.equal(responses.filter((res) => res.status === 401).length + busy.length, total,
               "o cerere a primit un cod care nu e nici refuz de credențiale, nici 503");
  assert.equal(failures().length, before + total - busy.length,
               "un refuz de supraîncărcare a fost numărat ca încercare eșuată");
});

// ---------------------------------------------------------------------------
// Numele de utilizator
// ---------------------------------------------------------------------------
test("un nume non-ASCII e refuzat de APLICAȚIE, cu mesaj", async () => {
  // `users.username` e `ascii_bin`, iar refuzul bazei e zgomotos doar sub
  // `STRICT_TRANS_TABLES` — `sql_mode` al găzduirii nu e măsurat. Sub un mod
  // nestrict, un cont s-ar crea sub un nume cu `?` pe care nimeni nu-l poate
  // retasta, cu o cheie unică peste el.
  const res = await login({ username: "operatoră" });
  assert.equal(res.status, 400);
  assert.match(await res.text(), /doar caractere ASCII/);

  // Și nu scrie nimic: refuzul se ia fără să se verifice vreo parolă — fără
  // Argon2, fără măcar o căutare de cont —, deci rândul lui ar fi combustibil
  // pentru plafonul global la preț de o inserare. Vezi „Ce are voie să
  // hrănească un plafon" în `lib/auth/login.ts`. Urma rămâne, dar în jurnalul
  // procesului, unde nu numără nimic.
  assert.equal(attempts().length, 0,
               "un nume non-ASCII a scris un rând într-o tabelă care e starea a " +
               "trei plafoane, fără să fi verificat nicio parolă");
  assert.ok(warn.lines.some((line) => line.join(" ").includes("nume non-ASCII")),
            "refuzul n-a lăsat nicio urmă nicăieri");
});

test("numele tastat se taie la 64 înainte să atingă registrul", async () => {
  // `login_attempts.username` are 64 de caractere. Fără tăiere, sub un `sql_mode`
  // nestrict rândul ar intra tăiat și tăcut, iar sub unul strict ar fi o eroare
  // de inserare — adică o autentificare care pică din alt motiv decât cel
  // adevărat.
  await login({ username: "a".repeat(200) });
  assert.equal(attempts().length, 1);
  assert.equal(String(attempts()[0].username).length, 64);
});

// ---------------------------------------------------------------------------
// Limitarea de rată, cele trei straturi
// ---------------------------------------------------------------------------
/**
 * Cererile pe care le poate trimite cineva care ȘTIE parola unui cont ce nu se
 * poate autentifica — dezactivat, sau fără al doilea factor înrolat.
 *
 * Amândouă ramurile scriu un rând `locked`, numărat de toate trei ferestrele, și
 * amândouă răspund același lucru de fiecare dată. De-aia sunt aici împreună:
 * fereastra per cont trebuie citită DEASUPRA amândurora.
 */
const CANNOT_LOG_IN: [string, Partial<UserRow>][] = [
  ["cont dezactivat", { disabled: 1 }],
  ["fără al doilea factor înrolat", { totp_confirmed_at: null }],
];

test("un cont care NU poate intra scrie cel mult `limit` rânduri per fereastră",
     async () => {
  // Sonda, verbatim: 12 cereri cu parola CORECTĂ pe fiecare formă de cont care
  // nu se poate autentifica.
  //
  // Ce se strică fără aserțiunea asta, măsurat: 12 cereri scriau 12 rânduri
  // numărate de toate cele trei ferestre. Cu 195 de rânduri deja în fereastra
  // globală, 5 cereri de pe un cont dezactivat duceau plafonul la 200, iar un AL
  // DOILEA cont, sănătos, primea 503. Cine poate face asta e exact cine știe
  // parola unui cont pe care operatorul tocmai l-a dezactivat — adică populația
  // pentru care s-a apăsat „dezactivează".
  //
  // Aserțiunea prinde și mutația care mută citirea ferestrei SUB ramurile care
  // scriu (`M-G`): atunci `perAccount` e citit prea târziu pentru amândouă, iar
  // numărul de rânduri sare înapoi la 12.
  for (const [what, over] of CANNOT_LOG_IN) {
    await seed(over);
    for (let i = 0; i < 12; i++) {
      const res = await login();
      assert.equal(res.status, 403, `${what}: cererea ${i + 1} a primit alt cod`);
    }
    assert.equal(failures().length, MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP,
                 `${what}: ${failures().length} rânduri numărate din 12 cereri; ` +
                 "fereastra per cont nu e citită deasupra ramurii care scrie");
    assert.equal(fixture.db.sessions.length, 0, `${what}: a primit o sesiune`);
  }
});

test("cu fereastra plină, un cont care nu poate intra nu mai scrie NIMIC",
     async () => {
  // Cealaltă jumătate: mărginirea nu e „mai rar", e „deloc". Dacă rândul refuzat
  // ar intra totuși în tabelă, ar hrăni chiar numărătoarea care l-a oprit, iar
  // plafonul global n-ar mai coborî cât timp cineva mai trimite o cerere din când
  // în când. Panoul n-are ieșire de urgență.
  await seed({ disabled: 1 });
  seedAccountFailures(MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP);
  const before = failures().length;

  for (let i = 0; i < 3; i++) {
    const res = await login();
    assert.equal(res.status, 403, `reîncercarea ${i + 1} a primit alt cod`);
  }
  assert.equal(failures().length, before,
               "un rând oprit de fereastră s-a adăugat totuși la propria ei " +
               "numărătoare");
  assert.ok(warn.lines.some((line) => line.join(" ").includes("nescris")),
            "rândul nescris n-a lăsat nicio urmă în jurnalul procesului");

  // Și mărginirea e o FEREASTRĂ, nu un plafon permanent: după ce eșecurile ies
  // din ea, contul scrie din nou. Fără asta, o tabelă odată plină ar fi tăcut
  // pentru totdeauna despre contul ăsta.
  fixture.db.nowMs += (FAILURE_WINDOW_MINUTES + 1) * 60_000;
  await login();
  assert.equal(failures().length, before + 1,
               "după ce fereastra s-a golit, contul tot nu mai scrie nimic");
});

test("fereastra unui cont numără DOAR eșecurile lui, și doar eșecurile", async () => {
  // Trei feluri de a strica stratul per cont fără ca nimic să pară stricat:
  //
  //   * fără filtrul pe nume, eșecurile ORICUI îl mărginesc pe toată lumea —
  //     adică rândurile legitime ale unui cont dispar din urmă fiindcă altcineva
  //     a greșit parola pe un cont care nici nu există;
  //   * fără `result <> 'ok'`, autentificările REUȘITE se numără ca eșecuri;
  //   * fără filtrul pe etapă, eșecurile de la al doilea factor se amestecă cu
  //     cele de parolă.
  //
  // Se observă pe contul care NU poate intra, fiindcă acolo fereastra chiar
  // decide ceva: pe unul sănătos, parola corectă trece oricum.
  await seed({ disabled: 1 });
  seedAccountFailures(MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP, "altcineva");
  for (let i = 0; i < MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP; i++) {
    fixture.db.loginAttempts.push({
      at: fixture.db.nowMs, username: USERNAME, ip: null, user_agent: null,
      result: "ok", stage: "password", session_id: null, detail: null,
    });
    fixture.db.loginAttempts.push({
      at: fixture.db.nowMs, username: USERNAME, ip: null, user_agent: null,
      result: "bad_totp", stage: "totp", session_id: null, detail: null,
    });
  }
  const before = failures().length;

  await login();
  assert.equal(failures().length, before + 1,
               "rândul contului nu s-a scris: fereastra lui a fost umplută de " +
               "eșecurile altcuiva, de propriile lui reușite, sau de eșecuri de " +
               "la altă etapă");
});

test("fereastra unui cont NU mai refuză parola CORECTĂ a operatorului", async () => {
  // Decizia operatorului din 17 august 2026. Până atunci, oricine putea scrie
  // `limit` eșecuri pe numele operatorului — 5 la fiecare 15 minute, adică ~20
  // de cereri pe oră, fără să știe nimic — iar operatorul primea 429 cu parola
  // bună în mână. Era ultima negare permanentă la îndemâna oricui.
  //
  // Proba merge până la CAPĂT, nu doar până la 303: fereastra etapei a doua
  // numără doar eșecurile ETAPEI A DOUA, altfel sesiunea tocmai obținută ar fi
  // revocată pe loc, iar operatorul ar vedea „Sesiune invalidă" la nesfârșit.
  // Adică aceeași ușă închisă, mutată cu un pas mai încolo.
  seedAccountFailures(MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP);

  const first = await login();
  assert.equal(first.status, 303,
               "parola corectă a fost refuzată de eșecurile scrise de altcineva");
  const token = cookiesOf(first).get("sentinel_session") as string;
  assert.ok(token, "prima etapă nu a pus cookie-ul de sesiune");

  const second = await totpPost(formRequest(
    "/totp",
    { code: currentCode(fixture.totpSecret),
      csrf_token: fixture.db.sessions[0].csrf_token },
    { cookies: { sentinel_session: token } }));
  assert.equal(second.status, 303, "al doilea factor a refuzat o sesiune validă");
  assert.equal(second.headers.get("location"), "/panel");
  assert.equal(fixture.db.sessions[0].pending_totp, 0,
               "sesiunea nu a fost promovată: operatorul e tot afară");
});

test("la etapa a doua, fereastra contului CHIAR refuză — și acolo cere parola",
     async () => {
  // Cealaltă față a aceleiași decizii: pârghia care închide o etapă cere
  // credențialul etapei dinainte. Codurile TOTP se ghicesc doar de cine a trecut
  // deja de parolă, deci acolo fereastra rămâne un refuz — 6 cifre n-ar rezista
  // altfel.
  const token = await loginToPending();
  const csrf = fixture.db.sessions[0].csrf_token;
  for (let i = 0; i < MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP; i++) {
    fixture.db.loginAttempts.push({
      at: fixture.db.nowMs, username: USERNAME, ip: null, user_agent: null,
      result: "bad_totp", stage: "totp", session_id: null, detail: null,
    });
  }

  const res = await totpPost(formRequest(
    "/totp", { code: currentCode(fixture.totpSecret), csrf_token: csrf },
    { cookies: { sentinel_session: token } }));
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/login?e=expired");
  assert.notEqual(fixture.db.sessions[0].revoked_at, null,
                  "sesiunea a supraviețuit peste plafonul de coduri greșite");
});

test("al doilea factor trece și el prin limitator, și nu scrie pe lângă el", async () => {
  // Etapa a doua scrie și ea în `login_attempts` (`bad_totp`). O scutire aici —
  // „are deja o sesiune, deci e de-ai casei" — ar fi a doua ușă pe lângă
  // limitator, exact ce s-a reparat la etapa întâi.
  const token = await loginToPending();
  const csrf = fixture.db.sessions[0].csrf_token;
  for (let i = 0; i < GLOBAL_FAILURE_LIMIT; i++) {
    fixture.db.loginAttempts.push({
      at: fixture.db.nowMs, username: `u${i}`, ip: null, user_agent: null,
      result: "bad_password", stage: "password", session_id: null, detail: null,
    });
  }
  const before = attempts().length;

  const res = await totpPost(formRequest(
    "/totp", { code: currentCode(fixture.totpSecret), csrf_token: csrf },
    { cookies: { sentinel_session: token } }));

  assert.equal(res.status, 503, "al doilea factor a trecut peste plafonul global");
  assert.ok(res.headers.get("retry-after"));
  assert.equal(attempts().length, before,
               "etapa a doua a scris un rând în tabela pe care o numără plafonul");
  assert.equal(fixture.db.sessions[0].pending_totp, 1,
               "sesiunea a fost promovată în timp ce panoul era sub plafon");
});

test("un cont peste plafon nu se trădează în fața unei parole greșite", async () => {
  // „Prea multe încercări pe contul ăsta" spune că un cont EXISTĂ. Îl aude doar
  // cine avea deja parola; pentru oricine altcineva mesajul rămâne cel generic.
  seedAccountFailures(MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP);
  const wrong = await login({ password: `${PASSWORD}-gresit` });
  assert.equal(wrong.status, 401);
  const body = await wrong.text();
  assert.ok(!/Prea multe încercări eșuate pe contul/.test(body),
            "refuzul a spus că un cont peste plafon există");
  assert.match(body, /Utilizator sau parolă incorectă/);
});

test("cu un antet de încredere, pragul per cont e cel mai larg", async () => {
  // Compensarea e observabilă, nu declarativă. Se observă pe contul care NU
  // poate intra: acolo pragul chiar decide câte rânduri se scriu, iar `10` și
  // `5` dau două numere diferite.
  //
  // Nu pe o parolă corectă și un 303, cum era scris până pe 17 august 2026:
  // fereastra nu mai refuză o parolă corectă, deci aserțiunea aia ar fi trecut
  // și cu pragul strict aplicat — un test verde care nu mai măsoară nimic.
  assert.ok(MAX_FAILED_LOGINS_WITH_TRUSTED_IP > MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP);
  await seed({ disabled: 1 });
  setEnv({ AGGREGATOR_CLIENT_IP_HEADER: IP_HEADER });
  const options = { headers: { [IP_HEADER]: CLIENT_IP } };

  for (let i = 0; i < MAX_FAILED_LOGINS_WITH_TRUSTED_IP + 2; i++) {
    const res = await login({}, options);
    assert.equal(res.status, 403, `cererea ${i + 1} a primit alt cod`);
  }
  assert.equal(failures().length, MAX_FAILED_LOGINS_WITH_TRUSTED_IP,
               "pragul strict s-a aplicat deși sursa e de încredere");
  // Iar adresa chiar ajunge în coloană, în forma mapată pe care o acceptă INET6.
  assert.equal(attempts()[0].ip, CLIENT_IP_STORED);
});

test("stratul per sursă oprește o rafală ÎNAINTE de orice verificare", async () => {
  setEnv({ AGGREGATOR_CLIENT_IP_HEADER: IP_HEADER });
  for (let i = 0; i < IP_FAILURE_LIMIT; i++) {
    fixture.db.loginAttempts.push({
      at: fixture.db.nowMs, username: "altcineva", ip: CLIENT_IP_STORED,
      user_agent: null, result: "bad_password", stage: "password",
      session_id: null, detail: null,
    });
  }

  const res = await login({}, { headers: { [IP_HEADER]: CLIENT_IP } });
  assert.equal(res.status, 429);
  assert.ok(res.headers.get("retry-after"));
  assert.equal(failures().filter((row) => row.username === USERNAME).length, 0,
               "refuzul per sursă a fost numărat contra contului");
  assert.equal(attempts().length, IP_FAILURE_LIMIT,
               "refuzul per sursă s-a scris în chiar tabela pe care o numără: " +
               "plafonul s-ar hrăni singur și nu s-ar mai stinge niciodată");
});

test("antetul declarat, sosit ca LISTĂ, nu e de încredere — și se vede în efect",
     async () => {
  // O listă înseamnă că marginea a ADĂUGAT la ce era, nu că a înlocuit. Deci
  // valoarea din față e aleasă de client, iar o limitare per sursă pe ea ar
  // permite oricui să blocheze adresa operatorului.
  setEnv({ AGGREGATOR_CLIENT_IP_HEADER: IP_HEADER });
  for (let i = 0; i < IP_FAILURE_LIMIT; i++) {
    fixture.db.loginAttempts.push({
      at: fixture.db.nowMs, username: "altcineva", ip: CLIENT_IP_STORED,
      user_agent: null, result: "bad_password", stage: "password",
      session_id: null, detail: null,
    });
  }

  const res = await login({ password: `${PASSWORD}-gresit` },
                          { headers: { [IP_HEADER]: `${CLIENT_IP}, 203.0.113.9` } });
  assert.equal(res.status, 401,
               "o adresă pretinsă printr-o listă a fost totuși folosită la limitare");
  const written = attempts()[attempts().length - 1];
  assert.equal(written.ip, null,
               "o adresă în care nu se poate avea încredere a ajuns într-o coloană INET6");
  assert.match(String(written.detail), /ip-pretins\(list\)/);
});

test("plafonul global → 503 pe ORICE formă de nume, iar refuzul nu se numără",
     async () => {
  // Ultima plasă: singurul strat care nu depinde de identitatea sursei. Costul
  // lui e o pârghie de negare de serviciu, iar atenuarea e ca refuzul să nu se
  // adauge la numărătoarea care l-a produs — altfel plafonul, o dată atins, nu
  // s-ar mai stinge niciodată.
  //
  // Cele TREI forme de nume, nu doar una: până pe 17 august 2026 testul ăsta
  // exersa doar un nume bine format — singura cale pe care proprietatea ținea.
  // Numele gol și cel non-ASCII își scriau rândul ȘI se întorceau ÎNAINTE de
  // limitator, deci cu plafonul atins fiecare cerere de-a atacatorului îl
  // prelungea: ~1 cerere la 4,5 secunde ținea panoul închis pentru totdeauna,
  // fără cont și fără parolă. Testul citea ca dovadă a proprietății generale și
  // dovedea cazul particular.
  for (let i = 0; i < GLOBAL_FAILURE_LIMIT; i++) {
    fixture.db.loginAttempts.push({
      at: fixture.db.nowMs, username: `u${i}`, ip: null, user_agent: null,
      result: "bad_password", stage: "password", session_id: null, detail: null,
    });
  }

  const shapes: [string, string][] = [
    ["nume normal", USERNAME],
    ["nume gol", ""],
    ["nume non-ASCII", "operatoră"],
  ];
  for (const [what, username] of shapes) {
    const before = attempts().length;
    const res = await login({ username });
    assert.equal(res.status, 503, `${what}: alt cod decât refuzul global`);
    assert.ok(res.headers.get("retry-after"), `${what}: refuzul n-are Retry-After`);
    // Textul, nu doar codul: o excepție scăpată din rută ar da tot 503, prin
    // `guarded`, cu alt corp — adică ordinea inversă ar trece drept reparație.
    assert.match(await res.text(), /sub o rafală/,
                 `${what}: 503-ul nu e cel al plafonului global`);
    assert.equal(attempts().length, before,
                 `${what}: refuzul global s-a scris în tabela pe care o numără`);
  }
  assert.equal(attempts().length, GLOBAL_FAILURE_LIMIT);
  assert.equal(fixture.db.sessions.length, 0);
});

test("nume gol, o cerere la 3 secunde, 40 de minute: operatorul intră la fiecare pas",
     async () => {
  // Sonda care a respins reparația de două ori, verbatim. Atacatorul trimite un
  // nume GOL la fiecare 3 secunde, fără cont și fără parolă; operatorul încearcă
  // cu parola CORECTĂ la fiecare 2 minute, 40 de minute la rând (ceasul dublului,
  // deci probă în secunde).
  //
  // Ce se măsura înainte, și de ce trecea: o singură cerere cu nume gol, cu
  // fereastra globală deja presaturată la 200 — adică EXACT starea în care
  // proprietatea ține, niciodată starea care o produce. Măsurat atunci: 598 de
  // rânduri scrise de atacator, iar operatorul primea 503 de la minutul 10
  // înainte, la nesfârșit.
  //
  // Bucla merge pe ceasul dublului fiindcă ferestrele sunt calculate în SQL din
  // `UTC_TIMESTAMP(6)`, iar dublul îl citește de acolo: 800 de pași de 3 secunde
  // sunt 40 de minute pentru limitator.
  const STEP_MS = 3_000;
  const OPERATOR_EVERY_MS = 120_000;
  const TOTAL_MS = 40 * 60_000;
  let operatorTries = 0;

  for (let elapsed = 0; elapsed < TOTAL_MS; elapsed += STEP_MS) {
    const attack = await login({ username: "" });
    assert.equal(attack.status, 401, `atacatorul a primit alt cod la ${elapsed} ms`);

    if (elapsed > 0 && elapsed % OPERATOR_EVERY_MS === 0) {
      const res = await login();
      assert.equal(res.status, 303,
                   `operatorul a fost refuzat (${res.status}) la minutul ` +
                   `${elapsed / 60_000}, cu parola CORECTĂ: plafonul global e ` +
                   "hrănit de cereri care nu verifică nicio parolă");
      operatorTries++;
    }
    fixture.db.nowMs += STEP_MS;
  }

  assert.equal(operatorTries, 19, `doar ${operatorTries} încercări ale operatorului`);
  assert.equal(failures().length, 0,
               `atacatorul a scris ${failures().length} rânduri numărate fără să ` +
               "aibă cont, parolă sau vreo verificare de parolă");
});

test("parolă goală: aceeași cerere gratuită, altă ușă — și nici ea nu hrănește",
     async () => {
  // Forma pe care n-a folosit-o nicio sondă de până acum: numele e BUN (trece de
  // amândouă verificările de nume, deci reparația de deasupra nu-l atinge), iar
  // parola e goală. `argon2Verify` aruncă pe o parolă goală, deci refuzul e al
  // nostru și se ia înainte de orice muncă — nici Argon2, nici căutarea contului.
  //
  // Adică exact predicatul din `login.ts`: nimeni n-a verificat nicio parolă.
  // Dacă regula ar fi fost aplicată doar celor două ramuri de NUME, ăsta ar fi
  // rămas un al treilea drum către același efect, la același preț.
  for (let i = 0; i < GLOBAL_FAILURE_LIMIT + 20; i++) {
    const res = await login({ password: "" });
    assert.equal(res.status, 401, `cererea ${i + 1} a primit alt cod`);
  }
  assert.equal(failures().length, 0,
               `${GLOBAL_FAILURE_LIMIT + 20} de cereri fără nicio parolă verificată ` +
               `au scris ${failures().length} rânduri numărate`);

  // Și panoul e deschis: plafonul global n-a fost armat de nimic din ce s-a
  // trimis mai sus.
  const ok = await login();
  assert.equal(ok.status, 303,
               "panoul e închis după o rafală de parole goale: plafonul global a " +
               "fost armat de cereri care nu costă nimic");
});

test("o numărătoare care nu se poate citi oprește autentificarea, nu o lasă să treacă",
     async () => {
  // „Nu știu" nu e „zero". Un limitator care, nereușind să citească, lasă să
  // treacă e un limitator care raportează că există — chiar tiparul din
  // `CLAUDE.md`.
  const db = fixture.db;
  const original = db.query.bind(db);
  db.query = async (sql: string, params: unknown[] = []) =>
    sql.includes("COUNT(*)") ? [[], []] : original(sql, params);

  const res = await login();
  assert.equal(res.status, 503);
  assert.equal(fixture.db.sessions.length, 0,
               "o autentificare a trecut cu limitatorul orb");
  assert.ok(error.lines.some((line) => line.join(" ").includes("POST /login")),
            "eșecul limitatorului nu a lăsat nicio urmă în jurnal");
});

// ---------------------------------------------------------------------------
// Conturi în stări speciale
// ---------------------------------------------------------------------------
test("o înrolare ÎNCEPUTĂ și neconfirmată NU cade înapoi pe parolă", async () => {
  // Eșecul pe care îl previne: operatorul cere `--totp`, greșește codul de
  // confirmare de trei ori, și contul rămâne cu secret dar neconfirmat. Dacă
  // starea asta ar intra cu parola singură, panoul ar arăta un cont „cu al
  // doilea factor" care de fapt nu-l cere niciodată — protejat pe hârtie.
  // De-asta ramura cu un singur factor se uită la LIPSA secretului, nu la
  // lipsa confirmării.
  await seed({ totp_confirmed_at: null });
  const res = await login();
  assert.equal(res.status, 403);
  assert.match(await res.text(), /neconfirmat/);
  assert.equal(fixture.db.sessions.length, 0,
               "o înrolare neterminată a deschis totuși o sesiune");
});

test("un cont fără NICIUN secret intră cu parola singură, direct în panou",
     async () => {
  // Al doilea factor e opțional de pe 19 august 2026. Eșecul pe care îl previne
  // testul: contul intră, dar cu o sesiune marcată `pending_totp`, iar
  // operatorul e trimis la `/totp`, unde nu poate face nimic fiindcă nu există
  // niciun secret din care să producă un cod — adică un cont creat cu succes și
  // imposibil de folosit.
  await seed({ totp_confirmed_at: null, totp_secret_enc: null });
  const res = await login();
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/panel",
               "un cont fără al doilea factor nu a ajuns in panou");
  assert.equal(fixture.db.sessions.length, 1);
  assert.equal(fixture.db.sessions[0].pending_totp, 0,
               "sesiunea a rămas în așteptare, deci moare în cinci minute");
});

test("un cont dezactivat NU intră, nici cu parola corectă", async () => {
  await seed({ disabled: 1 });
  const res = await login();
  assert.equal(res.status, 403);
  assert.equal(fixture.db.sessions.length, 0);
});

test("un hash de parolă stricat e o EROARE în jurnal, nu o «parolă greșită» tăcută",
     async () => {
  // `hash-wasm` raportează un hash ilizibil și o alocare eșuată prin același
  // `Error`, iar `verifyPassword` le înghite pe amândouă ca „parolă greșită".
  // Pentru operator, asta arată ca parola corectă respinsă la nesfârșit, fără
  // nimic nicăieri. Forma rândului se poate deosebi, deci se deosebește.
  await seed({ password_hash: "$2y$10$ceva-care-nu-e-argon2" });
  const res = await login();
  assert.equal(res.status, 401);
  assert.ok(error.lines.some((line) => line.join(" ").includes("Argon2id PHC")),
            "un rând stricat a trecut drept parolă greșită, fără nicio urmă");
});

test("un secret TOTP care nu se mai poate descifra spune ASTA, nu «cod greșit»",
     async () => {
  // Singurul eșec pe care nicio reîncercare nu-l poate repara. Spus ca „sesiune
  // expirată", trimite operatorul în roata formularului până îl limitează ceva —
  // exact ce s-a întâmplat pe server, și de-aia există `totp_key`.
  const token = await loginToPending();
  const csrf = fixture.db.sessions[0].csrf_token;
  // Secretul e rescris cu unul cifrat sub ALT secret de sesiune: chiar efectul
  // rotirii lui SENTINEL_SESSION_SECRET.
  fixture.db.users[0].totp_secret_enc = "v1.AAAA.BBBB.CCCC";

  const res = await totpPost(formRequest(
    "/totp", { code: currentCode(fixture.totpSecret), csrf_token: csrf },
    { cookies: { sentinel_session: token } }));
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/login?e=totp_key");
  assert.notEqual(fixture.db.sessions[0].revoked_at, null, "sesiunea nu a fost revocată");

  const page = await loginGet(getRequest("/login?e=totp_key"));
  assert.match(await page.text(), /reînrolat/);
});

// ---------------------------------------------------------------------------
// Deconectarea
// ---------------------------------------------------------------------------
test("GET /logout e 405, nu o deconectare", async () => {
  // Un `<img src=".../logout">` de pe orice pagină ostilă ar scoate operatorul
  // afară, iar simptomul ar arăta ca o pană a panoului.
  const res = await logoutGet();
  assert.equal(res.status, 405);
  assert.equal(res.headers.get("allow"), "POST");
});

test("POST /logout fără CSRF nu revocă nimic", async () => {
  const token = await loginToPending();
  const res = await logoutPost(formRequest("/logout", {},
                                           { cookies: { sentinel_session: token } }));
  assert.equal(res.status, 403);
  assert.equal(fixture.db.sessions[0].revoked_at, null,
               "o cerere fără CSRF a revocat sesiunea");
});

test("POST /logout revocă sesiunea și șterge cookie-urile", async () => {
  // Merge și pe o sesiune în AȘTEPTARE: butonul „Renunță" de pe pagina de al
  // doilea factor postează aici. Fără asta, cine a greșit contul așteaptă cinci
  // minute până expiră.
  const token = await loginToPending();
  const res = await logoutPost(formRequest(
    "/logout", { csrf_token: fixture.db.sessions[0].csrf_token },
    { cookies: { sentinel_session: token } }));

  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/login?e=logout");
  assert.notEqual(fixture.db.sessions[0].revoked_at, null, "sesiunea nu a fost revocată");
  assert.equal(fixture.db.sessions[0].revoked_reason, "logout");
  assert.equal(cookiesOf(res).get("sentinel_session"), "");
  assert.equal(cookiesOf(res).get("sentinel_csrf"), "");
});

test("deconectarea fără sesiune e o operație nulă REUȘITĂ", async () => {
  // Idempotentă: cine n-are sesiune e deja afară. Un refuz aici ar spune cuiva
  // dacă un cookie oarecare e o sesiune vie.
  const res = await logoutPost(formRequest("/logout", {}));
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/login?e=logout");
});
