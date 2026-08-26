/**
 * Antetele, cookie-urile și citirea formularelor pentru rutele de autentificare.
 *
 * Un singur loc, fiindcă fiecare dintre lucrurile de aici e o proprietate care
 * trebuie să fie pe FIECARE răspuns, inclusiv pe redirectări și pe refuzuri. O
 * rută care își compune singură antetele e o rută care le va uita pe una dintre
 * ramuri, iar ramura uitată e mereu cea de eroare.
 *
 * ## CSP: aceeași strictețe ca pe server, și de-aia panoul n-are nonce
 *
 * Politica de mai jos e cea din `deploy/nginx/sentinel-security-headers.conf`:
 * fără `unsafe-inline`, fără origini externe. Acordul dintre cele două e ținut
 * de `tests/unit/test_aggregator_csp_parity.py`, care citește AMBELE surse.
 * (Nu de `test_aggregator_auth_parity.py`, cum scria aici până pe 17 august
 * 2026: fișierul ăla nu conține cuvântul „Content-Security-Policy". O trimitere
 * greșită induce în eroare exact pe cine verifică următorul cuplajul ăsta.)
 *
 * Costul e că paginile de aici n-au niciun `<script>` și niciun `style=`. Ăsta
 * e prețul, și e plătit dinadins: alternativa — un nonce per răspuns — are pe un
 * CDN un mod de eșec anume. O pagină ajunsă în cache poartă un nonce expirat,
 * pagina se strică pentru toată lumea deodată, iar reparația evidentă sub
 * presiune e adăugarea lui `unsafe-inline`. Adică politica se pierde exact în
 * ziua în care e nevoie de ea. Zero JavaScript nu are cum să ajungă acolo.
 *
 * ## Cache: `no-store` pe fiecare răspuns, plus `force-dynamic` pe fiecare rută
 *
 * Pe un panou autentificat o pagină din cache nu e o problemă de prospețime, e
 * una de CONFIDENȚIALITATE: pagina unui om servită altuia. Trei mecanisme
 * independente, fiindcă apără de trei eșecuri diferite:
 *
 *   * `no-store` de aici — antetul de pe răspunsul propriu-zis;
 *   * antetul global din `next.config.mjs` — prinde o rută viitoare care uită;
 *   * `export const dynamic = "force-dynamic"` în fiecare rută — declarația
 *     către framework.
 *
 * Ce dovedește care: DOAR primul se poate proba de aici, citind antetul dintr-un
 * răspuns real (`tests/auth-routes.test.ts`). Că marginea CDN-ului îl respectă
 * NU se poate dovedi de pe mașina asta; proba aia e cea din
 * `watcher/INCARCARE-HOSTINGER.md` — două cereri la șase secunde distanță, cu o
 * valoare care trebuie să difere — și trebuie făcută pe gazdă, după publicare.
 */

/**
 * Politica de conținut. Identică, directivă cu directivă, cu cea a serverului.
 *
 * `form-action 'self'` nu e decorativ aici: fără el, o injecție care ar schimba
 * `action` a formularului de login ar trimite parola în altă parte, iar restul
 * politicii n-ar observa nimic.
 */
export const CONTENT_SECURITY_POLICY =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; " +
  "base-uri 'none'; object-src 'none'";

export const NO_STORE = "no-store, no-cache, must-revalidate, max-age=0";

/**
 * Antetele fiecărui răspuns al panoului.
 *
 * `Vary: Cookie` e acolo pentru cache-ul intermediar care ar ignora `no-store`:
 * dacă tot păstrează ceva, măcar să nu servească pagina unui om altuia. Nu e o
 * garanție — un intermediar care ignoră `no-store` poate ignora și asta — e a
 * doua încuietoare pe aceeași ușă.
 */
export function securityHeaders(): Record<string, string> {
  return {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "Cache-Control": NO_STORE,
    "Vary": "Cookie",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy":
      "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), " +
      "microphone=(), payment=(), usb=(), interest-cohort=()",
  };
}

// ---------------------------------------------------------------------------
// Cookie-uri
// ---------------------------------------------------------------------------
/** Numele cookie-ului de sesiune, ca pe server (`security.py:545`). */
export const SESSION_COOKIE = "sentinel_session";

/**
 * Fanioanele cookie-ului de sesiune. `Secure` e necondiționat.
 *
 * Nu depinde de nicio variabilă de mediu, și ăsta e chiar argumentul din
 * `security.py:548-554`: un `Secure` condiționat e cum ajunge o scurtătură de
 * dezvoltare în producție. Panoul e servit prin CDN peste HTTPS; nu există caz
 * legitim în clar.
 *
 * `SameSite=Strict`, nu `Lax`: cookie-ul nu pleacă nici măcar la o navigare
 * venită din altă parte, deci un link ostil nu poate declanșa nimic autentificat.
 */
export function sessionCookie(token: string, maxAgeS: number): string {
  return `${SESSION_COOKIE}=${token}; Max-Age=${Math.max(0, Math.floor(maxAgeS))}; ` +
         "Path=/; HttpOnly; Secure; SameSite=Strict";
}

/**
 * Cookie-ul pre-auth. Aceleași fanioane, dar `SameSite=Lax`.
 *
 * Motivul e cel scris în `security.py:563-573`: cookie-ul trebuie să
 * supraviețuiască unei navigări către `/login` venite dintr-un link extern,
 * altfel formularul servit atunci n-ar avea niciodată perechea lui. Ce-l face
 * sigur e SEMNĂTURA, nu modul SameSite — el nu autentifică pe nimeni, doar
 * dovedește că formularul e cel pe care l-am servit noi.
 */
export function preauthCookie(value: string, name: string, ttlS: number): string {
  return `${name}=${value}; Max-Age=${Math.floor(ttlS)}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

/** Șterge un cookie. `Max-Age=0` plus valoare goală, pe același `Path`. */
export function clearCookie(name: string): string {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

/**
 * Valoarea unui cookie din cerere, sau `null`.
 *
 * Scris pe față și nu cu o expresie regulată peste tot antetul: `sentinel_csrf`
 * e un prefix al lui... nimic azi, dar o potrivire pe subșir e chiar felul în
 * care un cookie viitor numit `sentinel_session_x` ar fi citit ca sesiune.
 */
export function readCookie(req: Request, name: string): string | null {
  const header = req.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    return part.slice(eq + 1).trim();
  }
  return null;
}

// ---------------------------------------------------------------------------
// Corpul formularului
// ---------------------------------------------------------------------------
/**
 * Cât are voie să aibă un formular de autentificare, în octeți.
 *
 * Aritmetica: 64 de caractere de utilizator + 1024 de parolă + 43 de jeton CSRF
 * + numele câmpurilor, totul în `application/x-www-form-urlencoded`, unde un
 * caracter poate deveni până la 9 octeți (`%F0%9F%98%80`). 8 KiB e de câteva ori
 * marginea și tot mult sub orice ar putea fi o pârghie.
 *
 * De ce ARE nevoie ruta de plafonul ăsta, deși `lib/auth/password.ts` are deja
 * unul: **`verifyPassword` NU aplică `MAX_PASSWORD_LENGTH`.** Doar `hashPassword`
 * cheamă `validatePasswordStrength`. Măsurat de verificator în piesa 1, o parolă
 * de 50 MB se verifică în 212 ms și costă +76 MiB rss — nu e o pârghie de CPU
 * puternică, dar e memorie alocată de cineva care n-are niciun cont. Ruta e
 * singurul loc unde câmpul poate fi mărginit, deci îl mărginește ea.
 *
 * Și se mărginește la CITIRE, în bucăți, nu bufferizând și măsurând după: un
 * corp de 50 MB măsurat după ce a fost citit e 50 MB deja alocați. Aceeași formă
 * ca `readBody` din ruta de ingestie.
 */
export const MAX_FORM_BYTES = 8 * 1024;

export type FormBody = Map<string, string>;

export type FormResult =
  | { ok: true; form: FormBody }
  | { ok: false; reason: "too-large" | "wrong-type" };

const FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";

/**
 * Corpul formularului, mărginit, sau motivul refuzului.
 *
 * `multipart/form-data` NU e acceptat, dinadins: niciun câmp de aici nu e un
 * fișier, iar un parser de multipart e cod care alocă după antete scrise de cine
 * trimite. Un tip de conținut necunoscut e un refuz, nu o încercare de a ghici.
 */
export async function readForm(req: Request): Promise<FormResult> {
  const contentType = (req.headers.get("content-type") ?? "").split(";")[0].trim()
    .toLowerCase();
  if (contentType !== FORM_CONTENT_TYPE) return { ok: false, reason: "wrong-type" };

  const declared = Number(req.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_FORM_BYTES) {
    return { ok: false, reason: "too-large" };
  }

  const stream = req.body;
  if (!stream) return { ok: true, form: new Map() };

  const reader = stream.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_FORM_BYTES) {
      // Se oprește ACUM. Restul nu se mai citește și nu se mai alocă.
      await reader.cancel();
      return { ok: false, reason: "too-large" };
    }
    chunks.push(Buffer.from(value));
  }

  const params = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
  const form: FormBody = new Map();
  // Prima apariție câștigă. `URLSearchParams.get` face la fel, dar scris pe față
  // fiindcă diferența contează: un formular cu două câmpuri `password` e o
  // încercare de a păcăli o verificare făcută pe unul și o folosire a celuilalt.
  for (const [key, value] of params) if (!form.has(key)) form.set(key, value);
  return { ok: true, form };
}

/** Câmpul, sau șirul gol. Niciodată `undefined`: fiecare apelant l-ar trata altfel. */
export function field(form: FormBody, name: string): string {
  return form.get(name) ?? "";
}

// ---------------------------------------------------------------------------
// Răspunsuri
// ---------------------------------------------------------------------------
type ResponseOptions = {
  status?: number;
  cookies?: string[];
  headers?: Record<string, string>;
};

function withHeaders(options: ResponseOptions, extra: Record<string, string>): Headers {
  const headers = new Headers({ ...securityHeaders(), ...extra, ...(options.headers ?? {}) });
  for (const cookie of options.cookies ?? []) headers.append("Set-Cookie", cookie);
  return headers;
}

export function htmlResponse(body: string, options: ResponseOptions = {}): Response {
  return new Response(body, {
    status: options.status ?? 200,
    headers: withHeaders(options, { "Content-Type": "text/html; charset=utf-8" }),
  });
}

/**
 * Redirectare 303.
 *
 * 303 și nu 302: după un POST reușit, 303 spune browserului să ceară destinația
 * cu GET. Cu 302 unele clienți repetă POST-ul, iar aici POST-ul repetat ar fi o
 * a doua autentificare.
 */
export function redirectResponse(location: string, options: ResponseOptions = {}): Response {
  return new Response(null, {
    status: options.status ?? 303,
    headers: withHeaders(options, { Location: location }),
  });
}

/**
 * Un răspuns JSON, cu aceleași antete ca oricare altul.
 *
 * `JSON.stringify` fără indentare, dinadins: corpul unui răspuns trebuie să fie
 * o funcție DOAR de ce s-a cerut. Rutele panoului se sprijină pe asta — un 404
 * pentru un obiect al altei instanțe trebuie să fie identic LA OCTET cu unul
 * pentru un id inexistent, iar orice ar varia în serializare (spații, ordinea
 * cheilor, o marcă de timp) ar fi tocmai diferența care spune că obiectul
 * există.
 */
export function jsonResponse(
  body: unknown, options: ResponseOptions = {},
): Response {
  return new Response(JSON.stringify(body), {
    status: options.status ?? 200,
    headers: withHeaders(options, { "Content-Type": "application/json; charset=utf-8" }),
  });
}

/** Un refuz scurt, în text. Pentru cazurile în care nu se poate randa o pagină. */
export function textResponse(
  body: string, status: number, options: ResponseOptions = {},
): Response {
  return new Response(body, {
    status,
    headers: withHeaders(options, { "Content-Type": "text/plain; charset=utf-8" }),
  });
}
