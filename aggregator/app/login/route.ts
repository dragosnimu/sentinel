/**
 * `/login` — etapa întâi: numele și parola.
 *
 *     GET  /login   → formularul, plus un jeton CSRF semnat, fără stare
 *     POST /login   → parola verificată → sesiune cu `pending_totp = 1` → /totp
 *
 * **`/` nu există încă.** Panoul e piesa 3, deci o autentificare dusă la capăt
 * se termină acum într-un 404. E scris aici ca să nu fie citit ca defect:
 * destinația e cea din `security.py` și rămâne aceeași când apare panoul.
 *
 * Niciun rând nu se creează până când o parolă n-a fost chiar acceptată. Jetonul
 * CSRF al formularului e SEMNAT, nu stocat, exact ca pe server: varianta
 * evidentă — un rând de sesiune de unică folosință per afișare — ar face din
 * `GET /login` un `INSERT`, iar cine cere pagina în buclă ar umple tabela. Vezi
 * `lib/auth/csrf.ts`.
 *
 * ## Ce se poate dovedi de aici și ce nu
 *
 * Antetele de mai jos se citesc dintr-un RĂSPUNS real, în
 * `tests/auth-routes.test.ts`: CSP fără `unsafe-inline`, `Cache-Control:
 * no-store`, fanioanele cookie-ului. Ce NU se poate dovedi de pe mașina asta e
 * că marginea CDN-ului le respectă — proba aia e cea din
 * `watcher/INCARCARE-HOSTINGER.md` (două cereri la șase secunde distanță, cu o
 * valoare care trebuie să difere) și se face pe gazdă, după publicare.
 *
 * `dynamic`/`revalidate` sunt declarația către framework. Ca la ruta de
 * ingestie: un Route Handler cu POST e dinamic oricum, deci exportul se
 * păstrează fiindcă supraviețuiește unei rute viitoare, nu fiindcă l-am văzut
 * având vreun efect. Ce ARE efect observabil e antetul de pe răspuns.
 */

import { PENDING_TOTP_TTL_S, sessionByToken } from "@/lib/auth/session";
import {
  PREAUTH_CSRF_COOKIE, PREAUTH_CSRF_TTL_S, PreAuthCsrf, csrfValid,
} from "@/lib/auth/csrf";
import { authContext, guarded } from "@/lib/auth/context";
import {
  SESSION_COOKIE, clearCookie, field, htmlResponse, preauthCookie, readCookie,
  readForm, redirectResponse, sessionCookie, textResponse,
} from "@/lib/auth/http";
import { SESSION_TTL_S } from "@/lib/auth/login";
import { loginPage } from "@/lib/auth/render";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

/**
 * Mesajele purtate prin `?e=`, ca pe server (`routers/auth.py:52-64`).
 *
 * `totp_key` e singurul eșec pe care o reîncercare nu-l poate repara niciodată.
 * Pe server, textul „sesiunea a expirat" pus aici a trimis operatorul în roata
 * formularului până l-a limitat nginx cu un 429, și nimic de pe ecran n-a
 * pomenit vreodată cauza reală.
 */
const MESSAGES: Record<string, string> = {
  csrf: "Formularul a expirat sau a venit din altă parte. Încearcă din nou.",
  expired: "Sesiunea a expirat.",
  logout: "Ai fost deconectat.",
  totp_key:
    "Secretul celui de-al doilea factor nu mai poate fi descifrat — cheia de " +
    "sesiune a agregatorului s-a schimbat. Contul trebuie reînrolat pe gazdă; " +
    "niciun cod nu va funcționa până atunci.",
};

/** Pagina, cu un jeton pre-auth PROASPĂT și cookie-ul lui. */
function formPage(
  preauth: PreAuthCsrf, options: { error?: string | null; username?: string;
                                  status?: number; retryAfterS?: number } = {},
): Response {
  const [cookieValue, formValue] = preauth.issue();
  const headers: Record<string, string> = {};
  if (options.retryAfterS) headers["Retry-After"] = String(options.retryAfterS);
  return htmlResponse(
    loginPage({ csrfToken: formValue, error: options.error, username: options.username }),
    {
      status: options.status ?? 200,
      cookies: [preauthCookie(cookieValue, PREAUTH_CSRF_COOKIE, PREAUTH_CSRF_TTL_S)],
      headers,
    });
}

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db, preauth } = built.context;

  return await guarded("GET /login", async () => {
    // Deja autentificat? Trimis unde mergea, nu pus în fața unui formular care
    // ar începe o a doua sesiune.
    const token = readCookie(req, SESSION_COOKIE);
    if (token) {
      const existing = await sessionByToken(db, token);
      if (existing) return redirectResponse(existing.pendingTotp ? "/totp" : "/panel");
    }
    const reason = new URL(req.url).searchParams.get("e") ?? "";
    return formPage(preauth, { error: MESSAGES[reason] ?? null });
  });
}

export async function POST(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db, auth, preauth, ip, userAgent } = built.context;

  return await guarded("POST /login", async () => {
    // Corpul, mărginit la CITIRE. Vezi `MAX_FORM_BYTES`: `verifyPassword` nu
    // aplică `MAX_PASSWORD_LENGTH`, deci un câmp nemărginit ar fi memorie
    // alocată de cineva care n-are niciun cont.
    //
    // Citirea e ÎN `guarded` fiindcă un flux care se rupe la mijloc e o excepție,
    // iar o excepție scăpată dintr-un Route Handler e un 500 fără nicio linie în
    // jurnal — adică un refuz care arată ca un defect al panoului.
    const body = await readForm(req);
    if (!body.ok) {
      console.warn(`[aggregator] POST /login refuzat la citire (${body.reason})`);
      return body.reason === "too-large"
        ? textResponse("Formularul depășește plafonul și a fost oprit la citire.", 413)
        : textResponse(
          "Formularul trebuie trimis ca application/x-www-form-urlencoded.", 415);
    }
    const form = body.form;
    const submitted = field(form, "csrf_token");

    // Aceeași regulă ca middleware-ul serverului (`web/app.py:192-198`): dacă
    // cererea poartă o sesiune, se cere jetonul SESIUNII; altfel cel pre-auth.
    // Nu „oricare dintre ele" — un jeton pre-auth acceptat cât timp există o
    // sesiune ar fi un jeton nelegat de nimic.
    const token = readCookie(req, SESSION_COOKIE);
    const session = token ? await sessionByToken(db, token) : null;
    const csrfOk = session === null
      ? preauth.validate(readCookie(req, PREAUTH_CSRF_COOKIE), submitted)
      : csrfValid(session.csrfToken, submitted);

    if (!csrfOk) {
      // 403 cu formularul, nu o redirectare: un refuz care se întoarce ca 303
      // arată, dintr-un test sau dintr-un `curl`, exact ca un drum bun.
      console.warn("[aggregator] POST /login fără jeton CSRF valid");
      return formPage(preauth, { error: MESSAGES.csrf, status: 403 });
    }

    const result = await auth.login({
      username: field(form, "username"),
      password: field(form, "password"),
      ip,
      userAgent,
    });

    // Contul fără al doilea factor primește sesiunea ÎNTREAGĂ chiar aici, cu
    // TTL-ul panoului — nu cu cele cinci minute ale așteptării, fiindcă nu mai
    // urmează nicio etapă care s-o promoveze. Un cookie cu TTL de așteptare pe o
    // sesiune deja completă ar deconecta operatorul după cinci minute, iar
    // simptomul („mă dă afară din senin") nu seamănă deloc cu cauza.
    if (result.outcome === "ok") {
      return redirectResponse("/panel", {
        cookies: [
          sessionCookie(result.sessionToken as string, SESSION_TTL_S),
          clearCookie(PREAUTH_CSRF_COOKIE),
        ],
      });
    }

    if (result.outcome !== "needs_totp") {
      return formPage(preauth, {
        error: result.message,
        username: field(form, "username"),
        status: result.status,
        retryAfterS: result.retryAfterS,
      });
    }

    // Cookie-ul primește TTL-ul sesiunii ÎN AȘTEPTARE, nu al panoului: o sesiune
    // doar-cu-parolă moare în cinci minute (`session.ts`), iar un cookie care ar
    // trăi mai mult decât rândul lui e doar un jeton mort ținut într-un browser.
    return redirectResponse("/totp", {
      cookies: [
        sessionCookie(result.sessionToken as string, PENDING_TOTP_TTL_S),
        // Jetonul pre-auth și-a făcut treaba; de aici încolo decide cel al sesiunii.
        clearCookie(PREAUTH_CSRF_COOKIE),
      ],
    });
  });
}
