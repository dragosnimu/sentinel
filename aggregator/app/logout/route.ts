/**
 * `/logout` — revocă sesiunea.
 *
 * **Numai POST.** Un `GET /logout` ar putea fi declanșat de pe orice pagină
 * ostilă cu un `<img src="…/logout">`, iar rezultatul — cineva scos afară fără
 * să înțeleagă de ce — arată ca o pană a panoului, nu ca un atac. Cererea prin
 * GET primește 405 cu `Allow: POST`, nu 404: diferența dintre „ruta nu există"
 * și „metoda nu se acceptă" e ce citește cine încearcă să înțeleagă.
 *
 * ## Merge și pe o sesiune ÎN AȘTEPTARE, dinadins
 *
 * Butonul „Renunță" de pe pagina de al doilea factor postează aici cu o sesiune
 * `pending_totp`. Dacă ruta ar cere o sesiune întreagă, ar redirecta înapoi la
 * `/totp` — o buclă din care nu se poate abandona o autentificare pe jumătate
 * făcută decât așteptând cinci minute. Aceeași alegere ca `optional_session` pe
 * server.
 *
 * ## Fără sesiune e o operație nulă REUȘITĂ
 *
 * Deconectarea e idempotentă: cine n-are sesiune e deja deconectat. Nu se
 * răspunde cu o eroare, fiindcă „ești deja afară" nu e un eșec — și fiindcă un
 * refuz ar spune cuiva dacă un cookie oarecare e sau nu o sesiune vie.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { PREAUTH_CSRF_COOKIE, csrfValid } from "@/lib/auth/csrf";
import { sessionByToken } from "@/lib/auth/session";
import {
  SESSION_COOKIE, clearCookie, field, readCookie, readForm, redirectResponse,
  textResponse,
} from "@/lib/auth/http";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  return textResponse("Deconectarea se face prin POST.", 405,
                      { headers: { Allow: "POST" } });
}

export async function POST(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db, auth } = built.context;

  return await guarded("POST /logout", async () => {
    // În `guarded`, ca la celelalte două rute: vezi comentariul din `/login`.
    const body = await readForm(req);
    if (!body.ok) {
      console.warn(`[aggregator] POST /logout refuzat la citire (${body.reason})`);
      return body.reason === "too-large"
        ? textResponse("Formularul depășește plafonul și a fost oprit la citire.", 413)
        : textResponse(
          "Formularul trebuie trimis ca application/x-www-form-urlencoded.", 415);
    }

    const token = readCookie(req, SESSION_COOKIE);
    const session = token ? await sessionByToken(db, token) : null;

    if (session !== null) {
      // Sesiune reală, deci jetonul ei decide. Fără verificarea asta, o pagină
      // ostilă ar putea deconecta operatorul ori de câte ori vrea — mărunt, dar
      // e chiar clasa de atac împotriva căreia există jetonul.
      if (!csrfValid(session.csrfToken, field(body.form, "csrf_token"))) {
        console.warn("[aggregator] POST /logout fără jeton CSRF valid");
        return textResponse("Formularul a expirat sau a venit din altă parte.", 403);
      }
      await auth.logout(session);
    }

    // Cookie-urile se șterg pe față, nu se lasă să expire: pe o mașină comună,
    // un jeton revocat rămas în borcan e o valoare pe care o citește următorul.
    return redirectResponse("/login?e=logout", {
      cookies: [clearCookie(SESSION_COOKIE), clearCookie(PREAUTH_CSRF_COOKIE)],
    });
  });
}
