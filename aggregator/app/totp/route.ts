/**
 * `/totp` — etapa a doua: codul din aplicația de autentificare.
 *
 *     GET  /totp   → formularul (cere o sesiune în așteptare)
 *     POST /totp   → codul verificat → jeton ROTIT, `pending_totp = 0` → /
 *
 * ## De ce jetonul se rotește
 *
 * Rotirea nu e igienă, e reparație (`lib/auth/session.ts`): dacă jetonul etapei
 * întâi a scăpat între cele două etape — un terminal partajat, un jurnal de
 * proxy, istoricul browserului —, valoarea scursă nu mai deschide nimic din
 * clipa în care al doilea factor a trecut. Cookie-ul se rescrie odată cu el.
 *
 * ## De ce CSRF-ul de aici e cel al SESIUNII
 *
 * Fiindcă există o sesiune, iar un jeton legat de ea e strict mai bun decât unul
 * pre-autentificare: jetonul unei alte sesiuni nu trece. Regula de alegere e cea
 * a middleware-ului de pe server (`web/app.py:192-198`), scrisă o singură dată,
 * în `lib/auth/csrf.ts`.
 *
 * ## Sesiunea care dispare sub formular
 *
 * Trei lucruri revocă sesiunea în etapa asta: o blocare de cont, un secret TOTP
 * care nu se mai poate descifra, și un cont dezactivat între etape. Toate trei
 * arată la fel pentru cine se uită doar la cookie — o sesiune care nu mai
 * există. Nu sunt la fel: pentru secretul indescifrabil, NICIUN cod nu va
 * funcționa vreodată, iar operatorului i se spune asta pe `/login?e=totp_key` în
 * loc să fie lăsat să încerce. Aceeași distincție ca `totp_undecryptable` pe
 * server.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { csrfValid } from "@/lib/auth/csrf";
import { sessionByToken } from "@/lib/auth/session";
import { findById } from "@/lib/auth/users";
import {
  SESSION_COOKIE, clearCookie, field, htmlResponse, readCookie, readForm,
  redirectResponse, sessionCookie, textResponse,
} from "@/lib/auth/http";
import { SESSION_TTL_S } from "@/lib/auth/login";
import { totpPage } from "@/lib/auth/render";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /totp", async () => {
    const token = readCookie(req, SESSION_COOKIE);
    const session = token ? await sessionByToken(db, token) : null;
    if (session === null) return redirectResponse("/login?e=expired");
    // O sesiune deja întreagă n-are ce căuta aici: al doilea factor s-a dat.
    if (!session.pendingTotp) return redirectResponse("/panel");

    const user = await findById(db, session.userId);
    if (user === null) return redirectResponse("/login?e=expired");
    return htmlResponse(
      totpPage({ csrfToken: session.csrfToken, username: user.username }));
  });
}

export async function POST(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db, auth, ip, userAgent } = built.context;

  return await guarded("POST /totp", async () => {
    // În `guarded`, ca la `/login`: un flux rupt la mijloc e o excepție, iar una
    // scăpată dintr-un Route Handler e un 500 fără nicio urmă în jurnal.
    const body = await readForm(req);
    if (!body.ok) {
      console.warn(`[aggregator] POST /totp refuzat la citire (${body.reason})`);
      return body.reason === "too-large"
        ? textResponse("Formularul depășește plafonul și a fost oprit la citire.", 413)
        : textResponse(
          "Formularul trebuie trimis ca application/x-www-form-urlencoded.", 415);
    }
    const form = body.form;

    const token = readCookie(req, SESSION_COOKIE);
    const session = token ? await sessionByToken(db, token) : null;
    if (session === null || !session.pendingTotp) {
      // Fără sesiune în așteptare nu există etapa a doua. Cookie-ul se șterge
      // ca un jeton mort să nu rămână într-un browser de pe o mașină comună.
      return redirectResponse("/login?e=expired",
                              { cookies: [clearCookie(SESSION_COOKIE)] });
    }

    if (!csrfValid(session.csrfToken, field(form, "csrf_token"))) {
      console.warn("[aggregator] POST /totp fără jeton CSRF valid");
      const user = await findById(db, session.userId);
      return htmlResponse(
        totpPage({ csrfToken: session.csrfToken, username: user?.username ?? "",
                   error: "Formularul a expirat sau a venit din altă parte. " +
                          "Încearcă din nou." }),
        { status: 403 });
    }

    const result = await auth.verifySecondFactor({
      session, code: field(form, "code"), ip, userAgent,
    });

    if (result.outcome === "ok") {
      return redirectResponse("/panel", {
        cookies: [sessionCookie(result.sessionToken as string, SESSION_TTL_S)],
      });
    }

    // Sesiunea a supraviețuit? Se întreabă BAZA, nu se deduce din verdict: e
    // singurul fapt care spune dacă formularul mai are pe ce sta.
    const survived = await sessionByToken(db, token as string);
    if (survived === null) {
      const reason = result.outcome === "totp_undecryptable" ? "totp_key" : "expired";
      return redirectResponse(`/login?e=${reason}`,
                              { cookies: [clearCookie(SESSION_COOKIE)] });
    }

    const user = await findById(db, session.userId);
    const headers: Record<string, string> = {};
    if (result.retryAfterS) headers["Retry-After"] = String(result.retryAfterS);
    return htmlResponse(
      totpPage({ csrfToken: survived.csrfToken, username: user?.username ?? "",
                 error: result.message }),
      { status: result.status, headers });
  });
}
