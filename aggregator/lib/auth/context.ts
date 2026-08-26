/**
 * Ce are nevoie o rută de autentificare ca să poată răspunde ceva.
 *
 * Construit într-un singur loc fiindcă ordinea contează: fără secretul de
 * sesiune nu există nici cifrarea TOTP, nici semnătura jetonului CSRF
 * pre-autentificare, deci nu se poate nici măcar SERVI formularul de login în
 * siguranță. Diferența dintre „nu sunt configurat" și „te-am refuzat" e ce
 * citește cel care instalează, iar aici e singura suprafață pe care o are — la
 * fel ca `500 nu sunt configurat` din ruta de ingestie.
 *
 * De ce nu se cade înapoi pe nimic: un secret de sesiune implicit ar face
 * jetoanele CSRF și secretele TOTP ale tuturor derivabile de oricine are
 * depozitul, care e public.
 */

import { CryptoConfigError } from "../crypto";
import { ConfigError, readSessionSecret } from "../env";
import { getPool } from "../db";
import { authDb } from "./db";
import { Authenticator } from "./login";
import { PreAuthCsrf } from "./csrf";
import { MAX_USER_AGENT_LENGTH } from "./users";
import { readClientIp } from "./client-ip";
import { jsonResponse, textResponse } from "./http";
import type { AuthDb } from "./db";
import type { ClientIp } from "./client-ip";

export type AuthContext = {
  db: AuthDb;
  auth: Authenticator;
  preauth: PreAuthCsrf;
  ip: ClientIp;
  userAgent: string | null;
};

export type ContextResult =
  | { ok: true; context: AuthContext }
  | { ok: false; response: Response };

export function authContext(req: Request): ContextResult {
  let secret: string;
  let db: AuthDb;
  try {
    secret = readSessionSecret();
    // Dublul de test se pune ÎN LOCUL DRIVERULUI, aici: cererea trece apoi prin
    // `authDb` și prin toată ruta, cod real. Un dublu pus mai sus ar confirma că
    // ne-am chemat propria imitație.
    db = authDb(getPool());
  } catch (err) {
    if (err instanceof ConfigError || err instanceof CryptoConfigError) {
      console.error("[aggregator] panoul nu e configurat:", (err as Error).message);
      return { ok: false,
               response: textResponse("Panoul nu e configurat.", 500) };
    }
    throw err;
  }

  const ip = readClientIp(req.headers);
  const rawAgent = req.headers.get("user-agent");
  return {
    ok: true,
    context: {
      db,
      auth: new Authenticator(db, secret),
      preauth: new PreAuthCsrf(secret),
      ip,
      userAgent: rawAgent ? rawAgent.slice(0, MAX_USER_AGENT_LENGTH) : null,
    },
  };
}

/**
 * Orice eroare neprevăzută dintr-o rută de autentificare devine 503, nu 500.
 *
 * Fail-closed, și motivul e că aici nu există un „eșec neutru": o numărătoare
 * care nu se poate citi, o bază care nu răspunde, o interogare refuzată — toate
 * ar fi, tratate ca „mergem mai departe", exact plafonul care dispare tăcut.
 * 503 spune celui care încearcă să revină, și lasă în jurnal ce s-a întâmplat.
 *
 * Nu ascunde defectul: mesajul real se scrie în jurnalul procesului, care pe
 * găzduire e vizibil în panoul de înregistrări (`watcher/INCARCARE-HOSTINGER.md`).
 */
export async function guarded(
  what: string, work: () => Promise<Response>,
  // Rutele de date ale panoului răspund JSON, inclusiv când răspunsul e un
  // refuz: un client care așteaptă JSON și primește text n-are cum să deosebească
  // „503, revino" de un răspuns stricat, iar diferența aia e chiar ce trebuie să
  // ajungă la operator. Implicitul rămâne textul, pentru paginile de
  // autentificare, unde cel care citește e un om.
  as: "text" | "json" = "text",
): Promise<Response> {
  try {
    return await work();
  } catch (err) {
    console.error(`[aggregator] ${what} a eșuat: ${(err as Error).message}`);
    const headers = { "Retry-After": "30" };
    return as === "json"
      ? jsonResponse({ error: "unavailable" }, { status: 503, headers })
      : textResponse(
        "Autentificarea nu e disponibilă acum. Reîncearcă în câteva momente.", 503,
        { headers });
  }
}
